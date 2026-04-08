/*
 * inotify_mon.c — inotify 백엔드 (상시 감시 realtime monitor)
 *
 * 역할:
 *   - 설정된 디렉토리를 상시(realtime) 감시
 *   - 재귀적 하위 디렉토리 감시 + 새 디렉토리 자동 추가
 *   - 자체 보호 경로(protect_paths) 변경 시 ALERT 로그
 *   - MODIFY 이벤트 시 파일 해시 검사 훅 포인트 제공
 *   - 런타임 watch 추가/제거 (SIGHUP/SIGUSR1)
 *   - 이벤트를 공유 큐에 push
 *
 * who-data (pid/uid/sid/comm):
 *   inotify 자체로는 변경자 정보 불가.
 *   kernel 5.8+ 에서 eBPF who-cache가 활성화된 경우
 *   main thread의 process_event()에서 보강됨.
 *   이 백엔드는 해당 필드를 0/""로 초기화한다.
 */

#include <stdarg.h>
#include <sys/inotify.h>
#include "monitor.h"


typedef struct {
    int  fd;
    int  wd_count;
    struct {
        int  wd;
        char path[FIM_MAX_PATH];
    } wd_map[FIM_MAX_WATCHES];
    fim_config_t *cfg;    /* 자체 보호 경로 접근용 */
} inotify_priv_t;

/* ── 유틸리티 ──────────────────────────────────── */

static fim_event_type_t inotify_mask_to_fim(uint32_t mask) {
    if (mask & IN_CREATE)      return FIM_EVENT_CREATE;
    if (mask & IN_MODIFY)      return FIM_EVENT_MODIFY;
    if (mask & IN_DELETE)       return FIM_EVENT_DELETE;
    if (mask & IN_DELETE_SELF)  return FIM_EVENT_DELETE;
    if (mask & IN_ATTRIB)       return FIM_EVENT_ATTRIB;
    if (mask & (IN_MOVED_FROM | IN_MOVED_TO)) return FIM_EVENT_MOVE;
    if (mask & IN_ACCESS)       return FIM_EVENT_ACCESS;
    return FIM_EVENT_UNKNOWN;
}

static const char *wd_to_path(inotify_priv_t *priv, int wd) {
    for (int i = 0; i < priv->wd_count; i++) {
        if (priv->wd_map[i].wd == wd)
            return priv->wd_map[i].path;
    }
    return "?";
}

static int is_protected_path(inotify_priv_t *priv, const char *path) {
    if (!priv->cfg) return 0;
    for (int i = 0; i < priv->cfg->protect_count; i++) {
        if (strcmp(priv->cfg->protect_paths[i].path, path) == 0)
            return 1;
    }
    return 0;
}

static int add_single_watch(inotify_priv_t *priv, const char *path) {
    if (priv->wd_count >= FIM_MAX_WATCHES) {
        LOG_WARN_FIM("[inotify] Insufficient watch slots: %s", path);
        return -1;
    }

    /* trailing slash 정규화 — 경로 조합 시 이중 슬래시 방지 */
    char npath[FIM_MAX_PATH];
    strncpy(npath, path, FIM_MAX_PATH - 1);
    npath[FIM_MAX_PATH - 1] = '\0';
    size_t plen = strlen(npath);
    while (plen > 1 && npath[plen - 1] == '/') npath[--plen] = '\0';

    /* 이미 등록된 경로인지 확인 */
    for (int i = 0; i < priv->wd_count; i++) {
        if (strcmp(priv->wd_map[i].path, npath) == 0) {
            LOG_DEBUG_FIM("[inotify] Already monitoring: %s", npath);
            return 0;
        }
    }

    uint32_t mask = IN_CREATE | IN_MODIFY | IN_DELETE | IN_DELETE_SELF
                  | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO;

    int wd = inotify_add_watch(priv->fd, npath, mask);
    if (wd < 0) {
        LOG_ERROR_FIM("[inotify] watch failed: %s (%s)", npath, strerror(errno));
        return -1;
    }

    priv->wd_map[priv->wd_count].wd = wd;
    strncpy(priv->wd_map[priv->wd_count].path, npath, FIM_MAX_PATH - 1);
    priv->wd_count++;

    LOG_DEBUG_FIM("[inotify] watch add: %s (wd=%d, total=%d)",
                  npath, wd, priv->wd_count);
    return 0;
}

static int add_recursive_watch(inotify_priv_t *priv, const char *base) {
    add_single_watch(priv, base);

    DIR *dir = opendir(base);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char subpath[FIM_MAX_PATH];
        snprintf(subpath, sizeof(subpath), "%s/%s", base, entry->d_name);
        add_recursive_watch(priv, subpath);
    }
    closedir(dir);
    return 0;
}

/* ── 백엔드 인터페이스 ─────────────────────────── */

static int inotify_init_be(fim_backend_t *self, fim_config_t *cfg,
                           fim_event_queue_t *queue) {
    inotify_priv_t *priv = calloc(1, sizeof(inotify_priv_t));
    if (!priv) return -1;

    priv->fd  = inotify_init1(IN_NONBLOCK);
    priv->cfg = cfg;   /* 자체 보호 경로 접근용 */

    if (priv->fd < 0) {
        LOG_ERROR_FIM("[inotify] init failed: %s", strerror(errno));
        free(priv);
        return -1;
    }

    self->priv  = priv;
    self->queue = queue;
    LOG_INFO_FIM("[inotify] initialize complete (fd=%d)", priv->fd);
    return 0;
}

static int inotify_add_watch_be(fim_backend_t *self, const char *path, int recursive) {
    inotify_priv_t *priv = (inotify_priv_t *)self->priv;

    /* trailing slash 정규화 */
    char npath[FIM_MAX_PATH];
    strncpy(npath, path, FIM_MAX_PATH - 1);
    npath[FIM_MAX_PATH - 1] = '\0';
    size_t plen = strlen(npath);
    while (plen > 1 && npath[plen - 1] == '/') npath[--plen] = '\0';

    if (recursive)
        return add_recursive_watch(priv, npath);
    return add_single_watch(priv, npath);
}

static int inotify_remove_watch_be(fim_backend_t *self, const char *path) {
    inotify_priv_t *priv = (inotify_priv_t *)self->priv;

    for (int i = 0; i < priv->wd_count; i++) {
        /* prefix 매칭: /tmp/test 삭제 → /tmp/test/sub 도 삭제 */
        if (strncmp(priv->wd_map[i].path, path, strlen(path)) == 0) {
            inotify_rm_watch(priv->fd, priv->wd_map[i].wd);
            LOG_INFO_FIM("[inotify] watch remove: %s (wd=%d)",
                         priv->wd_map[i].path, priv->wd_map[i].wd);

            /* 배열에서 제거 (마지막 원소로 덮어쓰기) */
            priv->wd_map[i] = priv->wd_map[priv->wd_count - 1];
            priv->wd_count--;
            i--;  /* 덮어쓴 자리 다시 검사 */
        }
    }
    return 0;
}

static int inotify_poll_events_be(fim_backend_t *self) {
    inotify_priv_t *priv = (inotify_priv_t *)self->priv;
    char buf[FIM_EVENT_BUF_SIZE];

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(priv->fd, &fds);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };  /* 200ms */
    int ret = select(priv->fd + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) return 0;

    ssize_t len = read(priv->fd, buf, sizeof(buf));
    if (len <= 0) return 0;

    int count = 0;
    char *ptr = buf;
    while (ptr < buf + len) {
        struct inotify_event *ev = (struct inotify_event *)ptr;

        if (ev->len > 0) {
            fim_event_t fe;
            memset(&fe, 0, sizeof(fe));
            fe.type      = inotify_mask_to_fim(ev->mask);
            fe.source    = FIM_SOURCE_INOTIFY;
            fe.timestamp = time(NULL);
            /* who-data: eBPF who-cache가 없으면 0/"" 유지 */
            fe.pid = 0;
            fe.uid = 0;
            fe.sid = 0;
            fe.comm[0] = '\0';

            const char *dir_path = wd_to_path(priv, ev->wd);
            snprintf(fe.path, FIM_MAX_PATH, "%s/%s", dir_path, ev->name);
            strncpy(fe.filename, ev->name, sizeof(fe.filename) - 1);

            /* 자체 보호 경로 변경 감지 */
            if (is_protected_path(priv, fe.path)) {
                LOG_ALERT_FIM("[inotify] self-protection path change detected: %s %s",
                              fe.path, fim_event_type_str(fe.type));
            }

            /*
             * TODO: 파일 해시 검사 훅 포인트
             *   MODIFY 이벤트 발생 시 baseline DB 대비 무결성 검증
             *   if (fe.type == FIM_EVENT_MODIFY) fim_hash_check(fe.path);
             *   구현 위치: src/scanner/baseline.c
             */

            /* 이벤트 큐에 push */
            fim_queue_push(self->queue, &fe);
            count++;

            /* 새 디렉토리 → 자동 watch 추가 */
            if ((ev->mask & IN_CREATE) && (ev->mask & IN_ISDIR)) {
                char newdir[FIM_MAX_PATH];
                snprintf(newdir, sizeof(newdir), "%s/%s", dir_path, ev->name);
                add_recursive_watch(priv, newdir);
            }
        }

        ptr += sizeof(struct inotify_event) + ev->len;
    }

    return count;
}

static void inotify_cleanup_be(fim_backend_t *self) {
    inotify_priv_t *priv = (inotify_priv_t *)self->priv;
    if (!priv) return;

    for (int i = 0; i < priv->wd_count; i++)
        inotify_rm_watch(priv->fd, priv->wd_map[i].wd);

    close(priv->fd);
    free(priv);
    self->priv = NULL;
    LOG_INFO_FIM("[inotify] Successfully cleaned");
}
    
/* ── 생성 함수 ─────────────────────────────────── */
fim_backend_t *fim_inotify_create(void) {
    fim_backend_t *be = calloc(1, sizeof(fim_backend_t));
    if (!be) return NULL;

    be->name         = "inotify";
    be->init         = inotify_init_be;
    be->add_watch    = inotify_add_watch_be;
    be->remove_watch = inotify_remove_watch_be;
    be->poll_events  = inotify_poll_events_be;
    be->cleanup      = inotify_cleanup_be;

    return be;
}
