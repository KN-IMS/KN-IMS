/*
 * fanotify_mon.c — fanotify 백엔드 (상시 감시 + 자체 보호)
 *
 * 역할:
 *   - 마운트 포인트 전체를 상시 감시 (백그라운드)
 *   - 어떤 프로세스(PID)가 파일을 변경했는지 추적
 *   - 데몬 바이너리/설정 파일 자체 보호 (protect_paths)
 *   - 이벤트를 공유 큐에 push
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include "monitor.h"

/* FID 모드 info 타입 (커널 5.1+, 헤더 없을 경우 대비) */
#ifndef FAN_EVENT_INFO_TYPE_FID
#define FAN_EVENT_INFO_TYPE_FID       1
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#define FAN_EVENT_INFO_TYPE_DFID      3
#endif

typedef struct {
    int  fd;
    int  watch_count;
    char watch_paths[FIM_MAX_WATCHES][FIM_MAX_PATH];

    /* 자체 보호 경로 */
    int  protect_count;
    char protect_paths[32][FIM_MAX_PATH];
} fanotify_priv_t;

/* ── 유틸리티 ──────────────────────────────────── */

static fim_event_type_t fanotify_mask_to_fim(uint64_t mask) {
    if (mask & FAN_CREATE)       return FIM_EVENT_CREATE;
    if (mask & FAN_MODIFY)       return FIM_EVENT_MODIFY;
    if (mask & FAN_DELETE)        return FIM_EVENT_DELETE;
    if (mask & FAN_ATTRIB)        return FIM_EVENT_ATTRIB;
    if (mask & (FAN_MOVED_FROM | FAN_MOVED_TO)) return FIM_EVENT_MOVE;
    if (mask & FAN_ACCESS)        return FIM_EVENT_ACCESS;
    if (mask & FAN_CLOSE_WRITE)   return FIM_EVENT_MODIFY;
    return FIM_EVENT_UNKNOWN;
}

static int get_path_from_fd(int fd, char *buf, size_t buflen) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(proc_path, buf, buflen - 1);
    if (len < 0) return -1;
    buf[len] = '\0';

    /* 커널이 삭제된 inode에 붙이는 " (deleted)" 접미사 제거 */
    char *deleted = strstr(buf, " (deleted)");
    if (deleted) *deleted = '\0';

    return 0;
}

/* FID 모드: fanotify_event_info_fid 에서 경로 복원 */
static int get_path_from_fid(struct fanotify_event_info_fid *fid,
                             char *buf, size_t buflen) {
    struct file_handle *fh = (struct file_handle *)fid->handle;

    /* 디렉토리 핸들로 fd 열기 (CAP_DAC_READ_SEARCH 필요) */
    int dirfd = open_by_handle_at(AT_FDCWD, fh, O_RDONLY | O_PATH);
    if (dirfd < 0) {
        if (errno == ESTALE)
            LOG_WARN_FIM("[fanotify] FID 만료 (삭제 직후 이벤트): %s", strerror(errno));
        else
            LOG_DEBUG_FIM("[fanotify] open_by_handle_at 실패: %s", strerror(errno));
        return -1;
    }

    char dirpath[FIM_MAX_PATH];
    if (get_path_from_fd(dirfd, dirpath, sizeof(dirpath)) < 0) {
        close(dirfd);
        return -1;
    }
    close(dirfd);

    /* DFID_NAME 타입: file_handle 뒤에 파일명이 붙어 있음 */
    if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
        char *fname = (char *)fh->f_handle + fh->handle_bytes;
        /* "." / ".." 는 디렉토리 자체를 가리키므로 append 하지 않음 */
        int is_dot = (fname[0] == '.' && fname[1] == '\0');
        int is_dotdot = (fname[0] == '.' && fname[1] == '.' && fname[2] == '\0');
        if (fname[0] != '\0' && !is_dot && !is_dotdot)
            snprintf(buf, buflen, "%s/%s", dirpath, fname);
        else
            strncpy(buf, dirpath, buflen - 1);
    } else {
        strncpy(buf, dirpath, buflen - 1);
    }
    buf[buflen - 1] = '\0';

    return 0;
}

static int is_watched_path(fanotify_priv_t *priv, const char *path) {
    for (int i = 0; i < priv->watch_count; i++) {
        if (strncmp(path, priv->watch_paths[i],
                    strlen(priv->watch_paths[i])) == 0)
            return 1;
    }
    return 0;
}

/* 자체 보호 대상인지 확인 */
static int is_protected_path(fanotify_priv_t *priv, const char *path) {
    for (int i = 0; i < priv->protect_count; i++) {
        if (strcmp(path, priv->protect_paths[i]) == 0)
            return 1;
    }
    return 0;
}

/* PID로 프로세스 이름 조회 */
static void get_process_name(pid_t pid, char *buf, size_t buflen) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);
    FILE *fp = fopen(proc_path, "r");
    if (fp) {
        if (fgets(buf, buflen, fp)) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
        }
        fclose(fp);
    } else {
        strncpy(buf, "unknown", buflen - 1);
    }
}

/* ── 백엔드 인터페이스 ─────────────────────────── */

static int fanotify_init_be(fim_backend_t *self, fim_config_t *cfg,
                            fim_event_queue_t *queue) {
    fanotify_priv_t *priv = calloc(1, sizeof(fanotify_priv_t));
    if (!priv) return -1;

    unsigned int flags = FAN_CLASS_NOTIF | FAN_NONBLOCK;

#ifdef FAN_REPORT_FID
    priv->fd = fanotify_init(flags | FAN_REPORT_FID | FAN_REPORT_DFID_NAME,
                             O_RDONLY);
    if (priv->fd >= 0) {
        LOG_INFO_FIM("[fanotify] FID 모드 초기화 (fd=%d)", priv->fd);
        goto init_done;
    }
    LOG_WARN_FIM("[fanotify] FID 모드 불가, 기본 모드로 fallback");
#endif

    priv->fd = fanotify_init(flags, O_RDONLY);
    if (priv->fd < 0) {
        LOG_ERROR_FIM("[fanotify] 초기화 실패: %s (root 필요)", strerror(errno));
        free(priv);
        return -1;
    }
    LOG_INFO_FIM("[fanotify] 기본 모드 초기화 (fd=%d)", priv->fd);

#ifdef FAN_REPORT_FID
init_done:
#endif
    /* 자체 보호 경로 복사 */
    priv->protect_count = cfg->protect_count;
    for (int i = 0; i < cfg->protect_count && i < 32; i++) {
        strncpy(priv->protect_paths[i], cfg->protect_paths[i].path,
                FIM_MAX_PATH - 1);
    }

    self->priv  = priv;
    self->queue = queue;
    return 0;
}

static int fanotify_add_watch_be(fim_backend_t *self, const char *path,
                                 int recursive) {
    (void)recursive;  /* fanotify는 마운트 전체 감시 */
    fanotify_priv_t *priv = (fanotify_priv_t *)self->priv;

    if (priv->watch_count >= FIM_MAX_WATCHES) return -1;

    uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_ACCESS;
#ifdef FAN_CREATE
    /* FAN_ONDIR: 디렉토리 자체에 대한 이벤트(생성/삭제 포함) 수신에 필수 */
    mask |= FAN_CREATE | FAN_DELETE | FAN_ATTRIB | FAN_MOVED_FROM | FAN_MOVED_TO
          | FAN_ONDIR;
#endif

    int ret = -1;
#ifdef FAN_MARK_FILESYSTEM
    ret = fanotify_mark(priv->fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                        mask, AT_FDCWD, path);
#endif
    if (ret < 0)
        ret = fanotify_mark(priv->fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                            mask, AT_FDCWD, path);

    if (ret < 0) {
        LOG_ERROR_FIM("[fanotify] mark 실패: %s (%s)", path, strerror(errno));
        return -1;
    }

    strncpy(priv->watch_paths[priv->watch_count], path, FIM_MAX_PATH - 1);
    priv->watch_count++;

    LOG_INFO_FIM("[fanotify] 상시 감시 등록: %s", path);
    return 0;
}

static int fanotify_remove_watch_be(fim_backend_t *self, const char *path) {
    fanotify_priv_t *priv = (fanotify_priv_t *)self->priv;

    uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_ACCESS;
#ifdef FAN_CREATE
    mask |= FAN_CREATE | FAN_DELETE | FAN_ATTRIB | FAN_MOVED_FROM | FAN_MOVED_TO
          | FAN_ONDIR;
#endif

    fanotify_mark(priv->fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                  mask, AT_FDCWD, path);

    /* 경로 목록에서도 제거 */
    for (int i = 0; i < priv->watch_count; i++) {
        if (strcmp(priv->watch_paths[i], path) == 0) {
            memmove(&priv->watch_paths[i], &priv->watch_paths[i+1],
                    (priv->watch_count - i - 1) * FIM_MAX_PATH);
            priv->watch_count--;
            break;
        }
    }

    LOG_INFO_FIM("[fanotify] 감시 해제: %s", path);
    return 0;
}

static int fanotify_poll_events_be(fim_backend_t *self) {
    fanotify_priv_t *priv = (fanotify_priv_t *)self->priv;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(priv->fd, &fds);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };  /* 200ms */
    int ret = select(priv->fd + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) return 0;

    char buf[8192];
    ssize_t len = read(priv->fd, buf, sizeof(buf));
    if (len <= 0) return 0;

    int count = 0;
    struct fanotify_event_metadata *meta =
        (struct fanotify_event_metadata *)buf;

    while (FAN_EVENT_OK(meta, len)) {
        if (meta->vers != FANOTIFY_METADATA_VERSION) break;

        char filepath[FIM_MAX_PATH] = {0};
        int got_path = 0;

        if (meta->fd >= 0) {
            /* 기본 모드: fd → /proc/self/fd/N */
            if (get_path_from_fd(meta->fd, filepath, sizeof(filepath)) == 0)
                got_path = 1;
            close(meta->fd);

        } else if (meta->fd == FAN_NOFD &&
                   meta->metadata_len < (uint16_t)meta->event_len) {
            /* FID 모드: metadata 뒤에 붙은 info 구조체 순회 */
            char *info_ptr = (char *)meta + meta->metadata_len;
            char *info_end = (char *)meta + meta->event_len;

            while (info_ptr < info_end) {
                struct fanotify_event_info_header *hdr =
                    (struct fanotify_event_info_header *)info_ptr;

                if (hdr->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME ||
                    hdr->info_type == FAN_EVENT_INFO_TYPE_FID      ||
                    hdr->info_type == FAN_EVENT_INFO_TYPE_DFID) {

                    struct fanotify_event_info_fid *fid =
                        (struct fanotify_event_info_fid *)info_ptr;

                    if (get_path_from_fid(fid, filepath, sizeof(filepath)) == 0) {
                        got_path = 1;
                        break;  /* 경로 하나면 충분 */
                    }
                }
                if (hdr->len == 0) break;
                info_ptr += hdr->len;
            }
        }

        /* 자기 자신(데몬)의 동작은 무시 */
        if (meta->pid == getpid()) {
            meta = FAN_EVENT_NEXT(meta, len);
            continue;
        }

        /* FID 경로 복원 실패 + DELETE 계열 → 경로 미상으로라도 기록 */
        if (!got_path && (meta->mask & (FAN_DELETE | FAN_DELETE_SELF |
                                        FAN_MOVED_FROM | FAN_MOVED_TO))) {
            /* 어느 watch 경로 하위인지는 알 수 없으므로 "?" 표기 */
            for (int wi = 0; wi < priv->watch_count; wi++) {
                fim_event_t fe;
                memset(&fe, 0, sizeof(fe));
                fe.type      = fanotify_mask_to_fim(meta->mask);
                fe.source    = FIM_SOURCE_FANOTIFY;
                fe.timestamp = time(NULL);
                fe.pid       = meta->pid;
                snprintf(fe.path, FIM_MAX_PATH, "%s<경로미상>",
                         priv->watch_paths[wi]);
                strncpy(fe.filename, "?", sizeof(fe.filename) - 1);
                fim_queue_push(self->queue, &fe);
            }
            meta = FAN_EVENT_NEXT(meta, len);
            continue;
        }

        if (got_path && is_watched_path(priv, filepath)) {
            fim_event_t fe;
            memset(&fe, 0, sizeof(fe));
            fe.type      = fanotify_mask_to_fim(meta->mask);
            fe.source    = FIM_SOURCE_FANOTIFY;
            fe.timestamp = time(NULL);
            fe.pid       = meta->pid;

            strncpy(fe.path, filepath, FIM_MAX_PATH - 1);
            fe.path[FIM_MAX_PATH - 1] = '\0';
            const char *slash = strrchr(filepath, '/');
            const char *basename = slash ? slash + 1 : filepath;
            if (meta->mask & FAN_ONDIR) {
                /* 디렉토리 이벤트임을 filename에 표시 */
                snprintf(fe.filename, sizeof(fe.filename), "[dir] %s", basename);
            } else {
                strncpy(fe.filename, basename, sizeof(fe.filename) - 1);
                fe.filename[sizeof(fe.filename) - 1] = '\0';
            }

            if (is_protected_path(priv, filepath)) {
                char pname[64] = {0};
                get_process_name(meta->pid, pname, sizeof(pname));
                LOG_ALERT_FIM("*** 자체 보호 위반! %s %s "
                              "(pid=%d, proc=%s) ***",
                              filepath, fim_event_type_str(fe.type),
                              meta->pid, pname);
            }

            fim_queue_push(self->queue, &fe);
            count++;
        }

        meta = FAN_EVENT_NEXT(meta, len);
    }

    return count;
}

static void fanotify_cleanup_be(fim_backend_t *self) {
    fanotify_priv_t *priv = (fanotify_priv_t *)self->priv;
    if (!priv) return;

    close(priv->fd);
    free(priv);
    self->priv = NULL;
    LOG_INFO_FIM("[fanotify] 정리 완료");
}

fim_backend_t *fim_fanotify_create(void) {
    fim_backend_t *be = calloc(1, sizeof(fim_backend_t));
    if (!be) return NULL;

    be->name         = "fanotify";
    be->init         = fanotify_init_be;
    be->add_watch    = fanotify_add_watch_be;
    be->remove_watch = fanotify_remove_watch_be;
    be->poll_events  = fanotify_poll_events_be;
    be->cleanup      = fanotify_cleanup_be;

    return be;
}
