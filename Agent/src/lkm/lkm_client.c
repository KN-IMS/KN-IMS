/*
 * lkm_client.c — fim_monitor 유저스페이스 ↔ fim_lkm.ko 통신 구현
 *
 * - stat()으로 st_dev/st_ino 추출 후 ioctl로 LKM에 정책 주입
 * - dev_t 인코딩 변환: glibc (major<<8)|minor → 커널 (major<<20)|minor
 * - lkm_add_from_baseline(): 베이스라인 DB 전체를 한 번에 주입
 */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/sysmacros.h>   /* major(), minor() */
#include <pthread.h>

#include "lkm_client.h"

static int g_lkm_fd = -1;

/* ── dev_t 변환 ──────────────────────────────────────────
 * 유저스페이스 stat() st_dev:  glibc 인코딩 (major << 8)  | minor
 * 커널 i_sb->s_dev:            커널 인코딩  (major << 20) | minor
 * major() / minor() 매크로가 glibc 인코딩을 올바르게 분해한다.
 * ──────────────────────────────────────────────────────── */
static uint64_t stat_dev_to_kernel(dev_t st_dev)
{
    return ((uint64_t)major(st_dev) << 20) | (uint64_t)minor(st_dev);
}

/* ── 초기화 / 정리 ──────────────────────────────────────── */

int lkm_client_init(void)
{
    g_lkm_fd = open(FIM_LKM_DEV_PATH, O_RDWR);
    if (g_lkm_fd < 0)
        return -errno;
    return 0;
}

void lkm_client_cleanup(void)
{
    if (g_lkm_fd >= 0) {
        close(g_lkm_fd);
        g_lkm_fd = -1;
    }
}

int lkm_client_ready(void)
{
    return g_lkm_fd >= 0;
}

/* ── 정책 조작 ──────────────────────────────────────────── */

int lkm_add_inode(dev_t st_dev, ino_t st_ino,
                  uint32_t mask, uint32_t block,
                  const char *path)
{
    struct fim_lkm_policy_req req = {0};
    req.dev   = stat_dev_to_kernel(st_dev);
    req.ino   = (uint64_t)st_ino;
    req.mask  = mask;
    req.block = block;
    if (path)
        strncpy(req.path, path, sizeof(req.path) - 1);
    return ioctl(g_lkm_fd, FIM_IOC_ADD_INODE, &req);
}

int lkm_remove_inode(dev_t st_dev, ino_t st_ino)
{
    struct fim_lkm_policy_req req = {0};
    req.dev = stat_dev_to_kernel(st_dev);
    req.ino = (uint64_t)st_ino;
    return ioctl(g_lkm_fd, FIM_IOC_REMOVE_INODE, &req);
}

int lkm_clear_all(void)
{
    return ioctl(g_lkm_fd, FIM_IOC_CLEAR_ALL, 0);
}

/*
 * lkm_add_from_baseline — 베이스라인 DB 전체를 LKM 정책으로 주입
 *
 * baseline entry에는 path만 있고 dev/ino가 없으므로
 * 각 파일에 stat()을 호출해서 가져온다.
 * 삭제되거나 접근 불가한 파일은 건너뜀.
 */
int lkm_add_from_baseline(fim_baseline_db_t *db, uint32_t block)
{
    int added = 0;
    uint32_t mask = FIM_OP_WRITE | FIM_OP_DELETE | FIM_OP_RENAME;

    pthread_rwlock_rdlock(&db->lock);

    for (int i = 0; i < db->data.count; i++) {
        const char *path = db->data.entries[i].path;
        struct stat st;

        if (stat(path, &st) < 0)
            continue;   /* 접근 불가 / 삭제된 파일 스킵 */

        if (lkm_add_inode(st.st_dev, st.st_ino, mask, block, path) == 0)
            added++;
    }

    pthread_rwlock_unlock(&db->lock);
    return added;
}

/* ── 이벤트 수신 ────────────────────────────────────────── */

int lkm_read_event(struct fim_lkm_event *ev)
{
    ssize_t n = read(g_lkm_fd, ev, sizeof(*ev));
    if (n < 0)                    return -errno;
    if (n != (ssize_t)sizeof(*ev)) return -EIO;
    return 0;
}

/*
 * lkm_read_event_timeout — timeout_ms 동안 이벤트 대기
 * 반환: 0=이벤트 수신, -ETIMEDOUT=타임아웃, 음수=오류
 * g_running 체크를 위해 메인 루프에서 짧은 타임아웃으로 폴링.
 */
int lkm_read_event_timeout(struct fim_lkm_event *ev, int timeout_ms)
{
    fd_set rfds;
    struct timeval tv;
    int ret;

    FD_ZERO(&rfds);
    FD_SET(g_lkm_fd, &rfds);
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(g_lkm_fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0)  return -errno;
    if (ret == 0) return -ETIMEDOUT;

    return lkm_read_event(ev);
}
