/*
 * lkm_client.c — im_monitor ↔ im_lkm.ko impl
 *
 * - Extract st_dev/st_ino using stat() and inject policy into LKM using ioctl
 * - dev_t encoding conversion: glibc (major<<8)|minor → kernel (major<<20)|minor
 * - lkm_add_from_baseline(): Inject the entire baseline DB at once
 */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/sysmacros.h>  
#include <pthread.h>

#include "lkm_client.h"

static int g_lkm_fd = -1;

static uint64_t stat_dev_to_kernel(dev_t st_dev)
{
    return ((uint64_t)major(st_dev) << 20) | (uint64_t)minor(st_dev);
}

int lkm_client_init(void)
{
    g_lkm_fd = open(IM_LKM_DEV_PATH, O_RDWR);
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

int lkm_add_inode(dev_t st_dev, ino_t st_ino,
                  uint32_t mask, uint32_t block,
                  const char *path)
{
    struct im_lkm_policy_req req = {0};
    req.dev   = stat_dev_to_kernel(st_dev);
    req.ino   = (uint64_t)st_ino;
    req.mask  = mask;
    req.block = block;
    if (path)
        strncpy(req.path, path, sizeof(req.path) - 1);
    return ioctl(g_lkm_fd, IM_IOC_ADD_INODE, &req);
}

int lkm_remove_inode(dev_t st_dev, ino_t st_ino)
{
    struct im_lkm_policy_req req = {0};
    req.dev = stat_dev_to_kernel(st_dev);
    req.ino = (uint64_t)st_ino;
    return ioctl(g_lkm_fd, IM_IOC_REMOVE_INODE, &req);
}

int lkm_clear_all(void)
{
    return ioctl(g_lkm_fd, IM_IOC_CLEAR_ALL, 0);
}

int lkm_add_from_baseline(im_baseline_db_t *db, uint32_t block)
{
    int added = 0;
    uint32_t mask = IM_OP_WRITE | IM_OP_DELETE | IM_OP_RENAME;

    pthread_rwlock_rdlock(&db->lock);

    for (int i = 0; i < db->data.count; i++) {
        const char *path = db->data.entries[i].path;
        struct stat st;

        if (stat(path, &st) < 0)
            continue;  

        if (lkm_add_inode(st.st_dev, st.st_ino, mask, block, path) == 0)
            added++;
    }

    pthread_rwlock_unlock(&db->lock);
    return added;
}

/* ── event polling ────────────────────────────────────────── */

int lkm_read_event(struct im_lkm_event *ev)
{
    ssize_t n = read(g_lkm_fd, ev, sizeof(*ev));
    if (n < 0)                    return -errno;
    if (n != (ssize_t)sizeof(*ev)) return -EIO;
    return 0;
}

int lkm_read_event_timeout(struct im_lkm_event *ev, int timeout_ms)
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
