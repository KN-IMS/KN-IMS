#include "pid_lock.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <syslog.h>

static int  g_lock_fd                  = -1;
static char g_lock_path[PATH_MAX]      = {0};
static int  g_released                 = 0;

int pid_lock_acquire(const char *path)
{
    strncpy(g_lock_path, path, sizeof(g_lock_path) - 1);

    /* 디렉토리 생성 — 0750: other 접근 차단 */
    char dir[PATH_MAX];
    strncpy(dir, path, sizeof(dir) - 1);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = '\0'; mkdir(dir, 0750); }

    g_lock_fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (g_lock_fd < 0) {
        syslog(LOG_ERR, "pid_lock: open failed: %s", strerror(errno));
        return -1;
    }

    /* fcntl write lock (비차단)
     * 프로세스 종료 시 OS가 fd를 닫으며 잠금 자동 해제 */
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(g_lock_fd, F_SETLK, &fl) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            char buf[16] = {0};
            if (read(g_lock_fd, buf, sizeof(buf) - 1) > 0)
                syslog(LOG_WARNING,
                    "fim-agent already running (PID %s)", buf);
        } else {
            syslog(LOG_ERR, "pid_lock: fcntl failed: %s", strerror(errno));
        }
        close(g_lock_fd);
        g_lock_fd = -1;
        return -1;
    }

    if (ftruncate(g_lock_fd, 0) < 0)
        syslog(LOG_WARNING, "pid_lock: ftruncate failed: %s", strerror(errno));

    char buf[16];
    int  len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    if (write(g_lock_fd, buf, len) < 0)
        syslog(LOG_WARNING, "pid_lock: write pid failed: %s", strerror(errno));
    fsync(g_lock_fd);

    g_released = 0;
    syslog(LOG_INFO, "pid lock acquired: %s (PID %d)", path, getpid());
    return 0;
}

void pid_lock_release(void)
{
    /* 중복 호출 방지 — SIGTERM 핸들러 + main 종료 경로 동시 실행 대비 */
    if (g_released) return;
    g_released = 1;

    if (g_lock_fd >= 0) {
        close(g_lock_fd);
        g_lock_fd = -1;
    }
    if (g_lock_path[0])
        unlink(g_lock_path);

    syslog(LOG_INFO, "pid lock released");
}
