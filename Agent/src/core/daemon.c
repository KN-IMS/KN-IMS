#include "daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

/* ── 시그널 플래그 ───────────────────────────────────────────
 * volatile sig_atomic_t: 시그널 핸들러·메인 루프 간 공유 변수
 * 이 타입만 핸들러 안에서 안전하게 읽고 쓸 수 있음          */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;

/* ── 시그널 핸들러 ───────────────────────────────────────────
 * async-signal-safe 함수만 허용
 * printf / malloc / syslog 전부 금지 — 플래그만 세우고 끝   */
static void handle_sigterm(int sig)
{
    (void)sig;
    g_running = 0;
}

static void handle_sighup(int sig)
{
    (void)sig;
    g_reload = 1;
}

static void handle_sigchld(int sig)
{
    (void)sig;
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved;
}

/* ── 시그널 등록 ─────────────────────────────────────────────*/
void daemon_init_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = handle_sigterm;
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    sa.sa_handler = handle_sighup;
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_handler = handle_sigchld;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sa.sa_flags   = 0;
    sigaction(SIGPIPE, &sa, NULL);
}

/* ── 데몬화 ──────────────────────────────────────────────────*/
int daemon_start(int foreground)
{
    /* 포그라운드/데몬 모드 공통 — 생성 파일 권한 제한 */
    umask(0027);

    if (foreground) {
        openlog("fim-agent", LOG_PID | LOG_PERROR, LOG_DAEMON);
        syslog(LOG_INFO, "starting in foreground mode");
        return 0;
    }

    /* ① 1번째 fork — 부모 종료 → 셸 프롬프트 복귀 */
    pid_t pid = fork();
    if (pid < 0) { perror("fork1"); return -1; }
    if (pid > 0) exit(EXIT_SUCCESS);

    /* ② 새 세션 생성 — 제어 터미널 완전 해제 */
    if (setsid() < 0) { perror("setsid"); return -1; }

    /* ③ 2번째 fork — 세션 리더 방지
     * 실패 시 _exit()로 종료 — atexit 핸들러 실행 방지      */
    pid = fork();
    if (pid < 0) { perror("fork2"); _exit(EXIT_FAILURE); }
    if (pid > 0) _exit(EXIT_SUCCESS);

    /* ④ 작업 디렉토리 → 루트 */
    if (chdir("/") < 0) { perror("chdir"); _exit(EXIT_FAILURE); }

    /* ⑤ 파일 생성 마스크 — 함수 진입 시 공통으로 설정됨 */

    /* ⑥ 상속된 불필요한 fd 전부 닫기 */
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        struct dirent *e;
        int dfd = dirfd(d);
        while ((e = readdir(d)) != NULL) {
            int fd = atoi(e->d_name);
            if (fd >= 3 && fd != dfd)
                close(fd);
        }
        closedir(d);
    } else {
        int maxfd = (int)sysconf(_SC_OPEN_MAX);
        for (int fd = 3; fd < maxfd; fd++) close(fd);
    }

    /* ⑦ stdin·stdout·stderr → /dev/null
     * 실패 시 _exit() — fd 0/1/2가 열린 채로 남는 보안 위험 방지 */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull < 0) { _exit(EXIT_FAILURE); }
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    if (devnull > STDERR_FILENO) close(devnull);

    /* ⑧ syslog 초기화 — 반드시 데몬화 이후에 */
    openlog("fim-agent", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    return 0;
}

/* ── 상태 조회 ───────────────────────────────────────────────*/
int daemon_is_running(void) { return (int)g_running; }

int daemon_need_reload(void)
{
    /* g_reload를 원자적으로 읽고 초기화
     * __sync_val_compare_and_swap: SIGHUP과의 레이스 컨디션 방지 */
    return __sync_val_compare_and_swap(&g_reload, 1, 0);
}

/* ── graceful shutdown ───────────────────────────────────────*/
void daemon_cleanup(void)
{
    syslog(LOG_INFO, "fim-agent stopped (PID %d)", getpid());
    closelog();
}

/* ── systemd sd_notify 래퍼 ──────────────────────────────────
 * HAVE_SYSTEMD 없으면 no-op — 비systemd 환경에서도 빌드 가능 */
void daemon_notify_ready(void)
{
#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1");
#endif
}

void daemon_watchdog_ping(void)
{
#ifdef HAVE_SYSTEMD
    sd_notify(0, "WATCHDOG=1");
#endif
}
