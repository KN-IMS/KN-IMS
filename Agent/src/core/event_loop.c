#include "event_loop.h"
#include "daemon.h"

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

/* ── 상수 ────────────────────────────────────────────────────
 * EL_MAX_FDS    : fd 슬롯 최대 수 (fd는 작은 정수)
 * EL_MAX_EVENTS : epoll_wait 한 번에 처리할 최대 이벤트 수  */
#define EL_MAX_FDS    64
#define EL_MAX_EVENTS 32

/* ── 내부 타입 ───────────────────────────────────────────────*/
typedef struct {
    el_handler_fn handler;
    void         *ctx;
} el_slot_t;

/* ── 전역 상태 ───────────────────────────────────────────────*/
static int          g_epoll_fd  = -1;
static int          g_signal_fd = -1;
static int          g_running   = 1;
static el_slot_t    g_slots[EL_MAX_FDS];
static el_reload_fn g_reload_cb = NULL;

/* ── signalfd 핸들러 ─────────────────────────────────────────
 * SIGTERM·SIGINT : g_running = 0 → 루프 탈출
 * SIGHUP         : 등록된 reload 콜백 호출               */
static void on_signal(int fd, uint32_t events, void *ctx)
{
    (void)events;
    (void)ctx;

    struct signalfd_siginfo info;
    if (read(fd, &info, sizeof(info)) != (ssize_t)sizeof(info))
        return;

    switch ((int)info.ssi_signo) {
    case SIGTERM:
    case SIGINT:
        syslog(LOG_INFO, "event_loop: signal %u — shutting down",
               info.ssi_signo);
        g_running = 0;
        break;
    case SIGHUP:
        syslog(LOG_INFO, "event_loop: SIGHUP — reloading config");
        if (g_reload_cb)
            g_reload_cb();
        break;
    default:
        break;
    }
}

/* ── 초기화 ──────────────────────────────────────────────────
 * 1. epoll 인스턴스 생성
 * 2. SIGTERM·SIGINT·SIGHUP 블록 → signalfd로 변환
 * 3. signalfd를 epoll에 등록                             */
int event_loop_init(void)
{
    memset(g_slots, 0, sizeof(g_slots));
    g_running = 1;

    /* epoll 인스턴스 */
    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd < 0) {
        syslog(LOG_ERR, "event_loop: epoll_create1: %s", strerror(errno));
        return -1;
    }

    /* SIGTERM·SIGINT·SIGHUP 블록 — signalfd가 수신 */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        syslog(LOG_ERR, "event_loop: sigprocmask: %s", strerror(errno));
        return -1;
    }

    /* signalfd 생성 */
    g_signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (g_signal_fd < 0) {
        syslog(LOG_ERR, "event_loop: signalfd: %s", strerror(errno));
        return -1;
    }

    /* signalfd → epoll 등록 */
    if (event_loop_add(g_signal_fd, EPOLLIN, on_signal, NULL) < 0)
        return -1;

    syslog(LOG_INFO, "event_loop: initialized (epoll=%d signal=%d)",
           g_epoll_fd, g_signal_fd);
    return 0;
}

void event_loop_set_reload_cb(el_reload_fn fn)
{
    g_reload_cb = fn;
}

/* ── fd 등록 ─────────────────────────────────────────────────
 * fd를 epoll에 추가하고 핸들러를 슬롯 테이블에 저장
 * 나중에 inotify fd, gRPC 소켓 fd를 여기에 추가          */
int event_loop_add(int fd, uint32_t events, el_handler_fn handler, void *ctx)
{
    if (fd < 0 || fd >= EL_MAX_FDS) {
        syslog(LOG_ERR, "event_loop: fd %d out of range (max %d)",
               fd, EL_MAX_FDS - 1);
        return -1;
    }

    g_slots[fd].handler = handler;
    g_slots[fd].ctx     = ctx;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events  = events;
    ev.data.fd = fd;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        syslog(LOG_ERR, "event_loop: epoll_ctl ADD fd=%d: %s",
               fd, strerror(errno));
        memset(&g_slots[fd], 0, sizeof(g_slots[fd]));
        return -1;
    }

    return 0;
}

/* ── fd 제거 ─────────────────────────────────────────────────*/
int event_loop_remove(int fd)
{
    if (fd < 0 || fd >= EL_MAX_FDS)
        return -1;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        syslog(LOG_ERR, "event_loop: epoll_ctl DEL fd=%d: %s",
               fd, strerror(errno));
        return -1;
    }

    memset(&g_slots[fd], 0, sizeof(g_slots[fd]));
    return 0;
}

/* ── 메인 루프 ───────────────────────────────────────────────
 * sleep() 없이 epoll_wait로 대기 — fd 이벤트 즉시 처리
 * SIGTERM 수신 시 on_signal()이 g_running=0 → 루프 탈출
 * 15초 타임아웃마다 systemd watchdog ping 전송           */
void event_loop_run(void)
{
    struct epoll_event events[EL_MAX_EVENTS];

    syslog(LOG_INFO, "event_loop: running");
    daemon_notify_ready();  /* systemd: READY=1 */

    while (g_running) {
        /* WatchdogSec=30s → 절반인 15초마다 ping */
        int n = epoll_wait(g_epoll_fd, events, EL_MAX_EVENTS, 15000);

        if (n < 0) {
            if (errno == EINTR) continue; /* 시그널 인터럽트 — 재시도 */
            syslog(LOG_ERR, "event_loop: epoll_wait: %s", strerror(errno));
            break;
        }

        if (n == 0) {
            /* 타임아웃 — 이벤트 없음, watchdog ping만 전송 */
            daemon_watchdog_ping();
            continue;
        }

        for (int i = 0; i < n && g_running; i++) {
            int fd = events[i].data.fd;
            if (fd >= 0 && fd < EL_MAX_FDS && g_slots[fd].handler)
                g_slots[fd].handler(fd, events[i].events, g_slots[fd].ctx);
        }

        daemon_watchdog_ping();  /* 이벤트 처리 후 ping */
    }

    syslog(LOG_INFO, "event_loop: stopped");
}

/* ── 정리 ────────────────────────────────────────────────────*/
void event_loop_cleanup(void)
{
    if (g_signal_fd >= 0) { close(g_signal_fd); g_signal_fd = -1; }
    if (g_epoll_fd  >= 0) { close(g_epoll_fd);  g_epoll_fd  = -1; }
    g_running = 1;
}
