#ifndef IM_DAEMON_H
#define IM_DAEMON_H

/* 데몬화 수행
 * foreground=1 이면 데몬화 건너뜀 (개발·디버그·CI 환경용)
 * 성공 0, 실패 -1 반환 */
int  daemon_start(int foreground);

/* SIGTERM·SIGHUP·SIGCHLD·SIGPIPE 핸들러 등록
 * 주의: event_loop_init() 사용 시 호출 불필요
 *       event_loop가 sigprocmask + signalfd로 시그널을 직접 처리함 */
void daemon_init_signals(void);

/* 메인 루프 계속 여부 (0이면 종료) */
int  daemon_is_running(void);

/* SIGHUP 재로드 요청 여부 — 읽으면 플래그 자동 초기화 */
int  daemon_need_reload(void);

/* graceful shutdown 뒷정리 */
void daemon_cleanup(void);

/* systemd sd_notify 래퍼 — HAVE_SYSTEMD 없으면 no-op
 * daemon_notify_ready() : 초기화 완료 신호 (READY=1)
 * daemon_watchdog_ping(): watchdog 생존 신호 (WATCHDOG=1) */
void daemon_notify_ready(void);
void daemon_watchdog_ping(void);

#endif /* IM_DAEMON_H */
