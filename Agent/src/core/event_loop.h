#ifndef FIM_EVENT_LOOP_H
#define FIM_EVENT_LOOP_H

#include <stdint.h>

/* ── 콜백 타입 ───────────────────────────────────────────────
 * el_handler_fn : epoll fd 이벤트 핸들러
 * el_reload_fn  : SIGHUP 재로드 콜백                        */
typedef void (*el_handler_fn)(int fd, uint32_t events, void *ctx);
typedef void (*el_reload_fn)(void);

/* ── API ─────────────────────────────────────────────────────
 * event_loop_init()        epoll + signalfd 초기화
 * event_loop_set_reload_cb SIGHUP 재로드 콜백 등록
 * event_loop_add()         fd를 epoll에 등록
 * event_loop_remove()      fd를 epoll에서 제거
 * event_loop_run()         메인 루프 실행 (블로킹)
 * event_loop_cleanup()     리소스 해제                      */
int  event_loop_init(void);
void event_loop_set_reload_cb(el_reload_fn fn);
int  event_loop_add(int fd, uint32_t events, el_handler_fn handler, void *ctx);
int  event_loop_remove(int fd);
void event_loop_run(void);
void event_loop_cleanup(void);

#endif /* FIM_EVENT_LOOP_H */
