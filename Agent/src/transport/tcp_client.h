#ifndef FIM_TCP_CLIENT_H
#define FIM_TCP_CLIENT_H

#include <openssl/ssl.h>
#include "tls_context.h"
#include "protocol.h"
#include "../realtime/monitor.h"
#include "../scanner/baseline.h"

typedef struct {
    SSL            *ssl;
    int             sockfd;
    fim_tls_ctx_t  *tls_ctx;
    const char     *host;
    int             port;
    volatile int    connected;
} fim_tcp_client_t;

/* TCP + TLS 연결 시도 (실패 시 -1) */
int  tcp_client_connect(fim_tcp_client_t *c);

/* 지수 백오프 재연결 (1→2→4→...→60초 상한) */
void tcp_client_reconnect_loop(fim_tcp_client_t *c);

/* 연결 종료 */
void tcp_client_disconnect(fim_tcp_client_t *c);

/* REGISTER 메시지 전송 → agent_id 수신 후 out_agent_id에 저장 */
int  tcp_client_register(fim_tcp_client_t *c,
                          const char *hostname,
                          const char *ip,
                          const char *version,
                          const char *os,
                          const char *monitor_type,
                          char *out_agent_id,
                          size_t id_size);

/* FILE_EVENT 전송 */
int  tcp_client_send_event(fim_tcp_client_t *c,
                            const char *agent_id,
                            const fim_event_t *ev);

/*
 * INTEGRITY_ALERT 전송 — MODIFY 이벤트 시 해시 불일치 감지 후 서버에 통보
 *   expected_hash : 베이스라인 해시 (없으면 "")
 *   actual_hash   : 현재 파일 해시
 */
int  tcp_client_send_integrity_alert(fim_tcp_client_t *c,
                                      const char *agent_id,
                                      const fim_event_t *ev,
                                      const char *expected_hash,
                                      const char *actual_hash);

/* COMMAND 수신 루프 (별도 스레드에서 호출) */
void *tcp_client_recv_loop(void *arg);

#endif /* FIM_TCP_CLIENT_H */
