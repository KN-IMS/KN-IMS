#ifndef FIM_TCP_CLIENT_H
#define FIM_TCP_CLIENT_H

#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include "tls_context.h"
#include "protocol.h"
#include "../realtime/monitor.h"

#define FIM_RECONNECT_INIT_SEC    1
#define FIM_RECONNECT_MAX_SEC     60
#define FIM_RECONNECT_MULTIPLIER  2
#define FIM_RECONNECT_JITTER_PCT  25
#define FIM_RECONNECT_MAX_RETRIES 20

#define FIM_SEND_MAX_RETRIES      3

#define FIM_KEEPALIVE_IDLE        60
#define FIM_KEEPALIVE_INTERVAL    10
#define FIM_KEEPALIVE_COUNT       3

typedef enum {
    FIM_CONN_DISCONNECTED = 0,
    FIM_CONN_CONNECTED    = 1
} fim_conn_state_t;

typedef struct {
    int              fd;
    SSL             *ssl;
    fim_tls_ctx_t   *tls;
    fim_conn_state_t state;

    char             host[256];
    uint16_t         port;

    uint32_t         seq_num;
    pthread_mutex_t  seq_lock;
    pthread_mutex_t  conn_lock;

    uint64_t         agent_id;
    int              send_failures;

    char             reg_hostname[256];
    char             reg_ip[64];
    uint8_t          reg_monitor_type;
    char             reg_os[64];
    int              reg_cached;
} fim_tcp_client_t;

int fim_tcp_init(fim_tcp_client_t *cli, fim_tls_ctx_t *tls,
                 const char *host, uint16_t port);
int fim_tcp_connect(fim_tcp_client_t *cli);
void fim_tcp_disconnect(fim_tcp_client_t *cli);
int fim_tcp_reconnect(fim_tcp_client_t *cli);

int fim_tcp_send_frame(fim_tcp_client_t *cli, uint8_t type,
                       const uint8_t *payload, uint32_t payload_len);
int fim_tcp_recv_frame(fim_tcp_client_t *cli, fim_frame_header_t *hdr,
                       uint8_t **payload);
void fim_tcp_free(fim_tcp_client_t *cli);

int fim_tcp_register(fim_tcp_client_t *cli,
                     const char *hostname,
                     const char *ip_str,
                     uint8_t monitor_type,
                     const char *os,
                     char *agent_id_out,
                     size_t id_size);

int fim_tcp_send_event(fim_tcp_client_t *cli, const fim_event_t *ev);

#endif /* FIM_TCP_CLIENT_H */
