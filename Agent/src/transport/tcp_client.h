#ifndef IG_TCP_CLIENT_H
#define IG_TCP_CLIENT_H

#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include "tls_context.h"
#include "protocol.h"
#include "../realtime/monitor.h"

#define IG_RECONNECT_INIT_SEC    1
#define IG_RECONNECT_MAX_SEC     60
#define IG_RECONNECT_MULTIPLIER  2
#define IG_RECONNECT_JITTER_PCT  25
#define IG_RECONNECT_MAX_RETRIES 20

#define IG_SEND_MAX_RETRIES      3

#define IG_KEEPALIVE_IDLE        60
#define IG_KEEPALIVE_INTERVAL    10
#define IG_KEEPALIVE_COUNT       3

typedef enum {
    IG_CONN_DISCONNECTED = 0,
    IG_CONN_CONNECTED    = 1
} ig_conn_state_t;

typedef struct {
    int              fd;
    SSL             *ssl;
    ig_tls_ctx_t   *tls;
    ig_conn_state_t state;

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
} ig_tcp_client_t;

int ig_tcp_init(ig_tcp_client_t *cli, ig_tls_ctx_t *tls,
                 const char *host, uint16_t port);
int ig_tcp_connect(ig_tcp_client_t *cli);
void ig_tcp_disconnect(ig_tcp_client_t *cli);
int ig_tcp_reconnect(ig_tcp_client_t *cli);

int ig_tcp_send_frame(ig_tcp_client_t *cli, uint8_t type,
                       const uint8_t *payload, uint32_t payload_len);
int ig_tcp_recv_frame(ig_tcp_client_t *cli, ig_frame_header_t *hdr,
                       uint8_t **payload);
void ig_tcp_free(ig_tcp_client_t *cli);

int ig_tcp_register(ig_tcp_client_t *cli,
                     const char *hostname,
                     const char *ip_str,
                     uint8_t monitor_type,
                     const char *os,
                     char *agent_id_out,
                     size_t id_size);

int ig_tcp_send_event(ig_tcp_client_t *cli, const ig_event_t *ev);

#endif /* IG_TCP_CLIENT_H */
