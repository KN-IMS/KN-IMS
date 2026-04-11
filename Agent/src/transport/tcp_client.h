#ifndef IM_TCP_CLIENT_H
#define IM_TCP_CLIENT_H

#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include "tls_context.h"
#include "protocol.h"
#include "../realtime/monitor.h"

#define IM_RECONNECT_INIT_SEC    1
#define IM_RECONNECT_MAX_SEC     60
#define IM_RECONNECT_MULTIPLIER  2
#define IM_RECONNECT_JITTER_PCT  25
#define IM_RECONNECT_MAX_RETRIES 20

#define IM_SEND_MAX_RETRIES      3

#define IM_KEEPALIVE_IDLE        60
#define IM_KEEPALIVE_INTERVAL    10
#define IM_KEEPALIVE_COUNT       3

typedef enum {
    IM_CONN_DISCONNECTED = 0,
    IM_CONN_CONNECTED    = 1
} im_conn_state_t;

typedef struct {
    int              fd;
    SSL             *ssl;
    im_tls_ctx_t   *tls;
    im_conn_state_t state;

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
} im_tcp_client_t;

int im_tcp_init(im_tcp_client_t *cli, im_tls_ctx_t *tls,
                 const char *host, uint16_t port);
int im_tcp_connect(im_tcp_client_t *cli);
void im_tcp_disconnect(im_tcp_client_t *cli);
int im_tcp_reconnect(im_tcp_client_t *cli);

int im_tcp_send_frame(im_tcp_client_t *cli, uint8_t type,
                       const uint8_t *payload, uint32_t payload_len);
int im_tcp_recv_frame(im_tcp_client_t *cli, im_frame_header_t *hdr,
                       uint8_t **payload);
void im_tcp_free(im_tcp_client_t *cli);

int im_tcp_register(im_tcp_client_t *cli,
                     const char *hostname,
                     const char *ip_str,
                     uint8_t monitor_type,
                     const char *os,
                     char *agent_id_out,
                     size_t id_size);

int im_tcp_send_event(im_tcp_client_t *cli, const im_event_t *ev);

#endif /* IM_TCP_CLIENT_H */
