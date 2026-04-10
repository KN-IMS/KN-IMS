#define _POSIX_C_SOURCE 200809L
#include "tcp_client.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

static uint32_t next_seq(fim_tcp_client_t *cli)
{
    pthread_mutex_lock(&cli->seq_lock);
    uint32_t seq = ++cli->seq_num;
    pthread_mutex_unlock(&cli->seq_lock);
    return seq;
}

static int set_keepalive(int fd)
{
    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0)
        return -1;

    int idle = FIM_KEEPALIVE_IDLE;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0)
        return -1;

    int interval = FIM_KEEPALIVE_INTERVAL;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0)
        return -1;

    int count = FIM_KEEPALIVE_COUNT;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) < 0)
        return -1;

    return 0;
}

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, buf + sent, (int)(len - sent));
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int ssl_read_all(SSL *ssl, uint8_t *buf, size_t len)
{
    size_t received = 0;
    while (received < len) {
        int n = SSL_read(ssl, buf + received, (int)(len - received));
        if (n <= 0) return -1;
        received += (size_t)n;
    }
    return 0;
}

static double apply_jitter(double base)
{
    double jitter = (double)(rand() % (FIM_RECONNECT_JITTER_PCT * 2) - FIM_RECONNECT_JITTER_PCT) / 100.0;
    return base * (1.0 + jitter);
}

static int fim_tcp_send_frame_locked(fim_tcp_client_t *cli, uint8_t type,
                                     const uint8_t *payload, uint32_t payload_len);

static int fim_tcp_recv_frame_locked(fim_tcp_client_t *cli, fim_frame_header_t *hdr,
                                     uint8_t **payload);

static int fim_tcp_register_internal_locked(fim_tcp_client_t *cli,
                                            const char *hostname,
                                            const char *ip_str,
                                            uint8_t monitor_type,
                                            const char *os,
                                            char *agent_id_out,
                                            size_t id_size)
{
    if (!cli || cli->state != FIM_CONN_CONNECTED) return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        syslog(LOG_ERR, "fim-tcp: 잘못된 IP: %s", ip_str);
        return -1;
    }

    fim_msg_register_t msg = {0};
    msg.hostname_len = (uint16_t)strlen(hostname);
    msg.hostname = (char *)hostname;
    msg.ip = ntohl(addr.s_addr);
    msg.monitor_type = monitor_type;
    msg.os_len = (uint16_t)strlen(os);
    msg.os = (char *)os;

    uint8_t buf[1024];
    int len = fim_register_encode(&msg, buf, sizeof(buf));
    if (len < 0) {
        syslog(LOG_ERR, "fim-tcp: REGISTER 직렬화 실패");
        return -1;
    }

    if (fim_tcp_send_frame_locked(cli, FIM_MSG_REGISTER, buf, (uint32_t)len) < 0) {
        syslog(LOG_ERR, "fim-tcp: REGISTER 전송 실패");
        return -1;
    }

    fim_frame_header_t hdr;
    uint8_t *payload = NULL;
    int plen = fim_tcp_recv_frame_locked(cli, &hdr, &payload);
    if (plen < 8 || hdr.type != FIM_MSG_REGISTER || !payload) {
        syslog(LOG_ERR, "fim-tcp: REGISTER ACK 수신 실패 (plen=%d)", plen);
        free(payload);
        return -1;
    }

    const uint8_t *p = payload;
    uint32_t hi;
    uint32_t lo;
    memcpy(&hi, p, 4);
    hi = ntohl(hi);
    memcpy(&lo, p + 4, 4);
    lo = ntohl(lo);
    cli->agent_id = ((uint64_t)hi << 32) | lo;
    free(payload);

    if (agent_id_out && id_size > 0) {
        snprintf(agent_id_out, id_size, "%llu",
                 (unsigned long long)cli->agent_id);
    }

    strncpy(cli->reg_hostname, hostname, sizeof(cli->reg_hostname) - 1);
    strncpy(cli->reg_ip, ip_str, sizeof(cli->reg_ip) - 1);
    strncpy(cli->reg_os, os, sizeof(cli->reg_os) - 1);
    cli->reg_hostname[sizeof(cli->reg_hostname) - 1] = '\0';
    cli->reg_ip[sizeof(cli->reg_ip) - 1] = '\0';
    cli->reg_os[sizeof(cli->reg_os) - 1] = '\0';
    cli->reg_monitor_type = monitor_type;
    cli->reg_cached = 1;

    syslog(LOG_INFO, "fim-tcp: 등록 완료 (agent_id=%llu)",
           (unsigned long long)cli->agent_id);
    return 0;
}

int fim_tcp_init(fim_tcp_client_t *cli, fim_tls_ctx_t *tls,
                 const char *host, uint16_t port)
{
    if (!cli || !tls || !host) return -1;

    memset(cli, 0, sizeof(*cli));
    cli->fd = -1;
    cli->tls = tls;
    cli->state = FIM_CONN_DISCONNECTED;
    cli->port = port;
    strncpy(cli->host, host, sizeof(cli->host) - 1);
    cli->host[sizeof(cli->host) - 1] = '\0';

    pthread_mutex_init(&cli->seq_lock, NULL);
    pthread_mutex_init(&cli->conn_lock, NULL);

    srand((unsigned)time(NULL));
    return 0;
}

static int fim_tcp_connect_locked(fim_tcp_client_t *cli)
{
    if (!cli || !cli->tls) return -1;

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int fd = -1;
    SSL *ssl = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", cli->port);

    if (getaddrinfo(cli->host, port_str, &hints, &res) != 0) {
        syslog(LOG_ERR, "fim-tcp: DNS 해석 실패: %s", cli->host);
        return -1;
    }

    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        syslog(LOG_ERR, "fim-tcp: 소켓 생성 실패: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        syslog(LOG_ERR, "fim-tcp: 연결 실패: %s:%u (%s)",
               cli->host, cli->port, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    if (set_keepalive(fd) < 0)
        syslog(LOG_WARNING, "fim-tcp: keepalive 설정 실패");

    ssl = fim_tls_wrap(cli->tls, fd);
    if (!ssl) {
        close(fd);
        return -1;
    }

    cli->fd = fd;
    cli->ssl = ssl;
    cli->state = FIM_CONN_CONNECTED;
    pthread_mutex_lock(&cli->seq_lock);
    cli->seq_num = 0;
    pthread_mutex_unlock(&cli->seq_lock);
    cli->send_failures = 0;

    syslog(LOG_INFO, "fim-tcp: 서버 연결 성공 %s:%u", cli->host, cli->port);
    return 0;
}

int fim_tcp_connect(fim_tcp_client_t *cli)
{
    int ret;
    if (!cli) return -1;

    pthread_mutex_lock(&cli->conn_lock);
    ret = fim_tcp_connect_locked(cli);
    pthread_mutex_unlock(&cli->conn_lock);
    return ret;
}

static void fim_tcp_disconnect_locked(fim_tcp_client_t *cli)
{
    if (!cli) return;

    SSL *ssl = NULL;
    int fd = -1;

    ssl = cli->ssl;
    fd = cli->fd;
    cli->ssl = NULL;
    cli->fd = -1;
    cli->state = FIM_CONN_DISCONNECTED;
    cli->send_failures = 0;
    pthread_mutex_lock(&cli->seq_lock);
    cli->seq_num = 0;
    pthread_mutex_unlock(&cli->seq_lock);

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
}

void fim_tcp_disconnect(fim_tcp_client_t *cli)
{
    if (!cli) return;

    pthread_mutex_lock(&cli->conn_lock);
    fim_tcp_disconnect_locked(cli);
    pthread_mutex_unlock(&cli->conn_lock);
}

int fim_tcp_reconnect(fim_tcp_client_t *cli)
{
    if (!cli) return -1;

    pthread_mutex_lock(&cli->conn_lock);
    fim_tcp_disconnect_locked(cli);

    double delay = FIM_RECONNECT_INIT_SEC;
    for (int i = 0; i < FIM_RECONNECT_MAX_RETRIES; i++) {
        double wait = apply_jitter(delay);
        struct timespec ts;

        syslog(LOG_INFO, "fim-tcp: 재연결 시도 %d/%d (%.1f초 후)",
               i + 1, FIM_RECONNECT_MAX_RETRIES, wait);

        ts.tv_sec = (time_t)wait;
        ts.tv_nsec = (long)((wait - ts.tv_sec) * 1e9);
        nanosleep(&ts, NULL);

        if (fim_tcp_connect_locked(cli) == 0) {
            if (!cli->reg_cached ||
                fim_tcp_register_internal_locked(cli,
                                                cli->reg_hostname,
                                                cli->reg_ip,
                                                cli->reg_monitor_type,
                                                cli->reg_os,
                                                NULL,
                                                0) == 0) {
                syslog(LOG_INFO, "fim-tcp: 재연결 성공 (시도 %d)", i + 1);
                pthread_mutex_unlock(&cli->conn_lock);
                return 0;
            }

            syslog(LOG_WARNING, "fim-tcp: 재연결 후 재등록 실패");
            fim_tcp_disconnect_locked(cli);
        }

        delay *= FIM_RECONNECT_MULTIPLIER;
        if (delay > FIM_RECONNECT_MAX_SEC)
            delay = FIM_RECONNECT_MAX_SEC;
    }

    syslog(LOG_ERR, "fim-tcp: 재연결 실패 — 최대 시도 횟수 초과 (%d회)",
           FIM_RECONNECT_MAX_RETRIES);
    pthread_mutex_unlock(&cli->conn_lock);
    return -1;
}

static int fim_tcp_send_frame_locked(fim_tcp_client_t *cli, uint8_t type,
                                     const uint8_t *payload, uint32_t payload_len)
{
    if (!cli) return -1;
    if (payload_len > FIM_MAX_FRAME_SIZE) return -1;

    fim_frame_header_t hdr;
    hdr.length = payload_len;
    hdr.type = type;
    int ret = -1;
    int failures = 0;
    int reconnect_needed = 0;
    uint8_t hdr_buf[FIM_FRAME_HEADER_SIZE];

    if (cli->state != FIM_CONN_CONNECTED || !cli->ssl) {
        return -1;
    }

    hdr.seq_num = next_seq(cli);
    fim_frame_header_encode(&hdr, hdr_buf);

    ret = ssl_write_all(cli->ssl, hdr_buf, FIM_FRAME_HEADER_SIZE);
    if (ret == 0 && payload_len > 0)
        ret = ssl_write_all(cli->ssl, payload, payload_len);

    if (ret < 0) {
        cli->send_failures++;
        failures = cli->send_failures;

        if (cli->send_failures >= FIM_SEND_MAX_RETRIES) {
            cli->send_failures = 0;
            reconnect_needed = 1;
        }
    } else {
        cli->send_failures = 0;
    }

    if (ret < 0) {
        syslog(LOG_ERR, "fim-tcp: 프레임 전송 실패 (type=0x%02x, 연속 %d회)",
               type, failures);
        if (reconnect_needed) {
            syslog(LOG_WARNING, "fim-tcp: 전송 %d회 실패 — 재연결 시작",
                   FIM_SEND_MAX_RETRIES);
            return -2;
        }
        return -1;
    }

    return 0;
}

int fim_tcp_send_frame(fim_tcp_client_t *cli, uint8_t type,
                       const uint8_t *payload, uint32_t payload_len)
{
    int ret;
    if (!cli)
        return -1;

    pthread_mutex_lock(&cli->conn_lock);
    ret = fim_tcp_send_frame_locked(cli, type, payload, payload_len);
    pthread_mutex_unlock(&cli->conn_lock);
    return ret;
}

static int fim_tcp_recv_frame_locked(fim_tcp_client_t *cli, fim_frame_header_t *hdr,
                                     uint8_t **payload)
{
    if (!cli || !hdr || !payload)
        return -1;

    *payload = NULL;

    if (cli->state != FIM_CONN_CONNECTED || !cli->ssl)
        return -1;

    uint8_t hdr_buf[FIM_FRAME_HEADER_SIZE];

    if (ssl_read_all(cli->ssl, hdr_buf, FIM_FRAME_HEADER_SIZE) < 0) {
        return -1;
    }

    fim_frame_header_decode(hdr_buf, hdr);

    if (hdr->length > FIM_MAX_FRAME_SIZE) {
        syslog(LOG_ERR, "fim-tcp: 프레임 크기 초과 (%u > %u)",
               hdr->length, FIM_MAX_FRAME_SIZE);
        return -1;
    }

    if (hdr->length > 0) {
        *payload = malloc(hdr->length);
        if (!*payload)
            return -1;

        if (ssl_read_all(cli->ssl, *payload, hdr->length) < 0) {
            free(*payload);
            *payload = NULL;
            return -1;
        }
    }

    return (int)hdr->length;
}

int fim_tcp_recv_frame(fim_tcp_client_t *cli, fim_frame_header_t *hdr,
                       uint8_t **payload)
{
    int ret;
    if (!cli || !hdr || !payload)
        return -1;

    pthread_mutex_lock(&cli->conn_lock);
    ret = fim_tcp_recv_frame_locked(cli, hdr, payload);
    pthread_mutex_unlock(&cli->conn_lock);
    return ret;
}

void fim_tcp_free(fim_tcp_client_t *cli)
{
    if (!cli) return;
    fim_tcp_disconnect(cli);
    pthread_mutex_destroy(&cli->seq_lock);
    pthread_mutex_destroy(&cli->conn_lock);
}

static uint8_t map_event_type(fim_event_type_t t)
{
    switch (t) {
    case FIM_EVENT_CREATE: return FIM_EVT_CREATE;
    case FIM_EVENT_MODIFY: return FIM_EVT_MODIFY;
    case FIM_EVENT_DELETE: return FIM_EVT_DELETE;
    case FIM_EVENT_ATTRIB: return FIM_EVT_ATTRIB;
    case FIM_EVENT_MOVE:   return FIM_EVT_MOVE;
    default:               return FIM_EVT_MODIFY;
    }
}

static uint8_t map_source(fim_event_source_t s)
{
    switch (s) {
    case FIM_SOURCE_EBPF:
        return FIM_MON_EBPF;
    case FIM_SOURCE_LKM:
        return FIM_MON_LKM;
    default:
        return 0;
    }
}

int fim_tcp_register(fim_tcp_client_t *cli,
                     const char *hostname,
                     const char *ip_str,
                     uint8_t monitor_type,
                     const char *os,
                     char *agent_id_out,
                     size_t id_size)
{
    int ret;
    if (!cli) return -1;

    pthread_mutex_lock(&cli->conn_lock);
    ret = fim_tcp_register_internal_locked(cli, hostname, ip_str, monitor_type,
                                           os, agent_id_out, id_size);
    pthread_mutex_unlock(&cli->conn_lock);
    return ret;
}

int fim_tcp_send_event(fim_tcp_client_t *cli, const fim_event_t *ev)
{
    if (!cli || cli->state != FIM_CONN_CONNECTED || !ev) return -1;

    fim_msg_file_event_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.agent_id = cli->agent_id;
    msg.event_type = map_event_type(ev->type);
    msg.file_path_len = (uint16_t)strlen(ev->path);
    msg.file_path = (char *)ev->path;
    msg.file_name_len = (uint16_t)strlen(ev->filename);
    msg.file_name = (char *)ev->filename;
    msg.file_permission = 0;
    msg.detected_by = map_source(ev->source);
    msg.pid = (uint32_t)ev->pid;
    msg.timestamp = (uint32_t)ev->timestamp;

    if (msg.detected_by == 0) {
        syslog(LOG_WARNING, "fim-tcp: 지원하지 않는 이벤트 source=%d — FILE_EVENT 전송 생략",
               (int)ev->source);
        return 0;
    }

    uint8_t buf[8192];
    int len = fim_file_event_encode(&msg, buf, sizeof(buf));
    if (len < 0) {
        syslog(LOG_ERR, "fim-tcp: FILE_EVENT 직렬화 실패");
        return -1;
    }

    int ret = fim_tcp_send_frame(cli, FIM_MSG_FILE_EVENT, buf, (uint32_t)len);
    if (ret < 0)
        syslog(LOG_WARNING, "fim-tcp: FILE_EVENT 전송 실패");

    return ret;
}
