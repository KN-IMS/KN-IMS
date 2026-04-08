#include "tcp_client.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>

int tcp_client_connect(fim_tcp_client_t *c)
{
    /* 1. TCP 소켓 생성 */
    c->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->sockfd < 0) {
        syslog(LOG_ERR, "transport: 소켓 생성 실패");
        return -1;
    }

    /* 2. 서버 주소 연결 */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)c->port);
    if (inet_pton(AF_INET, c->host, &addr.sin_addr) != 1) {
        syslog(LOG_ERR, "transport: 잘못된 서버 주소: %s", c->host);
        close(c->sockfd);
        return -1;
    }
    if (connect(c->sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_WARNING, "transport: 연결 실패 (%s:%d)", c->host, c->port);
        close(c->sockfd);
        return -1;
    }

    /* 3. TLS 핸드셰이크 */
    c->ssl = SSL_new(c->tls_ctx->ctx);
    if (!c->ssl) {
        syslog(LOG_ERR, "transport: SSL 객체 생성 실패");
        close(c->sockfd);
        return -1;
    }
    SSL_set_fd(c->ssl, c->sockfd);

    if (SSL_connect(c->ssl) != 1) {
        syslog(LOG_ERR, "transport: TLS 핸드셰이크 실패");
        SSL_free(c->ssl);
        c->ssl = NULL;
        close(c->sockfd);
        return -1;
    }

    c->connected = 1;
    syslog(LOG_INFO, "transport: mTLS 연결 성공 (%s:%d)", c->host, c->port);
    return 0;
}

void tcp_client_reconnect_loop(fim_tcp_client_t *c)
{
    int backoff = 1;
    while (!c->connected) {
        syslog(LOG_INFO, "transport: %d초 후 재연결 시도...", backoff);
        sleep((unsigned int)backoff);
        if (tcp_client_connect(c) == 0)
            return;
        backoff = (backoff * 2 > 60) ? 60 : backoff * 2;
    }
}

void tcp_client_disconnect(fim_tcp_client_t *c)
{
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->sockfd >= 0) {
        close(c->sockfd);
        c->sockfd = -1;
    }
    c->connected = 0;
}

int tcp_client_register(fim_tcp_client_t *c,
                         const char *hostname,
                         const char *ip,
                         const char *version,
                         const char *os,
                         const char *monitor_type,
                         char *out_agent_id,
                         size_t id_size)
{
    /* REGISTER JSON 조립 */
    char json[512];
    snprintf(json, sizeof(json),
        "{\"hostname\":\"%s\",\"ip\":\"%s\","
        "\"version\":\"%s\",\"os\":\"%s\","
        "\"monitor_type\":\"%s\"}",
        hostname, ip, version, os, monitor_type);

    if (fim_send_frame(c->ssl, FIM_MSG_REGISTER, json) < 0) {
        syslog(LOG_ERR, "transport: REGISTER 전송 실패");
        return -1;
    }

    /* RegisterAck 수신 → {"agent_id":"uuid"} */
    uint8_t msg_type = 0;
    char ack[256];
    if (fim_recv_frame(c->ssl, &msg_type, ack, sizeof(ack)) < 0) {
        syslog(LOG_ERR, "transport: RegisterAck 수신 실패");
        return -1;
    }

    /* agent_id 파싱 (간단 파싱) */
    const char *key = "\"agent_id\":\"";
    char *start = strstr(ack, key);
    if (!start) {
        syslog(LOG_ERR, "transport: agent_id 파싱 실패: %s", ack);
        return -1;
    }
    start += strlen(key);
    char *end = strchr(start, '"');
    if (!end) return -1;

    size_t len = (size_t)(end - start);
    if (len >= id_size) len = id_size - 1;
    memcpy(out_agent_id, start, len);
    out_agent_id[len] = '\0';

    syslog(LOG_INFO, "transport: 등록 완료 (agent_id=%s)", out_agent_id);
    return 0;
}

int tcp_client_send_event(fim_tcp_client_t *c,
                           const char *agent_id,
                           const fim_event_t *ev)
{
    if (!c->connected || !c->ssl) {
        syslog(LOG_WARNING, "transport: 연결 없음 — 이벤트 전송 건너뜀");
        return -1;
    }

    /* 이벤트 타입 변환 */
    const char *evt_str = FIM_EVT_MODIFY;
    switch (ev->type) {
        case FIM_EVENT_CREATE: evt_str = FIM_EVT_CREATE; break;
        case FIM_EVENT_MODIFY: evt_str = FIM_EVT_MODIFY; break;
        case FIM_EVENT_DELETE: evt_str = FIM_EVT_DELETE; break;
        case FIM_EVENT_ATTRIB: evt_str = FIM_EVT_ATTRIB; break;
        case FIM_EVENT_MOVE:   evt_str = FIM_EVT_MOVE;   break;
        default: break;
    }

    /* 탐지 소스 변환 */
    const char *src_str = FIM_SRC_INOTIFY;

    /* FILE_EVENT JSON 조립 (file_path 최대 4095 + 고정 필드 여유) */
    char json[6144];
    snprintf(json, sizeof(json),
        "{\"agent_id\":\"%s\","
        "\"event_type\":\"%s\","
        "\"file_path\":\"%s\","
        "\"file_name\":\"%s\","
        "\"file_hash\":\"\","
        "\"file_permission\":\"\","
        "\"detected_by\":\"%s\","
        "\"pid\":%d,"
        "\"timestamp\":%ld}",
        agent_id,
        evt_str,
        ev->path,
        ev->filename,
        src_str,
        ev->pid,
        (long)ev->timestamp);

    if (fim_send_frame(c->ssl, FIM_MSG_FILE_EVENT, json) < 0) {
        syslog(LOG_WARNING, "transport: FILE_EVENT 전송 실패 → 재연결");
        c->connected = 0;
        tcp_client_disconnect(c);
        tcp_client_reconnect_loop(c);
        return -1;
    }
    return 0;
}

int tcp_client_send_integrity_alert(fim_tcp_client_t *c,
                                     const char *agent_id,
                                     const fim_event_t *ev,
                                     const char *expected_hash,
                                     const char *actual_hash)
{
    if (!c->connected || !c->ssl) return -1;

    char json[8192];
    snprintf(json, sizeof(json),
        "{\"agent_id\":\"%s\","
        "\"event_type\":\"INTEGRITY_VIOLATION\","
        "\"file_path\":\"%s\","
        "\"file_name\":\"%s\","
        "\"expected_hash\":\"%s\","
        "\"actual_hash\":\"%s\","
        "\"detected_by\":\"inotify\","
        "\"pid\":%d,"
        "\"timestamp\":%ld}",
        agent_id,
        ev->path,
        ev->filename,
        expected_hash ? expected_hash : "",
        actual_hash   ? actual_hash   : "",
        ev->pid,
        (long)ev->timestamp);

    if (fim_send_frame(c->ssl, FIM_MSG_FILE_EVENT, json) < 0) {
        syslog(LOG_WARNING, "transport: INTEGRITY_ALERT 전송 실패");
        c->connected = 0;
        tcp_client_disconnect(c);
        tcp_client_reconnect_loop(c);
        return -1;
    }
    return 0;
}

void *tcp_client_recv_loop(void *arg)
{
    fim_tcp_client_t *c = (fim_tcp_client_t *)arg;

    while (c->connected) {
        uint8_t msg_type = 0;
        char buf[4096];

        if (fim_recv_frame(c->ssl, &msg_type, buf, sizeof(buf)) < 0) {
            syslog(LOG_WARNING, "transport: 서버 연결 끊김 → 재연결");
            c->connected = 0;
            tcp_client_disconnect(c);
            tcp_client_reconnect_loop(c);
            continue;
        }

        /* COMMAND 수신 처리 */
        if (msg_type == FIM_MSG_COMMAND) {
            syslog(LOG_INFO, "transport: COMMAND 수신 (무시): %s", buf);
            /* 무결성 검사는 inotify MODIFY 이벤트 시 에이전트가 자동 수행.
             * 서버 명령 기반 온디맨드 스캔은 지원하지 않음. */
        }
    }
    return NULL;
}
