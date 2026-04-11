/*
 * test_transport.c — transport 단독 테스트 바이너리
 *
 * 사용법:
 *   ./test_transport <server_host> <server_port>
 *
 * 인증서 기본 경로 (~/agent/certs/):
 *   ca.crt, agent.crt, agent.key
 *
 * 동작:
 *   1. mTLS 연결
 *   2. REGISTER → RegisterAck (agent_id 수신)
 *   3. 가짜 FILE_EVENT 3건 전송
 *   4. HEARTBEAT 3회 전송 (5초 간격)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tls_context.h"
#include "protocol.h"
#include "tcp_client.h"

/* monitor.h extern 변수 — test 바이너리 전용 더미 정의 */
FILE           *g_log_fp    = NULL;
int             g_use_syslog = 0;
int             g_verbose    = 1;
pthread_mutex_t g_log_lock  = PTHREAD_MUTEX_INITIALIZER;

/* ── 헬퍼: 현재 hostname / IP 가져오기 ──────────── */
static void get_hostname(char *buf, size_t len)
{
    if (gethostname(buf, len) != 0)
        strncpy(buf, "unknown-host", len);
    buf[len - 1] = '\0';
}

static void get_local_ip(const char *server_host, int port, char *buf, size_t len)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { strncpy(buf, "0.0.0.0", len); return; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, server_host, &addr.sin_addr);
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &local_len);
    inet_ntop(AF_INET, &local.sin_addr, buf, (socklen_t)len);
    close(sock);
}

/* ── 인증서 기본 경로 빌드 (~/agent/certs/) ──── */
static void build_cert_path(char *buf, size_t len, const char *filename)
{
    const char *home = getenv("HOME");
    if (!home) home = "/home/user";
    snprintf(buf, len, "%s/agent/certs/%s", home, filename);
}

/* ── 메인 ────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
            "사용법: %s <server_host> <server_port>\n"
            "예시  : %s 192.168.64.1 9000\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *server_host = argv[1];
    int         server_port = atoi(argv[2]);

    /* 인증서 경로 — ~/agent/certs/ 고정 */
    char ca_crt[512], agent_crt[512], agent_key[512];
    build_cert_path(ca_crt,    sizeof(ca_crt),    "ca.crt");
    build_cert_path(agent_crt, sizeof(agent_crt), "agent.crt");
    build_cert_path(agent_key, sizeof(agent_key), "agent.key");

    printf("인증서 경로:\n");
    printf("  CA:        %s\n", ca_crt);
    printf("  agent.crt: %s\n", agent_crt);
    printf("  agent.key: %s\n\n", agent_key);

    /* ── Step 1: TLS 컨텍스트 초기화 ────────────── */
    printf("[1] TLS 컨텍스트 초기화...\n");
    im_tls_ctx_t tls_ctx;
    if (tls_context_init(&tls_ctx, ca_crt, agent_crt, agent_key) < 0) {
        fprintf(stderr, "❌ TLS 컨텍스트 초기화 실패\n");
        return 1;
    }
    printf("    ✅ TLS 컨텍스트 초기화 완료\n");

    /* ── Step 2: TCP + mTLS 연결 ─────────────────── */
    printf("[2] 서버 연결 중... (%s:%d)\n", server_host, server_port);
    im_tcp_client_t client;
    if (im_tcp_init(&client, &tls_ctx, server_host, (uint16_t)server_port) < 0) {
        fprintf(stderr, "TCP 클라이언트 초기화 실패\n");
        tls_context_free(&tls_ctx);
        return 1;
    }

    if (im_tcp_connect(&client) < 0) {
        fprintf(stderr, "서버 연결 실패 (%s:%d)\n", server_host, server_port);
        im_tcp_free(&client);
        tls_context_free(&tls_ctx);
        return 1;
    }
    printf("\tmTLS 연결 성공\n");

    /* ── Step 3: REGISTER ────────────────────────── */
    printf("[3] REGISTER 전송 중...\n");
    char hostname[256] = {0};
    char local_ip[64]  = {0};
    get_hostname(hostname, sizeof(hostname));
    get_local_ip(server_host, server_port, local_ip, sizeof(local_ip));

    char agent_id[128] = {0};
    if (im_tcp_register(&client, hostname, local_ip, IM_MON_EBPF,
                         "Linux", agent_id, sizeof(agent_id)) < 0) {
        fprintf(stderr, "REGISTER 실패\n");
        im_tcp_free(&client);
        tls_context_free(&tls_ctx);
        return 1;
    }
    printf("\t등록 완료 — agent_id: %s\n", agent_id);

    /* ── Step 4: 가짜 FILE_EVENT 3건 ─────────────── */
    printf("[4] FILE_EVENT 전송 (3건)...\n");

    const char *test_paths[] = {
        "/etc/passwd",
        "/tmp/testfile.txt",
        "/home/user/documents/secret.key"
    };
    im_event_type_t test_types[] = {
        IM_EVENT_MODIFY,
        IM_EVENT_CREATE,
        IM_EVENT_DELETE
    };

    for (int i = 0; i < 3; i++) {
        im_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.type      = test_types[i];
        ev.source    = IM_SOURCE_EBPF;
        ev.timestamp = time(NULL);
        ev.pid       = 0;

        /* path / filename 분리 */
        strncpy(ev.path, test_paths[i], sizeof(ev.path) - 1);
        const char *slash = strrchr(test_paths[i], '/');
        strncpy(ev.filename, slash ? slash + 1 : test_paths[i],
                sizeof(ev.filename) - 1);

        if (im_tcp_send_event(&client, &ev) == 0) {
            printf("\t[FILE_EVENT %d] %s → %s\n",
                   i + 1, im_event_type_str(ev.type), ev.path);
        } else {
            printf("\t\t[FILE_EVENT %d] 전송 실패\n", i + 1);
        }
        sleep(1);
    }

    /* ── Step 5: HEARTBEAT 3회 ───────────────────── */
    printf("[5] HEARTBEAT 전송 (3회, 5초 간격)...\n");
    for (int i = 0; i < 3; i++) {
        im_msg_heartbeat_t hb = {
            .agent_id = client.agent_id,
            .status = IM_STATUS_HEALTHY,
            .timestamp = (uint32_t)time(NULL),
        };
        uint8_t buf[13];
        int len = im_heartbeat_encode(&hb, buf, sizeof(buf));

        if (len >= 0 &&
            im_tcp_send_frame(&client, IM_MSG_HEARTBEAT, buf, (uint32_t)len) == 0) {
            printf("\tHEARTBEAT %d 전송\n", i + 1);
        } else {
            printf("\tHEARTBEAT %d 전송 실패\n", i + 1);
        }

        if (i < 2) sleep(5);
    }

    /* ── Step 6: 정리 ────────────────────────────── */
    printf("[6] 연결 종료...\n");
    im_tcp_free(&client);
    tls_context_free(&tls_ctx);
    printf("\t테스트 완료\n");
    return 0;
}
