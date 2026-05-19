#define _POSIX_C_SOURCE 200809L
#include "enroll.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#define IG_ENROLL_FRAME_HEADER_SIZE 9
#define IG_ENROLL_MAX_FRAME_SIZE    65535
#define IG_XOR_NONCE_SIZE           32
#define IG_XOR_MAC_SIZE             32

#define IG_MSG_XOR_HELLO            0x21
#define IG_MSG_XOR_CHALLENGE        0x22
#define IG_MSG_XOR_ENROLL_REQUEST   0x23
#define IG_MSG_XOR_ENROLL_RESPONSE  0x24
#define IG_MSG_XOR_ENROLL_ACK       0x25
#define IG_MSG_XOR_ENROLL_ERROR     0x26

typedef struct {
    uint8_t session[32];
    uint8_t enc[32];
    uint8_t mac[32];
} ig_xor_session_t;

typedef struct {
    uint8_t  type;
    uint32_t seq;
    uint8_t *payload;
    uint32_t payload_len;
} ig_frame_t;

typedef struct {
    char    *agent_id;
    char    *agent_cert_pem;
    char    *agent_key_pem;
    char    *ca_cert_pem;
    uint64_t expires_at;
} ig_enroll_response_t;

void ig_secure_bzero(void *p, size_t n)
{
    if (!p || n == 0) return;
    OPENSSL_cleanse(p, n);
}

static uint16_t be16(uint16_t v) { return htons(v); }
static uint32_t be32(uint32_t v) { return htonl(v); }

static uint64_t be64_to_host(const uint8_t *p)
{
    uint32_t hi, lo;
    memcpy(&hi, p, 4);
    memcpy(&lo, p + 4, 4);
    return ((uint64_t)ntohl(hi) << 32) | ntohl(lo);
}

static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len)
{
    size_t received = 0;
    while (received < len) {
        ssize_t n = read(fd, buf + received, len - received);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        received += (size_t)n;
    }
    return 0;
}

static int write_string(uint8_t **p, size_t *remaining, const char *s)
{
    size_t len = s ? strlen(s) : 0;
    if (len > 65535 || *remaining < len + 2) return -1;
    uint16_t n = be16((uint16_t)len);
    memcpy(*p, &n, 2);
    *p += 2;
    *remaining -= 2;
    if (len > 0) {
        memcpy(*p, s, len);
        *p += len;
        *remaining -= len;
    }
    return 0;
}

static int write_bytes(uint8_t **p, size_t *remaining, const uint8_t *data, size_t len)
{
    if (len > 65535 || *remaining < len + 2) return -1;
    uint16_t n = be16((uint16_t)len);
    memcpy(*p, &n, 2);
    *p += 2;
    *remaining -= 2;
    if (len > 0) {
        memcpy(*p, data, len);
        *p += len;
        *remaining -= len;
    }
    return 0;
}

static char *read_string(const uint8_t **p, size_t *remaining)
{
    if (*remaining < 2) return NULL;
    uint16_t len;
    memcpy(&len, *p, 2);
    len = ntohs(len);
    *p += 2;
    *remaining -= 2;
    if (*remaining < len) return NULL;

    char *s = calloc(1, (size_t)len + 1);
    if (!s) return NULL;
    memcpy(s, *p, len);
    *p += len;
    *remaining -= len;
    return s;
}

static uint8_t *read_bytes(const uint8_t **p, size_t *remaining, size_t *out_len)
{
    if (*remaining < 2) return NULL;
    uint16_t len;
    memcpy(&len, *p, 2);
    len = ntohs(len);
    *p += 2;
    *remaining -= 2;
    if (*remaining < len) return NULL;

    uint8_t *b = calloc(1, len ? (size_t)len : 1);
    if (!b) return NULL;
    if (len > 0) memcpy(b, *p, len);
    *p += len;
    *remaining -= len;
    *out_len = len;
    return b;
}

static int connect_tcp(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int fd = -1;
    char port_str[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        syslog(LOG_ERR, "enroll: DNS 해석 실패: %s", host);
        return -1;
    }
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        syslog(LOG_ERR, "enroll: 소켓 생성 실패: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        syslog(LOG_ERR, "enroll: 연결 실패: %s:%u (%s)", host, port, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int write_text_file(const char *path, const char *data, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    if (fchmod(fd, mode) < 0) {
        close(fd);
        return -1;
    }
    size_t len = strlen(data);
    ssize_t written = write(fd, data, len);
    close(fd);
    return written == (ssize_t)len ? 0 : -1;
}

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32])
{
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len)) return -1;
    return out_len == 32 ? 0 : -1;
}

static int derive_session(const char *xor_key, const char *enrollment_id,
                          const uint8_t client_nonce[32],
                          const uint8_t server_nonce[32],
                          ig_xor_session_t *session)
{
    const char label[] = "knig enrollment v2 session";
    const char enc_label[] = "knig enrollment enc";
    const char mac_label[] = "knig enrollment mac";
    size_t id_len = strlen(enrollment_id);
    size_t label_len = sizeof(label) - 1;
    size_t data_len = label_len + 1 + id_len + 1 + 32 + 32;
    uint8_t *data = calloc(1, data_len);
    if (!data) return -1;

    uint8_t *p = data;
    memcpy(p, label, label_len);
    p += label_len + 1;
    memcpy(p, enrollment_id, id_len);
    p += id_len + 1;
    memcpy(p, client_nonce, 32);
    p += 32;
    memcpy(p, server_nonce, 32);

    int ret = -1;
    if (hmac_sha256((const uint8_t *)xor_key, strlen(xor_key), data, data_len, session->session) < 0) goto done;
    if (hmac_sha256(session->session, sizeof(session->session),
                    (const uint8_t *)enc_label, sizeof(enc_label) - 1, session->enc) < 0) goto done;
    if (hmac_sha256(session->session, sizeof(session->session),
                    (const uint8_t *)mac_label, sizeof(mac_label) - 1, session->mac) < 0) goto done;
    ret = 0;

done:
    ig_secure_bzero(data, data_len);
    free(data);
    return ret;
}

static int server_proof(const ig_xor_session_t *session, const char *enrollment_id,
                        const uint8_t client_nonce[32],
                        const uint8_t server_nonce[32],
                        uint8_t out[32])
{
    const char label[] = "knig enrollment server proof";
    size_t id_len = strlen(enrollment_id);
    size_t label_len = sizeof(label) - 1;
    size_t data_len = label_len + 1 + id_len + 1 + 32 + 32;
    uint8_t *data = calloc(1, data_len);
    if (!data) return -1;
    uint8_t *p = data;
    memcpy(p, label, label_len);
    p += label_len + 1;
    memcpy(p, enrollment_id, id_len);
    p += id_len + 1;
    memcpy(p, client_nonce, 32);
    p += 32;
    memcpy(p, server_nonce, 32);
    int ret = hmac_sha256(session->mac, sizeof(session->mac), data, data_len, out);
    ig_secure_bzero(data, data_len);
    free(data);
    return ret;
}

static int frame_mac(const ig_xor_session_t *session, uint8_t msg_type,
                     uint32_t seq, const uint8_t *ciphertext,
                     size_t ciphertext_len, uint8_t out[32])
{
    size_t data_len = 1 + 4 + ciphertext_len;
    uint8_t *data = calloc(1, data_len);
    if (!data) return -1;
    data[0] = msg_type;
    uint32_t seq_be = be32(seq);
    memcpy(data + 1, &seq_be, 4);
    if (ciphertext_len > 0) memcpy(data + 5, ciphertext, ciphertext_len);
    int ret = hmac_sha256(session->mac, sizeof(session->mac), data, data_len, out);
    ig_secure_bzero(data, data_len);
    free(data);
    return ret;
}

static int xor_crypt(const ig_xor_session_t *session, uint32_t seq,
                     const uint8_t *src, uint8_t *dst, size_t len)
{
    uint8_t input[8];
    uint8_t block[32];
    uint32_t seq_be = be32(seq);
    memcpy(input, &seq_be, 4);
    for (size_t offset = 0, counter = 0; offset < len; counter++) {
        uint32_t ctr_be = be32((uint32_t)counter);
        memcpy(input + 4, &ctr_be, 4);
        if (hmac_sha256(session->enc, sizeof(session->enc), input, sizeof(input), block) < 0) {
            ig_secure_bzero(block, sizeof(block));
            return -1;
        }
        for (size_t i = 0; i < sizeof(block) && offset < len; i++, offset++) {
            dst[offset] = src[offset] ^ block[i];
        }
    }
    ig_secure_bzero(input, sizeof(input));
    ig_secure_bzero(block, sizeof(block));
    return 0;
}

static int protect_payload(const ig_xor_session_t *session, uint8_t msg_type,
                           uint32_t seq, const uint8_t *plain, size_t plain_len,
                           uint8_t **out, uint32_t *out_len)
{
    if (plain_len + IG_XOR_MAC_SIZE > IG_ENROLL_MAX_FRAME_SIZE) return -1;
    uint8_t *buf = calloc(1, IG_XOR_MAC_SIZE + plain_len);
    if (!buf) return -1;
    uint8_t *ciphertext = buf + IG_XOR_MAC_SIZE;
    if (xor_crypt(session, seq, plain, ciphertext, plain_len) < 0 ||
        frame_mac(session, msg_type, seq, ciphertext, plain_len, buf) < 0) {
        ig_secure_bzero(buf, IG_XOR_MAC_SIZE + plain_len);
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = (uint32_t)(IG_XOR_MAC_SIZE + plain_len);
    return 0;
}

static int open_protected_payload(const ig_xor_session_t *session, uint8_t msg_type,
                                  uint32_t seq, const uint8_t *payload, size_t payload_len,
                                  uint8_t **out, uint32_t *out_len)
{
    if (payload_len < IG_XOR_MAC_SIZE) return -1;
    const uint8_t *got_mac = payload;
    const uint8_t *ciphertext = payload + IG_XOR_MAC_SIZE;
    size_t cipher_len = payload_len - IG_XOR_MAC_SIZE;
    uint8_t want_mac[32];
    if (frame_mac(session, msg_type, seq, ciphertext, cipher_len, want_mac) < 0) return -1;
    if (CRYPTO_memcmp(got_mac, want_mac, sizeof(want_mac)) != 0) {
        ig_secure_bzero(want_mac, sizeof(want_mac));
        return -1;
    }
    ig_secure_bzero(want_mac, sizeof(want_mac));
    uint8_t *plain = calloc(1, cipher_len ? cipher_len : 1);
    if (!plain) return -1;
    if (xor_crypt(session, seq, ciphertext, plain, cipher_len) < 0) {
        ig_secure_bzero(plain, cipher_len);
        free(plain);
        return -1;
    }
    *out = plain;
    *out_len = (uint32_t)cipher_len;
    return 0;
}

static int send_frame(int fd, uint8_t msg_type, uint32_t seq,
                      const uint8_t *payload, uint32_t payload_len)
{
    if ((uint64_t)payload_len + IG_ENROLL_FRAME_HEADER_SIZE > IG_ENROLL_MAX_FRAME_SIZE) return -1;
    uint8_t hdr[IG_ENROLL_FRAME_HEADER_SIZE];
    uint32_t frame_len = be32(payload_len + IG_ENROLL_FRAME_HEADER_SIZE);
    uint32_t seq_be = be32(seq);
    memcpy(hdr, &frame_len, 4);
    hdr[4] = msg_type;
    memcpy(hdr + 5, &seq_be, 4);
    if (write_all(fd, hdr, sizeof(hdr)) < 0) return -1;
    return payload_len ? write_all(fd, payload, payload_len) : 0;
}

static int read_frame(int fd, ig_frame_t *frame)
{
    uint8_t hdr[IG_ENROLL_FRAME_HEADER_SIZE];
    if (read_all(fd, hdr, sizeof(hdr)) < 0) return -1;
    uint32_t frame_len;
    memcpy(&frame_len, hdr, 4);
    frame_len = ntohl(frame_len);
    if (frame_len < IG_ENROLL_FRAME_HEADER_SIZE || frame_len > IG_ENROLL_MAX_FRAME_SIZE) return -1;

    memset(frame, 0, sizeof(*frame));
    frame->type = hdr[4];
    memcpy(&frame->seq, hdr + 5, 4);
    frame->seq = ntohl(frame->seq);
    frame->payload_len = frame_len - IG_ENROLL_FRAME_HEADER_SIZE;
    frame->payload = calloc(1, frame->payload_len ? frame->payload_len : 1);
    if (!frame->payload) return -1;
    if (frame->payload_len && read_all(fd, frame->payload, frame->payload_len) < 0) {
        free(frame->payload);
        memset(frame, 0, sizeof(*frame));
        return -1;
    }
    return 0;
}

static void frame_free(ig_frame_t *frame)
{
    if (!frame) return;
    free(frame->payload);
    memset(frame, 0, sizeof(*frame));
}

static int encode_hello(const char *enrollment_id, const uint8_t client_nonce[32],
                        uint8_t **out, uint32_t *out_len)
{
    size_t payload_len = 2 + strlen(enrollment_id) + 2 + 32;
    uint8_t *buf = calloc(1, payload_len);
    if (!buf) return -1;
    uint8_t *p = buf;
    size_t remaining = payload_len;
    if (write_string(&p, &remaining, enrollment_id) < 0 ||
        write_bytes(&p, &remaining, client_nonce, 32) < 0 ||
        remaining != 0) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = (uint32_t)payload_len;
    return 0;
}

static int decode_challenge(const ig_frame_t *frame, uint8_t server_nonce[32], uint8_t proof[32])
{
    if (frame->type == IG_MSG_XOR_ENROLL_ERROR) return -2;
    if (frame->type != IG_MSG_XOR_CHALLENGE) return -1;
    const uint8_t *p = frame->payload;
    size_t remaining = frame->payload_len;
    size_t nonce_len = 0, proof_len = 0;
    uint8_t *nonce = read_bytes(&p, &remaining, &nonce_len);
    uint8_t *proof_buf = read_bytes(&p, &remaining, &proof_len);
    int ret = -1;
    if (nonce && proof_buf && nonce_len == 32 && proof_len == 32 && remaining == 0) {
        memcpy(server_nonce, nonce, 32);
        memcpy(proof, proof_buf, 32);
        ret = 0;
    }
    if (nonce) {
        ig_secure_bzero(nonce, nonce_len);
        free(nonce);
    }
    if (proof_buf) {
        ig_secure_bzero(proof_buf, proof_len);
        free(proof_buf);
    }
    return ret;
}

static int encode_request_plain(const ig_enroll_config_t *cfg, uint8_t **out, uint32_t *out_len)
{
    size_t payload_len = 2 + strlen(cfg->hostname) +
                         2 + strlen(cfg->ip) +
                         2 + strlen(cfg->os) +
                         1;
    uint8_t *buf = calloc(1, payload_len);
    if (!buf) return -1;
    uint8_t *p = buf;
    size_t remaining = payload_len;
    if (write_string(&p, &remaining, cfg->hostname) < 0 ||
        write_string(&p, &remaining, cfg->ip) < 0 ||
        write_string(&p, &remaining, cfg->os) < 0 ||
        remaining < 1) {
        ig_secure_bzero(buf, payload_len);
        free(buf);
        return -1;
    }
    *p++ = cfg->monitor_type;
    remaining--;
    if (remaining != 0) {
        ig_secure_bzero(buf, payload_len);
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = (uint32_t)payload_len;
    return 0;
}

static int decode_response_plain(const uint8_t *payload, uint32_t payload_len, ig_enroll_response_t *resp)
{
    const uint8_t *p = payload;
    size_t remaining = payload_len;
    resp->agent_id = read_string(&p, &remaining);
    resp->agent_cert_pem = read_string(&p, &remaining);
    resp->agent_key_pem = read_string(&p, &remaining);
    resp->ca_cert_pem = read_string(&p, &remaining);
    if (!resp->agent_id || !resp->agent_cert_pem || !resp->agent_key_pem || !resp->ca_cert_pem || remaining < 8) {
        return -1;
    }
    resp->expires_at = be64_to_host(p);
    remaining -= 8;
    return remaining == 0 ? 0 : -1;
}

static void response_free(ig_enroll_response_t *resp)
{
    if (!resp) return;
    free(resp->agent_id);
    free(resp->agent_cert_pem);
    if (resp->agent_key_pem) {
        ig_secure_bzero(resp->agent_key_pem, strlen(resp->agent_key_pem));
        free(resp->agent_key_pem);
    }
    free(resp->ca_cert_pem);
    memset(resp, 0, sizeof(*resp));
}

static void log_error_frame(const ig_frame_t *frame)
{
    if (!frame || frame->type != IG_MSG_XOR_ENROLL_ERROR) return;
    const uint8_t *p = frame->payload;
    size_t remaining = frame->payload_len;
    char *msg = read_string(&p, &remaining);
    syslog(LOG_ERR, "enroll: Backend 거부: %s", msg ? msg : "unknown");
    free(msg);
}

int ig_enroll_needed(const char *agent_crt, const char *agent_key)
{
    return access(agent_crt, R_OK) != 0 || access(agent_key, R_OK) != 0;
}

int ig_enroll_execute(const ig_enroll_config_t *cfg)
{
    if (!cfg || !cfg->host || !cfg->ca_crt || !cfg->agent_crt || !cfg->agent_key ||
        !cfg->enrollment_id || !cfg->xor_key || !cfg->hostname || !cfg->ip || !cfg->os) {
        syslog(LOG_ERR, "enroll: 필수 설정 누락");
        return -1;
    }

    int fd = -1;
    int ret = -1;
    uint8_t client_nonce[32];
    uint8_t server_nonce[32];
    uint8_t expected_proof[32];
    uint8_t received_proof[32];
    ig_xor_session_t session;
    memset(&session, 0, sizeof(session));
    uint8_t *hello = NULL, *req_plain = NULL, *req_protected = NULL;
    uint8_t *resp_plain = NULL, *ack_protected = NULL;
    uint32_t hello_len = 0, req_plain_len = 0, req_protected_len = 0;
    uint32_t resp_plain_len = 0, ack_protected_len = 0;
    ig_frame_t frame = {0};
    ig_enroll_response_t resp = {0};

    if (RAND_bytes(client_nonce, sizeof(client_nonce)) != 1) {
        syslog(LOG_ERR, "enroll: nonce 생성 실패");
        goto done;
    }
    if (encode_hello(cfg->enrollment_id, client_nonce, &hello, &hello_len) < 0) {
        syslog(LOG_ERR, "enroll: hello 인코딩 실패");
        goto done;
    }

    fd = connect_tcp(cfg->host, cfg->port);
    if (fd < 0) goto done;

    if (send_frame(fd, IG_MSG_XOR_HELLO, 1, hello, hello_len) < 0) {
        syslog(LOG_ERR, "enroll: hello 전송 실패");
        goto done;
    }
    if (read_frame(fd, &frame) < 0) {
        syslog(LOG_ERR, "enroll: challenge 수신 실패");
        goto done;
    }
    if (frame.type == IG_MSG_XOR_ENROLL_ERROR) {
        log_error_frame(&frame);
        goto done;
    }
    if (decode_challenge(&frame, server_nonce, received_proof) < 0) {
        syslog(LOG_ERR, "enroll: challenge 디코딩 실패");
        goto done;
    }
    frame_free(&frame);

    if (derive_session(cfg->xor_key, cfg->enrollment_id, client_nonce, server_nonce, &session) < 0 ||
        server_proof(&session, cfg->enrollment_id, client_nonce, server_nonce, expected_proof) < 0) {
        syslog(LOG_ERR, "enroll: 세션 키 파생 실패");
        goto done;
    }
    if (CRYPTO_memcmp(expected_proof, received_proof, sizeof(expected_proof)) != 0) {
        syslog(LOG_ERR, "enroll: Backend proof 검증 실패");
        goto done;
    }

    if (encode_request_plain(cfg, &req_plain, &req_plain_len) < 0 ||
        protect_payload(&session, IG_MSG_XOR_ENROLL_REQUEST, 3, req_plain, req_plain_len,
                        &req_protected, &req_protected_len) < 0) {
        syslog(LOG_ERR, "enroll: 요청 보호 실패");
        goto done;
    }
    if (send_frame(fd, IG_MSG_XOR_ENROLL_REQUEST, 3, req_protected, req_protected_len) < 0) {
        syslog(LOG_ERR, "enroll: 요청 전송 실패");
        goto done;
    }

    if (read_frame(fd, &frame) < 0) {
        syslog(LOG_ERR, "enroll: 응답 수신 실패");
        goto done;
    }
    if (frame.type == IG_MSG_XOR_ENROLL_ERROR) {
        log_error_frame(&frame);
        goto done;
    }
    if (frame.type != IG_MSG_XOR_ENROLL_RESPONSE ||
        open_protected_payload(&session, frame.type, frame.seq, frame.payload, frame.payload_len,
                               &resp_plain, &resp_plain_len) < 0) {
        syslog(LOG_ERR, "enroll: 응답 검증 실패");
        goto done;
    }
    if (decode_response_plain(resp_plain, resp_plain_len, &resp) < 0) {
        syslog(LOG_ERR, "enroll: 응답 디코딩 실패");
        goto done;
    }

    if (write_text_file(cfg->ca_crt, resp.ca_cert_pem, 0644) < 0) {
        syslog(LOG_ERR, "enroll: CA 인증서 저장 실패: %s", cfg->ca_crt);
        goto done;
    }
    if (write_text_file(cfg->agent_crt, resp.agent_cert_pem, 0644) < 0) {
        syslog(LOG_ERR, "enroll: 인증서 저장 실패: %s", cfg->agent_crt);
        goto done;
    }
    if (write_text_file(cfg->agent_key, resp.agent_key_pem, 0600) < 0) {
        syslog(LOG_ERR, "enroll: 개인키 저장 실패: %s", cfg->agent_key);
        goto done;
    }

    if (protect_payload(&session, IG_MSG_XOR_ENROLL_ACK, 5, (const uint8_t *)"", 0,
                        &ack_protected, &ack_protected_len) == 0) {
        (void)send_frame(fd, IG_MSG_XOR_ENROLL_ACK, 5, ack_protected, ack_protected_len);
    }

    syslog(LOG_INFO, "enroll: 등록 성공 (agent_id=%s, expires_at=%llu)",
           resp.agent_id, (unsigned long long)resp.expires_at);
    ret = 0;

done:
    frame_free(&frame);
    response_free(&resp);
    if (hello) {
        ig_secure_bzero(hello, hello_len);
        free(hello);
    }
    if (req_plain) {
        ig_secure_bzero(req_plain, req_plain_len);
        free(req_plain);
    }
    if (req_protected) {
        ig_secure_bzero(req_protected, req_protected_len);
        free(req_protected);
    }
    if (resp_plain) {
        ig_secure_bzero(resp_plain, resp_plain_len);
        free(resp_plain);
    }
    if (ack_protected) {
        ig_secure_bzero(ack_protected, ack_protected_len);
        free(ack_protected);
    }
    ig_secure_bzero(client_nonce, sizeof(client_nonce));
    ig_secure_bzero(server_nonce, sizeof(server_nonce));
    ig_secure_bzero(expected_proof, sizeof(expected_proof));
    ig_secure_bzero(received_proof, sizeof(received_proof));
    ig_secure_bzero(&session, sizeof(session));
    if (fd >= 0) close(fd);
    return ret;
}
