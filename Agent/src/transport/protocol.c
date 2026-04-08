#include "protocol.h"
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

int fim_recv_frame(SSL *ssl,
                   uint8_t *out_type,
                   char *out_buf,
                   size_t buf_size)
{
    /* 1. 4byte 길이 읽기 (big-endian) */
    uint32_t net_len = 0;
    int r = SSL_read(ssl, &net_len, 4);
    if (r <= 0) {
        syslog(LOG_WARNING, "protocol: 프레임 길이 읽기 실패 (r=%d)", r);
        return -1;
    }
    uint32_t len = ntohl(net_len);

    if (len == 0 || len > (uint32_t)FIM_MAX_FRAME) {
        syslog(LOG_WARNING, "protocol: 잘못된 프레임 크기 (%u)", len);
        return -1;
    }

    /* 2. len 바이트 읽기 */
    char raw[FIM_MAX_FRAME];
    r = SSL_read(ssl, raw, (int)len);
    if (r <= 0 || (uint32_t)r != len) {
        syslog(LOG_WARNING, "protocol: 페이로드 읽기 실패");
        return -1;
    }

    /* 3. 첫 1byte = 타입, 나머지 = JSON */
    *out_type = (uint8_t)raw[0];
    size_t json_len = len - 1;
    if (json_len >= buf_size) {
        syslog(LOG_WARNING, "protocol: 버퍼 부족 (%zu > %zu)", json_len, buf_size);
        return -1;
    }
    memcpy(out_buf, raw + 1, json_len);
    out_buf[json_len] = '\0';
    return 0;
}

int fim_send_frame(SSL *ssl,
                   uint8_t msg_type,
                   const char *json_payload)
{
    size_t json_len  = strlen(json_payload);
    size_t frame_len = 1 + json_len;            /* 1byte 타입 + JSON */

    if (frame_len > FIM_MAX_FRAME) {
        syslog(LOG_WARNING, "protocol: 전송 프레임 초과 (%zu)", frame_len);
        return -1;
    }

    /* [4byte 길이][1byte 타입][JSON] */
    char frame[FIM_MAX_FRAME + 4];
    uint32_t net_len = htonl((uint32_t)frame_len);
    memcpy(frame,     &net_len, 4);
    frame[4] = (char)msg_type;
    memcpy(frame + 5, json_payload, json_len);

    int r = SSL_write(ssl, frame, (int)(4 + frame_len));
    if (r <= 0) {
        syslog(LOG_WARNING, "protocol: 프레임 전송 실패 (r=%d)", r);
        return -1;
    }
    return 0;
}
