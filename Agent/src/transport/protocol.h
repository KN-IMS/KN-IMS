#ifndef FIM_PROTOCOL_H
#define FIM_PROTOCOL_H

#include <stdint.h>
#include <openssl/ssl.h>

/* Go 서버 pkg/proto/message.go 와 동일한 메시지 타입 */
#define FIM_MSG_REGISTER    0x01
#define FIM_MSG_HEARTBEAT   0x02
#define FIM_MSG_FILE_EVENT  0x03
#define FIM_MSG_SCAN_RESULT 0x04
#define FIM_MSG_COMMAND     0x05

/* 프레임 최대 크기 (1MB) */
#define FIM_MAX_FRAME (1 << 20)

/* 이벤트 타입 문자열 (Go 서버 proto.Event* 상수와 동일) */
#define FIM_EVT_CREATE "CREATE"
#define FIM_EVT_MODIFY "MODIFY"
#define FIM_EVT_DELETE "DELETE"
#define FIM_EVT_ATTRIB "ATTRIB"
#define FIM_EVT_MOVE   "MOVE"

/* 탐지 소스 문자열 */
#define FIM_SRC_INOTIFY  "inotify"
#define FIM_SRC_FANOTIFY "fanotify"

/*
 * fim_recv_frame: SSL에서 프레임 수신
 * [4byte 길이][1byte 타입][payload JSON]
 * out_type: 메시지 타입, out_buf: JSON 페이로드
 */
int fim_recv_frame(SSL *ssl,
                   uint8_t *out_type,
                   char *out_buf,
                   size_t buf_size);

/*
 * fim_send_frame: SSL로 프레임 전송
 * msg_type: 메시지 타입, json_payload: JSON 문자열
 */
int fim_send_frame(SSL *ssl,
                   uint8_t msg_type,
                   const char *json_payload);

#endif /* FIM_PROTOCOL_H */
