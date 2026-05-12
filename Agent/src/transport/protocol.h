#ifndef IG_PROTOCOL_H
#define IG_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "../scanner/pid_ancestry.h"

/*
 * Frame Structure
 * length  : 4 bytes
 * type    : 1 byte
 * seq_num : 4 bytes
 * payload : N bytes
 */

#define IG_FRAME_HEADER_SIZE 9
#define IG_MAX_FRAME_SIZE    65535
#define IG_MAX_PAYLOAD       (IG_MAX_FRAME_SIZE - IG_FRAME_HEADER_SIZE)

typedef enum {
    IG_MSG_REGISTER   = 0x01,
    IG_MSG_HEARTBEAT  = 0x02,
    IG_MSG_FILE_EVENT = 0x03
} ig_msg_type_t;

typedef enum {
    IG_EVT_CREATE = 0x01,
    IG_EVT_MODIFY = 0x02,
    IG_EVT_DELETE = 0x03,
    IG_EVT_ATTRIB = 0x04,
    IG_EVT_MOVE   = 0x05
} ig_evt_type_t;

typedef enum {
    IG_MON_LKM      = 0x02,
    IG_MON_EBPF     = 0x03,
    IG_MON_FANOTIFY = 0x04
} ig_mon_type_t;

typedef enum {
    IG_STATUS_ONLINE  = 0x01,
    IG_STATUS_OFFLINE = 0x02,
    IG_STATUS_HEALTHY = 0x03,
    IG_STATUS_WARNING = 0x04,
    IG_STATUS_ERROR   = 0x05
} ig_status_t;

typedef struct __attribute__((packed)) {
    uint32_t length;
    uint8_t  type;
    uint32_t seq_num;
} ig_frame_header_t;

typedef struct {
    uint16_t hostname_len;
    char    *hostname;
    uint32_t ip;
    uint8_t  monitor_type;
    uint16_t os_len;
    char    *os;
} ig_msg_register_t;

typedef struct {
    uint64_t agent_id;
} ig_msg_register_resp_t;

typedef struct __attribute__((packed)) {
    uint64_t agent_id;
    uint8_t  status;
    uint32_t timestamp;
} ig_msg_heartbeat_t;

typedef struct {
    uint64_t agent_id;
    uint8_t  event_type;
    uint16_t file_path_len;
    char    *file_path;
    uint16_t file_name_len;
    char    *file_name;
    uint16_t file_permission;
    uint8_t  detected_by;
    uint32_t pid;
    uint32_t timestamp;
    /* v2 — target inode 식별 + chain.
     * 디코더는 wire 끝까지 읽고 남은 바이트가 있으면 v2 필드로 파싱.
     */
    uint64_t target_dev;
    uint64_t target_ino;
    uint8_t  blocked;
    ig_pid_chain_t *chain;   /* not owned; encoder가 직렬화. NULL 가능 */
} ig_msg_file_event_t;

int ig_frame_header_encode(const ig_frame_header_t *h, uint8_t *buf);
int ig_frame_header_decode(const uint8_t *buf, ig_frame_header_t *h);

int ig_register_encode(const ig_msg_register_t *msg, uint8_t *buf, size_t buf_size);
int ig_register_decode(const uint8_t *buf, size_t len, ig_msg_register_t *msg);

int ig_heartbeat_encode(const ig_msg_heartbeat_t *msg, uint8_t *buf, size_t buf_size);
int ig_heartbeat_decode(const uint8_t *buf, size_t len, ig_msg_heartbeat_t *msg);

int ig_file_event_encode(const ig_msg_file_event_t *msg, uint8_t *buf, size_t buf_size);
int ig_file_event_decode(const uint8_t *buf, size_t len, ig_msg_file_event_t *msg);

void ig_register_free(ig_msg_register_t *msg);
void ig_file_event_free(ig_msg_file_event_t *msg);

#endif /* IG_PROTOCOL_H */
