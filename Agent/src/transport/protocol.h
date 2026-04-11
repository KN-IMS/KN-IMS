#ifndef IM_PROTOCOL_H
#define IM_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

/*
 * Frame Structure
 * length  : 4 bytes
 * type    : 1 byte
 * seq_num : 4 bytes
 * payload : N bytes
 */

#define IM_FRAME_HEADER_SIZE 9
#define IM_MAX_FRAME_SIZE    65535

typedef enum {
    IM_MSG_REGISTER   = 0x01,
    IM_MSG_HEARTBEAT  = 0x02,
    IM_MSG_FILE_EVENT = 0x03
} im_msg_type_t;

typedef enum {
    IM_EVT_CREATE = 0x01,
    IM_EVT_MODIFY = 0x02,
    IM_EVT_DELETE = 0x03,
    IM_EVT_ATTRIB = 0x04,
    IM_EVT_MOVE   = 0x05
} im_evt_type_t;

typedef enum {
    IM_MON_LKM      = 0x02,
    IM_MON_EBPF     = 0x03,
    IM_MON_FANOTIFY = 0x04
} im_mon_type_t;

typedef enum {
    IM_STATUS_ONLINE  = 0x01,
    IM_STATUS_OFFLINE = 0x02,
    IM_STATUS_HEALTHY = 0x03,
    IM_STATUS_WARNING = 0x04,
    IM_STATUS_ERROR   = 0x05
} im_status_t;

typedef struct __attribute__((packed)) {
    uint32_t length;
    uint8_t  type;
    uint32_t seq_num;
} im_frame_header_t;

typedef struct {
    uint16_t hostname_len;
    char    *hostname;
    uint32_t ip;
    uint8_t  monitor_type;
    uint16_t os_len;
    char    *os;
} im_msg_register_t;

typedef struct {
    uint64_t agent_id;
} im_msg_register_resp_t;

typedef struct __attribute__((packed)) {
    uint64_t agent_id;
    uint8_t  status;
    uint32_t timestamp;
} im_msg_heartbeat_t;

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
} im_msg_file_event_t;

int im_frame_header_encode(const im_frame_header_t *h, uint8_t *buf);
int im_frame_header_decode(const uint8_t *buf, im_frame_header_t *h);

int im_register_encode(const im_msg_register_t *msg, uint8_t *buf, size_t buf_size);
int im_register_decode(const uint8_t *buf, size_t len, im_msg_register_t *msg);

int im_heartbeat_encode(const im_msg_heartbeat_t *msg, uint8_t *buf, size_t buf_size);
int im_heartbeat_decode(const uint8_t *buf, size_t len, im_msg_heartbeat_t *msg);

int im_file_event_encode(const im_msg_file_event_t *msg, uint8_t *buf, size_t buf_size);
int im_file_event_decode(const uint8_t *buf, size_t len, im_msg_file_event_t *msg);

void im_register_free(im_msg_register_t *msg);
void im_file_event_free(im_msg_file_event_t *msg);

#endif /* IM_PROTOCOL_H */
