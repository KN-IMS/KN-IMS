#ifndef FIM_PROTOCOL_H
#define FIM_PROTOCOL_H

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

#define FIM_FRAME_HEADER_SIZE 9
#define FIM_MAX_FRAME_SIZE    65536

typedef enum {
    FIM_MSG_REGISTER   = 0x01,
    FIM_MSG_HEARTBEAT  = 0x02,
    FIM_MSG_FILE_EVENT = 0x03
} fim_msg_type_t;

typedef enum {
    FIM_EVT_CREATE = 0x01,
    FIM_EVT_MODIFY = 0x02,
    FIM_EVT_DELETE = 0x03,
    FIM_EVT_ATTRIB = 0x04,
    FIM_EVT_MOVE   = 0x05
} fim_evt_type_t;

typedef enum {
    FIM_MON_LKM  = 0x02,
    FIM_MON_EBPF = 0x03
} fim_mon_type_t;

typedef enum {
    FIM_STATUS_ONLINE  = 0x01,
    FIM_STATUS_OFFLINE = 0x02,
    FIM_STATUS_HEALTHY = 0x03,
    FIM_STATUS_WARNING = 0x04,
    FIM_STATUS_ERROR   = 0x05
} fim_status_t;

typedef struct __attribute__((packed)) {
    uint32_t length;
    uint8_t  type;
    uint32_t seq_num;
} fim_frame_header_t;

typedef struct {
    uint16_t hostname_len;
    char    *hostname;
    uint32_t ip;
    uint8_t  monitor_type;
    uint16_t os_len;
    char    *os;
} fim_msg_register_t;

typedef struct {
    uint64_t agent_id;
} fim_msg_register_resp_t;

typedef struct __attribute__((packed)) {
    uint64_t agent_id;
    uint8_t  status;
    uint32_t timestamp;
} fim_msg_heartbeat_t;

typedef struct {
    uint64_t agent_id;
    uint8_t  event_type;
    uint16_t file_path_len;
    char    *file_path;
    uint16_t file_name_len;
    char    *file_name;
    uint8_t  file_hash[32];
    uint16_t file_permission;
    uint8_t  detected_by;
    uint32_t pid;
    uint32_t timestamp;
} fim_msg_file_event_t;

int fim_frame_header_encode(const fim_frame_header_t *h, uint8_t *buf);
int fim_frame_header_decode(const uint8_t *buf, fim_frame_header_t *h);

int fim_register_encode(const fim_msg_register_t *msg, uint8_t *buf, size_t buf_size);
int fim_register_decode(const uint8_t *buf, size_t len, fim_msg_register_t *msg);

int fim_heartbeat_encode(const fim_msg_heartbeat_t *msg, uint8_t *buf, size_t buf_size);
int fim_heartbeat_decode(const uint8_t *buf, size_t len, fim_msg_heartbeat_t *msg);

int fim_file_event_encode(const fim_msg_file_event_t *msg, uint8_t *buf, size_t buf_size);
int fim_file_event_decode(const uint8_t *buf, size_t len, fim_msg_file_event_t *msg);

void fim_register_free(fim_msg_register_t *msg);
void fim_file_event_free(fim_msg_file_event_t *msg);

#endif /* FIM_PROTOCOL_H */
