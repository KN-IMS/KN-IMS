#include "protocol.h"
#include <string.h>
#include <stdlib.h>

static inline void write_u8(uint8_t **p, uint8_t v)
{
    **p = v;
    (*p)++;
}

static inline void write_u16(uint8_t **p, uint16_t v)
{
    uint16_t net = htons(v);
    memcpy(*p, &net, 2);
    *p += 2;
}

static inline void write_u32(uint8_t **p, uint32_t v)
{
    uint32_t net = htonl(v);
    memcpy(*p, &net, 4);
    *p += 4;
}

static inline void write_u64(uint8_t **p, uint64_t v)
{
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)(v & 0xFFFFFFFFu));
    memcpy(*p, &hi, 4);
    memcpy(*p + 4, &lo, 4);
    *p += 8;
}

static inline void write_str(uint8_t **p, const char *s, uint16_t len)
{
    write_u16(p, len);
    if (len > 0) {
        memcpy(*p, s, len);
        *p += len;
    }
}

static inline void write_bytes(uint8_t **p, const uint8_t *data, size_t len)
{
    memcpy(*p, data, len);
    *p += len;
}

static inline uint8_t read_u8(const uint8_t **p)
{
    uint8_t v = **p;
    (*p)++;
    return v;
}

static inline uint16_t read_u16(const uint8_t **p)
{
    uint16_t net;
    memcpy(&net, *p, 2);
    *p += 2;
    return ntohs(net);
}

static inline uint32_t read_u32(const uint8_t **p)
{
    uint32_t net;
    memcpy(&net, *p, 4);
    *p += 4;
    return ntohl(net);
}

static inline uint64_t read_u64(const uint8_t **p)
{
    uint32_t hi;
    uint32_t lo;

    memcpy(&hi, *p, 4);
    memcpy(&lo, *p + 4, 4);
    *p += 8;
    return ((uint64_t)ntohl(hi) << 32) | ntohl(lo);
}

static inline int read_str(const uint8_t **p, const uint8_t *end, char **out, uint16_t *out_len)
{
    *out = NULL;
    *out_len = 0;

    if ((size_t)(end - *p) < 2)
        return -1;

    uint16_t len = read_u16(p);
    *out_len = len;
    if (len == 0)
        return 0;

    if ((size_t)(end - *p) < len)
        return -1;

    char *s = malloc(len + 1);
    if (!s)
        return -1;

    memcpy(s, *p, len);
    s[len] = '\0';
    *p += len;
    *out = s;
    return 0;
}

static inline void read_bytes(const uint8_t **p, uint8_t *dst, size_t len)
{
    memcpy(dst, *p, len);
    *p += len;
}

int im_frame_header_encode(const im_frame_header_t *h, uint8_t *buf)
{
    uint8_t *p = buf;
    write_u32(&p, h->length);
    write_u8(&p, h->type);
    write_u32(&p, h->seq_num);
    return IM_FRAME_HEADER_SIZE;
}

int im_frame_header_decode(const uint8_t *buf, im_frame_header_t *h)
{
    const uint8_t *p = buf;
    h->length = read_u32(&p);
    h->type = read_u8(&p);
    h->seq_num = read_u32(&p);
    return IM_FRAME_HEADER_SIZE;
}

int im_register_encode(const im_msg_register_t *msg, uint8_t *buf, size_t buf_size)
{
    size_t need = 2 + msg->hostname_len + 4 + 1 + 2 + msg->os_len;
    if (need > buf_size) return -1;

    uint8_t *p = buf;
    write_str(&p, msg->hostname, msg->hostname_len);
    write_u32(&p, msg->ip);
    write_u8(&p, msg->monitor_type);
    write_str(&p, msg->os, msg->os_len);
    return (int)(p - buf);
}

int im_register_decode(const uint8_t *buf, size_t len, im_msg_register_t *msg)
{
    const uint8_t *p = buf;
    const uint8_t *end = buf + len;
    memset(msg, 0, sizeof(*msg));

    if (read_str(&p, end, &msg->hostname, &msg->hostname_len) < 0)
        return -1;
    if ((size_t)(end - p) < 5) {
        im_register_free(msg);
        return -1;
    }

    msg->ip = read_u32(&p);
    msg->monitor_type = read_u8(&p);
    if (read_str(&p, end, &msg->os, &msg->os_len) < 0) {
        im_register_free(msg);
        return -1;
    }
    return (int)(p - buf);
}

void im_register_free(im_msg_register_t *msg)
{
    free(msg->hostname);
    free(msg->os);
    msg->hostname = NULL;
    msg->os = NULL;
}

int im_heartbeat_encode(const im_msg_heartbeat_t *msg, uint8_t *buf, size_t buf_size)
{
    if (buf_size < 13) return -1;

    uint8_t *p = buf;
    write_u64(&p, msg->agent_id);
    write_u8(&p, msg->status);
    write_u32(&p, msg->timestamp);
    return 13;
}

int im_heartbeat_decode(const uint8_t *buf, size_t len, im_msg_heartbeat_t *msg)
{
    if (len < 13) return -1;

    const uint8_t *p = buf;
    msg->agent_id = read_u64(&p);
    msg->status = read_u8(&p);
    msg->timestamp = read_u32(&p);
    return 13;
}

int im_file_event_encode(const im_msg_file_event_t *msg, uint8_t *buf, size_t buf_size)
{
    size_t need = 8 + 1
        + 2 + msg->file_path_len
        + 2 + msg->file_name_len
        + 2 + 1 + 4 + 4;
    if (need > buf_size) return -1;

    uint8_t *p = buf;
    write_u64(&p, msg->agent_id);
    write_u8(&p, msg->event_type);
    write_str(&p, msg->file_path, msg->file_path_len);
    write_str(&p, msg->file_name, msg->file_name_len);
    write_u16(&p, msg->file_permission);
    write_u8(&p, msg->detected_by);
    write_u32(&p, msg->pid);
    write_u32(&p, msg->timestamp);
    return (int)(p - buf);
}

int im_file_event_decode(const uint8_t *buf, size_t len, im_msg_file_event_t *msg)
{
    if (len < 24) return -1;

    const uint8_t *p = buf;
    const uint8_t *end = buf + len;
    memset(msg, 0, sizeof(*msg));

    msg->agent_id = read_u64(&p);
    msg->event_type = read_u8(&p);
    if (read_str(&p, end, &msg->file_path, &msg->file_path_len) < 0) {
        im_file_event_free(msg);
        return -1;
    }
    if (read_str(&p, end, &msg->file_name, &msg->file_name_len) < 0) {
        im_file_event_free(msg);
        return -1;
    }

    if ((size_t)(end - p) < 11) {
        im_file_event_free(msg);
        return -1;
    }
    msg->file_permission = read_u16(&p);
    msg->detected_by = read_u8(&p);
    msg->pid = read_u32(&p);
    msg->timestamp = read_u32(&p);
    return (int)(p - buf);
}

void im_file_event_free(im_msg_file_event_t *msg)
{
    free(msg->file_path);
    free(msg->file_name);
    msg->file_path = NULL;
    msg->file_name = NULL;
}
