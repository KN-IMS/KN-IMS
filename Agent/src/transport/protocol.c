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

int ig_frame_header_encode(const ig_frame_header_t *h, uint8_t *buf)
{
    uint8_t *p = buf;
    write_u32(&p, h->length);
    write_u8(&p, h->type);
    write_u32(&p, h->seq_num);
    return IG_FRAME_HEADER_SIZE;
}

int ig_frame_header_decode(const uint8_t *buf, ig_frame_header_t *h)
{
    const uint8_t *p = buf;
    h->length = read_u32(&p);
    h->type = read_u8(&p);
    h->seq_num = read_u32(&p);
    return IG_FRAME_HEADER_SIZE;
}

int ig_register_encode(const ig_msg_register_t *msg, uint8_t *buf, size_t buf_size)
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

int ig_register_decode(const uint8_t *buf, size_t len, ig_msg_register_t *msg)
{
    const uint8_t *p = buf;
    const uint8_t *end = buf + len;
    memset(msg, 0, sizeof(*msg));

    if (read_str(&p, end, &msg->hostname, &msg->hostname_len) < 0)
        return -1;
    if ((size_t)(end - p) < 5) {
        ig_register_free(msg);
        return -1;
    }

    msg->ip = read_u32(&p);
    msg->monitor_type = read_u8(&p);
    if (read_str(&p, end, &msg->os, &msg->os_len) < 0) {
        ig_register_free(msg);
        return -1;
    }
    return (int)(p - buf);
}

void ig_register_free(ig_msg_register_t *msg)
{
    free(msg->hostname);
    free(msg->os);
    msg->hostname = NULL;
    msg->os = NULL;
}

int ig_heartbeat_encode(const ig_msg_heartbeat_t *msg, uint8_t *buf, size_t buf_size)
{
    if (buf_size < 13) return -1;

    uint8_t *p = buf;
    write_u64(&p, msg->agent_id);
    write_u8(&p, msg->status);
    write_u32(&p, msg->timestamp);
    return 13;
}

int ig_heartbeat_decode(const uint8_t *buf, size_t len, ig_msg_heartbeat_t *msg)
{
    if (len < 13) return -1;

    const uint8_t *p = buf;
    msg->agent_id = read_u64(&p);
    msg->status = read_u8(&p);
    msg->timestamp = read_u32(&p);
    return 13;
}

/* chain entry 1개 직렬화. 가변 문자열 4개 (comm/tty/exe/cmdline) + 고정 필드 */
static int chain_entry_encode(const ig_proc_info_t *e,
                                uint8_t **p, const uint8_t *end)
{
    /* 고정: pid(4)+ppid(4)+uid(4)+euid(4)+sid(4)+start(8) = 28 */
    /* 가변: 4 strings × 2(len) + content */
    size_t comm_l = strnlen(e->comm,    sizeof(e->comm));
    size_t tty_l  = strnlen(e->tty,     sizeof(e->tty));
    size_t exe_l  = strnlen(e->exe,     sizeof(e->exe));
    size_t cmd_l  = strnlen(e->cmdline, sizeof(e->cmdline));
    size_t need = 28 + 8 + comm_l + tty_l + exe_l + cmd_l;
    if ((size_t)(end - *p) < need) return -1;

    write_u32(p, (uint32_t)e->pid);
    write_u32(p, (uint32_t)e->ppid);
    write_u32(p, (uint32_t)e->uid);
    write_u32(p, (uint32_t)e->euid);
    write_u32(p, (uint32_t)e->sid);
    write_u64(p, e->start_time_ns);
    write_str(p, e->comm,    (uint16_t)comm_l);
    write_str(p, e->tty,     (uint16_t)tty_l);
    write_str(p, e->exe,     (uint16_t)exe_l);
    write_str(p, e->cmdline, (uint16_t)cmd_l);
    return 0;
}

int ig_file_event_encode(const ig_msg_file_event_t *msg, uint8_t *buf, size_t buf_size)
{
    /* v1 minimum */
    size_t need_v1 = 8 + 1
        + 2 + msg->file_path_len
        + 2 + msg->file_name_len
        + 2 + 1 + 4 + 4;
    /* v2: dev(8)+ino(8)+blocked(1)+chain_depth(1)+chain_truncated(1) */
    size_t need_v2 = 8 + 8 + 1 + 1 + 1;
    if (need_v1 + need_v2 > buf_size) return -1;

    uint8_t *p = buf;
    const uint8_t *end = buf + buf_size;
    write_u64(&p, msg->agent_id);
    write_u8(&p, msg->event_type);
    write_str(&p, msg->file_path, msg->file_path_len);
    write_str(&p, msg->file_name, msg->file_name_len);
    write_u16(&p, msg->file_permission);
    write_u8(&p, msg->detected_by);
    write_u32(&p, msg->pid);
    write_u32(&p, msg->timestamp);

    /* v2 — target + chain */
    write_u64(&p, msg->target_dev);
    write_u64(&p, msg->target_ino);
    write_u8(&p, msg->blocked);
    {
        uint8_t depth = 0, trunc = 0;
        if (msg->chain) {
            depth = (uint8_t)((msg->chain->depth > 255) ? 255 : msg->chain->depth);
            trunc = (uint8_t)(msg->chain->truncated ? 1 : 0);
        }
        write_u8(&p, depth);
        write_u8(&p, trunc);
        if (msg->chain) {
            int i;
            for (i = 0; i < depth && i < IG_PA_MAX_DEPTH; i++) {
                if (chain_entry_encode(&msg->chain->chain[i], &p, end) < 0)
                    return -1;
            }
        }
    }
    return (int)(p - buf);
}

int ig_file_event_decode(const uint8_t *buf, size_t len, ig_msg_file_event_t *msg)
{
    if (len < 24) return -1;

    const uint8_t *p = buf;
    const uint8_t *end = buf + len;
    memset(msg, 0, sizeof(*msg));

    msg->agent_id = read_u64(&p);
    msg->event_type = read_u8(&p);
    if (read_str(&p, end, &msg->file_path, &msg->file_path_len) < 0) {
        ig_file_event_free(msg);
        return -1;
    }
    if (read_str(&p, end, &msg->file_name, &msg->file_name_len) < 0) {
        ig_file_event_free(msg);
        return -1;
    }

    if ((size_t)(end - p) < 11) {
        ig_file_event_free(msg);
        return -1;
    }
    msg->file_permission = read_u16(&p);
    msg->detected_by = read_u8(&p);
    msg->pid = read_u32(&p);
    msg->timestamp = read_u32(&p);
    return (int)(p - buf);
}

void ig_file_event_free(ig_msg_file_event_t *msg)
{
    free(msg->file_path);
    free(msg->file_name);
    msg->file_path = NULL;
    msg->file_name = NULL;
}
