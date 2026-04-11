#ifndef IM_TRACE_API_H
#define IM_TRACE_API_H

#include <stdint.h>
#include "realtime/monitor.h"

enum {
    IM_EBPF_OP_READ   = 0x01,
    IM_EBPF_OP_WRITE  = 0x02,
    IM_EBPF_OP_DELETE = 0x04,
    IM_EBPF_OP_ATTR   = 0x08,
};

/* block=0: AUDIT only (maintenance mode)
 * block=1: DENY   (lock mode) */
#define IM_EBPF_BLOCK_AUDIT 0u
#define IM_EBPF_BLOCK_DENY  1u

/* LSM 훅 ID — im_trace.bpf.c의 IM_HOOK_* 값과 반드시 일치해야 함 */
enum im_hook_id {
    IM_HOOK_FILE_PERMISSION = 1,
    IM_HOOK_FILE_OPEN       = 2,
    IM_HOOK_PATH_UNLINK     = 3,
    IM_HOOK_PATH_RENAME     = 4,
    IM_HOOK_PATH_TRUNCATE   = 5,
    IM_HOOK_PATH_CHMOD      = 6,
    IM_HOOK_INODE_SETATTR   = 7,
};

int   ebpf_policy_init(im_event_queue_t *queue);
void  ebpf_policy_stop(void);       /* poll thread 종료 신호 (join 전 호출) */
void  ebpf_policy_cleanup(void);    /* 리소스 해제 (join 후 호출) */
void *ebpf_poll_thread(void *arg);

int ebpf_policy_add_path_recursive(const char *path, uint32_t mask, uint32_t block);
int ebpf_policy_add_path(const char *path, uint32_t mask, uint32_t block);
int ebpf_policy_remove_path(const char *path);
int ebpf_policy_remove_path_recursive(const char *path);
int ebpf_policy_has_path(const char *path, uint32_t *mask, uint32_t *block);

#endif
