#ifndef IM_LKM_POLICY_H
#define IM_LKM_POLICY_H

#include <linux/hashtable.h>
#include <linux/rwlock.h>
#include "im_lkm_common.h"

#define IM_POLICY_BITS  8   /* 2^8 = 256 버킷 */
#define IM_MAX_PATH     256

struct im_policy_entry {
    uint64_t  dev;
    uint64_t  ino;
    uint32_t  mask;
    uint32_t  block;
    char      path[IM_MAX_PATH];
    struct hlist_node node;
};

/* rwlock — im_lkm_events.c에서 read_lock으로 접근 */
extern rwlock_t im_policy_lock;

/* 초기화 — module_init에서 호출 (hash_init은 정의 파일 내부에서만 가능) */
void im_policy_init(void);

int  inode_policy_add(uint64_t dev, uint64_t ino,
                      uint32_t mask, uint32_t block,
                      const char *path);
void inode_policy_remove(uint64_t dev, uint64_t ino);
void inode_policy_clear(void);

/* hook 내부에서 호출 — read_lock 내부에서 사용 */
int  inode_policy_lookup(uint64_t dev, uint64_t ino,
                         uint32_t op, uint32_t *out_block);

/* 경로 조회 (이벤트 emit 시) — read_lock 내부에서 사용 */
const char *inode_policy_path(uint64_t dev, uint64_t ino);

#endif /* IM_LKM_POLICY_H */
