#ifndef IG_LKM_POLICY_H
#define IG_LKM_POLICY_H

#include <linux/hashtable.h>
#include <linux/rwlock.h>
#include "ig_lkm_common.h"

#define IG_POLICY_BITS  8   /* 2^8 = 256 버킷 */
#define IG_MAX_LKM_PATH 256

struct ig_policy_entry {
    uint64_t  dev;
    uint64_t  ino;
    uint32_t  mask;
    uint32_t  block;
    char      path[IG_MAX_LKM_PATH];
    struct hlist_node node;
};

/* rwlock — ig_lkm_events.c에서 read_lock으로 접근 */
extern rwlock_t ig_policy_lock;

/* 초기화 — module_init에서 호출 (hash_init은 정의 파일 내부에서만 가능) */
void ig_policy_init(void);

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

#endif /* IG_LKM_POLICY_H */
