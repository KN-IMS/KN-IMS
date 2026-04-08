#ifndef FIM_LKM_POLICY_H
#define FIM_LKM_POLICY_H

#include <linux/hashtable.h>
#include <linux/rwlock.h>
#include "fim_lkm_common.h"

#define FIM_POLICY_BITS  8   /* 2^8 = 256 버킷 */
#define FIM_MAX_PATH     256

struct fim_policy_entry {
    uint64_t  dev;
    uint64_t  ino;
    uint32_t  mask;
    uint32_t  block;
    char      path[FIM_MAX_PATH];
    struct hlist_node node;
};

/* rwlock — fim_lkm_events.c에서 read_lock으로 접근 */
extern rwlock_t fim_policy_lock;

/* 초기화 — module_init에서 호출 (hash_init은 정의 파일 내부에서만 가능) */
void fim_policy_init(void);

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

#endif /* FIM_LKM_POLICY_H */
