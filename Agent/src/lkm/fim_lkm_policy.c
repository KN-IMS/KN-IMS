// SPDX-License-Identifier: GPL-2.0
/*
 * fim_lkm_policy.c — inode 기반 정책 해시테이블
 *
 * 키: {dev, ino}  (커널 dev_t 인코딩)
 * 값: {mask, block, path}
 *
 * 유저스페이스가 ioctl로 정책을 주입하면 여기에 저장되고,
 * kprobe 핸들러가 파일 접근 시 inode_policy_lookup()으로 조회한다.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/jhash.h>
#include "fim_lkm_policy.h"

DEFINE_HASHTABLE(fim_policy_ht, FIM_POLICY_BITS);
DEFINE_RWLOCK(fim_policy_lock);

void fim_policy_init(void)
{
    hash_init(fim_policy_ht);
}

/* ── 내부 헬퍼 ──────────────────────────────────────────── */

static u32 make_key(uint64_t dev, uint64_t ino)
{
    uint32_t data[4] = {
        (uint32_t)(dev >> 32),
        (uint32_t)(dev & 0xFFFFFFFFU),
        (uint32_t)(ino >> 32),
        (uint32_t)(ino & 0xFFFFFFFFU),
    };
    return jhash2(data, 4, 0) & ((1U << FIM_POLICY_BITS) - 1);
}

/* 락 없이 엔트리 탐색 — 반드시 read/write_lock 보유 상태에서 호출 */
static struct fim_policy_entry *find_entry(uint64_t dev, uint64_t ino)
{
    struct fim_policy_entry *e;
    u32 key = make_key(dev, ino);

    hash_for_each_possible(fim_policy_ht, e, node, key) {
        if (e->dev == dev && e->ino == ino)
            return e;
    }
    return NULL;
}

/* ── 공개 API ───────────────────────────────────────────── */

int inode_policy_add(uint64_t dev, uint64_t ino,
                     uint32_t mask, uint32_t block,
                     const char *path)
{
    struct fim_policy_entry *e;
    u32 key = make_key(dev, ino);
    unsigned long flags;

    /* 이미 있으면 덮어씀 */
    write_lock_irqsave(&fim_policy_lock, flags);
    e = find_entry(dev, ino);
    if (e) {
        e->mask  = mask;
        e->block = block;
        if (path)
            strncpy(e->path, path, FIM_MAX_PATH - 1);
        write_unlock_irqrestore(&fim_policy_lock, flags);
        return 0;
    }
    write_unlock_irqrestore(&fim_policy_lock, flags);

    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return -ENOMEM;

    e->dev   = dev;
    e->ino   = ino;
    e->mask  = mask;
    e->block = block;
    if (path)
        strncpy(e->path, path, FIM_MAX_PATH - 1);

    write_lock_irqsave(&fim_policy_lock, flags);
    hash_add(fim_policy_ht, &e->node, key);
    write_unlock_irqrestore(&fim_policy_lock, flags);

    pr_info("policy add: dev=%llu ino=%llu block=%s path=%s\n",
            dev, ino, block ? "DENY" : "AUDIT",
            path ? path : "(none)");
    return 0;
}

void inode_policy_remove(uint64_t dev, uint64_t ino)
{
    struct fim_policy_entry *e;
    unsigned long flags;

    write_lock_irqsave(&fim_policy_lock, flags);
    e = find_entry(dev, ino);
    if (e) {
        hash_del(&e->node);
        write_unlock_irqrestore(&fim_policy_lock, flags);
        kfree(e);
        pr_info("policy remove: dev=%llu ino=%llu\n", dev, ino);
        return;
    }
    write_unlock_irqrestore(&fim_policy_lock, flags);
}

void inode_policy_clear(void)
{
    struct fim_policy_entry *e;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;

    write_lock_irqsave(&fim_policy_lock, flags);
    hash_for_each_safe(fim_policy_ht, bkt, tmp, e, node) {
        hash_del(&e->node);
        kfree(e);
    }
    write_unlock_irqrestore(&fim_policy_lock, flags);
    pr_info("policy cleared\n");
}

/*
 * hook 내부에서 호출 — 성능 민감 경로.
 * read_lock으로 동시 다중 접근 허용.
 */
int inode_policy_lookup(uint64_t dev, uint64_t ino,
                        uint32_t op, uint32_t *out_block)
{
    struct fim_policy_entry *e;
    unsigned long flags;
    int found = 0;

    read_lock_irqsave(&fim_policy_lock, flags);
    e = find_entry(dev, ino);
    if (e && (e->mask & op)) {
        *out_block = e->block;
        found = 1;
    }
    read_unlock_irqrestore(&fim_policy_lock, flags);
    return found;
}

const char *inode_policy_path(uint64_t dev, uint64_t ino)
{
    /* 주의: read_lock 보유 상태에서 호출해야 하며,
     *        반환된 포인터는 락 해제 전에만 유효하다.
     *        이벤트 emit 시 strncpy로 복사해서 사용할 것. */
    struct fim_policy_entry *e = find_entry(dev, ino);
    return e ? e->path : "";
}
