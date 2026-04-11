// SPDX-License-Identifier: GPL-2.0
/*
 * im_lkm_policy.c — inode based policy hash table
 *
 * When the user space injects a policy via ioctl, it is stored here,
 * retrieved using inode_policy_lookup().
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/jhash.h>
#include "im_lkm_policy.h"

DEFINE_HASHTABLE(im_policy_ht, IM_POLICY_BITS);
DEFINE_RWLOCK(im_policy_lock);

void im_policy_init(void)
{
    hash_init(im_policy_ht);
}

static u32 make_key(uint64_t dev, uint64_t ino)
{
    uint32_t data[4] = {
        (uint32_t)(dev >> 32),
        (uint32_t)(dev & 0xFFFFFFFFU),
        (uint32_t)(ino >> 32),
        (uint32_t)(ino & 0xFFFFFFFFU),
    };
    return jhash2(data, 4, 0) & ((1U << IM_POLICY_BITS) - 1);
}

/* Search for entry without lock — must be called while holding read/write_lock */
static struct im_policy_entry *find_entry(uint64_t dev, uint64_t ino)
{
    struct im_policy_entry *e;
    u32 key = make_key(dev, ino);

    hash_for_each_possible(im_policy_ht, e, node, key) {
        if (e->dev == dev && e->ino == ino)
            return e;
    }
    return NULL;
}

/* ── Public API ───────────────────────────────────────────── */

int inode_policy_add(uint64_t dev, uint64_t ino,
                     uint32_t mask, uint32_t block,
                     const char *path)
{
    struct im_policy_entry *e;
    u32 key = make_key(dev, ino);
    unsigned long flags;

    write_lock_irqsave(&im_policy_lock, flags);
    e = find_entry(dev, ino);
    if (e) {
        e->mask  = mask;
        e->block = block;
        if (path)
            strncpy(e->path, path, IM_MAX_PATH - 1);
        write_unlock_irqrestore(&im_policy_lock, flags);
        return 0;
    }
    write_unlock_irqrestore(&im_policy_lock, flags);

    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return -ENOMEM;

    e->dev   = dev;
    e->ino   = ino;
    e->mask  = mask;
    e->block = block;
    if (path)
        strncpy(e->path, path, IM_MAX_PATH - 1);

    write_lock_irqsave(&im_policy_lock, flags);
    hash_add(im_policy_ht, &e->node, key);
    write_unlock_irqrestore(&im_policy_lock, flags);

    pr_info("policy add: dev=%llu ino=%llu block=%s path=%s\n",
            dev, ino, block ? "DENY" : "AUDIT",
            path ? path : "(none)");
    return 0;
}

void inode_policy_remove(uint64_t dev, uint64_t ino)
{
    struct im_policy_entry *e;
    unsigned long flags;

    write_lock_irqsave(&im_policy_lock, flags);
    e = find_entry(dev, ino);
    if (e) {
        hash_del(&e->node);
        write_unlock_irqrestore(&im_policy_lock, flags);
        kfree(e);
        pr_info("policy remove: dev=%llu ino=%llu\n", dev, ino);
        return;
    }
    write_unlock_irqrestore(&im_policy_lock, flags);
}

void inode_policy_clear(void)
{
    struct im_policy_entry *e;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;

    write_lock_irqsave(&im_policy_lock, flags);
    hash_for_each_safe(im_policy_ht, bkt, tmp, e, node) {
        hash_del(&e->node);
        kfree(e);
    }
    write_unlock_irqrestore(&im_policy_lock, flags);
    pr_info("policy cleared\n");
}

int inode_policy_lookup(uint64_t dev, uint64_t ino,
                        uint32_t op, uint32_t *out_block)
{
    struct im_policy_entry *e;
    unsigned long flags;
    int found = 0;

    read_lock_irqsave(&im_policy_lock, flags);
    e = find_entry(dev, ino);
    if (e && (e->mask & op)) {
        *out_block = e->block;
        found = 1;
    }
    read_unlock_irqrestore(&im_policy_lock, flags);
    return found;
}

const char *inode_policy_path(uint64_t dev, uint64_t ino)
{
    /* Note: Must be called while holding read_lock,
     * The returned pointer is valid only before the lock is released.
     * Copy to strncpy and use when emitting an event. */
    struct im_policy_entry *e = find_entry(dev, ino);
    return e ? e->path : "";
}
