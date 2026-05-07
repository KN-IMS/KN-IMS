// SPDX-License-Identifier: GPL-2.0
/*
 * lkm415.c — LSM Injection, page protection bypass (kernel 4.15 ~ 5.6)
 * Ubuntu 18.04 LTS (4.15), CentOS 8 / RHEL 8 (4.18), Ubuntu 20.04 LTS (5.4)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/kallsyms.h>
#include <linux/rcupdate.h>
#include <linux/lsm_hooks.h>
#include <linux/kprobes.h>

#include "../ig_lkm_policy.h"
#include "../ig_lkm_events.h"

static struct security_hook_heads *ig_hook_heads;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t ig_kallsyms_fn;

static int ig_resolve_kallsyms(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    /*
     * 5.7+: kallsyms_lookup_name unexported.
     * kprobe: the kernel fills in the symbol address, so extract that address.
     */
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0)
        return ret;
    ig_kallsyms_fn = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
#else
    ig_kallsyms_fn = kallsyms_lookup_name;
#endif
    return 0;
}

#define ig_lookup(name) ig_kallsyms_fn(name)

/* ── CR0 WP bit bypass ────────────────────────────────────
 * If CR0.WP (bit 16) is temporarily cleared,
 * it is possible to write to read-only pages in kernel mode — the same method as lkm310.c.
 * The risk section is short because WP is disabled only during hlist manipulation and immediately restored.
 */

static unsigned long ig_force_order;

static inline void ig_write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val), "+m"(ig_force_order));
}

static void ig_disable_wp(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    ig_write_cr0(cr0);
}

static void ig_enable_wp(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    ig_write_cr0(cr0);
}

static int ig_check_inode(struct inode *inode, uint32_t op,
                            const char *op_name)
{
    uint64_t dev, ino;
    uint32_t block_mode;

    if (!inode || !inode->i_sb)
        return 0;
    if (!S_ISREG(inode->i_mode))
        return 0;

    dev = (uint64_t)inode->i_sb->s_dev;
    ino = (uint64_t)inode->i_ino;

    if (!inode_policy_lookup(dev, ino, op, &block_mode))
        return 0;

    if (block_mode == IG_BLOCK_DENY) {
        pr_info("DENY %s: comm=%s dev=%llu ino=%llu\n",
                op_name, current->comm, dev, ino);
        ig_event_enqueue(dev, ino, op, 1);
        return -EPERM;
    }

    ig_event_enqueue(dev, ino, op, 0);
    return 0;
}

static int ig_check_dentry(struct dentry *dentry, uint32_t op,
                             const char *op_name)
{
    if (!dentry)
        return 0;
    return ig_check_inode(dentry->d_inode, op, op_name);
}

static int ig_check_delete_inode(struct inode *inode)
{
    uint64_t dev, ino;
    uint32_t block_mode;

    if (!inode || !inode->i_sb || !S_ISREG(inode->i_mode))
        return 0;

    dev = (uint64_t)inode->i_sb->s_dev;
    ino = (uint64_t)inode->i_ino;

    if (!inode_policy_lookup(dev, ino, IG_OP_DELETE, &block_mode))
        return 0;

    if (block_mode == IG_BLOCK_DENY) {
        pr_info("DENY delete: comm=%s dev=%llu ino=%llu\n",
                current->comm, dev, ino);
        ig_event_enqueue(dev, ino, IG_OP_DELETE, 1);
        return -EPERM;
    }

    ig_event_enqueue(dev, ino, IG_OP_DELETE, 0);
    inode_policy_remove(dev, ino);
    return 0;
}

/* ── LSM hooks ─────────────────────────────────────────── */

static int ig_inode_permission(struct inode *inode, int mask)
{
    if (!(mask & MAY_WRITE))
        return 0;
    return ig_check_inode(inode, IG_OP_WRITE, "inode_permission");
}

static int ig_mmap_file(struct file *file, unsigned long reqprot,
                         unsigned long prot, unsigned long flags)
{
    if (!file || !(prot & PROT_WRITE))
        return 0;
    return ig_check_inode(file->f_inode, IG_OP_WRITE, "mmap_write");
}

static int ig_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    return ig_check_delete_inode(dentry ? dentry->d_inode : NULL);
}

static int ig_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                            struct inode *new_dir, struct dentry *new_dentry)
{
    int rc;

    rc = ig_check_dentry(old_dentry, IG_OP_RENAME, "rename_src");
    if (rc)
        return rc;

    if (new_dentry && new_dentry->d_inode)
        rc = ig_check_dentry(new_dentry, IG_OP_RENAME, "rename_dst");

    return rc;
}

static int ig_inode_link(struct dentry *old_dentry, struct inode *dir,
                          struct dentry *new_dentry)
{
    return ig_check_dentry(old_dentry, IG_OP_WRITE, "link");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int ig_inode_setxattr(struct user_namespace *mnt_userns,
                              struct dentry *dentry, const char *name,
                              const void *value, size_t size, int flags)
#else
static int ig_inode_setxattr(struct dentry *dentry, const char *name,
                              const void *value, size_t size, int flags)
#endif
{
    return ig_check_dentry(dentry, IG_OP_WRITE, "setxattr");
}

static int ig_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    unsigned int ia_valid = attr ? attr->ia_valid : 0;

    if (!(ia_valid & (ATTR_SIZE | ATTR_MODE | ATTR_UID | ATTR_GID)))
        return 0;

    return ig_check_dentry(dentry, IG_OP_WRITE, "setattr");
}

// hook list
static struct security_hook_list ig_hooks[] = {
    { .hook = { .inode_permission = ig_inode_permission }, .lsm = "ig_lkm" },
    { .hook = { .mmap_file        = ig_mmap_file        }, .lsm = "ig_lkm" },
    { .hook = { .inode_unlink     = ig_inode_unlink     }, .lsm = "ig_lkm" },
    { .hook = { .inode_rename     = ig_inode_rename     }, .lsm = "ig_lkm" },
    { .hook = { .inode_link       = ig_inode_link       }, .lsm = "ig_lkm" },
    { .hook = { .inode_setxattr   = ig_inode_setxattr   }, .lsm = "ig_lkm" },
    { .hook = { .inode_setattr    = ig_inode_setattr    }, .lsm = "ig_lkm" },
};

int ig_hooks_init(void)
{
    int i, ret;

    /* 1) get kallsyms_lookup_name ptr (5.7+: Bypass using kprobe) */
    ret = ig_resolve_kallsyms();
    if (ret) {
        pr_err("failed to resolve kallsyms_lookup_name (%d)\n", ret);
        return ret;
    }

    // get address of security_hook_heads
    ig_hook_heads = (struct security_hook_heads *)
        ig_lookup("security_hook_heads");
    if (!ig_hook_heads) {
        pr_err("security_hook_heads not found in kallsyms\n");
        return -ENOENT;
    }

    ig_hooks[0].head = &ig_hook_heads->inode_permission;
    ig_hooks[1].head = &ig_hook_heads->mmap_file;
    ig_hooks[2].head = &ig_hook_heads->inode_unlink;
    ig_hooks[3].head = &ig_hook_heads->inode_rename;
    ig_hooks[4].head = &ig_hook_heads->inode_link;
    ig_hooks[5].head = &ig_hook_heads->inode_setxattr;
    ig_hooks[6].head = &ig_hook_heads->inode_setattr;

    // Bypass pages containing security_hook_heads
    ig_disable_wp();
    for (i = 0; i < ARRAY_SIZE(ig_hooks); i++)
        hlist_add_tail_rcu(&ig_hooks[i].list, ig_hooks[i].head);
    ig_enable_wp();

    pr_info("hooks installed (LSM injection 4.15+, %zu hooks)\n",
            ARRAY_SIZE(ig_hooks));
    return 0;
}

void ig_hooks_exit(void)
{
    int i;

    ig_disable_wp();
    for (i = 0; i < ARRAY_SIZE(ig_hooks); i++)
        hlist_del_rcu(&ig_hooks[i].list);
    ig_enable_wp();

    synchronize_rcu();

    pr_info("hooks removed (LSM 4.15+)\n");
}
