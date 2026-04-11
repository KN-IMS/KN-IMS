// SPDX-License-Identifier: GPL-2.0
/*
 * lkm417_syscall.c — sys_call_table hooking, using pt_regs(kernel >= 4.17) (syscall fallback)
 * CentOS 8 / RHEL 8 (4.18), Ubuntu 20.04 LTS (5.4)
 *
 * This file is a fallback for environments where the LSM hook method (lkm415.c) cannot be used.
 *   make HOOKS_IMPL=syscall  
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <linux/fcntl.h>
#include <linux/xattr.h>
#include <linux/version.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>

#include "../im_lkm_policy.h"
#include "../im_lkm_events.h"

/* ── sys_call_table ──────────────────────────────────────── */

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);

static sys_call_ptr_t *sys_call_table;

static sys_call_ptr_t orig_sys_write;
static sys_call_ptr_t orig_sys_unlink;
static sys_call_ptr_t orig_sys_unlinkat;
static sys_call_ptr_t orig_sys_rename;
static sys_call_ptr_t orig_sys_renameat;
#ifdef __NR_renameat2
static sys_call_ptr_t orig_sys_renameat2;
#endif
static sys_call_ptr_t orig_sys_truncate;
static sys_call_ptr_t orig_sys_ftruncate;
static sys_call_ptr_t orig_sys_open;
static sys_call_ptr_t orig_sys_openat;
static sys_call_ptr_t orig_sys_creat;
static sys_call_ptr_t orig_sys_chmod;
static sys_call_ptr_t orig_sys_fchmodat;
static sys_call_ptr_t orig_sys_chown;
static sys_call_ptr_t orig_sys_fchownat;
static sys_call_ptr_t orig_sys_link;
static sys_call_ptr_t orig_sys_linkat;
static sys_call_ptr_t orig_sys_setxattr;
static sys_call_ptr_t orig_sys_lsetxattr;
static sys_call_ptr_t orig_sys_fsetxattr;

static unsigned long im_force_order;

static inline void mywrite_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val), "+m"(im_force_order));
}

static void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

static void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}


/* x86_64: arg1=di, arg2=si, arg3=dx, arg4=r10, arg5=r8 */
static inline unsigned long arg1(const struct pt_regs *r) { return r->di; }
static inline unsigned long arg2(const struct pt_regs *r) { return r->si; }
static inline unsigned long arg3(const struct pt_regs *r) { return r->dx; }
static inline unsigned long arg4(const struct pt_regs *r) { return r->r10; }
static inline unsigned long arg5(const struct pt_regs *r) { return r->r8; }

static int pathat_to_devino(int dfd, const char __user *upath,
                             uint64_t *dev, uint64_t *ino)
{
    struct path p;

    if (user_path_at(dfd, upath, 0, &p))
        return 0;

    if (!p.dentry->d_inode || !p.dentry->d_inode->i_sb) {
        path_put(&p);
        return 0;
    }

    *dev = (uint64_t)p.dentry->d_inode->i_sb->s_dev;
    *ino = (uint64_t)p.dentry->d_inode->i_ino;
    path_put(&p);
    return 1;
}

static int path_to_devino(const char __user *upath,
                           uint64_t *dev, uint64_t *ino)
{
    return pathat_to_devino(AT_FDCWD, upath, dev, ino);
}

static int fd_to_devino(unsigned int fd, uint64_t *dev, uint64_t *ino)
{
    struct fd f = fdget(fd);

    if (!f.file)
        return 0;

    if (!f.file->f_inode || !f.file->f_inode->i_sb ||
        !S_ISREG(f.file->f_inode->i_mode)) {
        fdput(f);
        return 0;
    }

    *dev = (uint64_t)f.file->f_inode->i_sb->s_dev;
    *ino = (uint64_t)f.file->f_inode->i_ino;
    fdput(f);
    return 1;
}

static long im_check(uint64_t dev, uint64_t ino, uint32_t op,
                      const char *op_name)
{
    uint32_t block_mode;

    if (!inode_policy_lookup(dev, ino, op, &block_mode))
        return 0;

    if (block_mode == IM_BLOCK_DENY) {
        pr_info("DENY %s: comm=%s dev=%llu ino=%llu\n",
                op_name, current->comm, dev, ino);
        im_event_enqueue(dev, ino, op, 1);
        return -EPERM;
    }

    im_event_enqueue(dev, ino, op, 0);
    return 0;
}

static long im_check_delete(uint64_t dev, uint64_t ino)
{
    uint32_t block_mode;

    if (!inode_policy_lookup(dev, ino, IM_OP_DELETE, &block_mode))
        return 0;

    if (block_mode == IM_BLOCK_DENY) {
        pr_info("DENY delete: comm=%s dev=%llu ino=%llu\n",
                current->comm, dev, ino);
        im_event_enqueue(dev, ino, IM_OP_DELETE, 1);
        return -EPERM;
    }

    im_event_enqueue(dev, ino, IM_OP_DELETE, 0);
    inode_policy_remove(dev, ino);
    return 0;
}

static long check_rename(int olddfd, const char __user *oldname,
                         int newdfd, const char __user *newname)
{
    uint64_t dev, ino;
    uint32_t block_mode;
    long rc = 0;

    if (pathat_to_devino(olddfd, oldname, &dev, &ino)) {
        rc = im_check(dev, ino, IM_OP_RENAME, "rename(src)");
        if (rc)
            return rc;
    }

    if (pathat_to_devino(newdfd, newname, &dev, &ino)) {
        if (inode_policy_lookup(dev, ino, IM_OP_RENAME, &block_mode)
            && block_mode == IM_BLOCK_DENY) {
            pr_info("DENY rename(dst): comm=%s dev=%llu ino=%llu\n",
                    current->comm, dev, ino);
            im_event_enqueue(dev, ino, IM_OP_RENAME, 1);
            return -EPERM;
        }
    }

    return 0;
}

static long check_open_flags(int dfd, const char __user *upath, int flags)
{
    uint64_t dev, ino;

    if (!(flags & (O_WRONLY | O_RDWR | O_TRUNC)))
        return 0;

    if (!pathat_to_devino(dfd, upath, &dev, &ino))
        return 0;

    return im_check(dev, ino, IM_OP_WRITE, "open");
}

static asmlinkage long im_sys_write(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (fd_to_devino((unsigned int)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "write");

    return rc ? rc : orig_sys_write(regs);
}

static asmlinkage long im_sys_truncate(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino((const char __user *)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "truncate");

    return rc ? rc : orig_sys_truncate(regs);
}

static asmlinkage long im_sys_ftruncate(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (fd_to_devino((unsigned int)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "ftruncate");

    return rc ? rc : orig_sys_ftruncate(regs);
}

static asmlinkage long im_sys_open(const struct pt_regs *regs)
{
    long rc = check_open_flags(AT_FDCWD,
                               (const char __user *)arg1(regs),
                               (int)arg2(regs));
    return rc ? rc : orig_sys_open(regs);
}

static asmlinkage long im_sys_openat(const struct pt_regs *regs)
{
    long rc = check_open_flags((int)arg1(regs),
                               (const char __user *)arg2(regs),
                               (int)arg3(regs));
    return rc ? rc : orig_sys_openat(regs);
}

static asmlinkage long im_sys_creat(const struct pt_regs *regs)
{
    long rc = check_open_flags(AT_FDCWD,
                               (const char __user *)arg1(regs),
                               O_WRONLY | O_TRUNC);
    return rc ? rc : orig_sys_creat(regs);
}

static asmlinkage long im_sys_unlink(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino((const char __user *)arg1(regs), &dev, &ino))
        rc = im_check_delete(dev, ino);

    return rc ? rc : orig_sys_unlink(regs);
}

static asmlinkage long im_sys_unlinkat(const struct pt_regs *regs)
{
    int dfd   = (int)arg1(regs);
    const char __user *path = (const char __user *)arg2(regs);
    int flag  = (int)arg3(regs);
    uint64_t dev, ino;
    long rc = 0;

    if (!(flag & AT_REMOVEDIR) && pathat_to_devino(dfd, path, &dev, &ino))
        rc = im_check_delete(dev, ino);

    return rc ? rc : orig_sys_unlinkat(regs);
}

static asmlinkage long im_sys_rename(const struct pt_regs *regs)
{
    long rc = check_rename(AT_FDCWD,
                           (const char __user *)arg1(regs),
                           AT_FDCWD,
                           (const char __user *)arg2(regs));
    return rc ? rc : orig_sys_rename(regs);
}

static asmlinkage long im_sys_renameat(const struct pt_regs *regs)
{
    long rc = check_rename((int)arg1(regs),
                           (const char __user *)arg2(regs),
                           (int)arg3(regs),
                           (const char __user *)arg4(regs));
    return rc ? rc : orig_sys_renameat(regs);
}

#ifdef __NR_renameat2
static asmlinkage long im_sys_renameat2(const struct pt_regs *regs)
{
    long rc = check_rename((int)arg1(regs),
                           (const char __user *)arg2(regs),
                           (int)arg3(regs),
                           (const char __user *)arg4(regs));
    return rc ? rc : orig_sys_renameat2(regs);
}
#endif

static asmlinkage long im_sys_chmod(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino((const char __user *)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "chmod");

    return rc ? rc : orig_sys_chmod(regs);
}

static asmlinkage long im_sys_fchmodat(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (pathat_to_devino((int)arg1(regs),
                         (const char __user *)arg2(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "fchmodat");

    return rc ? rc : orig_sys_fchmodat(regs);
}

static asmlinkage long im_sys_chown(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino((const char __user *)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "chown");

    return rc ? rc : orig_sys_chown(regs);
}

static asmlinkage long im_sys_fchownat(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (pathat_to_devino((int)arg1(regs),
                         (const char __user *)arg2(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "fchownat");

    return rc ? rc : orig_sys_fchownat(regs);
}

static asmlinkage long im_sys_link(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino((const char __user *)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "link");

    return rc ? rc : orig_sys_link(regs);
}

static asmlinkage long im_sys_linkat(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (pathat_to_devino((int)arg1(regs),
                         (const char __user *)arg2(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "linkat");

    return rc ? rc : orig_sys_linkat(regs);
}

static asmlinkage long im_sys_setxattr(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino((const char __user *)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "setxattr");

    return rc ? rc : orig_sys_setxattr(regs);
}

static asmlinkage long im_sys_lsetxattr(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino((const char __user *)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "lsetxattr");

    return rc ? rc : orig_sys_lsetxattr(regs);
}

static asmlinkage long im_sys_fsetxattr(const struct pt_regs *regs)
{
    uint64_t dev, ino;
    long rc = 0;

    if (fd_to_devino((int)arg1(regs), &dev, &ino))
        rc = im_check(dev, ino, IM_OP_WRITE, "fsetxattr");

    return rc ? rc : orig_sys_fsetxattr(regs);
}

#define HOOK(name) \
    orig_sys_##name = sys_call_table[__NR_##name]; \
    sys_call_table[__NR_##name] = im_sys_##name

#define UNHOOK(name) \
    sys_call_table[__NR_##name] = orig_sys_##name

int im_hooks_init(void)
{
    sys_call_table = (sys_call_ptr_t *)
        kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        pr_err("sys_call_table not found in kallsyms\n");
        return -ENOENT;
    }

    disable_write_protection();
    HOOK(write);
    HOOK(truncate);
    HOOK(ftruncate);
    HOOK(open);
    HOOK(openat);
    HOOK(creat);
    HOOK(unlink);
    HOOK(unlinkat);
    HOOK(rename);
    HOOK(renameat);
#ifdef __NR_renameat2
    HOOK(renameat2);
#endif
    HOOK(chmod);
    HOOK(fchmodat);
    HOOK(chown);
    HOOK(fchownat);
    HOOK(link);
    HOOK(linkat);
    HOOK(setxattr);
    HOOK(lsetxattr);
    HOOK(fsetxattr);
    enable_write_protection();

    pr_info("hooks installed (sys_call_table pt_regs, %d syscalls)\n", 19);
    return 0;
}

void im_hooks_exit(void)
{
    if (!sys_call_table)
        return;

    disable_write_protection();
    UNHOOK(write);
    UNHOOK(truncate);
    UNHOOK(ftruncate);
    UNHOOK(open);
    UNHOOK(openat);
    UNHOOK(creat);
    UNHOOK(unlink);
    UNHOOK(unlinkat);
    UNHOOK(rename);
    UNHOOK(renameat);
#ifdef __NR_renameat2
    UNHOOK(renameat2);
#endif
    UNHOOK(chmod);
    UNHOOK(fchmodat);
    UNHOOK(chown);
    UNHOOK(fchownat);
    UNHOOK(link);
    UNHOOK(linkat);
    UNHOOK(setxattr);
    UNHOOK(lsetxattr);
    UNHOOK(fsetxattr);
    enable_write_protection();

    pr_info("hooks removed\n");
}
