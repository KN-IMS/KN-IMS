// SPDX-License-Identifier: GPL-2.0
/*
 * lkm310.c — sys_call_table 후킹 (kernel 3.10 ~ 4.1)
 * CentOS 7 (3.10), Ubuntu 14.04 LTS (3.13), Ubuntu 16.04 LTS (4.4)
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
#include <asm/unistd.h>

#include "../fim_lkm_policy.h"
#include "../fim_lkm_events.h"

typedef void *(*sys_call_ptr_t)(void);

typedef asmlinkage long (*orig_write_t)     (unsigned int, const char __user *, size_t);
typedef asmlinkage long (*orig_unlink_t)    (const char __user *);
typedef asmlinkage long (*orig_unlinkat_t)  (int, const char __user *, int);
typedef asmlinkage long (*orig_rename_t)    (const char __user *, const char __user *);
typedef asmlinkage long (*orig_renameat_t)  (int, const char __user *, int, const char __user *);
typedef asmlinkage long (*orig_renameat2_t) (int, const char __user *, int, const char __user *, unsigned int);
typedef asmlinkage long (*orig_truncate_t)  (const char __user *, long);
typedef asmlinkage long (*orig_ftruncate_t) (unsigned int, unsigned long);
typedef asmlinkage long (*orig_open_t)      (const char __user *, int, umode_t);
typedef asmlinkage long (*orig_openat_t)    (int, const char __user *, int, umode_t);
typedef asmlinkage long (*orig_creat_t)     (const char __user *, umode_t);
typedef asmlinkage long (*orig_chmod_t)     (const char __user *, umode_t);
typedef asmlinkage long (*orig_fchmodat_t)  (int, const char __user *, umode_t);
typedef asmlinkage long (*orig_chown_t)     (const char __user *, uid_t, gid_t);
typedef asmlinkage long (*orig_fchownat_t)  (int, const char __user *, uid_t, gid_t, int);
typedef asmlinkage long (*orig_link_t)      (const char __user *, const char __user *);
typedef asmlinkage long (*orig_linkat_t)    (int, const char __user *, int, const char __user *, int);
typedef asmlinkage long (*orig_setxattr_t)  (const char __user *, const char __user *, const void __user *, size_t, int);
typedef asmlinkage long (*orig_lsetxattr_t) (const char __user *, const char __user *, const void __user *, size_t, int);
typedef asmlinkage long (*orig_fsetxattr_t) (int, const char __user *, const void __user *, size_t, int);

static sys_call_ptr_t   *sys_call_table;
static orig_write_t      orig_sys_write;
static orig_unlink_t     orig_sys_unlink;
static orig_unlinkat_t   orig_sys_unlinkat;
static orig_rename_t     orig_sys_rename;
static orig_renameat_t   orig_sys_renameat;
#ifdef __NR_renameat2
static orig_renameat2_t  orig_sys_renameat2;
#endif
static orig_truncate_t   orig_sys_truncate;
static orig_ftruncate_t  orig_sys_ftruncate;
static orig_open_t       orig_sys_open;
static orig_openat_t     orig_sys_openat;
static orig_creat_t      orig_sys_creat;
static orig_chmod_t      orig_sys_chmod;
static orig_fchmodat_t   orig_sys_fchmodat;
static orig_chown_t      orig_sys_chown;
static orig_fchownat_t   orig_sys_fchownat;
static orig_link_t       orig_sys_link;
static orig_linkat_t     orig_sys_linkat;
static orig_setxattr_t   orig_sys_setxattr;
static orig_lsetxattr_t  orig_sys_lsetxattr;
static orig_fsetxattr_t  orig_sys_fsetxattr;

// cr0 wp bit confusion
static unsigned long fim_force_order;

static inline void mywrite_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val), "+m"(fim_force_order));
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

static long fim_check(uint64_t dev, uint64_t ino, uint32_t op,
                       const char *op_name)
{
    uint32_t block_mode;

    if (!inode_policy_lookup(dev, ino, op, &block_mode))
        return 0;

    if (block_mode == FIM_BLOCK_DENY) {
        pr_info("DENY %s: comm=%s dev=%llu ino=%llu\n",
                op_name, current->comm, dev, ino);
        fim_event_enqueue(dev, ino, op, 1);
        return -EPERM;
    }

    fim_event_enqueue(dev, ino, op, 0);
    return 0;
}

static long fim_check_delete(uint64_t dev, uint64_t ino)
{
    uint32_t block_mode;

    if (!inode_policy_lookup(dev, ino, FIM_OP_DELETE, &block_mode))
        return 0;

    if (block_mode == FIM_BLOCK_DENY) {
        pr_info("DENY delete: comm=%s dev=%llu ino=%llu\n",
                current->comm, dev, ino);
        fim_event_enqueue(dev, ino, FIM_OP_DELETE, 1);
        return -EPERM;
    }

    fim_event_enqueue(dev, ino, FIM_OP_DELETE, 0);
    inode_policy_remove(dev, ino);
    return 0;
}


static asmlinkage long fim_sys_write(unsigned int fd,
                                     const char __user *buf,
                                     size_t count)
{
    uint64_t dev, ino;
    long rc = 0;

    if (fd_to_devino(fd, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "write");

    if (rc)
        return rc;
    return orig_sys_write(fd, buf, count);
}

static asmlinkage long fim_sys_truncate(const char __user *path, long length)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino(path, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "truncate");

    if (rc)
        return rc;
    return orig_sys_truncate(path, length);
}

static asmlinkage long fim_sys_ftruncate(unsigned int fd, unsigned long length)
{
    uint64_t dev, ino;
    long rc = 0;

    if (fd_to_devino(fd, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "ftruncate");

    if (rc)
        return rc;
    return orig_sys_ftruncate(fd, length);
}

static long check_open_flags(int dfd, const char __user *upath, int flags)
{
    uint64_t dev, ino;

    if (!(flags & (O_WRONLY | O_RDWR | O_TRUNC)))
        return 0;

    if (!pathat_to_devino(dfd, upath, &dev, &ino))
        return 0;
    return fim_check(dev, ino, FIM_OP_WRITE, "open");
}

static asmlinkage long fim_sys_open(const char __user *filename,
                                    int flags, umode_t mode)
{
    long rc = check_open_flags(AT_FDCWD, filename, flags);
    if (rc)
        return rc;
    return orig_sys_open(filename, flags, mode);
}

static asmlinkage long fim_sys_openat(int dfd, const char __user *filename,
                                      int flags, umode_t mode)
{
    long rc = check_open_flags(dfd, filename, flags);
    if (rc)
        return rc;
    return orig_sys_openat(dfd, filename, flags, mode);
}

static asmlinkage long fim_sys_creat(const char __user *pathname, umode_t mode)
{
    long rc = check_open_flags(AT_FDCWD, pathname, O_WRONLY | O_TRUNC);
    if (rc)
        return rc;
    return orig_sys_creat(pathname, mode);
}

static asmlinkage long fim_sys_unlink(const char __user *pathname)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino(pathname, &dev, &ino))
        rc = fim_check_delete(dev, ino);

    if (rc)
        return rc;
    return orig_sys_unlink(pathname);
}

static asmlinkage long fim_sys_unlinkat(int dfd,
                                        const char __user *pathname,
                                        int flag)
{
    uint64_t dev, ino;
    long rc = 0;

    if (!(flag & AT_REMOVEDIR) && pathat_to_devino(dfd, pathname, &dev, &ino))
        rc = fim_check_delete(dev, ino);

    if (rc)
        return rc;
    return orig_sys_unlinkat(dfd, pathname, flag);
}

static long check_rename(int olddfd, const char __user *oldname,
                          int newdfd, const char __user *newname)
{
    uint64_t dev, ino;
    uint32_t block_mode;
    long rc = 0;

    if (pathat_to_devino(olddfd, oldname, &dev, &ino)) {
        rc = fim_check(dev, ino, FIM_OP_RENAME, "rename(src)");
        if (rc)
            return rc;
    }

    if (pathat_to_devino(newdfd, newname, &dev, &ino)) {
        if (inode_policy_lookup(dev, ino, FIM_OP_RENAME, &block_mode)
            && block_mode == FIM_BLOCK_DENY) {
            pr_info("DENY rename(dst): comm=%s dev=%llu ino=%llu\n",
                    current->comm, dev, ino);
            fim_event_enqueue(dev, ino, FIM_OP_RENAME, 1);
            return -EPERM;
        }
    }

    return 0;
}

static asmlinkage long fim_sys_rename(const char __user *oldname,
                                      const char __user *newname)
{
    long rc = check_rename(AT_FDCWD, oldname, AT_FDCWD, newname);
    if (rc)
        return rc;
    return orig_sys_rename(oldname, newname);
}

static asmlinkage long fim_sys_renameat(int olddfd,
                                        const char __user *oldname,
                                        int newdfd,
                                        const char __user *newname)
{
    long rc = check_rename(olddfd, oldname, newdfd, newname);
    if (rc)
        return rc;
    return orig_sys_renameat(olddfd, oldname, newdfd, newname);
}

#ifdef __NR_renameat2
static asmlinkage long fim_sys_renameat2(int olddfd,
                                         const char __user *oldname,
                                         int newdfd,
                                         const char __user *newname,
                                         unsigned int flags)
{
    long rc = check_rename(olddfd, oldname, newdfd, newname);
    if (rc)
        return rc;
    return orig_sys_renameat2(olddfd, oldname, newdfd, newname, flags);
}
#endif

static asmlinkage long fim_sys_chmod(const char __user *filename, umode_t mode)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino(filename, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "chmod");

    if (rc)
        return rc;
    return orig_sys_chmod(filename, mode);
}

static asmlinkage long fim_sys_fchmodat(int dfd,
                                        const char __user *filename,
                                        umode_t mode)
{
    uint64_t dev, ino;
    long rc = 0;

    if (pathat_to_devino(dfd, filename, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "fchmodat");

    if (rc)
        return rc;
    return orig_sys_fchmodat(dfd, filename, mode);
}

static asmlinkage long fim_sys_chown(const char __user *filename,
                                     uid_t user, gid_t group)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino(filename, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "chown");

    if (rc)
        return rc;
    return orig_sys_chown(filename, user, group);
}

static asmlinkage long fim_sys_fchownat(int dfd,
                                        const char __user *filename,
                                        uid_t user, gid_t group, int flag)
{
    uint64_t dev, ino;
    long rc = 0;

    if (pathat_to_devino(dfd, filename, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "fchownat");

    if (rc)
        return rc;
    return orig_sys_fchownat(dfd, filename, user, group, flag);
}

static asmlinkage long fim_sys_link(const char __user *oldname,
                                    const char __user *newname)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino(oldname, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "link");

    if (rc)
        return rc;
    return orig_sys_link(oldname, newname);
}

static asmlinkage long fim_sys_linkat(int olddfd,
                                      const char __user *oldname,
                                      int newdfd,
                                      const char __user *newname,
                                      int flags)
{
    uint64_t dev, ino;
    long rc = 0;

    if (pathat_to_devino(olddfd, oldname, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "linkat");

    if (rc)
        return rc;
    return orig_sys_linkat(olddfd, oldname, newdfd, newname, flags);
}

static asmlinkage long fim_sys_setxattr(const char __user *path,
                                        const char __user *name,
                                        const void __user *value,
                                        size_t size, int flags)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino(path, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "setxattr");

    if (rc)
        return rc;
    return orig_sys_setxattr(path, name, value, size, flags);
}

static asmlinkage long fim_sys_lsetxattr(const char __user *path,
                                         const char __user *name,
                                         const void __user *value,
                                         size_t size, int flags)
{
    uint64_t dev, ino;
    long rc = 0;

    if (path_to_devino(path, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "lsetxattr");

    if (rc)
        return rc;
    return orig_sys_lsetxattr(path, name, value, size, flags);
}

static asmlinkage long fim_sys_fsetxattr(int fd,
                                         const char __user *name,
                                         const void __user *value,
                                         size_t size, int flags)
{
    uint64_t dev, ino;
    long rc = 0;

    if (fd_to_devino(fd, &dev, &ino))
        rc = fim_check(dev, ino, FIM_OP_WRITE, "fsetxattr");

    if (rc)
        return rc;
    return orig_sys_fsetxattr(fd, name, value, size, flags);
}

#define HOOK(name) \
    orig_sys_##name = (orig_##name##_t)sys_call_table[__NR_##name]; \
    sys_call_table[__NR_##name] = (sys_call_ptr_t)fim_sys_##name

#define UNHOOK(name) \
    sys_call_table[__NR_##name] = (sys_call_ptr_t)orig_sys_##name

int fim_hooks_init(void)
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

    pr_info("hooks installed (sys_call_table direct-args, %d syscalls)\n", 19);
    return 0;
}

void fim_hooks_exit(void)
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
