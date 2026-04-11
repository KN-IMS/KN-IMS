// SPDX-License-Identifier: GPL-2.0
/*
 * im_trace.bpf.c — inode policy 기반 eBPF LSM 프로그램
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

enum {
    IM_EBPF_OP_READ   = 0x01,
    IM_EBPF_OP_WRITE  = 0x02,
    IM_EBPF_OP_DELETE = 0x04,
    IM_EBPF_OP_ATTR   = 0x08,
};

enum {
    IM_HOOK_FILE_PERMISSION = 1,
    IM_HOOK_FILE_OPEN       = 2,
    IM_HOOK_PATH_UNLINK     = 3,
    IM_HOOK_PATH_RENAME     = 4,
    IM_HOOK_PATH_TRUNCATE   = 5,
    IM_HOOK_PATH_CHMOD      = 6,
    IM_HOOK_INODE_SETATTR   = 7,
};

#ifndef EPERM
#define EPERM 1
#endif

#ifndef MAY_WRITE
#define MAY_WRITE 2
#endif
#ifndef MAY_READ
#define MAY_READ 4
#endif
#ifndef FMODE_READ
#define FMODE_READ 1
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE 2
#endif

/* ia_valid flags (from linux/fs.h) */
#ifndef ATTR_MODE
#define ATTR_MODE  0x00000001
#endif
#ifndef ATTR_UID
#define ATTR_UID   0x00000002
#endif
#ifndef ATTR_GID
#define ATTR_GID   0x00000004
#endif
#ifndef ATTR_SIZE
#define ATTR_SIZE  0x00000008
#endif

struct inode_key {
    __u64 dev;
    __u64 ino;
};

struct inode_policy {
    __u32 mask;
    __u32 block;
};

struct audit_event {
    __u64 dev;
    __u64 ino;
    __u32 pid;
    __u32 uid;
    __u32 op_mask;
    __u32 hook_id;
    __u32 denied;
    char  comm[16];
    __u64 ts_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct inode_key);
    __type(value, struct inode_policy);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} hook_stats SEC(".maps");

static __always_inline void count_hook(__u32 hook_id)
{
    __u64 *value = bpf_map_lookup_elem(&hook_stats, &hook_id);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int audit_inode(struct inode *inode, __u32 op_mask, __u32 hook_id)
{
    struct inode_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key.ino = BPF_CORE_READ(inode, i_ino);
    const struct inode_policy *policy = bpf_map_lookup_elem(&policy_map, &key);
    struct audit_event *e;
    __u64 pid_tgid;

    if (!policy || !(policy->mask & op_mask))
        return 0;

    count_hook(hook_id);

    e = bpf_ringbuf_reserve(&audit_rb, sizeof(*e), 0);
    if (!e)
        return policy->block ? -EPERM : 0;

    pid_tgid = bpf_get_current_pid_tgid();
    e->dev = key.dev;
    e->ino = key.ino;
    e->pid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->op_mask = op_mask;
    e->hook_id = hook_id;
    e->denied = policy->block ? 1 : 0;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return policy->block ? -EPERM : 0;
}

SEC("lsm/file_permission")
int BPF_PROG(check_file_permission, struct file *file, int mask, int ret)
{
    struct inode *inode;
    __u32 op_mask = 0;

    if (ret)
        return ret;
    if (!file)
        return 0;
    if (mask & MAY_READ)
        op_mask |= IM_EBPF_OP_READ;
    if (mask & MAY_WRITE)
        op_mask |= IM_EBPF_OP_WRITE;
    if (!op_mask)
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, op_mask, IM_HOOK_FILE_PERMISSION);
}

SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file, int ret)
{
    struct inode *inode;
    fmode_t mode;
    __u32 op_mask = 0;

    if (ret)
        return ret;
    if (!file)
        return 0;

    mode = BPF_CORE_READ(file, f_mode);
    if (mode & FMODE_READ)
        op_mask |= IM_EBPF_OP_READ;
    if (mode & FMODE_WRITE)
        op_mask |= IM_EBPF_OP_WRITE;
    if (!op_mask)
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, op_mask, IM_HOOK_FILE_OPEN);
}

SEC("lsm/path_unlink")
int BPF_PROG(check_path_unlink, const struct path *dir, struct dentry *dentry, int ret)
{
    struct inode *inode;

    if (ret)
        return ret;
    if (!dentry)
        return 0;

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, IM_EBPF_OP_DELETE, IM_HOOK_PATH_UNLINK);
}

SEC("lsm/path_rename")
int BPF_PROG(check_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry,
             unsigned int flags, int ret)
{
    struct inode *inode;
    int result;

    if (ret)
        return ret;

    /* source 파일 체크 */
    if (old_dentry) {
        inode = BPF_CORE_READ(old_dentry, d_inode);
        if (inode) {
            result = audit_inode(inode, IM_EBPF_OP_WRITE, IM_HOOK_PATH_RENAME);
            if (result)
                return result;
        }
    }

    /* destination 파일 체크 — mv vuln protect 처럼 보호 파일을 덮어쓰는 경우 차단
     * rename 시 destination이 존재하면 묵시적 unlink가 발생하므로
     * path_unlink 훅이 불리지 않아 별도로 체크해야 함 */
    if (new_dentry) {
        inode = BPF_CORE_READ(new_dentry, d_inode);
        if (inode) {
            result = audit_inode(inode, IM_EBPF_OP_DELETE, IM_HOOK_PATH_RENAME);
            if (result)
                return result;
        }
    }

    return 0;
}

SEC("lsm/path_truncate")
int BPF_PROG(check_path_truncate, const struct path *path, int ret)
{
    struct inode *inode;

    if (ret)
        return ret;
    if (!path)
        return 0;

    inode = BPF_CORE_READ(path, dentry, d_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, IM_EBPF_OP_WRITE, IM_HOOK_PATH_TRUNCATE);
}

SEC("lsm/path_chmod")
int BPF_PROG(check_path_chmod, const struct path *path, umode_t mode, int ret)
{
    struct inode *inode;

    if (ret)
        return ret;
    if (!path)
        return 0;

    inode = BPF_CORE_READ(path, dentry, d_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, IM_EBPF_OP_ATTR, IM_HOOK_PATH_CHMOD);
}

SEC("lsm/inode_setattr")
int BPF_PROG(check_inode_setattr, struct dentry *dentry, struct iattr *attr, int ret)
{
    struct inode *inode;
    __u32 op_mask = 0;
    __u32 valid;

    if (ret)
        return ret;
    if (!dentry || !attr)
        return 0;

    valid = BPF_CORE_READ(attr, ia_valid);
    if (valid & (ATTR_MODE | ATTR_UID | ATTR_GID))
        op_mask |= IM_EBPF_OP_ATTR;
    if (valid & ATTR_SIZE)
        op_mask |= IM_EBPF_OP_WRITE;
    if (!op_mask)
        return 0;

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, op_mask, IM_HOOK_INODE_SETATTR);
}

char LICENSE[] SEC("license") = "GPL";
