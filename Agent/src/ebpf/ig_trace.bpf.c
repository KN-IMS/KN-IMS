// SPDX-License-Identifier: GPL-2.0
/*
 * ig_trace.bpf.c — inode policy 기반 eBPF LSM 프로그램
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

enum {
    IG_EBPF_OP_READ   = 0x01,
    IG_EBPF_OP_WRITE  = 0x02,
    IG_EBPF_OP_DELETE = 0x04,
    IG_EBPF_OP_ATTR   = 0x08,
};

enum {
    IG_HOOK_FILE_PERMISSION = 1,
    IG_HOOK_FILE_OPEN       = 2,
    IG_HOOK_PATH_UNLINK     = 3,
    IG_HOOK_PATH_RENAME     = 4,
    IG_HOOK_PATH_TRUNCATE   = 5,
    IG_HOOK_PATH_CHMOD      = 6,
    IG_HOOK_INODE_SETATTR   = 7,
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

/* fork-time process cache — race-free chain reconstruction
 * BPF 스택 512B 제약 → entry는 compact (~200B)
 * exe는 d_path 비싸므로 생략, 유저측 /proc fallback */
struct ig_proc_entry {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 euid;
    __u32 sid;
    __u32 _pad;
    char  comm[16];
    char  tty[16];
    __u64 start_time_ns;
    char  cmdline[160];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct ig_proc_entry);
} proc_map SEC(".maps");

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
        op_mask |= IG_EBPF_OP_READ;
    if (mask & MAY_WRITE)
        op_mask |= IG_EBPF_OP_WRITE;
    if (!op_mask)
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, op_mask, IG_HOOK_FILE_PERMISSION);
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
        op_mask |= IG_EBPF_OP_READ;
    if (mode & FMODE_WRITE)
        op_mask |= IG_EBPF_OP_WRITE;
    if (!op_mask)
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, op_mask, IG_HOOK_FILE_OPEN);
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

    return audit_inode(inode, IG_EBPF_OP_DELETE, IG_HOOK_PATH_UNLINK);
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
            result = audit_inode(inode, IG_EBPF_OP_WRITE, IG_HOOK_PATH_RENAME);
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
            result = audit_inode(inode, IG_EBPF_OP_DELETE, IG_HOOK_PATH_RENAME);
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

    return audit_inode(inode, IG_EBPF_OP_WRITE, IG_HOOK_PATH_TRUNCATE);
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

    return audit_inode(inode, IG_EBPF_OP_ATTR, IG_HOOK_PATH_CHMOD);
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
        op_mask |= IG_EBPF_OP_ATTR;
    if (valid & ATTR_SIZE)
        op_mask |= IG_EBPF_OP_WRITE;
    if (!op_mask)
        return 0;

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    return audit_inode(inode, op_mask, IG_HOOK_INODE_SETATTR);
}

/* ── fork-time process tree — sched_process_{fork,exec,exit} ───────── */

static __always_inline void
fill_entry_from_task(struct task_struct *t, struct ig_proc_entry *e)
{
    struct task_struct *parent;
    struct signal_struct *sig;

    e->pid  = BPF_CORE_READ(t, tgid);
    parent  = BPF_CORE_READ(t, real_parent);
    e->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
    e->uid  = BPF_CORE_READ(t, cred, uid.val);
    e->euid = BPF_CORE_READ(t, cred, euid.val);
    sig     = BPF_CORE_READ(t, signal);
    e->sid  = sig ? BPF_CORE_READ(sig, pids[PIDTYPE_SID], numbers[0].nr) : 0;
    e->start_time_ns = BPF_CORE_READ(t, start_boottime);
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), BPF_CORE_READ(t, comm));
    /* tty: signal->tty->name */
    {
        struct tty_struct *tty = sig ? BPF_CORE_READ(sig, tty) : NULL;
        if (tty) {
            const char *name = BPF_CORE_READ(tty, name);
            if (name) bpf_probe_read_kernel_str(e->tty, sizeof(e->tty), name);
            else      e->tty[0] = '\0';
        } else {
            e->tty[0] = '\0';
        }
    }
    e->cmdline[0] = '\0';   /* exec에서 채움 */
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_sched_fork, struct task_struct *parent, struct task_struct *child)
{
    struct ig_proc_entry e = {};
    __u32 key;

    if (!child) return 0;
    fill_entry_from_task(child, &e);
    key = e.pid;
    bpf_map_update_elem(&proc_map, &key, &e, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_sched_exec, struct task_struct *t, pid_t old_pid,
             struct linux_binprm *bprm)
{
    struct ig_proc_entry *e;
    struct mm_struct *mm;
    unsigned long arg_start, arg_end, len;
    __u32 key;

    if (!t) return 0;
    key = BPF_CORE_READ(t, tgid);
    e = bpf_map_lookup_elem(&proc_map, &key);
    if (!e) {
        struct ig_proc_entry tmp = {};
        fill_entry_from_task(t, &tmp);
        bpf_map_update_elem(&proc_map, &key, &tmp, BPF_ANY);
        e = bpf_map_lookup_elem(&proc_map, &key);
        if (!e) return 0;
    }

    /* exec 후 comm 갱신 */
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), BPF_CORE_READ(t, comm));

    /* cmdline: arg_start..arg_end 를 user mem에서 읽기 */
    mm = BPF_CORE_READ(t, mm);
    if (!mm) return 0;
    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end   = BPF_CORE_READ(mm, arg_end);
    if (arg_end <= arg_start) return 0;

    len = arg_end - arg_start;
    if (len > sizeof(e->cmdline) - 1) len = sizeof(e->cmdline) - 1;
    bpf_probe_read_user(e->cmdline, len, (void *)arg_start);
    e->cmdline[len] = '\0';
    /* NUL → space */
    {
        unsigned int i;
        #pragma unroll
        for (i = 0; i < sizeof(e->cmdline) - 1; i++) {
            if (i >= len) break;
            if (e->cmdline[i] == '\0') e->cmdline[i] = ' ';
        }
    }
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_sched_exit, struct task_struct *t)
{
    __u32 key;
    if (!t) return 0;
    key = BPF_CORE_READ(t, tgid);
    bpf_map_delete_elem(&proc_map, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
