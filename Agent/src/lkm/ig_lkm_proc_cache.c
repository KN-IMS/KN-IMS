// SPDX-License-Identifier: GPL-2.0
/*
 * ig_lkm_proc_cache.c — fork-time process tree cache
 *
 * 단일 spinlock_irqsave + open hash + LRU.
 * sched_process_{fork,exec,exit} 세 개 tracepoint에 콜백 등록.
 *
 * 안전성:
 *   - fork/exit 콜백은 atomic context (스케줄러 안). spinlock OK, sleep 금지.
 *   - exec 콜백은 sleepable. mm 접근 후 spinlock 잠시 잡고 memcpy.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include <linux/tracepoint.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/tty.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#  include <linux/sched/task.h>
#  include <linux/sched/signal.h>
#  include <linux/sched/mm.h>
#endif

#include "ig_lkm_common.h"
#include "ig_lkm_proc_cache.h"

/* ── 튜닝 상수 ────────────────────────────────────── */
#define IG_PC_HASH_BITS      12                   /* 4096 buckets */
#define IG_PC_MAX_ENTRIES    8192
#define IG_PC_GRACE_NS       (5ULL * 60 * 1000000000ULL)  /* 5분 */
#define IG_PC_GC_INTERVAL    (60 * HZ)            /* 60s GC */
#define IG_PC_THROTTLE_RATE  10000                /* fork-bomb 보호 */

/* ── entry ─────────────────────────────────────────── */
struct ig_pc_entry {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t euid;
    uint32_t sid;
    char     comm[16];
    char     tty[16];
    uint64_t start_time_ns;
    char     exe[256];
    char     cmdline[512];
    uint64_t exit_time_ns;        /* 0 = alive */
    struct hlist_node hnode;
    struct list_head  lru;
};

static DEFINE_HASHTABLE(ig_pc_table, IG_PC_HASH_BITS);
static LIST_HEAD(ig_pc_lru);
static DEFINE_SPINLOCK(ig_pc_lock);

static atomic_t ig_pc_count    = ATOMIC_INIT(0);
static atomic_t ig_pc_inserts  = ATOMIC_INIT(0);
static atomic_t ig_pc_hits     = ATOMIC_INIT(0);
static atomic_t ig_pc_misses   = ATOMIC_INIT(0);
static atomic_t ig_pc_evicts   = ATOMIC_INIT(0);
static atomic_t ig_pc_throttle = ATOMIC_INIT(0);

/* throttle window */
static unsigned long ig_pc_window_jiffies;
static atomic_t      ig_pc_window_count = ATOMIC_INIT(0);

/* ── helpers ───────────────────────────────────────── */

static inline u64 task_start_ns(const struct task_struct *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    return t->start_boottime;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    return (u64)t->real_start_time;
#else
    return (u64)timespec_to_ns(&t->real_start_time);
#endif
}

/* tty 이름 안전한 추출 — 포인터 race 가드(READ_ONCE) */
static void capture_tty(struct task_struct *t, char *out, size_t outlen)
{
    struct signal_struct *sig;
    struct tty_struct *tty;

    out[0] = '\0';
    if (!t) return;
    sig = READ_ONCE(t->signal);
    if (!sig) return;
    tty = READ_ONCE(sig->tty);
    if (!tty) return;
    strncpy(out, tty->name, outlen - 1);
    out[outlen - 1] = '\0';
}

/* lock 보유 상태에서 호출 */
static struct ig_pc_entry *ig_pc_find_locked(uint32_t pid)
{
    struct ig_pc_entry *e;
    hash_for_each_possible(ig_pc_table, e, hnode, pid) {
        if (e->pid == pid) return e;
    }
    return NULL;
}

/* LRU 후미에서 가장 오래된 것 evict (이미 lock 보유) */
static void ig_pc_evict_one_locked(void)
{
    struct ig_pc_entry *victim;
    if (list_empty(&ig_pc_lru)) return;
    victim = list_last_entry(&ig_pc_lru, struct ig_pc_entry, lru);
    hash_del(&victim->hnode);
    list_del(&victim->lru);
    atomic_dec(&ig_pc_count);
    atomic_inc(&ig_pc_evicts);
    kfree(victim);
}

/* fork-bomb throttle: 1초 윈도우, 초과시 true (skip) */
static bool ig_pc_should_throttle(void)
{
    unsigned long now = jiffies;
    unsigned long w   = READ_ONCE(ig_pc_window_jiffies);
    if (time_after(now, w + HZ)) {
        WRITE_ONCE(ig_pc_window_jiffies, now);
        atomic_set(&ig_pc_window_count, 0);
    }
    if (atomic_inc_return(&ig_pc_window_count) > IG_PC_THROTTLE_RATE) {
        atomic_inc(&ig_pc_throttle);
        return true;
    }
    return false;
}

/* exec 시 mm에서 cmdline + exe 캡처 (sleepable context). 호출자 책임:
 * 이 함수는 lock 잡지 않음. 결과 buffer를 호출자가 lock 안에서 entry로 복사. */
static void capture_exec_meta(struct task_struct *t,
                               char *exe_out, size_t exe_len,
                               char *cmd_out, size_t cmd_len)
{
    struct mm_struct *mm;
    struct file *exe_file;
    char *path_buf;
    unsigned long arg_start, arg_end;
    int copied;

    exe_out[0] = '\0';
    cmd_out[0] = '\0';

    mm = get_task_mm(t);
    if (!mm) return;

    /* exe path */
    exe_file = get_mm_exe_file(mm);
    if (exe_file) {
        path_buf = (char *)__get_free_page(GFP_KERNEL);
        if (path_buf) {
            char *p = d_path(&exe_file->f_path, path_buf, PAGE_SIZE);
            if (!IS_ERR(p)) {
                strncpy(exe_out, p, exe_len - 1);
                exe_out[exe_len - 1] = '\0';
            }
            free_page((unsigned long)path_buf);
        }
        fput(exe_file);
    }

    /* cmdline (arg_start..arg_end) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
    arg_start = mm->arg_start;
    arg_end   = mm->arg_end;
    mmap_read_unlock(mm);
#else
    down_read(&mm->mmap_sem);
    arg_start = mm->arg_start;
    arg_end   = mm->arg_end;
    up_read(&mm->mmap_sem);
#endif

    if (arg_end > arg_start) {
        size_t want = (size_t)(arg_end - arg_start);
        if (want > cmd_len - 1) want = cmd_len - 1;
        copied = access_process_vm(t, arg_start, cmd_out, want, FOLL_ANON);
        if (copied <= 0) {
            cmd_out[0] = '\0';
        } else {
            int i;
            for (i = 0; i < copied - 1; i++)
                if (cmd_out[i] == '\0') cmd_out[i] = ' ';
            cmd_out[copied] = '\0';
        }
    }

    mmput(mm);
}

/* ── tracepoint 콜백 ──────────────────────────────── */

static void ig_pc_on_fork(void *ignore,
                            struct task_struct *parent,
                            struct task_struct *child)
{
    struct ig_pc_entry *e;
    const struct cred *cred;
    unsigned long flags;

    if (!child) return;
    if (ig_pc_should_throttle()) return;

    e = kzalloc(sizeof(*e), GFP_ATOMIC);
    if (!e) return;

    e->pid           = task_pid_nr(child);
    e->ppid          = parent ? task_pid_nr(parent) : 0;
    cred             = __task_cred(child);
    e->uid           = from_kuid(&init_user_ns, cred->uid);
    e->euid          = from_kuid(&init_user_ns, cred->euid);
    e->sid           = task_session_vnr(child);
    e->start_time_ns = task_start_ns(child);
    e->exit_time_ns  = 0;
    get_task_comm(e->comm, child);
    capture_tty(child, e->tty, sizeof(e->tty));

    spin_lock_irqsave(&ig_pc_lock, flags);

    /* 동일 pid 재사용 가드 (PID reuse) */
    {
        struct ig_pc_entry *old = ig_pc_find_locked(e->pid);
        if (old) {
            hash_del(&old->hnode);
            list_del(&old->lru);
            atomic_dec(&ig_pc_count);
            kfree(old);
        }
    }

    if (atomic_read(&ig_pc_count) >= IG_PC_MAX_ENTRIES)
        ig_pc_evict_one_locked();

    hash_add(ig_pc_table, &e->hnode, e->pid);
    list_add(&e->lru, &ig_pc_lru);
    atomic_inc(&ig_pc_count);
    atomic_inc(&ig_pc_inserts);

    spin_unlock_irqrestore(&ig_pc_lock, flags);
}

static void ig_pc_on_exec(void *ignore,
                            struct task_struct *t,
                            pid_t old_pid,
                            struct linux_binprm *bprm)
{
    char exe_buf[256], cmd_buf[512];
    struct ig_pc_entry *e;
    unsigned long flags;
    uint32_t pid;

    if (!t) return;
    pid = task_pid_nr(t);

    /* sleepable context — mm 접근 안전 */
    capture_exec_meta(t, exe_buf, sizeof(exe_buf), cmd_buf, sizeof(cmd_buf));

    spin_lock_irqsave(&ig_pc_lock, flags);
    e = ig_pc_find_locked(pid);
    if (e) {
        if (exe_buf[0]) {
            strncpy(e->exe, exe_buf, sizeof(e->exe) - 1);
            e->exe[sizeof(e->exe) - 1] = '\0';
        }
        if (cmd_buf[0]) {
            strncpy(e->cmdline, cmd_buf, sizeof(e->cmdline) - 1);
            e->cmdline[sizeof(e->cmdline) - 1] = '\0';
        }
        /* exec 시 comm + tty 갱신 (이름 바뀜) */
        get_task_comm(e->comm, t);
        capture_tty(t, e->tty, sizeof(e->tty));
        /* LRU 갱신 */
        list_move(&e->lru, &ig_pc_lru);
    }
    spin_unlock_irqrestore(&ig_pc_lock, flags);
}

static void ig_pc_on_exit(void *ignore, struct task_struct *t)
{
    struct ig_pc_entry *e;
    unsigned long flags;
    uint32_t pid;
    u64 now_ns = ktime_get_real_ns();

    if (!t) return;
    pid = task_pid_nr(t);

    spin_lock_irqsave(&ig_pc_lock, flags);
    e = ig_pc_find_locked(pid);
    if (e) {
        e->exit_time_ns = now_ns;
        /* tombstone — LRU 끝쪽으로 (GC 우선 대상) */
        list_move_tail(&e->lru, &ig_pc_lru);
    }
    spin_unlock_irqrestore(&ig_pc_lock, flags);
}

/* ── chain 수집 (외부 API) ─────────────────────────── */

int ig_proc_cache_collect_chain(uint32_t start_pid,
                                 struct ig_lkm_chain_entry *out,
                                 int max_depth,
                                 uint8_t *truncated_out)
{
    int depth = 0;
    uint32_t cur = start_pid;
    unsigned long flags;
    int i;

    if (truncated_out) *truncated_out = 0;
    if (!out || max_depth <= 0) return 0;

    spin_lock_irqsave(&ig_pc_lock, flags);
    for (i = 0; i < max_depth; i++) {
        struct ig_pc_entry *e = ig_pc_find_locked(cur);
        struct ig_lkm_chain_entry *o = &out[i];

        if (!e) {
            atomic_inc(&ig_pc_misses);
            if (truncated_out) *truncated_out = 1;
            break;
        }
        atomic_inc(&ig_pc_hits);

        memset(o, 0, sizeof(*o));
        o->pid           = e->pid;
        o->ppid          = e->ppid;
        o->uid           = e->uid;
        o->euid          = e->euid;
        o->sid           = e->sid;
        o->start_time_ns = e->start_time_ns;
        memcpy(o->comm, e->comm, sizeof(o->comm));
        memcpy(o->tty,  e->tty,  sizeof(o->tty));
        /* chain entry에 exe/cmdline 임베드. ig_lkm_common.h 길이에 맞춰 잘림 */
        strncpy(o->exe,     e->exe,     sizeof(o->exe) - 1);
        o->exe[sizeof(o->exe) - 1] = '\0';
        strncpy(o->cmdline, e->cmdline, sizeof(o->cmdline) - 1);
        o->cmdline[sizeof(o->cmdline) - 1] = '\0';

        depth = i + 1;
        if (e->ppid <= 1 || e->ppid == cur) break;
        cur = e->ppid;

        if (i == max_depth - 1 && truncated_out) *truncated_out = 1;
    }
    spin_unlock_irqrestore(&ig_pc_lock, flags);

    return depth;
}

/* exe/cmdline까지 회수하는 별도 lookup — events.c에서 chain 채울 때 호출 */
int ig_proc_cache_lookup_full(uint32_t pid,
                                char *comm_out,    size_t comm_len,
                                char *exe_out,     size_t exe_len,
                                char *cmdline_out, size_t cmd_len)
{
    struct ig_pc_entry *e;
    unsigned long flags;
    int found = 0;

    spin_lock_irqsave(&ig_pc_lock, flags);
    e = ig_pc_find_locked(pid);
    if (e) {
        found = 1;
        if (comm_out)    { strncpy(comm_out, e->comm, comm_len - 1);    comm_out[comm_len - 1] = '\0'; }
        if (exe_out)     { strncpy(exe_out, e->exe, exe_len - 1);       exe_out[exe_len - 1] = '\0'; }
        if (cmdline_out) { strncpy(cmdline_out, e->cmdline, cmd_len - 1); cmdline_out[cmd_len - 1] = '\0'; }
    }
    spin_unlock_irqrestore(&ig_pc_lock, flags);
    return found;
}

void ig_proc_cache_get_stats(uint32_t *count,
                              uint32_t *inserts,
                              uint32_t *hits,
                              uint32_t *misses,
                              uint32_t *evictions,
                              uint32_t *throttled)
{
    if (count)     *count     = atomic_read(&ig_pc_count);
    if (inserts)   *inserts   = atomic_read(&ig_pc_inserts);
    if (hits)      *hits      = atomic_read(&ig_pc_hits);
    if (misses)    *misses    = atomic_read(&ig_pc_misses);
    if (evictions) *evictions = atomic_read(&ig_pc_evicts);
    if (throttled) *throttled = atomic_read(&ig_pc_throttle);
}

/* ── GC: tombstone 5분 경과 제거 ──────────────────── */

static void ig_pc_gc_work(struct work_struct *w);
static DECLARE_DELAYED_WORK(ig_pc_gc_dw, ig_pc_gc_work);

static void ig_pc_gc_work(struct work_struct *w)
{
    struct ig_pc_entry *e, *tmp;
    unsigned long flags;
    u64 now_ns = ktime_get_real_ns();
    int reaped = 0;

    spin_lock_irqsave(&ig_pc_lock, flags);
    list_for_each_entry_safe_reverse(e, tmp, &ig_pc_lru, lru) {
        if (e->exit_time_ns == 0) continue;     /* 살아있음 */
        if (now_ns - e->exit_time_ns < IG_PC_GRACE_NS) continue;
        hash_del(&e->hnode);
        list_del(&e->lru);
        atomic_dec(&ig_pc_count);
        kfree(e);
        reaped++;
        if (reaped >= 256) break;               /* 한 번에 너무 많이 안 잡음 */
    }
    spin_unlock_irqrestore(&ig_pc_lock, flags);

    schedule_delayed_work(&ig_pc_gc_dw, IG_PC_GC_INTERVAL);
}

/* ── module load 시점 prepopulate ──────────────────
 * 이미 살아있는 프로세스(sshd, agent의 부모 bash 등)는 fork tracepoint를
 * 못 거쳤으므로 캐시에 없다. for_each_process로 한 번 훑어 전부 채움.
 * exe/cmdline은 mm 접근(sleepable) 필요 — 여기선 skeleton만 채우고
 * 사용자 측 /proc fallback에 맡긴다.
 */
static void ig_pc_preload(void)
{
    struct task_struct *t;
    unsigned long flags;
    int n = 0;

    rcu_read_lock();
    for_each_process(t) {
        struct ig_pc_entry *e;
        const struct cred *cred;

        e = kzalloc(sizeof(*e), GFP_ATOMIC);
        if (!e) continue;

        e->pid           = task_pid_nr(t);
        e->ppid          = t->real_parent ? task_pid_nr(t->real_parent) : 0;
        cred             = __task_cred(t);
        e->uid           = from_kuid(&init_user_ns, cred->uid);
        e->euid          = from_kuid(&init_user_ns, cred->euid);
        e->sid           = task_session_vnr(t);
        e->start_time_ns = task_start_ns(t);
        e->exit_time_ns  = 0;
        get_task_comm(e->comm, t);
        capture_tty(t, e->tty, sizeof(e->tty));

        spin_lock_irqsave(&ig_pc_lock, flags);
        if (atomic_read(&ig_pc_count) >= IG_PC_MAX_ENTRIES) {
            spin_unlock_irqrestore(&ig_pc_lock, flags);
            kfree(e);
            break;
        }
        if (ig_pc_find_locked(e->pid)) {
            spin_unlock_irqrestore(&ig_pc_lock, flags);
            kfree(e);
            continue;
        }
        hash_add(ig_pc_table, &e->hnode, e->pid);
        list_add(&e->lru, &ig_pc_lru);
        atomic_inc(&ig_pc_count);
        atomic_inc(&ig_pc_inserts);
        spin_unlock_irqrestore(&ig_pc_lock, flags);
        n++;
    }
    rcu_read_unlock();
    pr_info("proc_cache: preload %d existing processes\n", n);
}

/* ── tracepoint 포인터 lookup (RHEL/CentOS 등 미export 환경 우회) ── */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t pc_kallsyms_fn;

static int pc_resolve_kallsyms(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    pc_kallsyms_fn = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
#else
    pc_kallsyms_fn = kallsyms_lookup_name;
#endif
    return 0;
}

static struct tracepoint *tp_fork;
static struct tracepoint *tp_exec;
static struct tracepoint *tp_exit;
static int g_fork_reg, g_exec_reg, g_exit_reg;

/* ── init/exit ────────────────────────────────────── */

int ig_proc_cache_init(void)
{
    int ret;
    hash_init(ig_pc_table);
    INIT_LIST_HEAD(&ig_pc_lru);
    ig_pc_window_jiffies = jiffies;

    ret = pc_resolve_kallsyms();
    if (ret) {
        pr_err("proc_cache: kallsyms_lookup_name resolve failed: %d\n", ret);
        return ret;
    }

    tp_fork = (struct tracepoint *)pc_kallsyms_fn("__tracepoint_sched_process_fork");
    tp_exec = (struct tracepoint *)pc_kallsyms_fn("__tracepoint_sched_process_exec");
    tp_exit = (struct tracepoint *)pc_kallsyms_fn("__tracepoint_sched_process_exit");
    if (!tp_fork || !tp_exec || !tp_exit) {
        pr_err("proc_cache: tracepoint symbol not found "
                "(fork=%p exec=%p exit=%p)\n", tp_fork, tp_exec, tp_exit);
        return -ENOENT;
    }

    ret = tracepoint_probe_register(tp_fork, (void *)ig_pc_on_fork, NULL);
    if (ret) { pr_err("register fork tp failed: %d\n", ret); goto err1; }
    g_fork_reg = 1;

    ret = tracepoint_probe_register(tp_exec, (void *)ig_pc_on_exec, NULL);
    if (ret) { pr_err("register exec tp failed: %d\n", ret); goto err2; }
    g_exec_reg = 1;

    ret = tracepoint_probe_register(tp_exit, (void *)ig_pc_on_exit, NULL);
    if (ret) { pr_err("register exit tp failed: %d\n", ret); goto err3; }
    g_exit_reg = 1;

    /* tracepoint 등록 후 prepopulate — 그 사이 fork도 hash 중복 가드로 안전 */
    ig_pc_preload();

    schedule_delayed_work(&ig_pc_gc_dw, IG_PC_GC_INTERVAL);
    pr_info("proc_cache: tracepoints registered (max=%d, grace=300s)\n",
            IG_PC_MAX_ENTRIES);
    return 0;

err3: tracepoint_probe_unregister(tp_exec, (void *)ig_pc_on_exec, NULL); g_exec_reg = 0;
err2: tracepoint_probe_unregister(tp_fork, (void *)ig_pc_on_fork, NULL); g_fork_reg = 0;
err1: return ret;
}

void ig_proc_cache_exit(void)
{
    struct ig_pc_entry *e;
    struct hlist_node *tmp;
    int bkt;
    unsigned long flags;

    if (g_exit_reg && tp_exit) tracepoint_probe_unregister(tp_exit, (void *)ig_pc_on_exit, NULL);
    if (g_exec_reg && tp_exec) tracepoint_probe_unregister(tp_exec, (void *)ig_pc_on_exec, NULL);
    if (g_fork_reg && tp_fork) tracepoint_probe_unregister(tp_fork, (void *)ig_pc_on_fork, NULL);

    /* tracepoint synchronize: 등록 해제 후 in-flight 콜백 완료 대기 */
    tracepoint_synchronize_unregister();

    cancel_delayed_work_sync(&ig_pc_gc_dw);

    spin_lock_irqsave(&ig_pc_lock, flags);
    hash_for_each_safe(ig_pc_table, bkt, tmp, e, hnode) {
        hash_del(&e->hnode);
        list_del(&e->lru);
        kfree(e);
    }
    atomic_set(&ig_pc_count, 0);
    spin_unlock_irqrestore(&ig_pc_lock, flags);

    pr_info("proc_cache: exit (inserts=%u hits=%u misses=%u evicts=%u throttled=%u)\n",
            atomic_read(&ig_pc_inserts), atomic_read(&ig_pc_hits),
            atomic_read(&ig_pc_misses), atomic_read(&ig_pc_evicts),
            atomic_read(&ig_pc_throttle));
}
