// SPDX-License-Identifier: GPL-2.0
/*
 * ig_lkm_events.c — 이벤트 큐 (커널 → 유저스페이스)
 *   kprobe handler → ig_event_enqueue() → kfifo (atomic safe)
 *   workqueue      → ig_event_flush_work() → wake_up_interruptible()
 *   userspace read ← wait_event_interruptible ← ig_wq
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kfifo.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/ktime.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/pid.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#  include <linux/sched/task.h>
#  include <linux/sched/signal.h>
#endif

#include "ig_lkm_events.h"
#include "ig_lkm_policy.h"
#include "ig_lkm_proc_cache.h"

#define IG_EVENT_LKM_QUEUE_SIZE  64

static DEFINE_KFIFO(ig_fifo, struct ig_lkm_event, IG_EVENT_LKM_QUEUE_SIZE);
static DEFINE_SPINLOCK(ig_fifo_lock);
DECLARE_WAIT_QUEUE_HEAD(ig_wq);

/* workqueue: kprobe atomic context에서 wake_up을 분리하기 위해 사용 */
static void ig_event_flush_work(struct work_struct *w);
static DECLARE_WORK(ig_flush_work, ig_event_flush_work);

static void ig_event_flush_work(struct work_struct *w)
{
    if (!kfifo_is_empty(&ig_fifo))
        wake_up_interruptible(&ig_wq);
}

/* task->start time → ns. 커널 버전마다 멤버/타입 다름. */
static inline u64 ig_task_start_ns(const struct task_struct *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    return t->start_boottime;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    /* 3.17+: real_start_time이 u64 ns로 변경 */
    return (u64)t->real_start_time;
#else
    /* 3.10: timespec */
    return (u64)timespec_to_ns(&t->real_start_time);
#endif
}

/*
 * ig_collect_chain — fork-time 캐시 우선, miss 시 task_struct fallback.
 *   - 캐시 hit: 죽은 부모도 grace 안에선 복원 + exe/cmdline 직접 보유
 *   - 캐시 miss: live task_struct에서 skeleton만 (exe/cmdline 빈 문자열)
 */
static void ig_collect_chain(struct ig_lkm_event *ev)
{
    uint32_t start_pid;
    int cache_depth;
    uint8_t cache_truncated = 0;
    struct task_struct *t;
    int i;

    ev->chain_depth     = 0;
    ev->chain_truncated = 0;

    start_pid = task_pid_nr(current);

    /* 1) 캐시 lookup — 가장 강력한 경로 */
    cache_depth = ig_proc_cache_collect_chain(start_pid, ev->chain,
                                                IG_LKM_CHAIN_MAX,
                                                &cache_truncated);
    if (cache_depth > 0) {
        ev->chain_depth     = cache_depth;
        ev->chain_truncated = cache_truncated;
        return;
    }

    /* 2) Fallback — 캐시 부팅 직후 등 miss 시 live task_struct */
    rcu_read_lock();
    t = current;
    for (i = 0; i < IG_LKM_CHAIN_MAX; i++) {
        struct ig_lkm_chain_entry *e = &ev->chain[i];
        const struct cred *cred;
        struct task_struct *parent;

        if (!t) { ev->chain_truncated = 1; break; }

        memset(e, 0, sizeof(*e));
        e->pid  = task_pid_nr(t);
        cred    = __task_cred(t);
        e->uid  = from_kuid(&init_user_ns, cred->uid);
        e->euid = from_kuid(&init_user_ns, cred->euid);
        e->sid  = task_session_vnr(t);
        e->start_time_ns = ig_task_start_ns(t);
        get_task_comm(e->comm, t);

        parent = rcu_dereference(t->real_parent);
        e->ppid = parent ? task_pid_nr(parent) : 0;

        ev->chain_depth = i + 1;
        if (!parent || e->ppid <= 1 || parent == t) break;
        t = parent;
        if (i == IG_LKM_CHAIN_MAX - 1) ev->chain_truncated = 1;
    }
    rcu_read_unlock();
}

/*
* ig_event_enqueue — can be called in kprobe atomic context
* Schedule to workqueue instead of calling wake_up directly.
*/
void ig_event_enqueue(uint64_t dev, uint64_t ino,
                       uint32_t op, uint32_t blocked)
{
    struct ig_lkm_event ev;
    unsigned long flags;

    memset(&ev, 0, sizeof(ev));
    ev.dev     = dev;
    ev.ino     = ino;
    ev.op      = op;
    ev.blocked = blocked;
    ev.pid     = task_tgid_nr(current);
    ev.uid     = from_kuid(&init_user_ns, current_uid());
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
    ev.timestamp_ns = ktime_get_real_ns();
#else
    ev.timestamp_ns = ktime_to_ns(ktime_get_real());
#endif
    strncpy(ev.comm, current->comm, sizeof(ev.comm) - 1);

    /* PID ancestry chain 캡처 (race-free, in-kernel) */
    ig_collect_chain(&ev);

    /* Path: Safely retrieve with read_lock_irqsave */
    {
        unsigned long lflags;
        read_lock_irqsave(&ig_policy_lock, lflags);
        strncpy(ev.path, inode_policy_path(dev, ino), sizeof(ev.path) - 1);
        read_unlock_irqrestore(&ig_policy_lock, lflags);
    }

    spin_lock_irqsave(&ig_fifo_lock, flags);
    if (kfifo_in(&ig_fifo, &ev, 1) == 0)
        pr_warn("event queue full (ino=%llu)\n", ino);
    spin_unlock_irqrestore(&ig_fifo_lock, flags);

    /* wake_up is prohibited in the workqueue (process context) — directly in the atomic context */
    (void)schedule_work(&ig_flush_work);
}

bool ig_event_empty(void)
{
    return kfifo_is_empty(&ig_fifo);
}

int ig_event_pop(struct ig_lkm_event *ev)
{
    unsigned long flags;
    int ret;
    spin_lock_irqsave(&ig_fifo_lock, flags);
    ret = kfifo_out(&ig_fifo, ev, 1);
    spin_unlock_irqrestore(&ig_fifo_lock, flags);
    return ret;
}

void ig_events_flush_cancel(void)
{
    cancel_work_sync(&ig_flush_work);
}
