// SPDX-License-Identifier: GPL-2.0
/*
 * fim_lkm_events.c — 이벤트 큐 (커널 → 유저스페이스)
 *
 * 설계 원칙:
 *   kprobe 핸들러(atomic context)에서 직접 wake_up 등 스케줄러 호출은 위험.
 *   따라서 kprobe 핸들러는 kfifo에 push만 하고, 별도 workqueue가 wake_up을 담당.
 *
 *   kprobe handler → fim_event_enqueue() → kfifo (atomic safe)
 *   workqueue      → fim_event_flush_work() → wake_up_interruptible()
 *   userspace read ← wait_event_interruptible ← fim_wq
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

#include "fim_lkm_events.h"
#include "fim_lkm_policy.h"

#define FIM_EVENT_QUEUE_SIZE  64   /* 최대 대기 이벤트 수 (2의 제곱수) */

static DEFINE_KFIFO(fim_fifo, struct fim_lkm_event, FIM_EVENT_QUEUE_SIZE);
static DEFINE_SPINLOCK(fim_fifo_lock);
DECLARE_WAIT_QUEUE_HEAD(fim_wq);

/* workqueue: kprobe atomic context에서 wake_up을 분리하기 위해 사용 */
static void fim_event_flush_work(struct work_struct *w);
static DECLARE_WORK(fim_flush_work, fim_event_flush_work);

static void fim_event_flush_work(struct work_struct *w)
{
    /* process context이므로 wake_up 안전 */
    if (!kfifo_is_empty(&fim_fifo))
        wake_up_interruptible(&fim_wq);
}

/*
 * fim_event_enqueue — kprobe atomic context에서 호출 가능
 *
 * wake_up을 직접 호출하지 않고 workqueue에 schedule.
 */
void fim_event_enqueue(uint64_t dev, uint64_t ino,
                       uint32_t op, uint32_t blocked)
{
    struct fim_lkm_event ev;
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

    /* 경로: read_lock_irqsave로 안전하게 조회 */
    {
        unsigned long lflags;
        read_lock_irqsave(&fim_policy_lock, lflags);
        strncpy(ev.path, inode_policy_path(dev, ino), sizeof(ev.path) - 1);
        read_unlock_irqrestore(&fim_policy_lock, lflags);
    }

    spin_lock_irqsave(&fim_fifo_lock, flags);
    if (kfifo_in(&fim_fifo, &ev, 1) == 0)
        pr_warn("event queue full (ino=%llu)\n", ino);
    spin_unlock_irqrestore(&fim_fifo_lock, flags);

    /* wake_up은 workqueue(process context)에서 — atomic context에서 직접 금지 */
    (void)schedule_work(&fim_flush_work);
}

bool fim_event_empty(void)
{
    return kfifo_is_empty(&fim_fifo);
}

int fim_event_pop(struct fim_lkm_event *ev)
{
    unsigned long flags;
    int ret;
    spin_lock_irqsave(&fim_fifo_lock, flags);
    ret = kfifo_out(&fim_fifo, ev, 1);
    spin_unlock_irqrestore(&fim_fifo_lock, flags);
    return ret;
}

void fim_events_flush_cancel(void)
{
    cancel_work_sync(&fim_flush_work);
}
