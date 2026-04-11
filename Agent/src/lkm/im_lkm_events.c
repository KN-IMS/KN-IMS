// SPDX-License-Identifier: GPL-2.0
/*
 * im_lkm_events.c — 이벤트 큐 (커널 → 유저스페이스)
 *   kprobe handler → im_event_enqueue() → kfifo (atomic safe)
 *   workqueue      → im_event_flush_work() → wake_up_interruptible()
 *   userspace read ← wait_event_interruptible ← im_wq
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

#include "im_lkm_events.h"
#include "im_lkm_policy.h"

#define IM_EVENT_QUEUE_SIZE  64   

static DEFINE_KFIFO(im_fifo, struct im_lkm_event, IM_EVENT_QUEUE_SIZE);
static DEFINE_SPINLOCK(im_fifo_lock);
DECLARE_WAIT_QUEUE_HEAD(im_wq);

/* workqueue: kprobe atomic context에서 wake_up을 분리하기 위해 사용 */
static void im_event_flush_work(struct work_struct *w);
static DECLARE_WORK(im_flush_work, im_event_flush_work);

static void im_event_flush_work(struct work_struct *w)
{
    if (!kfifo_is_empty(&im_fifo))
        wake_up_interruptible(&im_wq);
}

/*
* im_event_enqueue — can be called in kprobe atomic context
* Schedule to workqueue instead of calling wake_up directly.
*/
void im_event_enqueue(uint64_t dev, uint64_t ino,
                       uint32_t op, uint32_t blocked)
{
    struct im_lkm_event ev;
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

    /* Path: Safely retrieve with read_lock_irqsave */
    {
        unsigned long lflags;
        read_lock_irqsave(&im_policy_lock, lflags);
        strncpy(ev.path, inode_policy_path(dev, ino), sizeof(ev.path) - 1);
        read_unlock_irqrestore(&im_policy_lock, lflags);
    }

    spin_lock_irqsave(&im_fifo_lock, flags);
    if (kfifo_in(&im_fifo, &ev, 1) == 0)
        pr_warn("event queue full (ino=%llu)\n", ino);
    spin_unlock_irqrestore(&im_fifo_lock, flags);

    /* wake_up is prohibited in the workqueue (process context) — directly in the atomic context */    
    (void)schedule_work(&im_flush_work);
}

bool im_event_empty(void)
{
    return kfifo_is_empty(&im_fifo);
}

int im_event_pop(struct im_lkm_event *ev)
{
    unsigned long flags;
    int ret;
    spin_lock_irqsave(&im_fifo_lock, flags);
    ret = kfifo_out(&im_fifo, ev, 1);
    spin_unlock_irqrestore(&im_fifo_lock, flags);
    return ret;
}

void im_events_flush_cancel(void)
{
    cancel_work_sync(&im_flush_work);
}
