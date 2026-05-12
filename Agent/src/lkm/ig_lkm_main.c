// SPDX-License-Identifier: GPL-2.0
/*
 * ig_lkm_main.c — 모듈 진입점
 *
 * initialize:
 *   1. Initialize policy hash table (inode_policy_clear)
 *   2. Register char device (/dev/ig_lkm)
 *   3. hooking (vfs_write, vfs_unlink, vfs_rename)
 *
 * release:
 *   3. release hook
 *   2. release char device
 *   1. release 테이블 해제
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>

#include "ig_lkm_common.h"
#include "ig_lkm_policy.h"
#include "ig_lkm_proc_cache.h"

extern int  ig_chardev_init(void);
extern void ig_chardev_exit(void);
extern int  ig_hooks_init(void);
extern void ig_hooks_exit(void);
extern void ig_events_flush_cancel(void);

static int __init ig_lkm_init(void)
{
    int ret;

    ig_policy_init();

    /* fork-time process tree cache 먼저 (hook이 chain 사용함) */
    ret = ig_proc_cache_init();
    if (ret)
        return ret;

    ret = ig_chardev_init();
    if (ret) {
        ig_proc_cache_exit();
        return ret;
    }

    ret = ig_hooks_init();
    if (ret) {
        ig_chardev_exit();
        ig_proc_cache_exit();
        return ret;
    }

    pr_info("loaded (kernel %d.%d.%d) ev_sz=%zu chain_entry_sz=%zu chain_max=%d\n",
            (LINUX_VERSION_CODE >> 16) & 0xFF,
            (LINUX_VERSION_CODE >> 8)  & 0xFF,
             LINUX_VERSION_CODE        & 0xFF,
             sizeof(struct ig_lkm_event),
             sizeof(struct ig_lkm_chain_entry),
             IG_LKM_CHAIN_MAX);
    return 0;
}

static void __exit ig_lkm_exit(void)
{
    ig_hooks_exit();           /* No enqueue afterwards */
    ig_events_flush_cancel();  /* Cancel pending workqueue work */
    ig_chardev_exit();
    ig_proc_cache_exit();      /* 마지막에 — chain lookup 호출자 모두 종료 후 */
    inode_policy_clear();
    pr_info("unloaded\n");
}

module_init(ig_lkm_init);
module_exit(ig_lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ig_monitor");
MODULE_DESCRIPTION("IG file blocking LKM — kprobe + inode policy");
MODULE_VERSION("1.0");
