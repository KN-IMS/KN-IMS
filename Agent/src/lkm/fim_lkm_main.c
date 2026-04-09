// SPDX-License-Identifier: GPL-2.0
/*
 * fim_lkm_main.c — 모듈 진입점
 *
 * initialize:
 *   1. Initialize policy hash table (inode_policy_clear)
 *   2. Register char device (/dev/fim_lkm)
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

#include "fim_lkm_policy.h"

extern int  fim_chardev_init(void);
extern void fim_chardev_exit(void);
extern int  fim_hooks_init(void);
extern void fim_hooks_exit(void);
extern void fim_events_flush_cancel(void);

static int __init fim_lkm_init(void)
{
    int ret;

    fim_policy_init();

    ret = fim_chardev_init();
    if (ret)
        return ret;

    ret = fim_hooks_init();
    if (ret) {
        fim_chardev_exit();
        return ret;
    }

    pr_info("loaded (kernel %d.%d.%d)\n",
            (LINUX_VERSION_CODE >> 16) & 0xFF,
            (LINUX_VERSION_CODE >> 8)  & 0xFF,
             LINUX_VERSION_CODE        & 0xFF);
    return 0;
}

static void __exit fim_lkm_exit(void)
{
    fim_hooks_exit();           /* No enqueue afterwards */
    fim_events_flush_cancel();  /* Cancel pending workqueue work */
    fim_chardev_exit();
    inode_policy_clear();
    pr_info("unloaded\n");
}

module_init(fim_lkm_init);
module_exit(fim_lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fim_monitor");
MODULE_DESCRIPTION("FIM file blocking LKM — kprobe + inode policy");
MODULE_VERSION("1.0");
