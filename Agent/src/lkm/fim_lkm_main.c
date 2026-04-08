// SPDX-License-Identifier: GPL-2.0
/*
 * fim_lkm_main.c — 모듈 진입점
 *
 * 초기화 순서:
 *   1. 정책 해시테이블 초기화 (inode_policy_clear)
 *   2. char device 등록 (/dev/fim_lkm)
 *   3. kprobe 후킹 (vfs_write, vfs_unlink, vfs_rename)
 *
 * 해제 순서 (역순):
 *   3. kprobe 해제
 *   2. char device 해제
 *   1. 정책 테이블 해제
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>

#include "fim_lkm_policy.h"

/* 외부 선언 — 각 .c 파일에 구현 */
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
    fim_hooks_exit();           /* kprobe 먼저 해제 — 이후 enqueue 없음 */
    fim_events_flush_cancel();  /* pending workqueue work 취소 */
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
