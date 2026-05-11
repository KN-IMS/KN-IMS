// SPDX-License-Identifier: GPL-2.0
/*
 * ig_lkm_chardev.c — /dev/ig_lkm char device
 *
 * Communication channel with user space.
 *   ioctl: Add/Remove/Reset policies
 *   read:  Receive event(blocking)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/poll.h>

#include "ig_lkm_common.h"
#include "ig_lkm_policy.h"
#include "ig_lkm_events.h"

static dev_t         ig_devno;
static struct cdev   ig_cdev;
static struct class *ig_class;

/* ── ioctl ──────────────────────────────────────────────── */

static long ig_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct ig_lkm_policy_req req;

    switch (cmd) {
    case IG_IOC_ADD_INODE:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.path[sizeof(req.path) - 1] = '\0';
        return inode_policy_add(req.dev, req.ino,
                                req.mask, req.block, req.path);

    case IG_IOC_REMOVE_INODE:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        inode_policy_remove(req.dev, req.ino);
        return 0;

    case IG_IOC_CLEAR_ALL:
        inode_policy_clear();
        return 0;

    default:
        return -ENOTTY;
    }
}

/* ── read (blocking) ────────────────────────────────────── */

static ssize_t ig_read(struct file *f, char __user *buf,
                         size_t count, loff_t *pos)
{
    struct ig_lkm_event ev;
    int ret;

    if (count < sizeof(ev))
        return -EINVAL;

    ret = wait_event_interruptible(ig_wq, !ig_event_empty());
    if (ret)
        return ret;

    if (!ig_event_pop(&ev))
        return 0;

    if (copy_to_user(buf, &ev, sizeof(ev)))
        return -EFAULT;

    return sizeof(ev);
}

static unsigned int ig_poll(struct file *f, poll_table *wait)
{
    poll_wait(f, &ig_wq, wait);
    return ig_event_empty() ? 0 : (POLLIN | POLLRDNORM);
}

static const struct file_operations ig_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = ig_ioctl,
    .read           = ig_read,
    .poll           = ig_poll,
};

int ig_chardev_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&ig_devno, 0, 1, IG_LKM_DEV_NAME);
    if (ret) {
        pr_err("alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }

    cdev_init(&ig_cdev, &ig_fops);
    ig_cdev.owner = THIS_MODULE;

    ret = cdev_add(&ig_cdev, ig_devno, 1);
    if (ret) {
        pr_err("cdev_add failed: %d\n", ret);
        goto err_cdev;
    }

    ig_class = class_create(THIS_MODULE, IG_LKM_DEV_NAME);
    if (IS_ERR(ig_class)) {
        ret = PTR_ERR(ig_class);
        pr_err("class_create failed: %d\n", ret);
        goto err_class;
    }

    if (IS_ERR(device_create(ig_class, NULL, ig_devno,
                              NULL, IG_LKM_DEV_NAME))) {
        ret = -ENOMEM;
        pr_err("device_create failed\n");
        goto err_device;
    }

    pr_info("chardev /dev/%s created (major=%d)\n",
            IG_LKM_DEV_NAME, MAJOR(ig_devno));
    return 0;

err_device: class_destroy(ig_class);
err_class:  cdev_del(&ig_cdev);
err_cdev:   unregister_chrdev_region(ig_devno, 1);
    return ret;
}

void ig_chardev_exit(void)
{
    device_destroy(ig_class, ig_devno);
    class_destroy(ig_class);
    cdev_del(&ig_cdev);
    unregister_chrdev_region(ig_devno, 1);
    pr_info("chardev removed\n");
}
