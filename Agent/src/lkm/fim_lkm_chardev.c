// SPDX-License-Identifier: GPL-2.0
/*
 * fim_lkm_chardev.c — /dev/fim_lkm char device
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

#include "fim_lkm_common.h"
#include "fim_lkm_policy.h"
#include "fim_lkm_events.h"

static dev_t         fim_devno;
static struct cdev   fim_cdev;
static struct class *fim_class;

/* ── ioctl ──────────────────────────────────────────────── */

static long fim_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct fim_lkm_policy_req req;

    switch (cmd) {
    case FIM_IOC_ADD_INODE:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.path[sizeof(req.path) - 1] = '\0';
        return inode_policy_add(req.dev, req.ino,
                                req.mask, req.block, req.path);

    case FIM_IOC_REMOVE_INODE:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        inode_policy_remove(req.dev, req.ino);
        return 0;

    case FIM_IOC_CLEAR_ALL:
        inode_policy_clear();
        return 0;

    default:
        return -ENOTTY;
    }
}

/* ── read (blocking) ────────────────────────────────────── */

static ssize_t fim_read(struct file *f, char __user *buf,
                         size_t count, loff_t *pos)
{
    struct fim_lkm_event ev;
    int ret;

    if (count < sizeof(ev))
        return -EINVAL;

    ret = wait_event_interruptible(fim_wq, !fim_event_empty());
    if (ret)
        return ret;   

    if (!fim_event_pop(&ev))
        return 0;

    if (copy_to_user(buf, &ev, sizeof(ev)))
        return -EFAULT;

    return sizeof(ev);
}

static unsigned int fim_poll(struct file *f, poll_table *wait)
{
    poll_wait(f, &fim_wq, wait);
    return fim_event_empty() ? 0 : (POLLIN | POLLRDNORM);
}

static const struct file_operations fim_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = fim_ioctl,
    .read           = fim_read,
    .poll           = fim_poll,
};

int fim_chardev_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&fim_devno, 0, 1, FIM_LKM_DEV_NAME);
    if (ret) {
        pr_err("alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }

    cdev_init(&fim_cdev, &fim_fops);
    fim_cdev.owner = THIS_MODULE;

    ret = cdev_add(&fim_cdev, fim_devno, 1);
    if (ret) {
        pr_err("cdev_add failed: %d\n", ret);
        goto err_cdev;
    }

    fim_class = class_create(THIS_MODULE, FIM_LKM_DEV_NAME);
    if (IS_ERR(fim_class)) {
        ret = PTR_ERR(fim_class);
        pr_err("class_create failed: %d\n", ret);
        goto err_class;
    }

    if (IS_ERR(device_create(fim_class, NULL, fim_devno,
                              NULL, FIM_LKM_DEV_NAME))) {
        ret = -ENOMEM;
        pr_err("device_create failed\n");
        goto err_device;
    }

    pr_info("chardev /dev/%s created (major=%d)\n",
            FIM_LKM_DEV_NAME, MAJOR(fim_devno));
    return 0;

err_device: class_destroy(fim_class);
err_class:  cdev_del(&fim_cdev);
err_cdev:   unregister_chrdev_region(fim_devno, 1);
    return ret;
}

void fim_chardev_exit(void)
{
    device_destroy(fim_class, fim_devno);
    class_destroy(fim_class);
    cdev_del(&fim_cdev);
    unregister_chrdev_region(fim_devno, 1);
    pr_info("chardev removed\n");
}
