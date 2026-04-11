// SPDX-License-Identifier: GPL-2.0
/*
 * im_lkm_chardev.c — /dev/im_lkm char device
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

#include "im_lkm_common.h"
#include "im_lkm_policy.h"
#include "im_lkm_events.h"

static dev_t         im_devno;
static struct cdev   im_cdev;
static struct class *im_class;

/* ── ioctl ──────────────────────────────────────────────── */

static long im_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct im_lkm_policy_req req;

    switch (cmd) {
    case IM_IOC_ADD_INODE:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.path[sizeof(req.path) - 1] = '\0';
        return inode_policy_add(req.dev, req.ino,
                                req.mask, req.block, req.path);

    case IM_IOC_REMOVE_INODE:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        inode_policy_remove(req.dev, req.ino);
        return 0;

    case IM_IOC_CLEAR_ALL:
        inode_policy_clear();
        return 0;

    default:
        return -ENOTTY;
    }
}

/* ── read (blocking) ────────────────────────────────────── */

static ssize_t im_read(struct file *f, char __user *buf,
                         size_t count, loff_t *pos)
{
    struct im_lkm_event ev;
    int ret;

    if (count < sizeof(ev))
        return -EINVAL;

    ret = wait_event_interruptible(im_wq, !im_event_empty());
    if (ret)
        return ret;   

    if (!im_event_pop(&ev))
        return 0;

    if (copy_to_user(buf, &ev, sizeof(ev)))
        return -EFAULT;

    return sizeof(ev);
}

static unsigned int im_poll(struct file *f, poll_table *wait)
{
    poll_wait(f, &im_wq, wait);
    return im_event_empty() ? 0 : (POLLIN | POLLRDNORM);
}

static const struct file_operations im_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = im_ioctl,
    .read           = im_read,
    .poll           = im_poll,
};

int im_chardev_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&im_devno, 0, 1, IM_LKM_DEV_NAME);
    if (ret) {
        pr_err("alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }

    cdev_init(&im_cdev, &im_fops);
    im_cdev.owner = THIS_MODULE;

    ret = cdev_add(&im_cdev, im_devno, 1);
    if (ret) {
        pr_err("cdev_add failed: %d\n", ret);
        goto err_cdev;
    }

    im_class = class_create(THIS_MODULE, IM_LKM_DEV_NAME);
    if (IS_ERR(im_class)) {
        ret = PTR_ERR(im_class);
        pr_err("class_create failed: %d\n", ret);
        goto err_class;
    }

    if (IS_ERR(device_create(im_class, NULL, im_devno,
                              NULL, IM_LKM_DEV_NAME))) {
        ret = -ENOMEM;
        pr_err("device_create failed\n");
        goto err_device;
    }

    pr_info("chardev /dev/%s created (major=%d)\n",
            IM_LKM_DEV_NAME, MAJOR(im_devno));
    return 0;

err_device: class_destroy(im_class);
err_class:  cdev_del(&im_cdev);
err_cdev:   unregister_chrdev_region(im_devno, 1);
    return ret;
}

void im_chardev_exit(void)
{
    device_destroy(im_class, im_devno);
    class_destroy(im_class);
    cdev_del(&im_cdev);
    unregister_chrdev_region(im_devno, 1);
    pr_info("chardev removed\n");
}
