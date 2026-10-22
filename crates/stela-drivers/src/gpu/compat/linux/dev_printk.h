/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_DEV_PRINTK_H
#define STELA_LINUX_DEV_PRINTK_H
#include <linux/kern_levels.h>
#include <linux/types.h>
struct device;
/* Each translation unit that logs defines Linux's device report, which must
 * return. */
static void _dev_printk(const char *level, const struct device *dev,
			const char *fmt, ...) __attribute__((format(printf, 3, 4)));
/* Copyright Linux kernel contributors; from dev_printk.h, without its printk
 * index. */
#define dev_printk(level, dev, fmt, ...)				\
	_dev_printk(level, dev, fmt, ##__VA_ARGS__)
#define dev_err(dev, fmt, ...) dev_printk(KERN_ERR, dev, fmt, ##__VA_ARGS__)
#define dev_warn(dev, fmt, ...) dev_printk(KERN_WARNING, dev, fmt, ##__VA_ARGS__)
#define dev_notice(dev, fmt, ...) dev_printk(KERN_NOTICE, dev, fmt, ##__VA_ARGS__)
#define dev_info(dev, fmt, ...) dev_printk(KERN_INFO, dev, fmt, ##__VA_ARGS__)
#define dev_dbg(dev, fmt, ...) dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__)
#endif
