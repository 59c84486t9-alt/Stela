/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_PRINTK_H
#define STELA_LINUX_PRINTK_H
#include <linux/kern_levels.h>
/* Each translation unit that logs defines Linux's kernel report, which must
 * return. */
static int _printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Copyright Linux kernel contributors; from printk.h. */
#define printk(fmt, ...) _printk(fmt, ##__VA_ARGS__)
#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#endif
