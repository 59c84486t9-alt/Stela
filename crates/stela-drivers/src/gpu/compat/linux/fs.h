/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_FS_H
#define STELA_LINUX_FS_H
#include <linux/compiler_types.h>
#include <linux/types.h>
struct inode;
struct module;
struct poll_table_struct;
struct vm_area_struct;
typedef unsigned int __poll_t;
typedef void *fl_owner_t;
/* Copyright Linux kernel contributors; from fs.h. */
typedef unsigned int __bitwise fop_flags_t;
#define FOP_UNSIGNED_OFFSET	((__force fop_flags_t)(1 << 5))
/* Stela has no VFS; these name the file a driver's operations would serve. */
struct file;
struct file_operations {
	struct module *owner;
	fop_flags_t fop_flags;
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	__poll_t (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
};
struct file {
	const struct file_operations *f_op;
	void *private_data;
};
#endif
