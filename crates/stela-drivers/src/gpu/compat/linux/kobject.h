/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_KOBJECT_H
#define STELA_LINUX_KOBJECT_H
#include <linux/compiler.h>
#include <linux/container_of.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/types.h>
/* Copyright (c) 2002-2003 Patrick Mochel, Copyright (c) 2002-2003 Open Source
 * Development Labs, Copyright (c) 2006-2008 Greg Kroah-Hartman and Copyright
 * (c) 2006-2008 Novell Inc.; from kobject.h. */
struct kobject {
	const char		*name;
	struct list_head	entry;
	struct kobject		*parent;
	struct kset		*kset;
	const struct kobj_type	*ktype;
	struct kref		kref;
};

struct kobj_type {
	void (*release)(struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
};

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
};

static inline struct kset *to_kset(struct kobject *kobj)
{
	return kobj ? container_of(kobj, struct kset, kobj) : NULL;
}

static inline const char *kobject_name(const struct kobject *kobj)
{
	return kobj->name;
}

/* Stela has no sysfs; Linux's kobject_sysfs_ops has nothing to show. */
static const struct sysfs_ops kobj_sysfs_ops;

/* Services the sources call, which each adapter defines. */
static int kobject_set_name(struct kobject *kobj, const char *name, ...);
static void kobject_init(struct kobject *kobj, const struct kobj_type *ktype);
static int kobject_add(struct kobject *kobj, struct kobject *parent,
		       const char *fmt, ...);
static int kobject_init_and_add(struct kobject *kobj,
				const struct kobj_type *ktype,
				struct kobject *parent, const char *fmt, ...);
static void kobject_put(struct kobject *kobj);
static int kset_register(struct kset *kset);
#endif
