/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_SYSFS_H
#define STELA_LINUX_SYSFS_H
#include <linux/build_bug.h>
#include <linux/stringify.h>
#include <linux/types.h>
/* Stela's Kconfig has no CONFIG_SYSFS: drivers keep their attribute
 * definitions, and Linux's own disabled-sysfs stubs answer every call. */
/* Copyright (c) 2001,2002 Patrick Mochel, Copyright (c) 2004 Silicon
 * Graphics, Inc., Copyright (c) 2007 SUSE Linux Products GmbH and Copyright
 * (c) 2007 Tejun Heo; from sysfs.h. */
struct kobject;

struct attribute {
	const char		*name;
	umode_t			mode;
};

struct attribute_group {
	const char		*name;
	umode_t			(*is_visible)(struct kobject *,
					      struct attribute *, int);
	union {
		struct attribute	**attrs;
		const struct attribute	*const *attrs_const;
	};
};

#define __ATTR(_name, _mode, _show, _store) {				\
	.attr = {.name = __stringify(_name),				\
		 .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _show,						\
	.store	= _store,						\
}

#define __ATTR_RO_MODE(_name, _mode) {					\
	.attr	= { .name = __stringify(_name),				\
		    .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _name##_show,						\
}

#define __ATTR_RO(_name)						\
	__ATTR_RO_MODE(_name, 0444)

#define __ATTRIBUTE_GROUPS(_name)				\
static const struct attribute_group *_name##_groups[] = {	\
	&_name##_group,						\
	NULL,							\
}

#define ATTRIBUTE_GROUPS(_name)					\
static const struct attribute_group _name##_group = {		\
	.attrs = _Generic(_name##_attrs,			\
			  struct attribute **:			\
				_name##_attrs,			\
			  const struct attribute *const *:	\
				(void *)_name##_attrs		\
	),							\
};								\
__ATTRIBUTE_GROUPS(_name)

struct sysfs_ops {
	ssize_t	(*show)(struct kobject *, struct attribute *, char *);
	ssize_t	(*store)(struct kobject *, struct attribute *, const char *, size_t);
};

static inline int sysfs_create_link(struct kobject *kobj,
				    struct kobject *target, const char *name)
{
	return 0;
}

__printf(2, 3)
static inline int sysfs_emit(char *buf, const char *fmt, ...)
{
	return 0;
}

__printf(3, 4)
static inline int sysfs_emit_at(char *buf, int at, const char *fmt, ...)
{
	return 0;
}

/* Permissions on a sysfs file: you didn't miss the 0 prefix did you? */
#define VERIFY_OCTAL_PERMISSIONS(perms)						\
	(BUILD_BUG_ON_ZERO((perms) < 0) +					\
	 BUILD_BUG_ON_ZERO((perms) > 0777) +					\
	 /* USER_READABLE >= GROUP_READABLE >= OTHER_READABLE */		\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 4) < (((perms) >> 3) & 4)) +	\
	 BUILD_BUG_ON_ZERO((((perms) >> 3) & 4) < ((perms) & 4)) +		\
	 /* USER_WRITABLE >= GROUP_WRITABLE */					\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 2) < (((perms) >> 3) & 2)) +	\
	 /* OTHER_WRITABLE?  Generally considered a bad idea. */		\
	 BUILD_BUG_ON_ZERO((perms) & 2) +					\
	 (perms))
#endif
