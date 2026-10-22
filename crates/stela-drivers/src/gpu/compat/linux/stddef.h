/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STDDEF_H
#define _LINUX_STDDEF_H
/* Linux's stddef.h, whose false and true come from <stdbool.h> instead, so
 * that C library headers can join Linux code. */
#include <stdbool.h>
#include <stddef.h>
#include <uapi/linux/stddef.h>

/* Copyright Linux kernel contributors; from stddef.h. */
#undef NULL
#define NULL ((void *)0)

#undef offsetof
#define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)

#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))

#define struct_group(NAME, MEMBERS...)	\
	__struct_group(/* no tag */, NAME, /* no attrs */, MEMBERS)

#define struct_group_attr(NAME, ATTRS, MEMBERS...) \
	__struct_group(/* no tag */, NAME, ATTRS, MEMBERS)

#define struct_group_tagged(TAG, NAME, MEMBERS...) \
	__struct_group(TAG, NAME, /* no attrs */, MEMBERS)

#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
	__DECLARE_FLEX_ARRAY(TYPE, NAME)

#define __TRAILING_OVERLAP(TYPE, NAME, FAM, ATTRS, MEMBERS)			\
	union {									\
		TYPE NAME;							\
		struct {							\
			unsigned char __offset_to_FAM[offsetof(TYPE, FAM)];	\
			MEMBERS							\
		} ATTRS;							\
	}

#define TRAILING_OVERLAP(TYPE, NAME, FAM, MEMBERS)				\
	__TRAILING_OVERLAP(TYPE, NAME, FAM, /* no attrs */, MEMBERS)
#endif
