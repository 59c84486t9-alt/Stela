/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_STDDEF_H
#define STELA_LINUX_STDDEF_H
/* Linux's version declares false and true itself; Stela uses <stdbool.h>. */
#include <stddef.h>
#include <uapi/linux/stddef.h>
/* Copyright Linux kernel contributors; from stddef.h. */
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
#define struct_group(NAME, MEMBERS...)	\
	__struct_group(/* no tag */, NAME, /* no attrs */, MEMBERS)
#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
	__DECLARE_FLEX_ARRAY(TYPE, NAME)
#endif
