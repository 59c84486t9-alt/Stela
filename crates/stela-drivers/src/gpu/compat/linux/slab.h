/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_SLAB_H
#define STELA_LINUX_SLAB_H
#include <linux/cleanup.h>
#include <linux/err.h>
#include <linux/overflow.h>
#include <linux/types.h>
/* Stela's GPU owners preallocate their state. A source that allocates
 * declares the allocator it uses as an adapter service. */
typedef unsigned int gfp_t;
#define GFP_KERNEL 0u
static void *kzalloc(size_t size, gfp_t flags);
static char *kstrdup(const char *s, gfp_t flags);
static void kfree(const void *object);
/* Copyright Linux kernel contributors; from slab.h. */
DEFINE_FREE(kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))

#define __default_gfp(a,b,...) b
#define default_gfp(...) __default_gfp(,##__VA_ARGS__,GFP_KERNEL)

#define __alloc_objs(KMALLOC, GFP, TYPE, COUNT)				\
({									\
	const size_t __obj_size = size_mul(sizeof(TYPE), COUNT);	\
	(TYPE *)KMALLOC(__obj_size, GFP);				\
})

#define __alloc_flex(KMALLOC, GFP, TYPE, FAM, COUNT)			\
({									\
	const size_t __count = (COUNT);					\
	const size_t __obj_size = struct_size_t(TYPE, FAM, __count);	\
	TYPE *__obj_ptr = KMALLOC(__obj_size, GFP);			\
	if (__obj_ptr)							\
		__set_flex_counter(__obj_ptr->FAM, __count);		\
	__obj_ptr;							\
})

#define kzalloc_flex(P, FAM, COUNT, ...)		\
	__alloc_flex(kzalloc, default_gfp(__VA_ARGS__), typeof(P), FAM, COUNT)
#define kzalloc_obj(P, ...) \
	__alloc_objs(kzalloc, default_gfp(__VA_ARGS__), typeof(P), 1)
#endif
