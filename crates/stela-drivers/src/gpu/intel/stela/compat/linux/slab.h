/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_SLAB_H
#define STELA_LINUX_SLAB_H
#include <linux/cleanup.h>
#include <linux/err.h>
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
#endif
