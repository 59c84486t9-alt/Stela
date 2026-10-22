/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_IO_H
#define STELA_LINUX_IO_H
#include <linux/types.h>
/* Copyright 2006 PathScale, Inc.  All Rights Reserved; from io.h. */
enum {
	/* See memremap() kernel-doc for usage description... */
	MEMREMAP_WB = 1 << 0,
	MEMREMAP_WT = 1 << 1,
	MEMREMAP_WC = 1 << 2,
	MEMREMAP_ENC = 1 << 3,
	MEMREMAP_DEC = 1 << 4,
};

/* Services the sources call, which each adapter defines. */
static void *memremap(resource_size_t offset, size_t size, unsigned long flags);
static void memunmap(void *addr);
#endif
