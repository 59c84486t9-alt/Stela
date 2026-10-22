/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef STELA_LINUX_XARRAY_H
#define STELA_LINUX_XARRAY_H
#include <linux/types.h>
/* An XArray's root, which Stela's owners never populate. */
struct xarray {
	void *xa_head;
};

/* Copyright (c) 2017 Microsoft Corporation; from xarray.h. */
static inline bool xa_empty(const struct xarray *xa)
{
	return xa->xa_head == NULL;
}
#endif
