/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_BO_H
#define STELA_XE_BO_H
#include <linux/bits.h>
#include <linux/err.h>
#include <linux/iosys-map.h>
#include "xe_device_types.h"
struct xe_tile;
/* Copyright © 2021 Intel Corporation; the flags from xe_bo.h. */
#define XE_BO_FLAG_SYSTEM		BIT(1)
#define XE_BO_FLAG_GGTT			BIT(5)
#define XE_BO_FLAG_GGTT_INVALIDATE	BIT(17)
/* Stela allocates buffer objects through its own owners; this only names one.
 * Each translation unit that creates or places one defines these. */
struct xe_bo {
	struct iosys_map vmap;
};
static struct xe_bo *xe_managed_bo_create_from_data(struct xe_device *xe, struct xe_tile *tile,
						    const void *data, size_t size, u32 flags);
static u32 xe_bo_ggtt_addr(struct xe_bo *bo);
#endif
