/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_MAP_H
#define STELA_XE_MAP_H
#include <linux/iosys-map.h>
#include "xe_device.h"
/* Defined by each translation unit that copies from a mapped buffer object. */
static void xe_map_memcpy_from(struct xe_device *xe, void *dst, const struct iosys_map *src,
			       size_t src_offset, size_t len);
#endif
