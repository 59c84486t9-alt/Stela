/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_MAP_H
#define STELA_XE_MAP_H
#include <linux/iosys-map.h>
#include <linux/stddef.h>
#include "xe_device.h"
/* Mapped buffer-object access is a service of the adapter's device. */
static void xe_map_memcpy_from(struct xe_device *xe, void *dst, const struct iosys_map *src,
			       size_t src_offset, size_t len);
static void xe_map_memcpy_to(struct xe_device *xe, struct iosys_map *dst, size_t dst_offset,
			     const void *src, size_t len);
static void xe_map_memset(struct xe_device *xe, struct iosys_map *dst, size_t offset, int value,
			  size_t len);
/* Field access with xe_map.h's meaning, through the copies above. */
#define xe_map_rd_field(xe__, map__, struct_offset__, struct_type__, field__) ({ \
	__typeof__(((struct_type__ *)0)->field__) __value; \
	xe_map_memcpy_from(xe__, &__value, map__, \
			   (struct_offset__) + offsetof(struct_type__, field__), sizeof(__value)); \
	__value; \
})
#define xe_map_wr_field(xe__, map__, struct_offset__, struct_type__, field__, val__) ({ \
	__typeof__(((struct_type__ *)0)->field__) __value = (val__); \
	xe_map_memcpy_to(xe__, map__, (struct_offset__) + offsetof(struct_type__, field__), \
			 &__value, sizeof(__value)); \
})
#endif
