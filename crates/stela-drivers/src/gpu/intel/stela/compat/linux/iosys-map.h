/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_IOSYS_MAP_H
#define STELA_LINUX_IOSYS_MAP_H
#include <linux/types.h>
/* Copyright (c) 2021 Intel Corporation; the layout from linux/iosys-map.h.
 * Stela maps no buffer objects into the CPU, so no accessor is provided. */
struct iosys_map {
	union {
		void __iomem *vaddr_iomem;
		void *vaddr;
	};
	bool is_iomem;
};
#endif
