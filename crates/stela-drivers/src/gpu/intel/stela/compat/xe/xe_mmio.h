/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_MMIO_H
#define STELA_XE_MMIO_H
#include <linux/errno.h>
#include "regs/xe_reg_defs.h"
#include "xe_device_types.h"
/* Defined by each translation unit that accesses registers. */
static u32 xe_mmio_read32(struct xe_mmio *mmio, struct xe_reg reg);
static void xe_mmio_write32(struct xe_mmio *mmio, struct xe_reg reg, u32 val);
/* Copyright © 2021-2023 Intel Corporation; from xe_mmio.c. */
static inline int xe_mmio_write32_and_verify(struct xe_mmio *mmio, struct xe_reg reg,
					     u32 val, u32 mask, u32 eval)
{
	u32 reg_val;

	xe_mmio_write32(mmio, reg, val);
	reg_val = xe_mmio_read32(mmio, reg);

	return (reg_val & mask) != eval ? -EINVAL : 0;
}
#endif
