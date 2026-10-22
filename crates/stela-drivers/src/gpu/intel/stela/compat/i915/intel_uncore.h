/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_INTEL_UNCORE_H
#define STELA_I915_INTEL_UNCORE_H
#include <linux/types.h>
#include "i915_reg_defs.h"
/* Register access is the adapter's MMIO service. */
struct intel_uncore {
	u32 gsi_offset;
};
static u32 intel_uncore_read_fw(struct intel_uncore *uncore, i915_reg_t reg);
static void intel_uncore_write(struct intel_uncore *uncore, i915_reg_t reg, u32 val);
#define intel_uncore_posting_read_fw(...) ((void)intel_uncore_read_fw(__VA_ARGS__))
#endif
