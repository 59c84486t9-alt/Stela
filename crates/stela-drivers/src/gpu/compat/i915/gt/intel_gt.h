/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_INTEL_GT_H
#define STELA_I915_INTEL_GT_H
#include "i915_drv.h"
#include "intel_engine.h"
/* The adapter answers microcontroller queries; no state is modeled. */
struct intel_uc {
};
/* Scratch-page offsets, from intel_gt_types.h. */
enum intel_gt_scratch_field {
	INTEL_GT_SCRATCH_FIELD_DEFAULT = 0,
	INTEL_GT_SCRATCH_FIELD_RENDER_FLUSH = 128,
	INTEL_GT_SCRATCH_FIELD_COHERENTL3_WA = 256,
};
struct i915_vma {
	u64 size;
};
struct intel_gt {
	struct intel_uncore *uncore;
	struct i915_vma *scratch;
	struct intel_uc uc;
};
static bool stela_i915_gt_ip_range(const struct intel_gt *gt, unsigned int from,
				   unsigned int until);
#define IS_GFX_GT_IP_RANGE(gt, from, until) stela_i915_gt_ip_range(gt, from, until)
static bool intel_uc_uses_guc_submission(struct intel_uc *uc);
static u32 intel_gt_scratch_offset(const struct intel_gt *gt,
				   enum intel_gt_scratch_field field);
#endif
