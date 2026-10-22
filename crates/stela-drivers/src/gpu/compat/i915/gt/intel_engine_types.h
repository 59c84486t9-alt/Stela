/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_INTEL_ENGINE_TYPES_H
#define STELA_I915_INTEL_ENGINE_TYPES_H
#include <asm/barrier.h>
#include <linux/bits.h>
#include <linux/types.h>
/* Engine classes, identifiers and emit flags, from intel_engine_types.h. */
#define RENDER_CLASS 0
#define VIDEO_DECODE_CLASS 1
#define VIDEO_ENHANCEMENT_CLASS 2
#define COPY_ENGINE_CLASS 3
#define OTHER_CLASS 4
#define COMPUTE_CLASS 5
enum intel_engine_id {
	RCS0 = 0,
	BCS0, BCS1, BCS2, BCS3, BCS4, BCS5, BCS6, BCS7, BCS8,
	VCS0, VCS1, VCS2, VCS3, VCS4, VCS5, VCS6, VCS7,
	VECS0, VECS1, VECS2, VECS3,
	CCS0, CCS1, CCS2, CCS3,
	GSC0,
	I915_NUM_ENGINES
};
#define EMIT_INVALIDATE BIT(0)
#define EMIT_FLUSH BIT(1)
#define I915_DISPATCH_SECURE BIT(0)
#define I915_DISPATCH_PINNED BIT(1)
struct drm_i915_private;
struct i915_request;
struct i915_vma;
struct intel_gt;
struct intel_uncore;
struct intel_engine_cs {
	struct drm_i915_private *i915;
	struct intel_gt *gt;
	struct intel_uncore *uncore;
	u32 mmio_base;
	u32 irq_enable_mask;
	u32 irq_keep_mask;
	enum intel_engine_id id;
	u8 class;
	struct {
		struct i915_vma *vma;
	} status_page;
	u32 *(*emit_fini_breadcrumb)(struct i915_request *rq, u32 *cs);
	void (*irq_handler)(struct intel_engine_cs *engine, u16 iir);
};
#endif
