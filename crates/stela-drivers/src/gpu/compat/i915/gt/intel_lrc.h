/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_INTEL_LRC_H
#define STELA_I915_INTEL_LRC_H
#include <asm/page.h>
#include <linux/sizes.h>
#include <linux/types.h>
/* Context image layout, from intel_lrc.h. */
#define LRC_PPHWSP_PN (0)
#define LRC_PPHWSP_SCRATCH 0x34
#define LRC_PPHWSP_SCRATCH_ADDR (LRC_PPHWSP_SCRATCH * sizeof(u32))
#define DG2_PREDICATE_RESULT_WA (PAGE_SIZE - sizeof(u64))
#define DG2_PREDICATE_RESULT_BB (2048)
struct i915_vma;
struct intel_context {
	struct i915_vma *state;
	u16 wa_bb_page;
};
static u32 lrc_indirect_bb(const struct intel_context *ce);
static u32 i915_ggtt_offset(const struct i915_vma *vma);
#endif
