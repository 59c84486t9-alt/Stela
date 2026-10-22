/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_REQUEST_H
#define STELA_I915_REQUEST_H
#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include "i915_gem.h"
#include "i915_ptr_util.h"
#include "gt/intel_engine_types.h"
/* Request flag bits, from i915_request.h after dma-fence's six. */
enum {
	I915_FENCE_FLAG_ACTIVE = 6,
	I915_FENCE_FLAG_PQUEUE,
	I915_FENCE_FLAG_HOLD,
	I915_FENCE_FLAG_INITIAL_BREADCRUMB,
	I915_FENCE_FLAG_SIGNAL,
	I915_FENCE_FLAG_NOPREEMPT,
	I915_FENCE_FLAG_SENTINEL,
	I915_FENCE_FLAG_BOOST,
	I915_FENCE_FLAG_SUBMIT_PARALLEL,
	I915_FENCE_FLAG_SKIP_PARALLEL,
	I915_FENCE_FLAG_COMPOSITE,
};
struct intel_context;
struct intel_ring;
struct i915_vma;
struct intel_timeline {
	struct i915_vma *hwsp_ggtt;
	u32 hwsp_offset;
	bool has_initial_breadcrumb;
};
/* The fields unchanged gen*_engine_cs.c read or write. */
struct i915_request {
	struct {
		u64 seqno;
		unsigned long flags;
	} fence;
	struct drm_i915_private *i915;
	struct intel_context *context;
	struct intel_engine_cs *engine;
	struct intel_ring *ring;
	struct intel_timeline *timeline;
	const u32 *hwsp_seqno;
	u32 head;
	u32 infix;
	u32 tail;
	u32 wa_tail;
};
static bool i915_request_has_nopreempt(const struct i915_request *rq);
static bool i915_request_has_initial_breadcrumb(const struct i915_request *rq);
static bool i915_request_signaled(const struct i915_request *rq);
static bool i915_request_started(const struct i915_request *rq);
static u32 i915_request_active_seqno(const struct i915_request *rq);
static struct intel_timeline *i915_request_timeline(const struct i915_request *rq);
static struct intel_timeline *i915_request_active_timeline(const struct i915_request *rq);
#endif
