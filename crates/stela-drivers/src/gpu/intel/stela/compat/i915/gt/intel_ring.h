/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_INTEL_RING_H
#define STELA_I915_INTEL_RING_H
#include <linux/err.h>
#include <linux/types.h>
#include "i915_gem.h"
#include "i915_request.h"
/* The adapter owns ring space: it reserves words for each packet and checks
 * that the emitter wrote exactly that many.
 */
struct intel_ring {
	void *vaddr;
	u32 size;
	u32 wrap;
	u32 emit;
};
static u32 *intel_ring_begin(struct i915_request *rq, unsigned int num_dwords);
static void intel_ring_advance(struct i915_request *rq, u32 *cs);
static u32 intel_ring_offset(const struct i915_request *rq, void *addr);
static void assert_ring_tail_valid(const struct intel_ring *ring, unsigned int tail);
static int intel_ring_direction(const struct intel_ring *ring, u32 next, u32 prev);
#endif
