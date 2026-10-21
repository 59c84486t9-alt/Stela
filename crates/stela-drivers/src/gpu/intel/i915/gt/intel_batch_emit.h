/* SPDX-License-Identifier: MIT */
/* Copyright © 2014 Intel Corporation */
#ifndef INTEL_BATCH_EMIT_H
#define INTEL_BATCH_EMIT_H

#include "intel_gpu_commands.h"

/* Pure packet bodies from gen8_emit_bb_start{,_noarb}(). Address/security
 * policy and request workarounds remain with their original callers.
 */
static inline u32 *__gen8_emit_bb_start_noarb(u32 *cs, u64 offset, u32 ppgtt_flag)
{
	*cs++ = MI_ARB_ON_OFF | MI_ARB_DISABLE;

	*cs++ = MI_BATCH_BUFFER_START_GEN8 | ppgtt_flag;
	*cs++ = lower_32_bits(offset);
	*cs++ = upper_32_bits(offset);

	return cs;
}

static inline u32 *__gen8_emit_bb_start_with_arb(u32 *cs, u64 offset, u32 ppgtt_flag)
{
	*cs++ = MI_ARB_ON_OFF | MI_ARB_ENABLE;

	*cs++ = MI_BATCH_BUFFER_START_GEN8 | ppgtt_flag;
	*cs++ = lower_32_bits(offset);
	*cs++ = upper_32_bits(offset);

	*cs++ = MI_ARB_ON_OFF | MI_ARB_DISABLE;
	*cs++ = MI_NOOP;

	return cs;
}

#endif
