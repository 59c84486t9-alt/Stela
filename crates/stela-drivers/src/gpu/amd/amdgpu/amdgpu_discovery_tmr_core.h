/*
 * Copyright 2018 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef AMDGPU_DISCOVERY_TMR_CORE_H
#define AMDGPU_DISCOVERY_TMR_CORE_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/errno.h>
#define AMDGPU_TMR_U32_MAX U32_MAX
#define AMDGPU_TMR_ENXIO ENXIO
#define AMDGPU_TMR_EINVAL EINVAL
#define AMDGPU_TMR_LE32(value) le32_to_cpu(value)
#else
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define AMDGPU_TMR_U32_MAX UINT32_MAX
#define AMDGPU_TMR_ENXIO 6
#define AMDGPU_TMR_EINVAL 22
#define AMDGPU_TMR_LE32(value) (value) /* Native consumer is x86-64 little endian. */
#endif
#include "amdgpu_discovery_tmr_limits.h"
#include "../include/discovery.h"
/* These original bootstrap register offsets are consistent across the SoCs. */
#define mmRCC_CONFIG_MEMSIZE 0xde3
#define mmMP0_SMN_C2PMSG_33 0x16061
#define mmDRIVER_SCRATCH_0 0x94
#define mmDRIVER_SCRATCH_1 0x95
#define mmDRIVER_SCRATCH_2 0x96
struct amdgpu_discovery_tmr_state {
 uint64_t offset;
 uint32_t size;
 bool is_sysmem;
 bool has_memory_size; /* Original bool output is untouched on RCC all-ones. */
};
struct amdgpu_discovery_tmr_ops {
 uint32_t (*read32)(void *, uint32_t);
 void (*sleep_ms)(void *, unsigned);
 /* Status covers caller preflight/services only. Original void VRAM reads
  * have no transport acknowledgement; Linux invokes the actual void reader. */
 int (*read_vram)(void *, uint64_t, uint32_t *, size_t);
 int (*acpi_tmr)(void *, uint64_t *, uint64_t *);
};
/* Original ordered policy, including nonfatal IFWI poll exhaustion and partial
 * state on error. All callbacks are real caller services, never optional stubs.
 * Native callers must bound every register/range and retain the actual owner.
 */
static inline int amdgpu_discovery_tmr_query_core(
 const struct amdgpu_discovery_tmr_ops *ops, void *context,
 bool is_vf, bool dynamic_region, uint64_t critical_offset,
 uint32_t critical_size, struct amdgpu_discovery_tmr_state *state)
{
	uint64_t vram_size, tmr_offset, tmr_size;
	uint32_t msg, tmr_offset_lo, tmr_offset_hi;
	int i, ret;

	if (!is_vf) {
		/* It can take up to two second for IFWI init to complete on some dGPUs,
		 * but generally it should be in the 60-100ms range.  Normally this starts
		 * as soon as the device gets power so by the time the OS loads this has long
		 * completed.  However, when a card is hotplugged via e.g., USB4, we need to
		 * wait for this to complete.  Once the C2PMSG is updated, we can
		 * continue.
		 */

		for (i = 0; i < 2000; i++) {
			msg = ops->read32(context, mmMP0_SMN_C2PMSG_33);
			if (msg & 0x80000000)
				break;
			ops->sleep_ms(context, 1);
		}
	}

	vram_size = ops->read32(context, mmRCC_CONFIG_MEMSIZE);
	if (vram_size == AMDGPU_TMR_U32_MAX)
		return -AMDGPU_TMR_ENXIO;
	else if (!vram_size)
		state->is_sysmem = true;
	else
		state->is_sysmem = false;

	state->has_memory_size = true;
	/* init the default tmr size and offset */
	state->size = DISCOVERY_TMR_SIZE;
	if (vram_size)
		state->offset = (vram_size << 20) - DISCOVERY_TMR_OFFSET;

	if (is_vf) {
		if (dynamic_region) {
			state->offset =
				critical_offset;
			state->size =
				critical_size;
			if (!state->size)
				return -AMDGPU_TMR_EINVAL;
		} else {
			goto out;
		}
	} else {
		if (state->offset) {
			uint32_t signature;

			/* If VRAM holds a valid discovery signature at the default
			 * discovery offset, use it as-is.
			 */
			ret = ops->read_vram(context, state->offset, &signature, sizeof(signature));
			if (ret)
				return ret;
			if (AMDGPU_TMR_LE32(signature) == BINARY_SIGNATURE)
				goto out;
		}

		tmr_size = ops->read32(context, mmDRIVER_SCRATCH_2);
		if (tmr_size) {
			/* It's preferred to transition to PSP mailbox reg interface
			 * for both bare-metal and passthrough if available */
			state->size = (uint32_t)tmr_size;
			tmr_offset_lo = ops->read32(context, mmDRIVER_SCRATCH_0);
			tmr_offset_hi = ops->read32(context, mmDRIVER_SCRATCH_1);
			state->offset = ((uint64_t)AMDGPU_TMR_LE32(tmr_offset_hi) << 32 |
						  AMDGPU_TMR_LE32(tmr_offset_lo));
		} else if (!vram_size) {
			/* fall back to apci approach to query tmr offset if vram_size is 0 */
			ret = ops->acpi_tmr(context, &tmr_offset, &tmr_size);
			if (ret)
				return ret;
			state->size = DISCOVERY_TMR_SIZE;
			state->offset = tmr_offset + tmr_size - DISCOVERY_TMR_OFFSET;
		}
	}
out:
 return 0;
}
#undef AMDGPU_TMR_ENXIO
#undef AMDGPU_TMR_EINVAL
#undef AMDGPU_TMR_U32_MAX
#undef AMDGPU_TMR_LE32
#endif
