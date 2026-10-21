/*
 * Copyright 2019 Advanced Micro Devices, Inc.
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
 */

#ifndef AMDGPU_VM_CPU_ENTRIES_H
#define AMDGPU_VM_CPU_ENTRIES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

/* Narrow service boundary for the existing CPU entry loop. The owner has
 * already waited on reservations and mapped/locked the complete destination.
 * Callbacks are synchronous and infallible for this prevalidated range. */
struct amdgpu_vm_cpu_entry_ops {
	uint64_t (*map_gart)(void *context, uint64_t addr);
	void (*override_flags)(void *context, uint64_t addr, uint64_t *flags);
	void (*set_pte_pde)(void *context, unsigned int index,
			    uint64_t addr, uint64_t flags);
};

static inline void
amdgpu_vm_cpu_write_entries(void *context,
			   const struct amdgpu_vm_cpu_entry_ops *ops,
			   bool pages_addr, bool override_pte,
			   uint64_t addr, unsigned int count, uint32_t incr,
			   uint64_t flags)
{
	unsigned int i;
	uint64_t value;

	if (!pages_addr && override_pte)
		ops->override_flags(context, addr, &flags);

	for (i = 0; i < count; i++) {
		uint64_t oflags = flags;

		value = pages_addr ? ops->map_gart(context, addr) : addr;

		if (pages_addr && override_pte)
			ops->override_flags(context, value, &oflags);

		ops->set_pte_pde(context, i, value, oflags);
		addr += incr;
	}
}

/* Address arithmetic from amdgpu_vm_map_gart, after the owner has resolved
 * the CPU-page index to its actual DMA address. GPU entries remain 4 KiB.\n * page_shift must describe a real CPU page size and be between 12 and 52. */
static inline uint64_t
amdgpu_vm_cpu_gart_address(uint64_t page_address, uint64_t addr,
			  unsigned int page_shift)
{
	uint64_t result;

	result = page_address;
	result |= addr & ((1ULL << page_shift) - 1);
	result &= 0xFFFFFFFFFFFFF000ULL;

	return result;
}

#endif
