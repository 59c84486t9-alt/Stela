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

/* Original amdgpu_vm_cpu.c Git blob: b31ff6f56f0d615ae74204174229e0597423ba76.
 * Entry body SHA256: 15c134ade83a6797908b38d53d980561accc90d51c5145b4b5c4b2f83f391126.
 * Immutable CPU-encoding oracle: pre-extraction entry loop, with test-only
 * service wrappers. This is never compiled into a production GPU backend. */
static void
reference_cpu_update(struct reference_params *p, uintptr_t pe, uint64_t addr,
                     unsigned count, uint32_t incr, uint64_t flags)
{
	unsigned int i;
	uint64_t value;

	if (!p->pages_addr && p->override_pte)
		amdgpu_gmc_override_vm_pte_flags(p->adev, p->vm, addr, &flags);

	for (i = 0; i < count; i++) {
		u64 oflags = flags;

		value = p->pages_addr ?
			amdgpu_vm_map_gart(p->pages_addr, addr) :
			addr;

		if (p->pages_addr && p->override_pte)
			amdgpu_gmc_override_vm_pte_flags(p->adev, p->vm, value, &oflags);

		amdgpu_gmc_set_pte_pde(p->adev, (void *)(uintptr_t)pe,
				       i, value, oflags);
		addr += incr;
	}
}
