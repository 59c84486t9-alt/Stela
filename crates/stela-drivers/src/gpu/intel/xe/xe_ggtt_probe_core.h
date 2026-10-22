/* SPDX-License-Identifier: MIT */
/* Copyright © 2021 Intel Corporation */
#ifndef XE_GGTT_PROBE_CORE_H
#define XE_GGTT_PROBE_CORE_H
#ifndef XE_GGTT_PROBE_ASSERT
#error "GGTT probe requires the real caller's invariant binding"
#endif
/* Original PF geometry and PTE index policies. No allocation, ONLINE state,
 * mappings, write, scratch, invalidation, PAT or firmware readiness exists. */
static unsigned int xe_ggtt_probe_gsm_decode(u16 gmch_ctl)
{
	u16 ggms;

	ggms = (gmch_ctl >> BDW_GMCH_GGMS_SHIFT) & BDW_GMCH_GGMS_MASK;
	return ggms ? SZ_1M << ggms : 0;
}
static bool xe_ggtt_probe_fixed_gsm(u32 graphics_verx100)
{
	return graphics_verx100 >= 1250;
}
static u64 xe_ggtt_probe_gsm_offset(void)
{
	return SZ_8M;
}
static void xe_ggtt_probe_pf_range(unsigned int gsm_size, u64 wopcm,
				 u64 *ggtt_start, u64 *ggtt_size)
{
	*ggtt_start = wopcm;
	*ggtt_size = (gsm_size / 8) * (u64)XE_PAGE_SIZE - *ggtt_start;
}
static void xe_ggtt_probe_clamp_range(u64 ggtt_start, u64 *ggtt_size)
{
	if (*ggtt_size + ggtt_start > GUC_GGTT_TOP)
		*ggtt_size = GUC_GGTT_TOP - ggtt_start;
}
static u64 xe_ggtt_probe_pte_index(void *context, u64 start, u64 size, u64 addr)
{
	XE_GGTT_PROBE_ASSERT(context, !(addr & XE_PTE_MASK));
	XE_GGTT_PROBE_ASSERT(context, addr < start + size);

	return addr >> XE_PTE_SHIFT;
}
#undef XE_GGTT_PROBE_ASSERT
#endif
