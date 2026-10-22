/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_DEVICE_TYPES_H
#define STELA_XE_DEVICE_TYPES_H
#include <drm/drm_device.h>
#include <linux/types.h>
#include "xe_platform_types.h"
#include "xe_pt_types.h"
#include "xe_sriov_types.h"
#include "xe_step_types.h"
#include "xe_tile_types.h"
/* Copyright © 2022-2023 Intel Corporation; from xe_device_types.h. */
#define GRAPHICS_VER(xe) ((xe)->info.graphics_verx100 / 100)
#define MEDIA_VER(xe) ((xe)->info.media_verx100 / 100)
#define GRAPHICS_VERx100(xe) ((xe)->info.graphics_verx100)
#define MEDIA_VERx100(xe) ((xe)->info.media_verx100)
#define IS_DGFX(xe) ((xe)->info.is_dgfx)
#define XE_VRAM_FLAGS_NEED64K		BIT(0)
#define XE_GT0		0
#define XE_GT1		1
#define XE_MAX_TILES_PER_DEVICE	(XE_GT1 + 1)
#define XE_MAX_GT_PER_TILE 2
struct xe_pat_ops;
struct xe_pat_table_entry;
struct xe_device {
	struct drm_device drm;
	struct intel_device_info {
		const char *platform_name;
		const char *graphics_name;
		const char *media_name;
		u32 graphics_verx100;
		u32 media_verx100;
		u32 mem_region_mask;
		enum xe_platform platform;
		enum xe_subplatform subplatform;
		u16 devid;
		u8 revid;
		struct xe_step_info step;
		u8 dma_mask_size;
		u8 vram_flags;
		u8 tile_count;
		u8 max_gt_per_tile;
		u8 multi_lrc_mask;
		u8 gt_count;
		u8 vm_max_level;
		u8 va_bits;
		u8 force_execlist:1;
		u8 has_access_counter:1;
		u8 has_asid:1;
		u8 has_atomic_enable_pte_bit:1;
		u8 has_cached_pt:1;
		u8 has_device_atomics_on_smem:1;
		u8 has_fan_control:1;
		u8 has_flat_ccs:1;
		u8 has_gsc_nvm:1;
		u8 has_heci_cscfi:1;
		u8 has_heci_gscfi:1;
		u8 has_i2c:1;
		u8 has_late_bind:1;
		u8 has_llc:1;
		u8 has_mbx_power_limits:1;
		u8 has_mbx_thermal_info:1;
		u8 has_mem_copy_instr:1;
		u8 has_mert:1;
		u8 has_page_reclaim_hw_assist:1;
		u8 has_pre_prod_wa:1;
		u8 has_pxp:1;
		u8 has_ctx_tlb_inval:1;
		u8 has_range_tlb_inval:1;
		u8 has_soc_remapper_sysctrl:1;
		u8 has_soc_remapper_telem:1;
		u8 has_sriov:1;
		u8 has_sysctrl:1;
		u8 has_usm:1;
		u8 has_64bit_timestamp:1;
		u8 is_dgfx:1;
		u8 needs_scratch:1;
		u8 probe_display:1;
		u8 skip_guc_pc:1;
		u8 skip_pcode:1;
		u8 needs_shared_vf_gt_wq:1;
	} info;
	struct {
		enum xe_sriov_mode __mode;
	} sriov;
	struct xe_tile tiles[XE_MAX_TILES_PER_DEVICE];
	struct {
		const struct xe_pat_ops *ops;
		const struct xe_pat_table_entry *table;
		int n_entries;
		const struct xe_pat_table_entry *pat_ats;
		const struct xe_pat_table_entry *pat_primary_pta;
		const struct xe_pat_table_entry *pat_media_pta;
		u16 idx[__XE_CACHE_LEVEL_COUNT];
	} pat;
};
#endif
