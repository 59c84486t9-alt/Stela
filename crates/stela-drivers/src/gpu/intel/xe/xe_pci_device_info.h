// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */
#ifndef XE_PCI_DEVICE_INFO_H
#define XE_PCI_DEVICE_INFO_H
#ifndef XE_PCI_ID_TYPE
#define XE_PCI_ID_TYPE struct pci_device_id
#endif
__diag_push();
__diag_ignore_all("-Woverride-init", "Allow field overrides in table");

#define PLATFORM(x)		\
	.platform = XE_##x,	\
	.platform_name = #x

#define NOP(x)	x

static const struct xe_graphics_desc graphics_xelp = {
	.hw_engine_mask = BIT(XE_HW_ENGINE_RCS0) | BIT(XE_HW_ENGINE_BCS0),
	.num_geometry_xecore_fuse_regs = 1,
};

#define XE_HP_FEATURES \
	.has_range_tlb_inval = true

static const struct xe_graphics_desc graphics_xehpg = {
	.hw_engine_mask =
		BIT(XE_HW_ENGINE_RCS0) | BIT(XE_HW_ENGINE_BCS0) |
		BIT(XE_HW_ENGINE_CCS0) | BIT(XE_HW_ENGINE_CCS1) |
		BIT(XE_HW_ENGINE_CCS2) | BIT(XE_HW_ENGINE_CCS3),
	.num_geometry_xecore_fuse_regs = 1,
	.num_compute_xecore_fuse_regs = 1,

	XE_HP_FEATURES,
};

static const struct xe_graphics_desc graphics_xehpc = {
	.hw_engine_mask =
		BIT(XE_HW_ENGINE_BCS0) | BIT(XE_HW_ENGINE_BCS1) |
		BIT(XE_HW_ENGINE_BCS2) | BIT(XE_HW_ENGINE_BCS3) |
		BIT(XE_HW_ENGINE_BCS4) | BIT(XE_HW_ENGINE_BCS5) |
		BIT(XE_HW_ENGINE_BCS6) | BIT(XE_HW_ENGINE_BCS7) |
		BIT(XE_HW_ENGINE_BCS8) |
		BIT(XE_HW_ENGINE_CCS0) | BIT(XE_HW_ENGINE_CCS1) |
		BIT(XE_HW_ENGINE_CCS2) | BIT(XE_HW_ENGINE_CCS3),

	XE_HP_FEATURES,

	.has_access_counter = 1,
	.has_asid = 1,
	.has_atomic_enable_pte_bit = 1,
	.has_usm = 1,
	.num_compute_xecore_fuse_regs = 2,
};

static const struct xe_graphics_desc graphics_xelpg = {
	.hw_engine_mask =
		BIT(XE_HW_ENGINE_RCS0) | BIT(XE_HW_ENGINE_BCS0) |
		BIT(XE_HW_ENGINE_CCS0),
	.num_geometry_xecore_fuse_regs = 1,
	.num_compute_xecore_fuse_regs = 1,

	XE_HP_FEATURES,
};

#define XE2_GFX_FEATURES \
	.has_access_counter = 1, \
	.has_asid = 1, \
	.has_atomic_enable_pte_bit = 1, \
	.has_range_tlb_inval = 1, \
	.has_usm = 1, \
	.has_64bit_timestamp = 1, \
	.hw_engine_mask = \
		BIT(XE_HW_ENGINE_RCS0) | \
		BIT(XE_HW_ENGINE_BCS8) | BIT(XE_HW_ENGINE_BCS0) | \
		GENMASK(XE_HW_ENGINE_CCS3, XE_HW_ENGINE_CCS0)

static const struct xe_graphics_desc graphics_xe2 = {
	XE2_GFX_FEATURES,
	.num_geometry_xecore_fuse_regs = 3,
	.num_compute_xecore_fuse_regs = 3,
};

static const struct xe_graphics_desc graphics_xe3p_lpg = {
	XE2_GFX_FEATURES,
	.has_indirect_ring_state = 1,
	.multi_queue_engine_class_mask = BIT(XE_ENGINE_CLASS_COPY) | BIT(XE_ENGINE_CLASS_COMPUTE),
	.num_geometry_xecore_fuse_regs = 3,
	.num_compute_xecore_fuse_regs = 3,
};

static const struct xe_graphics_desc graphics_xe3p_xpc = {
	XE2_GFX_FEATURES,
	.has_access_counter = 0,
	.has_indirect_ring_state = 1,
	.hw_engine_mask =
		GENMASK(XE_HW_ENGINE_BCS8, XE_HW_ENGINE_BCS1) |
		GENMASK(XE_HW_ENGINE_CCS3, XE_HW_ENGINE_CCS0),
	.multi_queue_engine_class_mask = BIT(XE_ENGINE_CLASS_COPY) |
					 BIT(XE_ENGINE_CLASS_COMPUTE),
	.num_geometry_xecore_fuse_regs = 4,
	.num_compute_xecore_fuse_regs = 4,
};

static const struct xe_media_desc media_xem = {
	.hw_engine_mask =
		GENMASK(XE_HW_ENGINE_VCS7, XE_HW_ENGINE_VCS0) |
		GENMASK(XE_HW_ENGINE_VECS3, XE_HW_ENGINE_VECS0),
};

static const struct xe_media_desc media_xelpmp = {
	.hw_engine_mask =
		GENMASK(XE_HW_ENGINE_VCS7, XE_HW_ENGINE_VCS0) |
		GENMASK(XE_HW_ENGINE_VECS3, XE_HW_ENGINE_VECS0) |
		BIT(XE_HW_ENGINE_GSCCS0)
};

/* Pre-GMDID Graphics IPs */
static const struct xe_ip graphics_ip_xelp = { 1200, "Xe_LP", &graphics_xelp };
static const struct xe_ip graphics_ip_xelpp = { 1210, "Xe_LP+", &graphics_xelp };
static const struct xe_ip graphics_ip_xehpg = { 1255, "Xe_HPG", &graphics_xehpg };
static const struct xe_ip graphics_ip_xehpc = { 1260, "Xe_HPC", &graphics_xehpc };

/* GMDID-based Graphics IPs */
static const struct xe_ip graphics_ips[] = {
	{ 1270, "Xe_LPG", &graphics_xelpg },
	{ 1271, "Xe_LPG", &graphics_xelpg },
	{ 1274, "Xe_LPG+", &graphics_xelpg },
	{ 2001, "Xe2_HPG", &graphics_xe2 },
	{ 2002, "Xe2_HPG", &graphics_xe2 },
	{ 2004, "Xe2_LPG", &graphics_xe2 },
	{ 3000, "Xe3_LPG", &graphics_xe2 },
	{ 3001, "Xe3_LPG", &graphics_xe2 },
	{ 3003, "Xe3_LPG", &graphics_xe2 },
	{ 3004, "Xe3_LPG", &graphics_xe2 },
	{ 3005, "Xe3_LPG", &graphics_xe2 },
	{ 3510, "Xe3p_LPG", &graphics_xe3p_lpg },
	{ 3511, "Xe3p_XPC", &graphics_xe3p_xpc },
};

/* Pre-GMDID Media IPs */
static const struct xe_ip media_ip_xem = { 1200, "Xe_M", &media_xem };
static const struct xe_ip media_ip_xehpm = { 1255, "Xe_HPM", &media_xem };

/* GMDID-based Media IPs */
static const struct xe_ip media_ips[] = {
	{ 1300, "Xe_LPM+", &media_xelpmp },
	{ 1301, "Xe2_HPM", &media_xelpmp },
	{ 2000, "Xe2_LPM", &media_xelpmp },
	{ 3000, "Xe3_LPM", &media_xelpmp },
	{ 3002, "Xe3_LPM", &media_xelpmp },
	{ 3500, "Xe3p_LPM", &media_xelpmp },
	{ 3503, "Xe3p_HPM", &media_xelpmp },
};

#define MULTI_LRC_MASK \
	.multi_lrc_mask = BIT(XE_ENGINE_CLASS_VIDEO_DECODE) | \
			  BIT(XE_ENGINE_CLASS_VIDEO_ENHANCE)

static const struct xe_device_desc tgl_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xelp,
	.pre_gmdid_media_ip = &media_ip_xem,
	PLATFORM(TIGERLAKE),
	.dma_mask_size = 39,
	.has_cached_pt = true,
	.has_display = true,
	.has_llc = true,
	.has_sriov = true,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 48,
	.vm_max_level = 3,
};

static const struct xe_device_desc rkl_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xelp,
	.pre_gmdid_media_ip = &media_ip_xem,
	PLATFORM(ROCKETLAKE),
	.dma_mask_size = 39,
	.has_cached_pt = true,
	.has_display = true,
	.has_llc = true,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 48,
	.vm_max_level = 3,
};

static const u16 adls_rpls_ids[] = { INTEL_RPLS_IDS(NOP), 0 };

static const struct xe_device_desc adl_s_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xelp,
	.pre_gmdid_media_ip = &media_ip_xem,
	PLATFORM(ALDERLAKE_S),
	.dma_mask_size = 39,
	.has_cached_pt = true,
	.has_display = true,
	.has_llc = true,
	.has_sriov = true,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.subplatforms = (const struct xe_subplatform_desc[]) {
		{ XE_SUBPLATFORM_ALDERLAKE_S_RPLS, "RPLS", adls_rpls_ids },
		{},
	},
	.va_bits = 48,
	.vm_max_level = 3,
};

static const u16 adlp_rplu_ids[] = { INTEL_RPLU_IDS(NOP), 0 };

static const struct xe_device_desc adl_p_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xelp,
	.pre_gmdid_media_ip = &media_ip_xem,
	PLATFORM(ALDERLAKE_P),
	.dma_mask_size = 39,
	.has_cached_pt = true,
	.has_display = true,
	.has_llc = true,
	.has_sriov = true,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.subplatforms = (const struct xe_subplatform_desc[]) {
		{ XE_SUBPLATFORM_ALDERLAKE_P_RPLU, "RPLU", adlp_rplu_ids },
		{},
	},
	.va_bits = 48,
	.vm_max_level = 3,
};

static const struct xe_device_desc adl_n_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xelp,
	.pre_gmdid_media_ip = &media_ip_xem,
	PLATFORM(ALDERLAKE_N),
	.dma_mask_size = 39,
	.has_cached_pt = true,
	.has_display = true,
	.has_llc = true,
	.has_sriov = true,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 48,
	.vm_max_level = 3,
};

#define DGFX_FEATURES \
	.is_dgfx = 1

static const struct xe_device_desc dg1_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xelpp,
	.pre_gmdid_media_ip = &media_ip_xem,
	DGFX_FEATURES,
	PLATFORM(DG1),
	.dma_mask_size = 39,
	.has_display = true,
	.has_gsc_nvm = 1,
	.has_heci_gscfi = 1,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 48,
	.vm_max_level = 3,
};

static const u16 dg2_g10_ids[] = { INTEL_DG2_G10_IDS(NOP), INTEL_ATS_M150_IDS(NOP), 0 };
static const u16 dg2_g11_ids[] = { INTEL_DG2_G11_IDS(NOP), INTEL_ATS_M75_IDS(NOP), 0 };
static const u16 dg2_g12_ids[] = { INTEL_DG2_G12_IDS(NOP), 0 };

#define DG2_FEATURES \
	DGFX_FEATURES, \
	PLATFORM(DG2), \
	.has_flat_ccs = 1, \
	.has_gsc_nvm = 1, \
	.has_heci_gscfi = 1, \
	.subplatforms = (const struct xe_subplatform_desc[]) { \
		{ XE_SUBPLATFORM_DG2_G10, "G10", dg2_g10_ids }, \
		{ XE_SUBPLATFORM_DG2_G11, "G11", dg2_g11_ids }, \
		{ XE_SUBPLATFORM_DG2_G12, "G12", dg2_g12_ids }, \
		{ } \
	}, \
	.va_bits = 48, \
	.vm_max_level = 3, \
	.vram_flags = XE_VRAM_FLAGS_NEED64K

static const struct xe_device_desc ats_m_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xehpg,
	.pre_gmdid_media_ip = &media_ip_xehpm,
	.dma_mask_size = 46,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,

	DG2_FEATURES,
	.has_display = false,
	.has_sriov = true,
};

static const struct xe_device_desc dg2_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xehpg,
	.pre_gmdid_media_ip = &media_ip_xehpm,
	.dma_mask_size = 46,
	.max_gt_per_tile = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,

	DG2_FEATURES,
	.has_display = true,
	.has_fan_control = true,
	.has_mbx_power_limits = false,
};

static const __maybe_unused struct xe_device_desc pvc_desc = {
	.pre_gmdid_graphics_ip = &graphics_ip_xehpc,
	DGFX_FEATURES,
	PLATFORM(PVC),
	.dma_mask_size = 52,
	.has_display = false,
	.has_gsc_nvm = 1,
	.has_heci_gscfi = 1,
	.max_gt_per_tile = 1,
	.max_remote_tiles = 1,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 57,
	.vm_max_level = 4,
	.vram_flags = XE_VRAM_FLAGS_NEED64K,
	.has_mbx_power_limits = false,
};

static const struct xe_device_desc mtl_desc = {
	/* .graphics and .media determined via GMD_ID */
	.require_force_probe = true,
	PLATFORM(METEORLAKE),
	.dma_mask_size = 46,
	.has_display = true,
	.has_pxp = true,
	.max_gt_per_tile = 2,
	MULTI_LRC_MASK,
	.va_bits = 48,
	.vm_max_level = 3,
};

static const struct xe_device_desc lnl_desc = {
	PLATFORM(LUNARLAKE),
	.dma_mask_size = 46,
	.has_display = true,
	.has_flat_ccs = 1,
	.has_pxp = true,
	.max_gt_per_tile = 2,
	MULTI_LRC_MASK,
	.needs_scratch = true,
	.va_bits = 48,
	.vm_max_level = 4,
};

static const u16 bmg_g21_ids[] = { INTEL_BMG_G21_IDS(NOP), 0 };

static const struct xe_device_desc bmg_desc = {
	DGFX_FEATURES,
	PLATFORM(BATTLEMAGE),
	.dma_mask_size = 46,
	.has_display = true,
	.has_fan_control = true,
	.has_flat_ccs = 1,
	.has_mbx_power_limits = true,
	.has_mbx_thermal_info = true,
	.has_gsc_nvm = 1,
	.has_heci_cscfi = 1,
	.has_i2c = true,
	.has_late_bind = true,
	.has_pre_prod_wa = 1,
	.has_soc_remapper_telem = true,
	.has_sriov = true,
	.max_gt_per_tile = 2,
	MULTI_LRC_MASK,
	.needs_scratch = true,
	.subplatforms = (const struct xe_subplatform_desc[]) {
		{ XE_SUBPLATFORM_BATTLEMAGE_G21, "G21", bmg_g21_ids },
		{ }
	},
	.va_bits = 48,
	.vm_max_level = 4,
};

static const struct xe_device_desc ptl_desc = {
	PLATFORM(PANTHERLAKE),
	.dma_mask_size = 46,
	.has_display = true,
	.has_flat_ccs = 1,
	.has_sriov = true,
	.has_pre_prod_wa = 1,
	.has_pxp = true,
	.max_gt_per_tile = 2,
	MULTI_LRC_MASK,
	.needs_scratch = true,
	.needs_shared_vf_gt_wq = true,
	.va_bits = 48,
	.vm_max_level = 4,
};

static const struct xe_device_desc nvls_desc = {
	PLATFORM(NOVALAKE_S),
	.dma_mask_size = 46,
	.has_display = true,
	.has_flat_ccs = 1,
	.has_pre_prod_wa = 1,
	.has_sriov = true,
	.max_gt_per_tile = 2,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 48,
	.vm_max_level = 4,
};

static const struct xe_device_desc cri_desc = {
	DGFX_FEATURES,
	PLATFORM(CRESCENTISLAND),
	.dma_mask_size = 52,
	.has_display = false,
	.has_flat_ccs = false,
	.has_gsc_nvm = 1,
	.has_i2c = true,
	.has_mbx_power_limits = true,
	.has_mbx_thermal_info = true,
	.has_mert = true,
	.has_pre_prod_wa = 1,
	.has_soc_remapper_sysctrl = true,
	.has_soc_remapper_telem = true,
	.has_sriov = true,
	.has_sysctrl = true,
	.max_gt_per_tile = 2,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 57,
	.vm_max_level = 4,
};

static const struct xe_device_desc nvlp_desc = {
	PLATFORM(NOVALAKE_P),
	.dma_mask_size = 46,
	.has_cached_pt = true,
	.has_display = true,
	.has_flat_ccs = 1,
	.has_page_reclaim_hw_assist = true,
	.has_pre_prod_wa = true,
	.has_sriov = true,
	.max_gt_per_tile = 2,
	MULTI_LRC_MASK,
	.require_force_probe = true,
	.va_bits = 48,
	.vm_max_level = 4,
};

#undef PLATFORM
__diag_pop();

/*
 * Make sure any device matches here are from most specific to most
 * general.  For example, since the Quanta match is based on the subsystem
 * and subvendor IDs, we need it to come before the more general IVB
 * PCI ID matches, otherwise we'll use the wrong info struct above.
 */
static const XE_PCI_ID_TYPE pciidlist[] = {
	INTEL_TGL_IDS(INTEL_VGA_DEVICE, &tgl_desc),
	INTEL_RKL_IDS(INTEL_VGA_DEVICE, &rkl_desc),
	INTEL_ADLS_IDS(INTEL_VGA_DEVICE, &adl_s_desc),
	INTEL_ADLP_IDS(INTEL_VGA_DEVICE, &adl_p_desc),
	INTEL_ADLN_IDS(INTEL_VGA_DEVICE, &adl_n_desc),
	INTEL_RPLU_IDS(INTEL_VGA_DEVICE, &adl_p_desc),
	INTEL_RPLP_IDS(INTEL_VGA_DEVICE, &adl_p_desc),
	INTEL_RPLS_IDS(INTEL_VGA_DEVICE, &adl_s_desc),
	INTEL_DG1_IDS(INTEL_VGA_DEVICE, &dg1_desc),
	INTEL_ATS_M_IDS(INTEL_VGA_DEVICE, &ats_m_desc),
	INTEL_ARL_IDS(INTEL_VGA_DEVICE, &mtl_desc),
	INTEL_DG2_IDS(INTEL_VGA_DEVICE, &dg2_desc),
	INTEL_MTL_IDS(INTEL_VGA_DEVICE, &mtl_desc),
	INTEL_LNL_IDS(INTEL_VGA_DEVICE, &lnl_desc),
	INTEL_BMG_IDS(INTEL_VGA_DEVICE, &bmg_desc),
	INTEL_PTL_IDS(INTEL_VGA_DEVICE, &ptl_desc),
	INTEL_WCL_IDS(INTEL_VGA_DEVICE, &ptl_desc),
	INTEL_NVLS_IDS(INTEL_VGA_DEVICE, &nvls_desc),
	INTEL_CRI_IDS(INTEL_PCI_DEVICE, &cri_desc),
	INTEL_NVLP_IDS(INTEL_VGA_DEVICE, &nvlp_desc),
	{ }
};
#endif
