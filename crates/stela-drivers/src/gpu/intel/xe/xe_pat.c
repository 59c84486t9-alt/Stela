// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */

#include "xe_pat.h"

#include <uapi/drm/xe_drm.h>

#include <generated/xe_wa_oob.h>

#include "regs/xe_gt_regs.h"
#include "regs/xe_reg_defs.h"
#include "xe_assert.h"
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_gt.h"
#include "xe_gt_mcr.h"
#include "xe_mmio.h"
#include "xe_sriov.h"
#include "xe_wa.h"

#include "xe_pat_tables.h"

#define PAT_LABEL_LEN 20

static const char *XELP_MEM_TYPE_STR_MAP[] = { "UC", "WC", "WT", "WB" };

static void xe_pat_index_label(char *label, size_t len, int index)
{
	snprintf(label, len, "PAT[%2d] ", index);
}

static void xelp_pat_entry_dump(struct drm_printer *p, int index, u32 pat)
{
	u8 mem_type = REG_FIELD_GET(XELP_MEM_TYPE_MASK, pat);

	drm_printf(p, "PAT[%2d] = %s (%#8x)\n", index,
		   XELP_MEM_TYPE_STR_MAP[mem_type], pat);
}

static void xehpc_pat_entry_dump(struct drm_printer *p, int index, u32 pat)
{
	drm_printf(p, "PAT[%2d] = [ %u, %u ] (%#8x)\n", index,
		   REG_FIELD_GET(XELP_MEM_TYPE_MASK, pat),
		   REG_FIELD_GET(XEHPC_CLOS_LEVEL_MASK, pat), pat);
}

static void xelpg_pat_entry_dump(struct drm_printer *p, int index, u32 pat)
{
	drm_printf(p, "PAT[%2d] = [ %u, %u ] (%#8x)\n", index,
		   REG_FIELD_GET(XELPG_L4_POLICY_MASK, pat),
		   REG_FIELD_GET(XELPG_INDEX_COH_MODE_MASK, pat), pat);
}

struct xe_pat_ops {
	void (*program_graphics)(struct xe_gt *gt, const struct xe_pat_table_entry table[],
				 int n_entries);
	void (*program_media)(struct xe_gt *gt, const struct xe_pat_table_entry table[],
			      int n_entries);
	int (*dump)(struct xe_gt *gt, struct drm_printer *p);
	void (*entry_dump)(struct drm_printer *p, const char *label, u32 pat, bool rsvd);
};


u16 xe_pat_index_get_coh_mode(struct xe_device *xe, u16 pat_index)
{
	WARN_ON(pat_index >= xe->pat.n_entries);
	return xe->pat.table[pat_index].coh_mode;
}

bool xe_pat_index_get_comp_en(struct xe_device *xe, u16 pat_index)
{
	WARN_ON(pat_index >= xe->pat.n_entries);
	return !!(xe->pat.table[pat_index].value & XE2_COMP_EN);
}

u16 xe_pat_index_get_l3_policy(struct xe_device *xe, u16 pat_index)
{
	WARN_ON(pat_index >= xe->pat.n_entries);

	return REG_FIELD_GET(XE2_L3_POLICY, xe->pat.table[pat_index].value);
}

static const struct xe_pat_table_entry *gt_pta_entry(struct xe_gt *gt)
{
	struct xe_device *xe = gt_to_xe(gt);

	if (xe_gt_is_main_type(gt))
		return xe->pat.pat_primary_pta;

	if (xe_gt_is_media_type(gt))
		return xe->pat.pat_media_pta;

	xe_assert(xe, false);
	return NULL;
}

#define XE_PAT_PROGRAM_WRITE(context, reg, value) \
 xe_mmio_write32(&((struct xe_gt *)(context))->mmio, reg, value)
#include "xe_pat_program.h"

static void program_pat(struct xe_gt *gt, const struct xe_pat_table_entry table[],
			int n_entries)
{
	struct xe_device *xe = gt_to_xe(gt);
	const struct xe_pat_table_entry *pta_entry = gt_pta_entry(gt);

	xe_pat_program_direct(gt, table, n_entries, xe->pat.pat_ats, pta_entry);
}

static void program_pat_mcr(struct xe_gt *gt, const struct xe_pat_table_entry table[],
			    int n_entries)
{
	struct xe_device *xe = gt_to_xe(gt);
	const struct xe_pat_table_entry *pta_entry = gt_pta_entry(gt);

	for (int i = 0; i < n_entries; i++) {
		struct xe_reg_mcr reg_mcr = XE_REG_MCR(_PAT_INDEX(i));

		xe_gt_mcr_multicast_write(gt, reg_mcr, table[i].value);
	}

	if (xe->pat.pat_ats)
		xe_gt_mcr_multicast_write(gt, XE_REG_MCR(_PAT_ATS), xe->pat.pat_ats->value);

	if (pta_entry)
		xe_gt_mcr_multicast_write(gt, XE_REG_MCR(_PAT_PTA), pta_entry->value);
}

static int xelp_dump(struct xe_gt *gt, struct drm_printer *p)
{
	struct xe_device *xe = gt_to_xe(gt);
	int i;

	CLASS(xe_force_wake, fw_ref)(gt_to_fw(gt), XE_FW_GT);
	if (!fw_ref.domains)
		return -ETIMEDOUT;

	drm_printf(p, "PAT table:\n");

	for (i = 0; i < xe->pat.n_entries; i++) {
		u32 pat = xe_mmio_read32(&gt->mmio, XE_REG(_PAT_INDEX(i)));

		xelp_pat_entry_dump(p, i, pat);
	}

	return 0;
}

static const struct xe_pat_ops xelp_pat_ops = {
	.program_graphics = program_pat,
	.dump = xelp_dump,
};

static int xehp_dump(struct xe_gt *gt, struct drm_printer *p)
{
	struct xe_device *xe = gt_to_xe(gt);
	int i;

	CLASS(xe_force_wake, fw_ref)(gt_to_fw(gt), XE_FW_GT);
	if (!fw_ref.domains)
		return -ETIMEDOUT;

	drm_printf(p, "PAT table:\n");

	for (i = 0; i < xe->pat.n_entries; i++) {
		u32 pat = xe_gt_mcr_unicast_read_any(gt, XE_REG_MCR(_PAT_INDEX(i)));

		xelp_pat_entry_dump(p, i, pat);
	}

	return 0;
}

static const struct xe_pat_ops xehp_pat_ops = {
	.program_graphics = program_pat_mcr,
	.dump = xehp_dump,
};

static int xehpc_dump(struct xe_gt *gt, struct drm_printer *p)
{
	struct xe_device *xe = gt_to_xe(gt);
	int i;

	CLASS(xe_force_wake, fw_ref)(gt_to_fw(gt), XE_FW_GT);
	if (!fw_ref.domains)
		return -ETIMEDOUT;

	drm_printf(p, "PAT table:\n");

	for (i = 0; i < xe->pat.n_entries; i++) {
		u32 pat = xe_gt_mcr_unicast_read_any(gt, XE_REG_MCR(_PAT_INDEX(i)));

		xehpc_pat_entry_dump(p, i, pat);
	}

	return 0;
}

static const struct xe_pat_ops xehpc_pat_ops = {
	.program_graphics = program_pat_mcr,
	.dump = xehpc_dump,
};

static int xelpg_dump(struct xe_gt *gt, struct drm_printer *p)
{
	struct xe_device *xe = gt_to_xe(gt);
	int i;

	CLASS(xe_force_wake, fw_ref)(gt_to_fw(gt), XE_FW_GT);
	if (!fw_ref.domains)
		return -ETIMEDOUT;

	drm_printf(p, "PAT table:\n");

	for (i = 0; i < xe->pat.n_entries; i++) {
		u32 pat;

		if (xe_gt_is_media_type(gt))
			pat = xe_mmio_read32(&gt->mmio, XE_REG(_PAT_INDEX(i)));
		else
			pat = xe_gt_mcr_unicast_read_any(gt, XE_REG_MCR(_PAT_INDEX(i)));

		xelpg_pat_entry_dump(p, i, pat);
	}

	return 0;
}

/*
 * SAMedia register offsets are adjusted by the write methods and they target
 * registers that are not MCR, while for normal GT they are MCR
 */
static const struct xe_pat_ops xelpg_pat_ops = {
	.program_graphics = program_pat,
	.program_media = program_pat_mcr,
	.dump = xelpg_dump,
};

static void xe2_pat_entry_dump(struct drm_printer *p, const char *label, u32 pat, bool rsvd)
{
	drm_printf(p, "%s= [ %u, %u, %u, %u, %u, %u ]  (%#8x)%s\n", label,
		   !!(pat & XE2_NO_PROMOTE),
		   !!(pat & XE2_COMP_EN),
		   REG_FIELD_GET(XE2_L3_CLOS, pat),
		   REG_FIELD_GET(XE2_L3_POLICY, pat),
		   REG_FIELD_GET(XE2_L4_POLICY, pat),
		   REG_FIELD_GET(XE2_COH_MODE, pat),
		   pat, rsvd ? " *" : "");
}

static void xe3p_xpc_pat_entry_dump(struct drm_printer *p, const char *label, u32 pat, bool rsvd)
{
	drm_printf(p, "%s= [ %u, %u, %u, %u, %u ]  (%#8x)%s\n", label,
		   !!(pat & XE2_NO_PROMOTE),
		   REG_FIELD_GET(XE2_L3_CLOS, pat),
		   REG_FIELD_GET(XE2_L3_POLICY, pat),
		   REG_FIELD_GET(XE2_L4_POLICY, pat),
		   REG_FIELD_GET(XE2_COH_MODE, pat),
		   pat, rsvd ? " *" : "");
}

static int xe2_dump(struct xe_gt *gt, struct drm_printer *p)
{
	struct xe_device *xe = gt_to_xe(gt);
	u32 pat;
	int i;
	char label[PAT_LABEL_LEN];

	CLASS(xe_force_wake, fw_ref)(gt_to_fw(gt), XE_FW_GT);
	if (!fw_ref.domains)
		return -ETIMEDOUT;

	drm_printf(p, "PAT table: (* = reserved entry)\n");

	for (i = 0; i < xe->pat.n_entries; i++) {
		if (xe_gt_is_media_type(gt))
			pat = xe_mmio_read32(&gt->mmio, XE_REG(_PAT_INDEX(i)));
		else
			pat = xe_gt_mcr_unicast_read_any(gt, XE_REG_MCR(_PAT_INDEX(i)));

		xe_pat_index_label(label, sizeof(label), i);
		xe->pat.ops->entry_dump(p, label, pat, !xe->pat.table[i].valid);
	}

	/*
	 * Also print PTA_MODE, which describes how the hardware accesses
	 * PPGTT entries.
	 */
	if (xe_gt_is_media_type(gt))
		pat = xe_mmio_read32(&gt->mmio, XE_REG(_PAT_PTA));
	else
		pat = xe_gt_mcr_unicast_read_any(gt, XE_REG_MCR(_PAT_PTA));

	drm_printf(p, "Page Table Access:\n");
	xe->pat.ops->entry_dump(p, "PTA_MODE", pat, false);

	if (xe_gt_is_media_type(gt))
		pat = xe_mmio_read32(&gt->mmio, XE_REG(_PAT_ATS));
	else
		pat = xe_gt_mcr_unicast_read_any(gt, XE_REG_MCR(_PAT_ATS));

	drm_printf(p, "PCIe ATS/PASID:\n");
	xe->pat.ops->entry_dump(p, "PAT_ATS ", pat, false);

	return 0;
}

static const struct xe_pat_ops xe2_pat_ops = {
	.program_graphics = program_pat_mcr,
	.program_media = program_pat,
	.dump = xe2_dump,
	.entry_dump = xe2_pat_entry_dump,
};

static const struct xe_pat_ops xe3p_xpc_pat_ops = {
	.program_graphics = program_pat_mcr,
	.program_media = program_pat,
	.dump = xe2_dump,
	.entry_dump = xe3p_xpc_pat_entry_dump,
};

#define XE_PAT_SELECT_WARN(context, condition) ((void)(context), WARN_ON_ONCE(condition))
#define XE_PAT_SELECT_MISSING(context, version) \
 drm_err(&((struct xe_device *)(context))->drm, \
 "Missing PAT table for platform with graphics version %d.%02d!\n", \
 (int)((version) / 100), (int)((version) % 100))
#include "xe_pat_select.h"

void xe_pat_init_early(struct xe_device *xe)
{
 struct xe_pat_selection selection = {
  .table = xe->pat.table, .pat_ats = xe->pat.pat_ats,
  .pat_primary_pta = xe->pat.pat_primary_pta, .pat_media_pta = xe->pat.pat_media_pta,
  .n_entries = xe->pat.n_entries,
 };
 for (int i = 0; i < __XE_CACHE_LEVEL_COUNT; i++) selection.idx[i] = xe->pat.idx[i];
 (void)xe_pat_select(&selection, xe->info.platform, GRAPHICS_VERx100(xe),
                     IS_DGFX(xe), xe->info.has_llc, xe);
 switch (selection.profile) {
 case XE_PAT_PROFILE_XELP: xe->pat.ops = &xelp_pat_ops; break;
 case XE_PAT_PROFILE_XEHP: xe->pat.ops = &xehp_pat_ops; break;
 case XE_PAT_PROFILE_XEHPC: xe->pat.ops = &xehpc_pat_ops; break;
 case XE_PAT_PROFILE_XELPG: xe->pat.ops = &xelpg_pat_ops; break;
 case XE_PAT_PROFILE_XE2: xe->pat.ops = &xe2_pat_ops; break;
 case XE_PAT_PROFILE_XE3P_XPC: xe->pat.ops = &xe3p_xpc_pat_ops; break;
 default: break; /* Original missing-policy path preserves existing ops. */
 }
 xe->pat.table = selection.table; xe->pat.n_entries = selection.n_entries;
 xe->pat.pat_ats = selection.pat_ats;
 xe->pat.pat_primary_pta = selection.pat_primary_pta;
 xe->pat.pat_media_pta = selection.pat_media_pta;
 for (int i = 0; i < __XE_CACHE_LEVEL_COUNT; i++) xe->pat.idx[i] = selection.idx[i];

	xe_assert(xe, xe->pat.ops->dump);
	xe_assert(xe, xe->pat.ops->program_graphics);
	xe_assert(xe, MEDIA_VER(xe) < 13 || xe->pat.ops->program_media);
	xe_assert(xe, GRAPHICS_VER(xe) < 20 || xe->pat.ops->entry_dump);
}

void xe_pat_init(struct xe_gt *gt)
{
	struct xe_device *xe = gt_to_xe(gt);

	if (IS_SRIOV_VF(xe))
		return;

	if (xe_gt_is_media_type(gt))
		xe->pat.ops->program_media(gt, xe->pat.table, xe->pat.n_entries);
	else
		xe->pat.ops->program_graphics(gt, xe->pat.table, xe->pat.n_entries);
}

/**
 * xe_pat_dump() - Dump GT PAT table into a drm printer.
 * @gt: the &xe_gt
 * @p: the &drm_printer
 *
 * Return: 0 on success or a negative error code on failure.
 */
int xe_pat_dump(struct xe_gt *gt, struct drm_printer *p)
{
	struct xe_device *xe = gt_to_xe(gt);

	if (IS_SRIOV_VF(xe))
		return -EOPNOTSUPP;

	return xe->pat.ops->dump(gt, p);
}

/**
 * xe_pat_dump_sw_config() - Dump the software-configured GT PAT table into a drm printer.
 * @gt: the &xe_gt
 * @p: the &drm_printer
 *
 * Return: 0 on success or a negative error code on failure.
 */
int xe_pat_dump_sw_config(struct xe_gt *gt, struct drm_printer *p)
{
	struct xe_device *xe = gt_to_xe(gt);
	const struct xe_pat_table_entry *pta_entry = gt_pta_entry(gt);
	char label[PAT_LABEL_LEN];

	if (!xe->pat.table || !xe->pat.n_entries)
		return -EOPNOTSUPP;

	drm_printf(p, "PAT table:%s\n", GRAPHICS_VER(xe) >= 20 ? " (* = reserved entry)" : "");
	for (u32 i = 0; i < xe->pat.n_entries; i++) {
		u32 pat = xe->pat.table[i].value;

		if (GRAPHICS_VER(xe) >= 20) {
			xe_pat_index_label(label, sizeof(label), i);
			xe->pat.ops->entry_dump(p, label, pat, !xe->pat.table[i].valid);
		} else if (xe->info.platform == XE_METEORLAKE) {
			xelpg_pat_entry_dump(p, i, pat);
		} else if (xe->info.platform == XE_PVC) {
			xehpc_pat_entry_dump(p, i, pat);
		} else if (xe->info.platform == XE_DG2 || GRAPHICS_VERx100(xe) <= 1210) {
			xelp_pat_entry_dump(p, i, pat);
		} else {
			return -EOPNOTSUPP;
		}
	}

	if (pta_entry) {
		u32 pat = pta_entry->value;

		drm_printf(p, "Page Table Access:\n");
		xe->pat.ops->entry_dump(p, "PTA_MODE", pat, false);
	}

	if (xe->pat.pat_ats) {
		u32 pat = xe->pat.pat_ats->value;

		drm_printf(p, "PCIe ATS/PASID:\n");
		xe->pat.ops->entry_dump(p, "PAT_ATS ", pat, false);
	}

	drm_printf(p, "Cache Level:\n");
	drm_printf(p, "IDX[XE_CACHE_NONE] = %d\n", xe->pat.idx[XE_CACHE_NONE]);
	drm_printf(p, "IDX[XE_CACHE_WT] = %d\n", xe->pat.idx[XE_CACHE_WT]);
	drm_printf(p, "IDX[XE_CACHE_WB] = %d\n", xe->pat.idx[XE_CACHE_WB]);
	if (GRAPHICS_VER(xe) >= 20) {
		drm_printf(p, "IDX[XE_CACHE_NONE_COMPRESSION] = %d\n",
			   xe->pat.idx[XE_CACHE_NONE_COMPRESSION]);
		drm_printf(p, "IDX[XE_CACHE_WB_COMPRESSION] = %d\n",
			   xe->pat.idx[XE_CACHE_WB_COMPRESSION]);
	}

	return 0;
}
