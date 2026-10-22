/* SPDX-License-Identifier: MIT */
/* Copyright © 2023 Intel Corporation */
#ifndef XE_PAT_SELECT_H
#define XE_PAT_SELECT_H
#include "xe_cache_level.h"
#include "xe_platform_types.h"
#include "xe_pat_tables.h"
#ifndef XE_PAT_SELECT_WARN
#error "PAT selector needs actual warning binding"
#endif
#ifndef XE_PAT_SELECT_MISSING
#error "PAT selector needs actual missing-policy diagnostic binding"
#endif
enum xe_pat_profile { XE_PAT_PROFILE_NONE,
 XE_PAT_PROFILE_XELP,
 XE_PAT_PROFILE_XEHP,
 XE_PAT_PROFILE_XEHPC,
 XE_PAT_PROFILE_XELPG,
 XE_PAT_PROFILE_XE2,
 XE_PAT_PROFILE_XE3P_XPC,
};
struct xe_pat_selection {
 enum xe_pat_profile profile;
 const struct xe_pat_table_entry *table, *pat_ats, *pat_primary_pta, *pat_media_pta;
 int n_entries;
 u16 idx[__XE_CACHE_LEVEL_COUNT];
};
static inline bool xe_pat_select(struct xe_pat_selection *selection,
 enum xe_platform platform, u32 graphics_verx100, bool discrete, bool has_llc,
 void *context)
{
	selection->idx[XE_CACHE_WB_COMPRESSION] = XE_PAT_INVALID_IDX;
	selection->idx[XE_CACHE_NONE_COMPRESSION] = XE_PAT_INVALID_IDX;
	if (graphics_verx100 == 3511) {
		selection->profile = XE_PAT_PROFILE_XE3P_XPC;
		selection->table = xe3p_xpc_pat_table;
		selection->pat_ats = &xe3p_xpc_pat_ats;
		selection->pat_primary_pta = &xe3p_xpc_pat_pta;
		selection->pat_media_pta = &xe3p_xpc_pat_pta;
		selection->n_entries = ARRAY_SIZE(xe3p_xpc_pat_table);
		selection->idx[XE_CACHE_NONE] = 3;
		selection->idx[XE_CACHE_WT] = 3;	/* N/A (no display); use UC */
		selection->idx[XE_CACHE_WB] = 2;
	} else if ((graphics_verx100 / 100) == 35) {
		selection->profile = XE_PAT_PROFILE_XE2;
		selection->table = xe3p_lpg_pat_table;
		selection->pat_ats = &xe2_pat_ats;
		if (!discrete) {
			selection->pat_primary_pta = &xe3p_primary_pat_pta;
			selection->pat_media_pta = &xe3p_media_pat_pta;
		}
		selection->n_entries = ARRAY_SIZE(xe3p_lpg_pat_table);
		selection->idx[XE_CACHE_NONE] = 3;
		selection->idx[XE_CACHE_WT] = 15;
		selection->idx[XE_CACHE_WB] = 2;
		selection->idx[XE_CACHE_NONE_COMPRESSION] = 12;
		selection->idx[XE_CACHE_WB_COMPRESSION] = 16;
	} else if ((graphics_verx100 / 100) == 30 || (graphics_verx100 / 100) == 20) {
		selection->profile = XE_PAT_PROFILE_XE2;
		if ((graphics_verx100 / 100) == 30) {
			selection->table = xe3_lpg_pat_table;
			selection->idx[XE_CACHE_WB_COMPRESSION] = 16;
		} else {
			selection->table = xe2_pat_table;
		}
		selection->pat_ats = &xe2_pat_ats;
		if (discrete) {
			selection->pat_primary_pta = &xe2_pat_pta;
			selection->pat_media_pta = &xe2_pat_pta;
		}

		/* Wa_16023588340. XXX: Should use XE_WA */
		if (graphics_verx100 == 2001)
			selection->n_entries = 28; /* Disable CLOS3 */
		else
			selection->n_entries = ARRAY_SIZE(xe2_pat_table);

		selection->idx[XE_CACHE_NONE] = 3;
		selection->idx[XE_CACHE_WT] = 15;
		selection->idx[XE_CACHE_WB] = 2;
		selection->idx[XE_CACHE_NONE_COMPRESSION] = 12; /*Applicable on xe2 and beyond */
	} else if (platform == XE_METEORLAKE) {
		selection->profile = XE_PAT_PROFILE_XELPG;
		selection->table = xelpg_pat_table;
		selection->n_entries = ARRAY_SIZE(xelpg_pat_table);
		selection->idx[XE_CACHE_NONE] = 2;
		selection->idx[XE_CACHE_WT] = 1;
		selection->idx[XE_CACHE_WB] = 3;
	} else if (platform == XE_PVC) {
		selection->profile = XE_PAT_PROFILE_XEHPC;
		selection->table = xehpc_pat_table;
		selection->n_entries = ARRAY_SIZE(xehpc_pat_table);
		selection->idx[XE_CACHE_NONE] = 0;
		selection->idx[XE_CACHE_WT] = 2;
		selection->idx[XE_CACHE_WB] = 3;
	} else if (platform == XE_DG2) {
		/*
		 * Table is the same as previous platforms, but programming
		 * method has changed.
		 */
		selection->profile = XE_PAT_PROFILE_XEHP;
		selection->table = xelp_pat_table;
		selection->n_entries = ARRAY_SIZE(xelp_pat_table);
		selection->idx[XE_CACHE_NONE] = 3;
		selection->idx[XE_CACHE_WT] = 2;
		selection->idx[XE_CACHE_WB] = 0;
	} else if (graphics_verx100 <= 1210) {
		XE_PAT_SELECT_WARN(context, !discrete && !has_llc);
		selection->profile = XE_PAT_PROFILE_XELP;
		selection->table = xelp_pat_table;
		selection->n_entries = ARRAY_SIZE(xelp_pat_table);
		selection->idx[XE_CACHE_NONE] = 3;
		selection->idx[XE_CACHE_WT] = 2;
		selection->idx[XE_CACHE_WB] = 0;
	} else {
		/*
		 * Going forward we expect to need new PAT settings for most
		 * new platforms; failure to provide a new table can easily
		 * lead to subtle, hard-to-debug problems.  If none of the
		 * conditions above match the platform we're running on we'll
		 * raise an error rather than trying to silently inherit the
		 * most recent platform's behavior.
		 */
		XE_PAT_SELECT_MISSING(context, graphics_verx100);
		return false;
	}

 return true;
}
#undef XE_PAT_SELECT_WARN
#undef XE_PAT_SELECT_MISSING
#endif
