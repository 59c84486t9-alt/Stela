/* SPDX-License-Identifier: MIT */
/* Copyright © 2023 Intel Corporation */
#ifndef XE_PAT_TABLES_H
#define XE_PAT_TABLES_H
#include "xe_pat.h"
#define _PAT_ATS				0x47fc
#define _PAT_INDEX(index)			_PICK_EVEN_2RANGES(index, 8, \
								   0x4800, 0x4804, \
								   0x4848, 0x484c)
#define _PAT_PTA				0x4820

#define XE2_NO_PROMOTE				REG_BIT(10)
#define XE2_COMP_EN				REG_BIT(9)
#define XE2_L3_CLOS				REG_GENMASK(7, 6)
#define XE2_L3_POLICY				REG_GENMASK(5, 4)
#define XE2_L4_POLICY				REG_GENMASK(3, 2)
#define XE2_COH_MODE				REG_GENMASK(1, 0)

#define XELPG_L4_POLICY_MASK			REG_GENMASK(3, 2)
#define XELPG_PAT_3_UC				REG_FIELD_PREP(XELPG_L4_POLICY_MASK, 3)
#define XELPG_PAT_1_WT				REG_FIELD_PREP(XELPG_L4_POLICY_MASK, 1)
#define XELPG_PAT_0_WB				REG_FIELD_PREP(XELPG_L4_POLICY_MASK, 0)
#define XELPG_INDEX_COH_MODE_MASK		REG_GENMASK(1, 0)
#define XELPG_3_COH_2W				REG_FIELD_PREP(XELPG_INDEX_COH_MODE_MASK, 3)
#define XELPG_2_COH_1W				REG_FIELD_PREP(XELPG_INDEX_COH_MODE_MASK, 2)
#define XELPG_0_COH_NON				REG_FIELD_PREP(XELPG_INDEX_COH_MODE_MASK, 0)

#define XEHPC_CLOS_LEVEL_MASK			REG_GENMASK(3, 2)
#define XEHPC_PAT_CLOS(x)			REG_FIELD_PREP(XEHPC_CLOS_LEVEL_MASK, x)

#define XELP_MEM_TYPE_MASK			REG_GENMASK(1, 0)
#define XELP_PAT_WB				REG_FIELD_PREP(XELP_MEM_TYPE_MASK, 3)
#define XELP_PAT_WT				REG_FIELD_PREP(XELP_MEM_TYPE_MASK, 2)
#define XELP_PAT_WC				REG_FIELD_PREP(XELP_MEM_TYPE_MASK, 1)
#define XELP_PAT_UC				REG_FIELD_PREP(XELP_MEM_TYPE_MASK, 0)

static const struct xe_pat_table_entry xelp_pat_table[] = {
	[0] = { XELP_PAT_WB, XE_COH_1WAY },
	[1] = { XELP_PAT_WC, XE_COH_NONE },
	[2] = { XELP_PAT_WT, XE_COH_NONE },
	[3] = { XELP_PAT_UC, XE_COH_NONE },
};

static const struct xe_pat_table_entry xehpc_pat_table[] = {
	[0] = { XELP_PAT_UC, XE_COH_NONE },
	[1] = { XELP_PAT_WC, XE_COH_NONE },
	[2] = { XELP_PAT_WT, XE_COH_NONE },
	[3] = { XELP_PAT_WB, XE_COH_1WAY },
	[4] = { XEHPC_PAT_CLOS(1) | XELP_PAT_WT, XE_COH_NONE },
	[5] = { XEHPC_PAT_CLOS(1) | XELP_PAT_WB, XE_COH_1WAY },
	[6] = { XEHPC_PAT_CLOS(2) | XELP_PAT_WT, XE_COH_NONE },
	[7] = { XEHPC_PAT_CLOS(2) | XELP_PAT_WB, XE_COH_1WAY },
};

static const struct xe_pat_table_entry xelpg_pat_table[] = {
	[0] = { XELPG_PAT_0_WB, XE_COH_NONE },
	[1] = { XELPG_PAT_1_WT, XE_COH_NONE },
	[2] = { XELPG_PAT_3_UC, XE_COH_NONE },
	[3] = { XELPG_PAT_0_WB | XELPG_2_COH_1W, XE_COH_1WAY },
	[4] = { XELPG_PAT_0_WB | XELPG_3_COH_2W, XE_COH_2WAY },
};

/*
 * The Xe2 table is getting large/complicated so it's easier to review if
 * provided in a form that exactly matches the bspec's formatting.  The meaning
 * of the fields here are:
 *   - no_promote:  0=promotable, 1=no promote
 *   - comp_en:     0=disable, 1=enable
 *   - l3clos:      L3 class of service (0-3)
 *   - l3_policy:   0=WB, 1=XD ("WB - Transient Display"),
 *                  2=XA ("WB - Transient App" for Xe3p), 3=UC
 *   - l4_policy:   0=WB, 1=WT, 3=UC
 *   - coh_mode:    0=no snoop, 2=1-way coherent, 3=2-way coherent
 *
 * Reserved entries should be programmed with the maximum caching, minimum
 * coherency (which matches an all-0's encoding), so we can just omit them
 * in the table.
 *
 * Note: There is an implicit assumption in the driver that compression and
 * coh_1way+ are mutually exclusive for platforms prior to Xe3. Starting
 * with Xe3, compression can be combined with coherency. If using compression
 * with coherency, userptr and imported dma-buf from external device will
 * have uncleared ccs state. See also xe_bo_needs_ccs_pages().
 */
#define XE2_PAT(no_promote, comp_en, l3clos, l3_policy, l4_policy, __coh_mode) \
	{ \
		.value = (no_promote ? XE2_NO_PROMOTE : 0) | \
			(comp_en ? XE2_COMP_EN : 0) | \
			REG_FIELD_PREP(XE2_L3_CLOS, l3clos) | \
			REG_FIELD_PREP(XE2_L3_POLICY, l3_policy) | \
			REG_FIELD_PREP(XE2_L4_POLICY, l4_policy) | \
			REG_FIELD_PREP(XE2_COH_MODE, __coh_mode), \
		.coh_mode = __coh_mode ? __coh_mode : XE_COH_NONE, \
		.valid = 1 \
	}

static const struct xe_pat_table_entry xe2_pat_table[] = {
	[ 0] = XE2_PAT( 0, 0, 0, 0, 3, 0 ),
	[ 1] = XE2_PAT( 0, 0, 0, 0, 3, 2 ),
	[ 2] = XE2_PAT( 0, 0, 0, 0, 3, 3 ),
	[ 3] = XE2_PAT( 0, 0, 0, 3, 3, 0 ),
	[ 4] = XE2_PAT( 0, 0, 0, 3, 0, 2 ),
	[ 5] = XE2_PAT( 0, 0, 0, 3, 3, 2 ),
	[ 6] = XE2_PAT( 1, 0, 0, 1, 3, 0 ),
	[ 7] = XE2_PAT( 0, 0, 0, 3, 0, 3 ),
	[ 8] = XE2_PAT( 0, 0, 0, 3, 0, 0 ),
	[ 9] = XE2_PAT( 0, 1, 0, 0, 3, 0 ),
	[10] = XE2_PAT( 0, 1, 0, 3, 0, 0 ),
	[11] = XE2_PAT( 1, 1, 0, 1, 3, 0 ),
	[12] = XE2_PAT( 0, 1, 0, 3, 3, 0 ),
	[13] = XE2_PAT( 0, 0, 0, 0, 0, 0 ),
	[14] = XE2_PAT( 0, 1, 0, 0, 0, 0 ),
	[15] = XE2_PAT( 1, 1, 0, 1, 1, 0 ),
	/* 16..19 are reserved; leave set to all 0's */
	[20] = XE2_PAT( 0, 0, 1, 0, 3, 0 ),
	[21] = XE2_PAT( 0, 1, 1, 0, 3, 0 ),
	[22] = XE2_PAT( 0, 0, 1, 0, 3, 2 ),
	[23] = XE2_PAT( 0, 0, 1, 0, 3, 3 ),
	[24] = XE2_PAT( 0, 0, 2, 0, 3, 0 ),
	[25] = XE2_PAT( 0, 1, 2, 0, 3, 0 ),
	[26] = XE2_PAT( 0, 0, 2, 0, 3, 2 ),
	[27] = XE2_PAT( 0, 0, 2, 0, 3, 3 ),
	[28] = XE2_PAT( 0, 0, 3, 0, 3, 0 ),
	[29] = XE2_PAT( 0, 1, 3, 0, 3, 0 ),
	[30] = XE2_PAT( 0, 0, 3, 0, 3, 2 ),
	[31] = XE2_PAT( 0, 0, 3, 0, 3, 3 ),
};

static const struct xe_pat_table_entry xe3_lpg_pat_table[] = {
	[ 0] = XE2_PAT( 0, 0, 0, 0, 3, 0 ),
	[ 1] = XE2_PAT( 0, 0, 0, 0, 3, 2 ),
	[ 2] = XE2_PAT( 0, 0, 0, 0, 3, 3 ),
	[ 3] = XE2_PAT( 0, 0, 0, 3, 3, 0 ),
	[ 4] = XE2_PAT( 0, 0, 0, 3, 0, 2 ),
	[ 5] = XE2_PAT( 0, 0, 0, 3, 3, 2 ),
	[ 6] = XE2_PAT( 1, 0, 0, 1, 3, 0 ),
	[ 7] = XE2_PAT( 0, 0, 0, 3, 0, 3 ),
	[ 8] = XE2_PAT( 0, 0, 0, 3, 0, 0 ),
	[ 9] = XE2_PAT( 0, 1, 0, 0, 3, 0 ),
	[10] = XE2_PAT( 0, 1, 0, 3, 0, 0 ),
	[11] = XE2_PAT( 1, 1, 0, 1, 3, 0 ),
	[12] = XE2_PAT( 0, 1, 0, 3, 3, 0 ),
	[13] = XE2_PAT( 0, 0, 0, 0, 0, 0 ),
	[14] = XE2_PAT( 0, 1, 0, 0, 0, 0 ),
	[15] = XE2_PAT( 1, 1, 0, 1, 1, 0 ),
	[16] = XE2_PAT( 0, 1, 0, 0, 3, 2 ),
	/* 17..19 are reserved; leave set to all 0's */
	[20] = XE2_PAT( 0, 0, 1, 0, 3, 0 ),
	[21] = XE2_PAT( 0, 1, 1, 0, 3, 0 ),
	[22] = XE2_PAT( 0, 0, 1, 0, 3, 2 ),
	[23] = XE2_PAT( 0, 0, 1, 0, 3, 3 ),
	[24] = XE2_PAT( 0, 0, 2, 0, 3, 0 ),
	[25] = XE2_PAT( 0, 1, 2, 0, 3, 0 ),
	[26] = XE2_PAT( 0, 0, 2, 0, 3, 2 ),
	[27] = XE2_PAT( 0, 0, 2, 0, 3, 3 ),
	[28] = XE2_PAT( 0, 0, 3, 0, 3, 0 ),
	[29] = XE2_PAT( 0, 1, 3, 0, 3, 0 ),
	[30] = XE2_PAT( 0, 0, 3, 0, 3, 2 ),
	[31] = XE2_PAT( 0, 0, 3, 0, 3, 3 ),
};
/* Special PAT values programmed outside the main table */
static const struct xe_pat_table_entry xe2_pat_ats = XE2_PAT( 0, 0, 0, 0, 3, 3 );
static const struct xe_pat_table_entry xe2_pat_pta = XE2_PAT( 0, 0, 0, 0, 3, 0 );

/*
 * Xe3p_XPC PAT table uses the same layout as Xe2/Xe3, except that there's no
 * option for compression.  Also note that the "L3" and "L4" register fields
 * actually control L2 and L3 cache respectively on this platform.
 */
#define XE3P_XPC_PAT(no_promote, l3clos, l3_policy, l4_policy, __coh_mode) \
	XE2_PAT(no_promote, 0, l3clos, l3_policy, l4_policy, __coh_mode)

static const struct xe_pat_table_entry xe3p_xpc_pat_ats = XE3P_XPC_PAT( 0, 0, 0, 0, 3 );
static const struct xe_pat_table_entry xe3p_xpc_pat_pta = XE3P_XPC_PAT( 0, 0, 0, 0, 0 );

static const struct xe_pat_table_entry xe3p_xpc_pat_table[] = {
	[ 0] = XE3P_XPC_PAT( 0, 0, 0, 0, 0 ),
	[ 1] = XE3P_XPC_PAT( 0, 0, 0, 0, 2 ),
	[ 2] = XE3P_XPC_PAT( 0, 0, 0, 0, 3 ),
	[ 3] = XE3P_XPC_PAT( 0, 0, 3, 3, 0 ),
	[ 4] = XE3P_XPC_PAT( 0, 0, 3, 3, 2 ),
	[ 5] = XE3P_XPC_PAT( 0, 0, 3, 0, 0 ),
	[ 6] = XE3P_XPC_PAT( 0, 0, 3, 0, 2 ),
	[ 7] = XE3P_XPC_PAT( 0, 0, 3, 0, 3 ),
	[ 8] = XE3P_XPC_PAT( 0, 0, 0, 3, 0 ),
	[ 9] = XE3P_XPC_PAT( 0, 0, 0, 3, 2 ),
	[10] = XE3P_XPC_PAT( 0, 0, 0, 3, 3 ),
	/* 11..22 are reserved; leave set to all 0's */
	[23] = XE3P_XPC_PAT( 0, 1, 0, 0, 0 ),
	[24] = XE3P_XPC_PAT( 0, 1, 0, 0, 2 ),
	[25] = XE3P_XPC_PAT( 0, 1, 0, 0, 3 ),
	[26] = XE3P_XPC_PAT( 0, 2, 0, 0, 0 ),
	[27] = XE3P_XPC_PAT( 0, 2, 0, 0, 2 ),
	[28] = XE3P_XPC_PAT( 0, 2, 0, 0, 3 ),
	[29] = XE3P_XPC_PAT( 0, 3, 0, 0, 0 ),
	[30] = XE3P_XPC_PAT( 0, 3, 0, 0, 2 ),
	[31] = XE3P_XPC_PAT( 0, 3, 0, 0, 3 ),
};

static const struct xe_pat_table_entry xe3p_primary_pat_pta = XE2_PAT(0, 0, 0, 0, 0, 3);
static const struct xe_pat_table_entry xe3p_media_pat_pta = XE2_PAT(0, 0, 0, 0, 0, 2);

static const struct xe_pat_table_entry xe3p_lpg_pat_table[] = {
	[ 0] = XE2_PAT( 0, 0, 0, 0, 3, 0 ),
	[ 1] = XE2_PAT( 0, 0, 0, 0, 3, 2 ),
	[ 2] = XE2_PAT( 0, 0, 0, 0, 3, 3 ),
	[ 3] = XE2_PAT( 0, 0, 0, 3, 3, 0 ),
	[ 4] = XE2_PAT( 0, 0, 0, 3, 0, 2 ),
	[ 5] = XE2_PAT( 0, 0, 0, 3, 3, 2 ),
	[ 6] = XE2_PAT( 1, 0, 0, 1, 3, 0 ),
	[ 7] = XE2_PAT( 0, 0, 0, 3, 0, 3 ),
	[ 8] = XE2_PAT( 0, 0, 0, 3, 0, 0 ),
	[ 9] = XE2_PAT( 0, 1, 0, 0, 3, 0 ),
	[10] = XE2_PAT( 0, 1, 0, 3, 0, 0 ),
	[11] = XE2_PAT( 1, 1, 0, 1, 3, 0 ),
	[12] = XE2_PAT( 0, 1, 0, 3, 3, 0 ),
	[13] = XE2_PAT( 0, 0, 0, 0, 0, 0 ),
	[14] = XE2_PAT( 0, 1, 0, 0, 0, 0 ),
	[15] = XE2_PAT( 1, 1, 0, 1, 1, 0 ),
	[16] = XE2_PAT( 0, 1, 0, 0, 3, 2 ),
	/* 17 is reserved; leave set to all 0's */
	[18] = XE2_PAT( 1, 0, 0, 2, 3, 0 ),
	[19] = XE2_PAT( 1, 0, 0, 2, 3, 2 ),
	[20] = XE2_PAT( 0, 0, 1, 0, 3, 0 ),
	[21] = XE2_PAT( 0, 1, 1, 0, 3, 0 ),
	[22] = XE2_PAT( 0, 0, 1, 0, 3, 2 ),
	[23] = XE2_PAT( 0, 0, 1, 0, 3, 3 ),
	[24] = XE2_PAT( 0, 0, 2, 0, 3, 0 ),
	[25] = XE2_PAT( 0, 1, 2, 0, 3, 0 ),
	[26] = XE2_PAT( 0, 0, 2, 0, 3, 2 ),
	[27] = XE2_PAT( 0, 0, 2, 0, 3, 3 ),
	[28] = XE2_PAT( 0, 0, 3, 0, 3, 0 ),
	[29] = XE2_PAT( 0, 1, 3, 0, 3, 0 ),
	[30] = XE2_PAT( 0, 0, 3, 0, 3, 2 ),
	[31] = XE2_PAT( 0, 0, 3, 0, 3, 3 ),
};

#endif
