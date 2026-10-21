/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_RING_EMIT_H
#define XE_RING_EMIT_H

#include "instructions/xe_mi_commands.h"

/* Pure emitters shared by the existing Xe job path and Stela's bounded native
 * command writer. Bodies are retained from xe_ring_ops.c; engine workarounds,
 * cache policy and queue scheduling remain in their original higher layers.
 */
static inline int emit_user_interrupt(u32 *dw, int i)
{
	dw[i++] = MI_USER_INTERRUPT;
	dw[i++] = MI_ARB_ON_OFF | MI_ARB_ENABLE;
	dw[i++] = MI_ARB_CHECK;

	return i;
}

static inline int emit_flush_dw(u32 *dw, int i)
{
	dw[i++] = MI_FLUSH_DW | MI_FLUSH_IMM_DW;
	dw[i++] = 0;
	dw[i++] = 0;
	dw[i++] = 0;

	return i;
}

static inline int emit_bb_start(u64 batch_addr, u32 ppgtt_flag, u32 *dw, int i)
{
	dw[i++] = MI_BATCH_BUFFER_START | ppgtt_flag | XE_INSTR_NUM_DW(3);
	dw[i++] = lower_32_bits(batch_addr);
	dw[i++] = upper_32_bits(batch_addr);

	return i;
}

static inline int emit_store_imm_ppgtt_posted(u64 addr, u64 value,
				           u32 *dw, int i)
{
	dw[i++] = MI_STORE_DATA_IMM | MI_SDI_NUM_QW(1);
	dw[i++] = lower_32_bits(addr);
	dw[i++] = upper_32_bits(addr);
	dw[i++] = lower_32_bits(value);
	dw[i++] = upper_32_bits(value);

	return i;
}

#endif
