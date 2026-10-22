/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_LRC_H
#define STELA_XE_LRC_H
#include <linux/types.h>
/* Copyright © 2021 Intel Corporation; the per-process status-page offsets from
 * xe_lrc.h.
 */
#define LRC_PPHWSP_FLUSH_INVAL_SCRATCH_ADDR (0x34 * 4)
#define LRC_PPHWSP_PXP_INVAL_SCRATCH_ADDR (0x40 * 4)
/* The fields unchanged Xe sources read from a logical ring context, and the
 * context services they call.
 */
struct xe_lrc {
	struct {
		u32 tail;
	} ring;
};
static u32 xe_lrc_ggtt_addr(struct xe_lrc *lrc);
static u32 xe_lrc_seqno_ggtt_addr(struct xe_lrc *lrc);
static u32 xe_lrc_start_seqno_ggtt_addr(struct xe_lrc *lrc);
static u32 xe_lrc_ctx_timestamp_ggtt_addr(struct xe_lrc *lrc);
static u32 xe_lrc_ctx_job_timestamp_ggtt_addr(struct xe_lrc *lrc);
static bool xe_lrc_is_multi_queue(struct xe_lrc *lrc);
static void xe_lrc_write_ring(struct xe_lrc *lrc, const void *data, size_t size);
#endif
