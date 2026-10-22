/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_SCHED_JOB_H
#define STELA_XE_SCHED_JOB_H
#include <linux/types.h>
struct xe_exec_queue;
/* Copyright © 2022 Intel Corporation; from xe_sched_job_types.h, with the
 * fields unchanged Xe sources read from a job.
 */
struct xe_job_ptrs {
	u64 batch_addr;
	u32 head;
};
struct xe_sched_job {
	struct xe_exec_queue *q;
	struct {
		bool used;
		u64 addr;
		u64 value;
	} user_fence;
	u32 migrate_flush_flags;
	bool ring_ops_flush_tlb;
	bool ring_ops_force_reset;
	bool ggtt;
	struct xe_job_ptrs ptrs[];
};
static bool xe_sched_job_is_migration(struct xe_exec_queue *q);
static u32 xe_sched_job_lrc_seqno(struct xe_sched_job *job);
#endif
