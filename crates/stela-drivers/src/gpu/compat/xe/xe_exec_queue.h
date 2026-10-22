/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_EXEC_QUEUE_H
#define STELA_XE_EXEC_QUEUE_H
#include <linux/types.h>
#include "xe_hw_engine_types.h"
struct xe_gt;
struct xe_lrc;
struct xe_vm;
/* The fields unchanged Xe sources read from an execution queue. */
struct xe_exec_queue {
	struct xe_gt *gt;
	struct xe_hw_engine *hwe;
	struct xe_vm *vm;
	enum xe_engine_class class;
	u16 width;
	struct xe_lrc *lrc[];
};
static bool xe_exec_queue_is_multi_queue(struct xe_exec_queue *q);
#endif
