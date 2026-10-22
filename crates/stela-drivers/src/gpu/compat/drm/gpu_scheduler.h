/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_GPU_SCHEDULER_H
#define STELA_DRM_GPU_SCHEDULER_H
#include <linux/types.h>
/* Stela runs no DRM scheduler; a ring names one, and a source that waits for
 * one declares the time conversion it uses. */
struct drm_gpu_scheduler {
	bool ready;
};
static unsigned long msecs_to_jiffies(const unsigned int m);

/* Copyright 2015 Advanced Micro Devices, Inc.; from gpu_scheduler.h. */
#define MAX_WAIT_SCHED_ENTITY_Q_EMPTY msecs_to_jiffies(1000)
#endif
