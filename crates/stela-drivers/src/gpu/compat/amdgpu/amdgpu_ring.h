/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_RING_H
#define STELA_AMDGPU_RING_H
#include <drm/gpu_scheduler.h>
/* Copyright 2016 Advanced Micro Devices, Inc.; from amdgpu_ring.h. */
#define AMDGPU_MAX_RINGS		149

/* The ring state unchanged sources read; Stela's rings are its own. */
struct amdgpu_ring {
	struct drm_gpu_scheduler sched;
};
/* A service the sources call, which each adapter defines. */
static int amdgpu_fence_wait_empty(struct amdgpu_ring *ring);
#endif
