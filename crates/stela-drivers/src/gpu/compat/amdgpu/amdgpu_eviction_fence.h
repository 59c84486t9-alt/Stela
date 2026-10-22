/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_EVICTION_FENCE_H
#define STELA_AMDGPU_EVICTION_FENCE_H
/* Stela evicts no user buffers; the type names a file's manager. */
struct amdgpu_eviction_fence_mgr {
};
/* Services the sources call, which each adapter defines. */
static void amdgpu_evf_mgr_shutdown(struct amdgpu_eviction_fence_mgr *evf_mgr);
static void amdgpu_evf_mgr_flush_suspend(struct amdgpu_eviction_fence_mgr *evf_mgr);
static void amdgpu_evf_mgr_fini(struct amdgpu_eviction_fence_mgr *evf_mgr);
#endif
