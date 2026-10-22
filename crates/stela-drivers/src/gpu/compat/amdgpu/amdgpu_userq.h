/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_USERQ_H
#define STELA_AMDGPU_USERQ_H
struct drm_device;
struct drm_file;
/* Stela runs no user queues; the type names a file's manager. */
struct amdgpu_userq_mgr {
};
/* Services the sources call, which each adapter defines. */
static int amdgpu_userq_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static void amdgpu_userq_mgr_cancel_resume(struct amdgpu_userq_mgr *userq_mgr);
static void amdgpu_userq_mgr_fini(struct amdgpu_userq_mgr *userq_mgr);
#endif
