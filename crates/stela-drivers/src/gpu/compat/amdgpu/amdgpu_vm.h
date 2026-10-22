/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_VM_H
#define STELA_AMDGPU_VM_H
struct drm_device;
struct drm_file;
/* Stela's VM owner is Rust; the type names a file's address space. */
struct amdgpu_vm {
};
/* Services the sources call, which each adapter defines. */
static long amdgpu_vm_wait_idle(struct amdgpu_vm *vm, long timeout);
static int amdgpu_vm_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
#endif
