/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_GEM_H
#define STELA_DRM_GEM_H
struct file;
struct vm_area_struct;
/* Stela has no GEM objects; a source that names a GEM file operation
 * declares it. */
struct drm_gem_object;
static int drm_gem_mmap(struct file *filp, struct vm_area_struct *vma);
#endif
