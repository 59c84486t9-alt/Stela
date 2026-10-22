/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_XCP_H
#define STELA_AMDGPU_XCP_H
struct amdgpu_device;
struct pci_device_id;
/* Services the sources call, which each adapter defines. */
static int amdgpu_xcp_dev_register(struct amdgpu_device *adev,
				   const struct pci_device_id *ent);
static void amdgpu_xcp_dev_unplug(struct amdgpu_device *adev);
#endif
