/* SPDX-License-Identifier: MIT */
#ifndef INTEL_DEVICE_INFO_PRIVATE_H
#define INTEL_DEVICE_INFO_PRIVATE_H

#include "intel_device_info.h"

/* Shared by static compiler targets and the separate device-query layer. */
bool intel_device_info_init_common(int pci_id, bool building,
                                  struct intel_device_info *devinfo);
void intel_device_info_apply_workarounds(struct intel_device_info *devinfo);

#endif
