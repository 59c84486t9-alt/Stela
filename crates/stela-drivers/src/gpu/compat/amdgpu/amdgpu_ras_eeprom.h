/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_RAS_EEPROM_H
#define STELA_AMDGPU_RAS_EEPROM_H
struct amdgpu_device;
/* A service the sources call, which each adapter defines. */
static void amdgpu_ras_eeprom_check_and_recover(struct amdgpu_device *adev);
#endif
