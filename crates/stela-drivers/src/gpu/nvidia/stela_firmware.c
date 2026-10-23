/* SPDX-License-Identifier: MIT */
#include "version.h"
/* Same original package-name policy as kernel-open/nvidia/nv.c at the retained
 * NVIDIA pin. version.h is generated from the existing vendor version.mk. */
#define NV_FIRMWARE_FOR_NAME(name) "nvidia/" NVIDIA_VERSION "/" name ".bin"
#include "stela_firmware.h"
/* Original optional log tables use intentional zero-filled partial initializers. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#include "nv-firmware-chip-family-select.h"
#pragma GCC diagnostic pop
#include "libelf.h"

_Static_assert(sizeof(nv_firmware_type_t) == sizeof(NvU32) &&
               sizeof(nv_firmware_chip_family_t) == sizeof(NvU32),
               "native firmware enum ABI");

NvU32 stela_nvidia_firmware_family(NvU32 architecture, NvU32 implementation)
{
    return nv_firmware_get_chip_family(architecture, implementation);
}

NvU64 stela_nvidia_firmware_alignment(void)
{
    return _Alignof(LibosElf64Header) > _Alignof(LibosElf64SectionHeader) ?
           _Alignof(LibosElf64Header) : _Alignof(LibosElf64SectionHeader);
}

const char *stela_nvidia_firmware_version(void)
{
    return NVIDIA_VERSION;
}

const void *NV_API_CALL nv_get_firmware(nv_state_t *nv,
                                       nv_firmware_type_t type,
                                       nv_firmware_chip_family_t family,
                                       const void **buffer, NvU32 *bytes)
{
    if (nv == NULL || nv->os_state == NULL || buffer == NULL || bytes == NULL)
        return NULL;
    const char *name = nv_firmware_for_chip_family(type, family);
    const char *hardware = nv_firmware_chip_family_to_string(family);
    if (name[0] == '\0' || hardware[0] == '\0')
        return NULL;
    return stela_nvidia_get_firmware(nv->os_state, nv, family, name, hardware,
                                     NVIDIA_VERSION, buffer, bytes);
}

void NV_API_CALL nv_put_firmware(const void *token)
{
    if (token != NULL)
        stela_nvidia_put_firmware(token);
}
