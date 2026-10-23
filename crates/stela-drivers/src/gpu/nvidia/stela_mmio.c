/* SPDX-License-Identifier: MIT */
#include "os-interface.h"
#include "stela_mmio.h"

/* Original vendor declarations stay unchanged. Only the native Stela build
 * selects these hooks; Linux's reference implementation remains separate. */
void *NV_API_CALL os_map_kernel_space(NvU64 physical, NvU64 bytes, NvU32 mode)
{
    return stela_nvidia_map_mmio(physical, bytes, mode);
}

void NV_API_CALL os_unmap_kernel_space(void *address, NvU64 bytes)
{
    stela_nvidia_unmap_mmio(address, bytes);
}
