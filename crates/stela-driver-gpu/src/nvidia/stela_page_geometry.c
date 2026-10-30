/* SPDX-License-Identifier: MIT */
#include "stela_page_geometry.h"

/* Actual original os-interface.h data types. No guessed platform defaults;
 * native owner publication is a prerequisite for every original RM accessor.
 */
NvU64 os_page_size;
NvU64 os_max_page_size;
NvU64 os_page_mask;
NvU8 os_page_shift;

NV_STATUS stela_nvidia_set_page_geometry(NvU64 base, NvU64 max, NvU64 mask, NvU8 shift)
{
    if (shift < 12 || shift >= 63 || base != (1ULL << shift) ||
        max < base || max > (1ULL << 62) || (max & (max - 1)) ||
        mask != ~(base - 1))
        return NV_ERR_INVALID_ARGUMENT;
    /* nv_alloc_pages currently accepts only the configured base granule. */
    if (max != base)
        return NV_ERR_NOT_SUPPORTED;
    if (os_page_size || os_max_page_size || os_page_mask || os_page_shift)
        return os_page_size == base && os_max_page_size == max &&
               os_page_mask == mask && os_page_shift == shift ? NV_OK : NV_ERR_INVALID_STATE;
    os_max_page_size = max;
    os_page_mask = mask;
    os_page_shift = shift;
    os_page_size = base;
    return NV_OK;
}
