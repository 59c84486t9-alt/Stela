/* SPDX-License-Identifier: MIT */
/* Original global-data ABI plus unchanged original accessor bodies, linked in
 * a fresh hosted process. No actual RAM/cache/physical support is attested. */
#include "../stela_page_geometry.h"
#include "page_geometry_accessors.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef NDEBUG
#error "page geometry tests require assertions"
#endif
static void unchanged(NvU64 base, NvU64 max, NvU64 mask, NvU8 shift)
{
    assert(os_page_size == base && os_max_page_size == max &&
           os_page_mask == mask && os_page_shift == shift);
}
int main(int argc, char **argv)
{
    assert(argc == 3);
    unsigned base_shift = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned max_shift = (unsigned)strtoul(argv[2], NULL, 10);
    assert(base_shift >= 12 && base_shift <= max_shift && max_shift <= 62);
    NvU64 base = 1ULL << base_shift, max = 1ULL << max_shift, mask = ~(base - 1);
    unchanged(0, 0, 0, 0);
    const struct { NvU64 base, max, mask; NvU8 shift; } bad[] = {
        {0, 0, 0, 0}, {4096, 4096, ~4095ULL, 11},
        {4096, 4096, ~4095ULL, 63}, {4096, 4096, ~4095ULL, 255},
        {8192, 8192, ~8191ULL, 12}, {4096, 0, ~4095ULL, 12},
        {8192, 4096, ~8191ULL, 13}, {4096, 6144, ~4095ULL, 12},
        {4096, 1ULL << 63, ~4095ULL, 12}, {4096, ~0ULL, ~4095ULL, 12},
        {4096, 4096, 0, 12},
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(stela_nvidia_set_page_geometry(bad[i].base, bad[i].max, bad[i].mask, bad[i].shift)
               == NV_ERR_INVALID_ARGUMENT);
        unchanged(0, 0, 0, 0);
    }
    if (base_shift != max_shift) {
        assert(stela_nvidia_set_page_geometry(base, max, mask, (NvU8)base_shift)
               == NV_ERR_NOT_SUPPORTED);
        unchanged(0, 0, 0, 0);
        printf("original RM broad page profile refused before publication: base%u max%u; CPU-only\n",
               base_shift, max_shift);
        return 0;
    }
    assert(stela_nvidia_set_page_geometry(base, max, mask, (NvU8)base_shift) == NV_OK);
    unchanged(base, max, mask, (NvU8)base_shift);
    assert(osGetPageSize() == base && osGetPageShift() == base_shift);
    NvU64 supported = osGetSupportedSysmemPageSizeMask();
    for (unsigned i = 0; i < 64; i++)
        assert(!!(supported & (1ULL << i)) == (i >= base_shift && i <= max_shift));
    assert(stela_nvidia_set_page_geometry(base, max, mask, (NvU8)base_shift) == NV_OK);
    assert(stela_nvidia_set_page_geometry(4096, 16384, ~4095ULL, 12) == NV_ERR_NOT_SUPPORTED);
    unchanged(base, max, mask, (NvU8)base_shift);
    NvU64 other_base = base_shift == 12 ? 16384 : 4096;
    NvU8 other_shift = base_shift == 12 ? 14 : 12;
    assert(stela_nvidia_set_page_geometry(other_base, other_base, ~(other_base - 1), other_shift)
           == NV_ERR_INVALID_STATE);
    unchanged(base, max, mask, (NvU8)base_shift);
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(stela_nvidia_set_page_geometry(bad[i].base, bad[i].max, bad[i].mask, bad[i].shift)
               == NV_ERR_INVALID_ARGUMENT);
        unchanged(base, max, mask, (NvU8)base_shift);
    }
    printf("original RM page globals/accessors: base%u max%u, exact mask and atomic refusals; CPU-only\n",
           base_shift, max_shift);
    return 0;
}
