/* SPDX-License-Identifier: MIT */
/* GSM geometry against the GMCH field layout and GGTT bounds; CPU only. */
#include "../ggtt_probe.h"
#include <linux/types.h>
#include "regs/xe_gtt_defs.h"
#include "xe_device_types.h"
#include "xe_wopcm.h"
#include <stela/linux.h>
#include <stela/test.h>
#include <linux/string.h>
int main(void)
{
    const struct stela_intel_gsm_geometry sentinel = {1, 2, 3, 4};
    struct stela_intel_gsm_geometry out = sentinel;
    uint16_t config = UINT16_MAX;
    assert(stela_intel_gsm_config(1200, &config) == 0 && config == 0x50);
    config = UINT16_MAX;
    assert(stela_intel_gsm_config(1250, &config) == 1 && config == UINT16_MAX);
    assert(stela_intel_gsm_config(0, &config) == -22 && config == UINT16_MAX);
    assert(stela_intel_gsm_config(1200, NULL) == -22);
    unsigned comparisons = 0;
    for (unsigned word = 0; word <= UINT16_MAX; ++word) {
        /* GGMS, bits 7:6, selects a 2^GGMS MiB GSM; zero has none. */
        unsigned ggms = word >> 6 & 3, gsm = ggms ? (1u << ggms) << 20 : 0;
        for (unsigned p = XE_TIGERLAKE; p <= XE_NOVALAKE_P; ++p) {
            for (unsigned d = 0; d <= 1; ++d) {
                out = sentinel;
                int status = stela_intel_gsm_geometry(p, 1200, d != 0, 16 << 20, true, (u16)word,
                    &out);
                if (!gsm) {
                    assert(status == -12 && !memcmp(&out, &sentinel, sizeof(out)));
                    continue;
                }
                assert(!status && out.gsm_offset == 8 << 20 && out.gsm_bytes == gsm);
                struct xe_device xe = {
                    .info = {.platform = (enum xe_platform)p, .is_dgfx = d != 0}};
                stela_linux_enter(&stela_linux_bare);
                u64 start = xe_wopcm_size(&xe), size = (u64)gsm * 512 - start;
                stela_linux_exit();
                if (start + size > GUC_GGTT_TOP) size = GUC_GGTT_TOP - start;
                assert(out.ggtt_start == start && out.ggtt_bytes == size);
                assert(start ==
                    (p >= XE_LUNARLAKE              ? 8u :
                            d || p == XE_METEORLAKE ? 4u :
                                                      2u) *
                        1024 * 1024);
                assert(start + size == (gsm == 8 << 20 ? 0xfee00000u : (u64)gsm * 512));
                const u64 addresses[] = {0, start - 4096, start, start + size - 4096};
                for (unsigned a = 0; a < sizeof(addresses)/sizeof(*addresses); ++a) {
                    size_t offset = SIZE_MAX;
                    assert(!stela_intel_gsm_pte_offset(&out, addresses[a], &offset));
                    assert(offset == addresses[a] / 4096 * 8 && offset + 8 <= out.gsm_bytes);
                }
                ++comparisons;
            }
        }
    }
    // Fixed-8MiB policy ignores absent/zero configuration; full BAR span still
    // mandatory, and geometry does not get fabricated from a short mapping.
    assert(!stela_intel_gsm_geometry(XE_DG2, 1250, true, 16 << 20, false, 0, &out));
    assert(out.gsm_bytes == 8 << 20 && out.ggtt_start == 4 << 20);
    assert(out.ggtt_bytes + out.ggtt_start == GUC_GGTT_TOP);
    size_t offset = 123;
    assert(stela_intel_gsm_pte_offset(&out, out.ggtt_start + out.ggtt_bytes, &offset) == -22 &&
        offset == 123);
    assert(stela_intel_gsm_pte_offset(&out, 1, &offset) == -22 && offset == 123);
    assert(stela_intel_gsm_pte_offset(&out, UINT64_MAX, &offset) == -22 && offset == 123);
    assert(stela_intel_gsm_pte_offset(NULL, 0, &offset) == -22 && offset == 123);
    struct stela_intel_gsm_geometry bad = out;
    bad.gsm_bytes = 8;
    assert(stela_intel_gsm_pte_offset(&bad, 4096, &offset) == -34 && offset == 123);
    bad = out; bad.ggtt_bytes = UINT64_MAX;
    assert(stela_intel_gsm_pte_offset(&bad, 0, &offset) == -22 && offset == 123);
    bad = out; bad.ggtt_start = UINT64_MAX;
    assert(stela_intel_gsm_pte_offset(&bad, 0, &offset) == -22 && offset == 123);
    for (unsigned which = 0; which < 5; ++which) {
        out = sentinel;
        int status;
        switch(which) {
        case 0:
            status = stela_intel_gsm_geometry(XE_TIGERLAKE, 1200, false, 16 << 20, false, 0, &out);
            assert(status == -95);
            break;
        case 1:
            status = stela_intel_gsm_geometry(XE_DG2, 1250, true, (16 << 20) - 1, false, 0, &out);
            assert(status == -34);
            break;
        case 2:
            status = stela_intel_gsm_geometry(XE_DG2, 1250, true, 0, false, 0, &out);
            assert(status == -34);
            break;
        case 3:
            status = stela_intel_gsm_geometry(0, 1250, true, 16 << 20, false, 0, &out);
            assert(status == -22);
            break;
        default:
            status = stela_intel_gsm_geometry(UINT32_MAX, 1250, true, 16 << 20, false, 0, &out);
            assert(status == -22);
            break;
        }
        assert(!memcmp(&out, &sentinel, sizeof(out)));
    }
    printf("Intel GSM: %u geometry cases, independent field/span/index and output-preserving "
           "refusals; CPU-only\n",
        comparisons);
    return 0;
}
