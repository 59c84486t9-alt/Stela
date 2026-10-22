/* SPDX-License-Identifier: MIT */
/* Frozen original arithmetic/assertions, separate original-source object.
 * Scalar test context only, not a fake Linux GGTT/device/MMIO implementation. */
#include "ggtt_probe_donor.h"
#include <linux/types.h>
#include "regs/xe_gtt_defs.h"
#include "ggtt_probe_defs.h"
#include <assert.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
unsigned int stela_gsm_donor_decode(uint16_t gmch_ctl)
{
    u16 ggms;
#include "donor-gsm-decode.inc"
}
#pragma clang diagnostic pop
void stela_gsm_donor_range(unsigned int gsm_size, uint64_t wopcm, uint64_t *out_start, uint64_t *out_size)
{
    u64 ggtt_start, ggtt_size;
#include "donor-pf-range.inc"
#include "donor-range-clamp.inc"
    *out_start = ggtt_start; *out_size = ggtt_size;
}
uint64_t stela_gsm_donor_index(uint64_t start, uint64_t size, uint64_t addr)
{
#include "donor-pte-index.inc"
}
