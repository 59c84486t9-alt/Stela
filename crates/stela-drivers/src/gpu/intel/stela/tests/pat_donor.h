/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_PAT_DONOR_H
#define STELA_INTEL_PAT_DONOR_H
#include "xe_pat.h"
#include "xe_cache_level.h"
#include "xe_platform_types.h"
struct stela_pat_test_policy {
 uint32_t profile, count, warning, missing, special;
 uint16_t indices[__XE_CACHE_LEVEL_COUNT];
 struct xe_pat_table_entry entries[32], ats, primary, media;
};
struct stela_pat_trace { uint32_t count, offset[34], value[34]; };
void stela_pat_donor_policy(enum xe_platform, uint32_t graphics, bool discrete,
                           bool llc, struct stela_pat_test_policy *);
void stela_pat_donor_program(const struct stela_pat_test_policy *, struct stela_pat_trace *);
#endif
