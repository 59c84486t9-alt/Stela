/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_FP_CONTROLS_ELK_H
#define STELA_INTEL_FP_CONTROLS_ELK_H
#include <stdbool.h>
struct elk_compiler;
struct stela_intel_fp_stats {
    unsigned writes, clear, preserve, floating, conversions, swsb_syncs;
};
void stela_intel_elk_fp_control_stats(const struct elk_compiler *, const void *, unsigned,
                                     const char *, bool, struct stela_intel_fp_stats *);
#endif
