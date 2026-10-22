/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_GGTT_PROBE_DONOR_H
#define STELA_INTEL_GGTT_PROBE_DONOR_H
#include "../ggtt_probe.h"
unsigned int stela_gsm_donor_decode(uint16_t);
void stela_gsm_donor_range(unsigned int, uint64_t, uint64_t *, uint64_t *);
uint64_t stela_gsm_donor_index(uint64_t, uint64_t, uint64_t);
#endif
