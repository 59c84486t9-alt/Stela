/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_GGTT_PROBE_H
#define STELA_INTEL_GGTT_PROBE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Scalar geometry only, never an allocation/ONLINE/PAT/firmware capability.
 * Native physical entry binds these to an actual same-device owned GSM lease. */
struct stela_intel_gsm_geometry {
    uint64_t gsm_offset, gsm_bytes, ggtt_start, ggtt_bytes;
};
_Static_assert(sizeof(struct stela_intel_gsm_geometry) == 32, "GSM geometry ABI");
_Static_assert(offsetof(struct stela_intel_gsm_geometry, ggtt_start) == 16, "GGTT start ABI");
/* 0: actual SAME-function PCI read16 at output offset is required.
 * 1: original fixed-size policy, no PCI read required. Negative: invalid.
 * Every error/no-config result preserves output. No PCI access occurs here. */
int stela_intel_gsm_config(uint32_t graphics_verx100, uint16_t *offset);
/* Immutable actual Device facts and complete BAR extent supplied by the owned
 * native caller. config_present attests only to its real canonical PCI read;
 * this metadata function alone establishes no hardware/service ownership.
 * All errors preserve output. No pointer formation or MMIO occurs here. */
int stela_intel_gsm_geometry(uint32_t platform, uint32_t graphics_verx100, bool discrete,
    uint64_t actual_bar_bytes, bool config_present, uint16_t gmch_control,
    struct stela_intel_gsm_geometry *);
/* Original PTE index/assertion policy with checked CPU span before readq.
 * Native owner must still read through actual ordered64 canonical MMIO.
 * No reads/writes occur here; error leaves byte offset output unchanged. */
int stela_intel_gsm_pte_offset(const struct stela_intel_gsm_geometry *, uint64_t address,
                              size_t *offset);
#endif
