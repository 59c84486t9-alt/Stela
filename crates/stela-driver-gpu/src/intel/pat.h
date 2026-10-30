/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_PAT_H
#define STELA_INTEL_PAT_H
#include "activation.h"
struct stela_intel_pat_result {
 uint32_t writes, n_entries;
 uint16_t cache_none, cache_wt, cache_wb, cache_none_compression, cache_wb_compression, reserved;
 uint32_t entries[4];
};
_Static_assert(sizeof(struct stela_intel_pat_result) == 36, "PAT result ABI");
_Static_assert(offsetof(struct stela_intel_pat_result, entries) == 20, "PAT entries ABI");
/* Private same-Device adapter: genuine descriptor/GT facts, exclusive root GT
 * wake, original WA/MMIO/cache/power/reset prerequisites and same canonical
 * UC view are mandatory. No default callbacks, allocator or guest pointers.
 * Unsupported methods refuse before I/O; error preserves output. Success only
 * records original ordered writes issued, not readback/ACK/READY/cache drain.
 * Unexpected access faults fail-stop under the actual retained owner contract.
 */
/* Opaque actual Device-state entry, not caller-constructed policy/facts. */
int stela_intel_activation_pat(struct stela_intel_activation *, struct stela_intel_pat_result *);
int stela_intel_pat_program(const struct stela_intel_activation_io *, void *,
 const struct stela_intel_activation_facts *, struct stela_intel_pat_result *);
#endif
