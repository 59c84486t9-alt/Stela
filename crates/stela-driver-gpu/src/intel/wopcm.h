/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_WOPCM_H
#define STELA_INTEL_WOPCM_H
#include "activation.h"

/* Evidence from one serialized attempt, never firmware READY/auth/upload.
 * Layout fields are only usable on success. Raw register fields are the latest
 * actual reads. writes is marked BEFORE each owner write; no post-write heap
 * reservation or cleanup callback is permitted. Diagnostics bits0..9 are the
 * original events; bits16..24 are the original true warning conditions. */
struct stela_intel_wopcm_result {
    uint32_t total_bytes, guc_base, guc_bytes;
    uint32_t diagnostics, writes, raw_offset, raw_size, firmware_diagnostics;
};
_Static_assert(sizeof(struct stela_intel_wopcm_result) == 32, "WOPCM result ABI");
_Static_assert(offsetof(struct stela_intel_wopcm_result, writes) == 16, "exposure ABI");
/* Private bounded adapter: activation.c supplies its SAME actual owned context
 * and actual immutable facts after acknowledging the root GT awake. No new
 * provider, mapping, allocation or firmware status exists here. All callbacks
 * are mandatory and non-unwinding. The original initializer still gets real
 * HuC inputs in its Linux caller; this native path refuses selected HuC,
 * admitting only original unsupported-role or missing-default-path cases. */
int stela_intel_wopcm_prepare(const struct stela_intel_activation_io *, void *,
    uint32_t platform, uint32_t graphics_verx100, bool discrete,
    const uint8_t *guc_bytes, size_t guc_size, struct stela_intel_wopcm_result *);
/* Actual owned-state entry. Failed exposed writes poison the native epoch;
 * caller MUST retain/quarantine owner/view/forcewake rather than retire it. */
int stela_intel_activation_wopcm(struct stela_intel_activation *,
    const uint8_t *, size_t, struct stela_intel_wopcm_result *);
#endif
