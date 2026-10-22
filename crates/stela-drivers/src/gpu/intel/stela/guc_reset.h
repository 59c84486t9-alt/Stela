/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_GUC_RESET_H
#define STELA_INTEL_GUC_RESET_H
#include "activation.h"
struct stela_intel_guc_reset_result {
    uint32_t writes, warnings, gdrst, guc_status, ready_status, sram_status;
};
_Static_assert(sizeof(struct stela_intel_guc_reset_result) == 24, "GuC reset result ABI");
_Static_assert(offsetof(struct stela_intel_guc_reset_result, guc_status) == 12, "GuC status ABI");
/* Explicit hardware handshake only; not xe_uc_sanitize_reset, firmware/CT/job
 * state, a reset/recovery epoch or proof of whole-device DMA quiescence.
 * Actual exclusive same-Device no-DMA/no-IRQ/no-CT/no-submission ownership,
 * canonical UC view and acknowledged GT wake are required before entry. */
int stela_intel_activation_guc_reset(struct stela_intel_activation *,
                                    struct stela_intel_guc_reset_result *);
/* Private actual-State adapter. Error before I/O preserves output; an exposed
 * failure returns exact observations/writes for permanent owner quarantine.
 * No fallible operation or allocation follows register effects. */
int stela_intel_guc_reset(const struct stela_intel_activation_io *, void *,
    struct stela_intel_activation *, const struct stela_intel_activation_facts *,
    struct stela_intel_guc_reset_result *);
void stela_intel_activation_assert_gt(struct stela_intel_activation *);
#endif
