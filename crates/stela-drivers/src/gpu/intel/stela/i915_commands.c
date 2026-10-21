/* SPDX-License-Identifier: MIT */
#include "i915_commands.h"
#include "../i915/gt/intel_batch_emit.h"

int stela_intel_i915_batch_start(struct stela_intel_commands *commands, uint32_t encoding,
                                uint64_t address, bool secure, bool no_preempt)
{
    if (!commands || !commands->words || commands->used > commands->capacity ||
        commands->capacity > SIZE_MAX / sizeof(uint32_t) ||
        (commands->address_bits != 48 && commands->address_bits != 57))
        return -22;
    size_t count;
    u32 selector;
    switch (encoding) {
    case STELA_INTEL_I915_BATCH_GEN4:
        selector = MI_BATCH_GTT | (secure ? 0 : MI_BATCH_NON_SECURE_I965);
        count = 2;
        break;
    case STELA_INTEL_I915_BATCH_GEN6:
        selector = secure ? 0 : MI_BATCH_NON_SECURE_I965;
        count = 2;
        break;
    case STELA_INTEL_I915_BATCH_HASWELL:
        selector = secure ? 0 : MI_BATCH_PPGTT_HSW | MI_BATCH_NON_SECURE_HSW;
        count = 2;
        break;
    case STELA_INTEL_I915_BATCH_GEN8:
        selector = secure ? 0 : BIT(8);
        count = no_preempt ? 4 : 6;
        break;
    default:
        return -22;
    }
    if ((address & 7) || address >= (UINT64_C(1) << (count == 2 ? 32 : 48)) ||
        (no_preempt && encoding != STELA_INTEL_I915_BATCH_GEN8))
        return -22;
    if (count > commands->capacity - commands->used)
        return -28;
    u32 *cs = commands->words + commands->used;
    if (encoding == STELA_INTEL_I915_BATCH_GEN8) {
        if (no_preempt)
            (void)__gen8_emit_bb_start_noarb(cs, address, selector);
        else
            (void)__gen8_emit_bb_start_with_arb(cs, address, selector);
    } else {
        /* Same real two-DW emitter called by gen6/Haswell i915 paths. Gen4's
         * ring submission writes these same words with its own selector.
         */
        (void)__gen6_emit_bb_start(cs, (u32)address, selector);
    }
    commands->used += count;
    return 0;
}
