/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_I915_COMMANDS_H
#define STELA_INTEL_I915_COMMANDS_H

#include "commands.h"

/* Encoding selection, not an initialized-device or supported-feature table.
 * The engine owner selects this from the real i915 platform/engine policy,
 * including Haswell's distinct security/address-space selector and Gen8's
 * no-preemption workaround. Do not infer the mode from a PCI vendor ID.
 */
enum stela_intel_i915_batch {
    STELA_INTEL_I915_BATCH_GEN4 = 4, /* Gen4/5: GGTT and i965 security bit */
    STELA_INTEL_I915_BATCH_GEN6 = 6, /* Gen6/7: i965 bit also selects PPGTT */
    STELA_INTEL_I915_BATCH_HASWELL = 75,
    STELA_INTEL_I915_BATCH_GEN8 = 8, /* retained Gen8+ i915 packet path */
};

/* Bounded packet writes using retained i915 emitters. No ring, GPU mappings,
 * context state, flushes, workarounds or completion are synthesized. The secure
 * selector is only for a trusted native owner; untrusted jobs must never gain
 * privileged execution through it. Gen4–7 use a 32-bit address; Gen8–11 use 48
 * bits. Addresses are 8-byte aligned. no_preempt is valid only for Gen8 form;
 * its owner must eventually restore arbitration using real request teardown.
 * Errors match commands.h; failure leaves storage and cursor unchanged.
 * Gen2/i830/i845 workaround paths are explicitly not implemented here.
 */
int stela_intel_i915_batch_start(struct stela_intel_commands *, uint32_t encoding,
                                uint64_t address, bool secure, bool no_preempt);

#endif
