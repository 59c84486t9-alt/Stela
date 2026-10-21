/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_COMMANDS_H
#define STELA_INTEL_COMMANDS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A borrowed CPU mapping of command-buffer storage, not a guest pointer.
 * The owner provides the actual GPU VA width (48 or 57), validates mappings
 * and serializes access. Only the low address_bits of GPU addresses may be
 * set; canonical-address conversion belongs to that VA owner.
 *
 * The MI forms here are those used by Xe (Gen12+). This is not an entire job,
 * render/compute state setup, Metal barrier, submission or completion. Cache
 * policy/workarounds, ring padding, DMA visibility, queue tail publication and
 * interrupts stay with the real device/engine owner. Older i915 support remains
 * separate work; these primitives do not advertise a supported Metal device.
 */
struct stela_intel_commands {
    uint32_t *words;
    size_t capacity;
    size_t used;
    uint32_t address_bits;
};
_Static_assert(offsetof(struct stela_intel_commands, capacity) == sizeof(size_t), "Rust/C capacity ABI");
_Static_assert(offsetof(struct stela_intel_commands, used) == 2 * sizeof(size_t), "Rust/C used ABI");
_Static_assert(offsetof(struct stela_intel_commands, address_bits) == 3 * sizeof(size_t), "Rust/C address ABI");

/* Errors: -22 invalid arguments; -28 insufficient space. An error leaves the
 * command storage and used count unchanged. No memory is allocated or retained.
 */
int stela_intel_batch_start(struct stela_intel_commands *, uint64_t address, bool ppgtt);
/* MI_STORE_DATA_IMM additionally restricts address to the low 48 bits. */
int stela_intel_store_qword(struct stela_intel_commands *, uint64_t address, uint64_t value);
int stela_intel_batch_end(struct stela_intel_commands *);
int stela_intel_user_interrupt(struct stela_intel_commands *);

#endif
