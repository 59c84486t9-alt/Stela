/* SPDX-License-Identifier: MIT */
/* The unchanged Linux i915 batch-start emitters, writing into the borrowed
 * command storage through a request whose ring is that storage. */
#include "i915_commands.h"
#include <linux/string.h>
#include <stela/linux.h>
#include <unsupported.h>
#include "gt/gen2_engine_cs.c"
#include "gt/gen6_engine_cs.c"
#include "gt/gen8_engine_cs.c"

/* The batch-start emitters use only the request's ring; interrupts and
 * contexts belong to an engine Stela does not run. */
STELA_UNSUPPORTED(void, gen5_gt_disable_irq, struct intel_gt *, u32)
STELA_UNSUPPORTED(void, gen5_gt_enable_irq, struct intel_gt *, u32)
STELA_UNSUPPORTED(void, gen6_gt_pm_mask_irq, struct intel_gt *, u32)
STELA_UNSUPPORTED(void, gen6_gt_pm_unmask_irq, struct intel_gt *, u32)
STELA_UNSUPPORTED(u32, lrc_indirect_bb, const struct intel_context *)

/* Stela's ring is the unused rest of the command storage: a request claims
 * dwords from it in order, as intel_ring.c's does from a ring buffer, and
 * never wraps. */
u32 *intel_ring_begin(struct i915_request *rq, unsigned int num_dwords)
{
    struct intel_ring *ring = rq->ring;
    if (num_dwords > (ring->size - ring->emit) / sizeof(u32)) return ERR_PTR(-ENOSPC);
    u32 *cs = (u32 *)ring->vaddr + ring->emit / sizeof(u32);
    ring->emit += num_dwords * (u32)sizeof(u32);
    return cs;
}

/* The request a packet is emitted for. Only the running Linux owner uses
 * it, so there is one. */
static struct {
    struct i915_request rq;
    struct intel_ring ring;
} request;

int stela_intel_i915_batch_start(struct stela_intel_commands *commands, uint32_t encoding,
                                uint64_t address, bool secure, bool no_preempt)
{
    if (!commands || !commands->words || commands->used > commands->capacity ||
        commands->capacity > SIZE_MAX / sizeof(uint32_t) ||
        (commands->address_bits != 48 && commands->address_bits != 57))
        return -EINVAL;
    int (*emit)(struct i915_request *, u64, u32, unsigned int);
    unsigned int address_bits = 32;
    switch (encoding) {
    case STELA_INTEL_I915_BATCH_GEN4:
        emit = gen4_emit_bb_start;
        break;
    case STELA_INTEL_I915_BATCH_GEN6:
        emit = gen6_emit_bb_start;
        break;
    case STELA_INTEL_I915_BATCH_HASWELL:
        emit = hsw_emit_bb_start;
        break;
    case STELA_INTEL_I915_BATCH_GEN8:
        emit = gen8_emit_bb_start;
        address_bits = 48;
        break;
    default:
        return -EINVAL;
    }
    /* The Gen4-7 emitters store the low 32 address bits; reject the rest. */
    if ((address & 7) || address >= (UINT64_C(1) << address_bits) ||
        (no_preempt && encoding != STELA_INTEL_I915_BATCH_GEN8))
        return -EINVAL;
    size_t free = commands->capacity - commands->used;
    stela_linux_enter(&stela_linux_bare);
    memset(&request, 0, sizeof(request));
    request.ring.vaddr = commands->words + commands->used;
    request.ring.size = (u32)min_t(size_t, free, U32_MAX / sizeof(u32)) * (u32)sizeof(u32);
    request.rq.ring = &request.ring;
    if (no_preempt) __set_bit(I915_FENCE_FLAG_NOPREEMPT, &request.rq.fence.flags);
    int status = emit(&request.rq, address, 0, secure ? I915_DISPATCH_SECURE : 0);
    if (!status) commands->used += request.ring.emit / sizeof(u32);
    stela_linux_exit();
    return status;
}
