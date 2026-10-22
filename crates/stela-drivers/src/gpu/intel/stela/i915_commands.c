/* SPDX-License-Identifier: MIT */
#include "i915_commands.h"
#include "unsupported.h"
#include <linux/container_of.h>

#include "gt/gen2_engine_cs.c"
#include "gt/gen6_engine_cs.c"
#include "gt/gen8_engine_cs.c"

/* One packet request: the ring is the borrowed command storage. */
struct stela_request {
    struct i915_request rq;
    struct intel_ring ring;
    struct intel_engine_cs engine;
    struct stela_intel_commands *commands;
    unsigned int reserved;
    bool no_preempt;
};

static struct stela_request *request(const struct i915_request *rq)
{
    return container_of(rq, struct stela_request, rq);
}

static u32 *intel_ring_begin(struct i915_request *rq, unsigned int num_dwords)
{
    struct stela_request *request_ = request(rq);
    struct stela_intel_commands *commands = request_->commands;

    if (num_dwords > commands->capacity - commands->used)
        return ERR_PTR(-ENOSPC);
    request_->reserved = num_dwords;
    return commands->words + commands->used;
}

static void intel_ring_advance(struct i915_request *rq, u32 *cs)
{
    struct stela_request *request_ = request(rq);
    struct stela_intel_commands *commands = request_->commands;

    /* An emitter that wrote other than what it reserved is a broken source. */
    if (cs != commands->words + commands->used + request_->reserved)
        __builtin_trap();
    commands->used += request_->reserved;
}

static bool i915_request_has_nopreempt(const struct i915_request *rq)
{
    return request(rq)->no_preempt;
}

/* The batch-start emitters use only the ring and request services above. */
STELA_UNSUPPORTED(unsigned int, stela_i915_graphics_ver, const struct drm_i915_private *)
STELA_UNSUPPORTED(unsigned int, stela_i915_graphics_ver_full, const struct drm_i915_private *)
STELA_UNSUPPORTED(bool, stela_i915_is_dg2, const struct drm_i915_private *)
STELA_UNSUPPORTED(bool, stela_i915_is_g4x, const struct drm_i915_private *)
STELA_UNSUPPORTED(bool, stela_i915_is_kabylake, const struct drm_i915_private *)
STELA_UNSUPPORTED(bool, stela_i915_has_flat_ccs, const struct drm_i915_private *)
STELA_UNSUPPORTED(bool, stela_i915_has_3d_pipeline, const struct drm_i915_private *)
STELA_UNSUPPORTED(bool, stela_i915_is_graphics_step, const struct drm_i915_private *, int, int)
STELA_UNSUPPORTED(bool, stela_i915_gt_ip_range, const struct intel_gt *, unsigned int, unsigned int)
STELA_UNSUPPORTED(bool, intel_uc_uses_guc_submission, struct intel_uc *)
STELA_UNSUPPORTED(u32, intel_gt_scratch_offset, const struct intel_gt *, enum intel_gt_scratch_field)
STELA_UNSUPPORTED(bool, intel_engine_has_semaphores, const struct intel_engine_cs *)
STELA_UNSUPPORTED(bool, intel_engine_uses_wa_hold_switchout, struct intel_engine_cs *)
STELA_UNSUPPORTED(u32, intel_uncore_read_fw, struct intel_uncore *, i915_reg_t)
STELA_UNSUPPORTED(void, intel_uncore_write, struct intel_uncore *, i915_reg_t, u32)
STELA_UNSUPPORTED(u32, intel_ring_offset, const struct i915_request *, void *)
STELA_UNSUPPORTED(void, assert_ring_tail_valid, const struct intel_ring *, unsigned int)
STELA_UNSUPPORTED(u32, i915_request_active_seqno, const struct i915_request *)
STELA_UNSUPPORTED(struct intel_timeline *, i915_request_timeline, const struct i915_request *)
STELA_UNSUPPORTED(u32, lrc_indirect_bb, const struct intel_context *)
STELA_UNSUPPORTED(u32, i915_ggtt_offset, const struct i915_vma *)
STELA_UNSUPPORTED_EXTERN(void, gen5_gt_enable_irq, struct intel_gt *, u32)
STELA_UNSUPPORTED_EXTERN(void, gen5_gt_disable_irq, struct intel_gt *, u32)
STELA_UNSUPPORTED_EXTERN(void, gen6_gt_pm_unmask_irq, struct intel_gt *, u32)
STELA_UNSUPPORTED_EXTERN(void, gen6_gt_pm_mask_irq, struct intel_gt *, u32)

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
    struct stela_request request_ = {.commands = commands, .no_preempt = no_preempt};
    request_.rq.engine = &request_.engine;
    request_.rq.ring = &request_.ring;
    return emit(&request_.rq, address, 0, secure ? I915_DISPATCH_SECURE : 0);
}
