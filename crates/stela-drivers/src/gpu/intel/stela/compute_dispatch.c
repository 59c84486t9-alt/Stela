/* SPDX-License-Identifier: MIT */
#include "compute_dispatch_internal.h"

int stela_intel_compute_dispatch(struct stela_intel_commands *commands,
                                 const struct stela_intel_compute_dispatch *input)
{
    if (!commands || !input || !commands->words || commands->used > commands->capacity ||
        commands->capacity > SIZE_MAX / sizeof(uint32_t) ||
        (commands->address_bits != 48 && commands->address_bits != 57))
        return -22;
    /* Snapshot metadata before modifying output, including for aliased inputs. */
    const struct stela_intel_compute_dispatch dispatch = *input;
    const struct stela_intel_compute_encoder *encoder;
    switch (dispatch.gfx_verx10) {
    case 125: encoder = &stela_intel_compute_encoder_125; break;
    case 200: encoder = &stela_intel_compute_encoder_200; break;
    case 300: encoder = &stela_intel_compute_encoder_300; break;
    case 350: encoder = &stela_intel_compute_encoder_350; break;
    default: return -95;
    }
    if (dispatch.push_bytes)
        return -95;
    if ((dispatch.simd_size != 8 && dispatch.simd_size != 16 && dispatch.simd_size != 32) ||
        (dispatch.gfx_verx10 >= 200 && dispatch.simd_size == 8))
        return -22;
    uint64_t group_size = 1;
    for (unsigned i = 0; i < 3; ++i) {
        if (!dispatch.local_size[i] || dispatch.local_size[i] > 1024 || !dispatch.groups[i])
            return -22;
        group_size *= dispatch.local_size[i];
    }
    if (group_size > 1024 || !dispatch.threads ||
        dispatch.threads != (group_size + dispatch.simd_size - 1) / dispatch.simd_size)
        return -22;
    /* Match BRW's bounded hardware-local-ID contract: power-of-two X/Y and
     * the complete X/XY/XYZ prefix through the highest nontrivial dimension.
     * Mask zero retains the actual compiler's software/payload path. */
    if (dispatch.generate_local_id) {
        uint32_t mask = dispatch.local_size[2] > 1 ? 7 :
                        dispatch.local_size[1] > 1 ? 3 :
                        dispatch.local_size[0] > 1 ? 1 : 0;
        if ((dispatch.local_size[0] & (dispatch.local_size[0] - 1)) ||
            (dispatch.local_size[1] & (dispatch.local_size[1] - 1)) ||
            dispatch.generate_local_id != mask)
            return -22;
    }
    uint32_t final_lanes = (uint32_t)group_size - (dispatch.threads - 1) * dispatch.simd_size;
    if (dispatch.right_mask != (UINT32_MAX >> (32 - final_lanes)) ||
        (dispatch.kernel_offset & 63) || (dispatch.sampler_offset & 31) ||
        (dispatch.binding_table_offset & 31) || dispatch.binding_table_offset > 0x1fffe0 ||
        dispatch.binding_table_entry_count > 31 || dispatch.sampler_count > 4 ||
        dispatch.barrier_encoding > 7 || dispatch.thread_group_dispatch_size > 3 ||
        dispatch.walk_order > 5 || dispatch.uses_sampler > 1 ||
        (dispatch.sampler_count && !dispatch.uses_sampler) ||
        !dispatch.post_sync_mocs || dispatch.post_sync_mocs > 127 ||
        (dispatch.generate_local_id != 0 && dispatch.generate_local_id != 1 &&
         dispatch.generate_local_id != 3 && dispatch.generate_local_id != 7))
        return -22;
    if (dispatch.gfx_verx10 == 125) {
        if (dispatch.slm_encoding > 7 ||
            (dispatch.preferred_slm_encoding != 0 && dispatch.preferred_slm_encoding < 8) ||
            dispatch.preferred_slm_encoding > 15)
            return -22;
    } else if (dispatch.slm_encoding > 14 || dispatch.preferred_slm_encoding > 10) {
        return -22;
    }
    if ((dispatch.gfx_verx10 < 300 && dispatch.register_blocks != 0) ||
        dispatch.register_blocks > 7 || dispatch.register_blocks == 6)
        return -22;
    if (encoder->words > commands->capacity - commands->used)
        return -28;
    encoder->pack(commands->words + commands->used, &dispatch);
    commands->used += encoder->words;
    return 0;
}
