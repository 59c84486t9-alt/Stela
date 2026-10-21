/* SPDX-License-Identifier: MIT */
/* Field policy from Iris iris_upload_gpgpu_walker(); encodings remain generated
 * by Mesa's unchanged XML packing algorithms, never transcribed by hand.
 */
#include "dispatch.h"

#include "dispatch_internal.h"

int stela_intel_gpgpu_dispatch(struct stela_intel_commands *commands,
                              const struct stela_intel_gpgpu_dispatch *dispatch)
{
    if (!commands || !dispatch || !commands->words || commands->used > commands->capacity ||
        commands->capacity > SIZE_MAX / sizeof(uint32_t) ||
        (commands->address_bits != 48 && commands->address_bits != 57))
        return -22;
    const struct stela_intel_gpgpu_encoder *encoder;
    switch (dispatch->gfx_verx10) {
    case 70: encoder = &stela_intel_gpgpu_encoder_70; break;
    case 75: encoder = &stela_intel_gpgpu_encoder_75; break;
    case 80: encoder = &stela_intel_gpgpu_encoder_80; break;
    case 90: encoder = &stela_intel_gpgpu_encoder_90; break;
    case 110: encoder = &stela_intel_gpgpu_encoder_110; break;
    case 120: encoder = &stela_intel_gpgpu_encoder_120; break;
    default: return -95;
    }
    if ((dispatch->simd_size != 8 && dispatch->simd_size != 16 && dispatch->simd_size != 32) ||
        dispatch->threads == 0 || dispatch->threads > 64 ||
        dispatch->group_size <= (dispatch->threads - 1) * dispatch->simd_size ||
        dispatch->group_size > dispatch->threads * dispatch->simd_size ||
        !dispatch->groups[0] || !dispatch->groups[1] || !dispatch->groups[2])
        return -22;
    uint32_t final_lanes = dispatch->group_size - (dispatch->threads - 1) * dispatch->simd_size;
    if (dispatch->right_mask != (UINT32_MAX >> (32 - final_lanes)))
        return -22;
    if (encoder->words > commands->capacity - commands->used)
        return -28;
    uint32_t *words = commands->words + commands->used;
    encoder->pack(words, dispatch);
    commands->used += encoder->words;
    return 0;
}
