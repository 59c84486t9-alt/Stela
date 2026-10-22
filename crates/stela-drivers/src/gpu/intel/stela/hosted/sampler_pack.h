/* SPDX-License-Identifier: MIT */
#include "sampler_internal.h"
#define __gen_address_type uint64_t
#define __gen_user_data void
static inline uint64_t combine_address(void *data, void *location,
                                       uint64_t address, uint32_t delta)
{
    (void)data; (void)location;
    return address + delta;
}
#define __gen_combine_address combine_address
#include "intel/genxml/gen_macros.h"
#include "intel/genxml/genX_pack.h"

_Static_assert(GENX(SAMPLER_STATE_length) == STELA_INTEL_SAMPLER_STATE_DWORDS,
               "Actual sampler state must match the owned output ABI");

static uint32_t wrap_mode(unsigned wrap)
{
    switch (wrap) {
    case PIPE_TEX_WRAP_REPEAT: return TCM_WRAP;
    case PIPE_TEX_WRAP_CLAMP_TO_EDGE: return TCM_CLAMP;
    case PIPE_TEX_WRAP_MIRROR_REPEAT: return TCM_MIRROR;
    default: return TCM_MIRROR_ONCE;
    }
}

static uint32_t map_filter(unsigned filter)
{
    return filter == PIPE_TEX_FILTER_LINEAR ? MAPFILTER_LINEAR : MAPFILTER_NEAREST;
}

/* SAMPLER_STATE for what sampler.c admits, with Iris's field policy: OpenGL
 * LOD pre-clamping, clamps to the hardware's LOD range and address rounding
 * for linear filters. Without mipmaps a positive minimum LOD selects the
 * minification filter at every level, so LOD 0 magnifies with it. */
void STELA_SAMPLER_PACK(const struct pipe_sampler_state *sampler, uint32_t *output)
{
    const bool no_mips = sampler->min_mip_filter == PIPE_TEX_MIPFILTER_NONE && sampler->min_lod > 0.0f;
    const bool min_linear = sampler->min_img_filter != PIPE_TEX_FILTER_NEAREST;
    const bool mag_linear = sampler->mag_img_filter != PIPE_TEX_FILTER_NEAREST;
    const struct GENX(SAMPLER_STATE) state = {
        .TCXAddressControlMode = wrap_mode(sampler->wrap_s),
        .TCYAddressControlMode = wrap_mode(sampler->wrap_t),
        .TCZAddressControlMode = wrap_mode(sampler->wrap_r),
        .MinModeFilter = map_filter(sampler->min_img_filter),
        .MagModeFilter = map_filter(no_mips ? sampler->min_img_filter : sampler->mag_img_filter),
        .MipModeFilter = sampler->min_mip_filter == PIPE_TEX_MIPFILTER_LINEAR ? MIPFILTER_LINEAR :
                         sampler->min_mip_filter == PIPE_TEX_MIPFILTER_NEAREST ? MIPFILTER_NEAREST :
                         MIPFILTER_NONE,
        .MaximumAnisotropy = RATIO21,
        .UAddressMinFilterRoundingEnable = min_linear,
        .VAddressMinFilterRoundingEnable = min_linear,
        .RAddressMinFilterRoundingEnable = min_linear,
        .UAddressMagFilterRoundingEnable = mag_linear,
        .VAddressMagFilterRoundingEnable = mag_linear,
        .RAddressMagFilterRoundingEnable = mag_linear,
        .LODPreClampMode = CLAMP_MODE_OGL,
        .MinLOD = CLAMP(no_mips ? 0.0f : sampler->min_lod, 0, 14),
        .MaxLOD = CLAMP(sampler->max_lod, 0, 14),
        .TextureLODBias = CLAMP(sampler->lod_bias, -16, 15),
    };
    GENX(SAMPLER_STATE_pack)(NULL, output, &state);
}
