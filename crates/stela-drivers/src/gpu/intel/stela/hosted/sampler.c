/* SPDX-License-Identifier: MIT */
#include "sampler_internal.h"
#include "intel/dev/intel_device_info.h"
#include <math.h>

static bool wrap_supported(unsigned mode)
{
    return mode == PIPE_TEX_WRAP_REPEAT || mode == PIPE_TEX_WRAP_CLAMP_TO_EDGE ||
           mode == PIPE_TEX_WRAP_MIRROR_REPEAT || mode == PIPE_TEX_WRAP_MIRROR_CLAMP_TO_EDGE;
}

int stela_intel_sampler_state(const struct isl_device *dev,
                              const struct stela_intel_image_desc *image_input,
                              const struct pipe_sampler_state *sampler_input,
                              void *output, size_t capacity)
{
    if (!image_input || !sampler_input || !output ||
        (uintptr_t)output % _Alignof(uint32_t)) return -22;
    /* Snapshot borrowed descriptions before writing potentially aliasing output. */
    const struct stela_intel_image_desc image = *image_input;
    const struct pipe_sampler_state sampler = *sampler_input;
    struct isl_surf layout;
    int err = stela_intel_image_layout(dev, &image, &layout);
    if (err) return err;
    if (dev->info->ver < 8 || !(image.usage & ISL_SURF_USAGE_TEXTURE_BIT)) return -95;
    if (!isfinite(sampler.min_lod) || !isfinite(sampler.max_lod) ||
        !isfinite(sampler.lod_bias) || sampler.min_lod > sampler.max_lod || sampler.pad ||
        sampler.min_mip_filter > PIPE_TEX_MIPFILTER_NONE)
        return -22;
    if (!wrap_supported(sampler.wrap_s) || !wrap_supported(sampler.wrap_t) ||
        !wrap_supported(sampler.wrap_r) || sampler.unnormalized_coords ||
        sampler.max_anisotropy > 1 || sampler.compare_mode != PIPE_TEX_COMPARE_NONE ||
        sampler.seamless_cube_map || sampler.reduction_mode != PIPE_TEX_REDUCTION_WEIGHTED_AVERAGE)
        return -95;
    if ((sampler.min_img_filter == PIPE_TEX_FILTER_LINEAR ||
         sampler.mag_img_filter == PIPE_TEX_FILTER_LINEAR ||
         sampler.min_mip_filter == PIPE_TEX_MIPFILTER_LINEAR) &&
        !isl_format_supports_filtering(dev->info, image.format))
        return -95;
    void (*pack)(const struct pipe_sampler_state *, uint32_t *);
    switch (dev->info->verx10) {
    case 80: pack = stela_intel_sampler_pack_80; break;
    case 90: pack = stela_intel_sampler_pack_90; break;
    case 110: pack = stela_intel_sampler_pack_110; break;
    case 120: pack = stela_intel_sampler_pack_120; break;
    case 125: pack = stela_intel_sampler_pack_125; break;
    case 200: pack = stela_intel_sampler_pack_200; break;
    case 300: pack = stela_intel_sampler_pack_300; break;
    case 350: pack = stela_intel_sampler_pack_350; break;
    default: return -95;
    }
    if (capacity < STELA_INTEL_SAMPLER_STATE_DWORDS * sizeof(uint32_t)) return -28;
    pack(&sampler, output);
    return STELA_INTEL_SAMPLER_STATE_DWORDS * sizeof(uint32_t);
}
