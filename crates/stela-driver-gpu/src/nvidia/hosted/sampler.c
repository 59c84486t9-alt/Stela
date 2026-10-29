/* SPDX-License-Identifier: MIT */
#include "sampler.h"
#include "nouveau/headers/drf.h"
#include "nouveau/headers/nvidia/classes/cl9097tex.h"
#include "nouveau/headers/nvidia/classes/cla097tex.h"
#include "nouveau/headers/nvidia/classes/clb197.h"
#include "nouveau/headers/nvidia/classes/clb197tex.h"
#include <math.h>

static bool integer_border(VkBorderColor color)
{
    return color == VK_BORDER_COLOR_INT_TRANSPARENT_BLACK || color == VK_BORDER_COLOR_INT_OPAQUE_BLACK ||
           color == VK_BORDER_COLOR_INT_OPAQUE_WHITE || color == VK_BORDER_COLOR_INT_CUSTOM_EXT;
}

static int check_border(const struct stela_nvidia_sampler_state *state)
{
    switch (state->border_color) {
    case VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK:
    case VK_BORDER_COLOR_FLOAT_OPAQUE_BLACK:
    case VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE:
    case VK_BORDER_COLOR_INT_TRANSPARENT_BLACK:
    case VK_BORDER_COLOR_INT_OPAQUE_BLACK:
    case VK_BORDER_COLOR_INT_OPAQUE_WHITE:
        break;
    case VK_BORDER_COLOR_FLOAT_CUSTOM_EXT:
    case VK_BORDER_COLOR_INT_CUSTOM_EXT:
        return -95;
    default:
        return -22;
    }
    /* The payload must hold the standard color's values. */
    const uint32_t rgb = state->border_color == VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE ||
                         state->border_color == VK_BORDER_COLOR_INT_OPAQUE_WHITE;
    const uint32_t alpha = state->border_color != VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK &&
                           state->border_color != VK_BORDER_COLOR_INT_TRANSPARENT_BLACK;
    for (unsigned c = 0; c < 4; c++) {
        const uint32_t expected = c == 3 ? alpha : rgb;
        if (integer_border(state->border_color)) {
            /* The Vulkan runtime stores int32 0/1, whose bit patterns are
             * also unsigned 0/1. */
            if (state->border_color_value.uint32[c] != expected) return -22;
        } else if (state->border_color_value.float32[c] != (float)expected) {
            return -22;
        }
    }
    const VkComponentMapping swizzle = state->border_color_component_mapping;
    if (swizzle.r != VK_COMPONENT_SWIZZLE_IDENTITY || swizzle.g != VK_COMPONENT_SWIZZLE_IDENTITY ||
        swizzle.b != VK_COMPONENT_SWIZZLE_IDENTITY || swizzle.a != VK_COMPONENT_SWIZZLE_IDENTITY)
        return -95;
    return 0;
}

static uint32_t address_mode(VkSamplerAddressMode mode)
{
    switch (mode) {
    case VK_SAMPLER_ADDRESS_MODE_REPEAT: return NV9097_TEXSAMP0_ADDRESS_U_WRAP;
    case VK_SAMPLER_ADDRESS_MODE_MIRRORED_REPEAT: return NV9097_TEXSAMP0_ADDRESS_U_MIRROR;
    case VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE: return NV9097_TEXSAMP0_ADDRESS_U_CLAMP_TO_EDGE;
    case VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER: return NV9097_TEXSAMP0_ADDRESS_U_BORDER;
    default: return NV9097_TEXSAMP0_ADDRESS_U_MIRROR_ONCE_CLAMP_TO_EDGE;
    }
}

/* NVK's anisotropy ratio steps and the trilinear optimization it pairs with
 * each ratio. */
static uint32_t anisotropy(float ratio)
{
    if (ratio >= 16.0f) return NV9097_TEXSAMP0_MAX_ANISOTROPY_ANISO_16_TO_1;
    if (ratio >= 12.0f) return NV9097_TEXSAMP0_MAX_ANISOTROPY_ANISO_12_TO_1;
    return (uint32_t)ratio / 2;
}
static uint32_t trilinear_optimization(float ratio)
{
    return ratio >= 12.0f ? 0 : ratio >= 4.0f ? 6 : ratio >= 2.0f ? 4 : 0;
}

/* LOD values carry 8 fraction bits. */
static uint32_t fixed_lod(float lod)
{
    return (uint32_t)(int32_t)lroundf(lod * 256.0f);
}

/* TEXSAMP for a validated state in the supported subset: the standard border
 * colors' sRGB bytes are 0 or 255, and their payload words are stored as
 * given. */
static struct stela_nvidia_sampler_header pack(const struct nv_device_info *device,
                                           const struct stela_nvidia_sampler_state *state)
{
    const bool linear_min = state->min_filter == VK_FILTER_LINEAR;
    const uint32_t srgb_border = state->border_color == VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE ? 255 : 0;
    struct stela_nvidia_sampler_header header = {.bits = {
        NVVAL(NV9097, TEXSAMP0, ADDRESS_U, address_mode(state->address_mode_u)) |
            NVVAL(NV9097, TEXSAMP0, ADDRESS_V, address_mode(state->address_mode_v)) |
            NVVAL(NV9097, TEXSAMP0, ADDRESS_P, address_mode(state->address_mode_w)) |
            NVVAL(NV9097, TEXSAMP0, S_R_G_B_CONVERSION, 1) |
            NVDEF(NV9097, TEXSAMP0, FONT_FILTER_WIDTH, SIZE_2) |
            NVDEF(NV9097, TEXSAMP0, FONT_FILTER_HEIGHT, SIZE_2) |
            (state->anisotropy_enable ?
                NVVAL(NV9097, TEXSAMP0, MAX_ANISOTROPY, anisotropy(state->max_anisotropy)) : 0),
        (state->mag_filter == VK_FILTER_LINEAR ? NVDEF(NV9097, TEXSAMP1, MAG_FILTER, MAG_LINEAR) :
                                                 NVDEF(NV9097, TEXSAMP1, MAG_FILTER, MAG_POINT)) |
            (!linear_min ? NVDEF(NV9097, TEXSAMP1, MIN_FILTER, MIN_POINT) :
             state->anisotropy_enable ? NVDEF(NV9097, TEXSAMP1, MIN_FILTER, MIN_ANISO) :
                                        NVDEF(NV9097, TEXSAMP1, MIN_FILTER, MIN_LINEAR)) |
            (state->mipmap_mode == VK_SAMPLER_MIPMAP_MODE_LINEAR ?
                NVDEF(NV9097, TEXSAMP1, MIP_FILTER, MIP_LINEAR) : NVDEF(NV9097, TEXSAMP1, MIP_FILTER, MIP_POINT)) |
            NVDEF(NVA097, TEXSAMP1, CUBEMAP_INTERFACE_FILTERING, AUTO_SPAN_SEAM) |
            (device->cls_eng3d >= MAXWELL_B ? NVDEF(NVB197, TEXSAMP1, REDUCTION_FILTER, RED_NONE) : 0) |
            NVVAL(NV9097, TEXSAMP1, MIP_LOD_BIAS, fixed_lod(state->mip_lod_bias)) |
            NVDEF(NVA097, TEXSAMP1, FLOAT_COORD_NORMALIZATION, USE_HEADER_SETTING) |
            NVVAL(NV9097, TEXSAMP1, TRILIN_OPT, trilinear_optimization(state->max_anisotropy)),
        NVVAL(NV9097, TEXSAMP2, MIN_LOD_CLAMP, fixed_lod(state->min_lod)) |
            NVVAL(NV9097, TEXSAMP2, MAX_LOD_CLAMP, fixed_lod(state->max_lod)) |
            NVVAL(NV9097, TEXSAMP2, S_R_G_B_BORDER_COLOR_R, srgb_border),
        NVVAL(NV9097, TEXSAMP3, S_R_G_B_BORDER_COLOR_G, srgb_border) |
            NVVAL(NV9097, TEXSAMP3, S_R_G_B_BORDER_COLOR_B, srgb_border),
    }};
    for (unsigned c = 0; c < 4; c++)
        header.bits[4 + c] = state->border_color_value.uint32[c];
    return header;
}

int stela_nvidia_sampler_encode(const struct stela_nvidia_image *image,
                            const struct stela_nvidia_sampler_state *input, struct stela_nvidia_sampler *out)
{
    if (!image || !image->owner || !input || !out) return -22;
    const struct stela_nvidia_sampler_state state = *input;
    struct stela_nvidia_image rebuilt;
    int err = stela_nvidia_image_init(image->device, image->owner, &image->request, &rebuilt);
    if (err) return err;
    if (image->cls_eng3d != rebuilt.cls_eng3d || image->device_type != rebuilt.device_type)
        return -22;
    if (!(rebuilt.request.usage & STELA_NVIDIA_IMAGE_TEXTURE)) return -95;
    if ((unsigned)state.mag_filter > VK_FILTER_LINEAR ||
        (unsigned)state.min_filter > VK_FILTER_LINEAR ||
        (unsigned)state.mipmap_mode > VK_SAMPLER_MIPMAP_MODE_LINEAR ||
        (unsigned)state.address_mode_u > VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE ||
        (unsigned)state.address_mode_v > VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE ||
        (unsigned)state.address_mode_w > VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE ||
        (unsigned)state.compare_op > VK_COMPARE_OP_ALWAYS ||
        (unsigned)state.reduction_mode > VK_SAMPLER_REDUCTION_MODE_MAX ||
        !isfinite(state.mip_lod_bias) || state.mip_lod_bias < -16.0f || state.mip_lod_bias > 4095.0f / 256.0f ||
        !isfinite(state.min_lod) || state.min_lod < 0.0f ||
        !isfinite(state.max_lod) || state.max_lod > 4095.0f / 256.0f || state.min_lod > state.max_lod ||
        !isfinite(state.max_anisotropy) || state.max_anisotropy < 1.0f || state.max_anisotropy > 16.0f ||
        (!state.anisotropy_enable && state.max_anisotropy != 1.0f) ||
        state.image_view_is_srgb != util_format_is_srgb(rebuilt.request.format))
        return -22;
    if (state.flags || state.compare_enable || state.unnormalized_coordinates ||
        state.reduction_mode != VK_SAMPLER_REDUCTION_MODE_WEIGHTED_AVERAGE)
        return -95;
    err = check_border(&state);
    if (err) return err;
    if (integer_border(state.border_color) != util_format_is_pure_integer(rebuilt.request.format))
        return -22;
    if ((state.mag_filter == VK_FILTER_LINEAR || state.min_filter == VK_FILTER_LINEAR ||
         state.mipmap_mode == VK_SAMPLER_MIPMAP_MODE_LINEAR || state.anisotropy_enable) &&
        !nil_format_supports_filtering(rebuilt.device, rebuilt.request.format))
        return -95;

    const struct stela_nvidia_sampler sampler = {
        .device = rebuilt.device, .image_owner = rebuilt.owner,
        .header = pack(rebuilt.device, &state),
    };
    *out = sampler;
    return 0;
}
