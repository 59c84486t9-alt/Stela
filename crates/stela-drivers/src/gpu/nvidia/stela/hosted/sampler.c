/* SPDX-License-Identifier: MIT */
#include "sampler.h"
#include <math.h>

static int check_border(const struct nil_sampler_state *state)
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
    /* Validate standard value semantics; original color conversion and word
     * packing remain solely in the extracted donor functions. No new enum map.
     */
    const uint32_t rgb = state->border_color == VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE ||
                         state->border_color == VK_BORDER_COLOR_INT_OPAQUE_WHITE;
    const uint32_t alpha = state->border_color != VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK &&
                           state->border_color != VK_BORDER_COLOR_INT_TRANSPARENT_BLACK;
    for (unsigned c = 0; c < 4; c++) {
        const uint32_t expected = c == 3 ? alpha : rgb;
        if (vk_color_value_is_int(state->border_color)) {
            /* Original vk_border_color_value uses int32 literals0/1. Their
             * stored uint32 bit patterns are also exact unsigned0/1 values.
             */
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

int stela_nv_sampler_encode(const struct stela_nv_image *image,
                            const struct nil_sampler_state *input, struct stela_nv_sampler *out)
{
    if (!image || !image->owner || !input || !out) return -22;
    const struct nil_sampler_state state = *input;
    struct stela_nv_image rebuilt;
    int err = stela_nv_image_init(image->device, image->owner, &image->request, &rebuilt);
    if (err) return err;
    if (image->cls_eng3d != rebuilt.cls_eng3d || image->device_type != rebuilt.device_type)
        return -22;
    if (!(rebuilt.request.usage & STELA_NV_IMAGE_TEXTURE)) return -95;
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
    if (vk_color_value_is_int(state.border_color) != util_format_is_pure_integer(rebuilt.request.format))
        return -22;
    if ((state.mag_filter == VK_FILTER_LINEAR || state.min_filter == VK_FILTER_LINEAR ||
         state.mipmap_mode == VK_SAMPLER_MIPMAP_MODE_LINEAR || state.anisotropy_enable) &&
        !nil_format_supports_filtering(rebuilt.device, rebuilt.request.format))
        return -95;

    const struct stela_nv_sampler sampler = {
        .device = rebuilt.device, .image_owner = rebuilt.owner,
        .header = nil_sampler_pack(rebuilt.device, &state),
    };
    *out = sampler;
    return 0;
}
