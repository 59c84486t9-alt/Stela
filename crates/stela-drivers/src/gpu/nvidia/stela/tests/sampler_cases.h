/* SPDX-License-Identifier: MIT */
#ifndef STELA_NV_SAMPLER_CASES_H
#define STELA_NV_SAMPLER_CASES_H
/* Test values only; sampler_expected.h holds NVK's headers for them. */
#define STELA_NV_SAMPLER_CASES 42
static SAMPLER_CASE_STATE sampler_case(unsigned index)
{
    SAMPLER_CASE_STATE state = {
        .mag_filter = VK_FILTER_NEAREST, .min_filter = VK_FILTER_NEAREST,
        .mipmap_mode = VK_SAMPLER_MIPMAP_MODE_NEAREST,
        .address_mode_u = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE,
        .address_mode_v = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE,
        .address_mode_w = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE,
        .max_anisotropy = 1.0f, .max_lod = 8.0f,
        .border_color = VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK,
        .reduction_mode = VK_SAMPLER_REDUCTION_MODE_WEIGHTED_AVERAGE,
    };
    switch (index) {
    case 0: break;
    case 1: state.mag_filter = VK_FILTER_LINEAR; break;
    case 2: state.min_filter = VK_FILTER_LINEAR; break;
    case 3: state.mipmap_mode = VK_SAMPLER_MIPMAP_MODE_LINEAR; break;
    case 4: state.address_mode_u = VK_SAMPLER_ADDRESS_MODE_REPEAT; break;
    case 5: state.address_mode_v = VK_SAMPLER_ADDRESS_MODE_MIRRORED_REPEAT; break;
    case 6: state.address_mode_w = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER; break;
    case 7: state.address_mode_u = VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE; break;
    case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15:
        state.compare_enable = true; state.compare_op = index - 8; break;
    case 16: case 17: case 18: case 19: case 20: case 21: case 22:
        state.anisotropy_enable = true; state.min_filter = VK_FILTER_LINEAR;
        state.max_anisotropy = index == 22 ? 16.0f : (float)(index - 15) * 2.0f; break;
    case 23: state.mip_lod_bias = -1.5f; break;
    case 24: state.mip_lod_bias = 4095.0f / 256.0f; break;
    case 25: state.min_lod = 2.25f; break;
    case 26: state.max_lod = 4095.0f / 256.0f; break;
    case 27: state.flags = VK_SAMPLER_CREATE_NON_SEAMLESS_CUBE_MAP_BIT_EXT; break;
    case 28: state.unnormalized_coordinates = true; break;
    case 29: state.reduction_mode = VK_SAMPLER_REDUCTION_MODE_MIN; break;
    case 30: state.reduction_mode = VK_SAMPLER_REDUCTION_MODE_MAX; break;
    case 31: state.border_color = VK_BORDER_COLOR_FLOAT_OPAQUE_BLACK;
             state.border_color_value.float32[3] = 1.0f; break;
    case 32: case 37:
        state.border_color = VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE;
        state.border_color_value = (VkClearColorValue){.float32 = {1, 1, 1, 1}};
        state.image_view_is_srgb = index == 37; break;
    case 33: state.border_color = VK_BORDER_COLOR_INT_TRANSPARENT_BLACK; break;
    case 34: state.border_color = VK_BORDER_COLOR_INT_OPAQUE_WHITE;
             state.border_color_value = (VkClearColorValue){.uint32 = {1, 1, 1, 1}}; break;
    case 35: case 36:
        state.border_color = VK_BORDER_COLOR_FLOAT_CUSTOM_EXT;
        state.border_color_value = (VkClearColorValue){.float32 = {0.003f, 0.3f, 0.5f, 0.8f}};
        state.image_view_is_srgb = true;
        if (index == 36)
            state.border_color_component_mapping = (VkComponentMapping){
                VK_COMPONENT_SWIZZLE_ZERO, VK_COMPONENT_SWIZZLE_ONE,
                VK_COMPONENT_SWIZZLE_B, VK_COMPONENT_SWIZZLE_A};
        break;
    case 38: state.min_lod = 1.125f; state.max_lod = 3.75f; state.mip_lod_bias = -16.0f; break;
    case 39: case 40:
        state.anisotropy_enable = true; state.min_filter = VK_FILTER_LINEAR;
        state.max_anisotropy = index == 39 ? 1.0f : 12.1f; break;
    case 41:
        state.border_color = VK_BORDER_COLOR_INT_CUSTOM_EXT;
        state.border_color_value = (VkClearColorValue){.uint32 = {13, 42, 71, 99}};
        state.border_color_component_mapping = (VkComponentMapping){
            VK_COMPONENT_SWIZZLE_A, VK_COMPONENT_SWIZZLE_ONE,
            VK_COMPONENT_SWIZZLE_ZERO, VK_COMPONENT_SWIZZLE_R};
        break;
    default: assert(!"invalid sampler case");
    }
    return state;
}
#endif
