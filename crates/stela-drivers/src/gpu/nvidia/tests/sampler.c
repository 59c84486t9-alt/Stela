/* SPDX-License-Identifier: MIT */
#include "../hosted/sampler.h"
#include "nouveau/headers/drf.h"
#include "nouveau/headers/nvidia/classes/cl9097tex.h"
#include "nouveau/headers/nvidia/classes/clb097.h"
#include "nouveau/headers/nvidia/classes/clb197.h"
#include "nouveau/headers/nvidia/classes/clc097.h"
#include "nouveau/headers/nvidia/classes/clc197.h"
#include "nouveau/headers/nvidia/classes/clc397.h"
#include "nouveau/headers/nvidia/classes/clc597.h"
#include "nouveau/headers/nvidia/classes/clc697.h"
#include "nouveau/headers/nvidia/classes/clc797.h"
#include "nouveau/headers/nvidia/classes/clc997.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#define SAMPLER_CASE_STATE struct stela_nvidia_sampler_state
#include "sampler_cases.h"
#undef SAMPLER_CASE_STATE
#include "sampler_expected.h"

static const unsigned owner = 1;

static struct stela_nvidia_image make_image(const struct nv_device_info *dev, enum pipe_format format)
{
    const struct stela_nvidia_image_request req = {
        .format = format, .width = 129, .height = 87, .layers = 3, .levels = 8,
        .usage = STELA_NVIDIA_IMAGE_TEXTURE,
    };
    struct stela_nvidia_image image;
    assert(stela_nvidia_image_init(dev, &owner, &req, &image) == 0);
    return image;
}

static bool integer_color(VkBorderColor color)
{
    return color == VK_BORDER_COLOR_INT_CUSTOM_EXT || (color <= VK_BORDER_COLOR_INT_OPAQUE_WHITE && color % 2);
}

/* Fields decoded independently of the expected words. */
static void decoded_fields(const struct stela_nvidia_sampler_state *state, const uint32_t *bits)
{
    assert(!NVVAL_GET_X(bits[0], NV9097_TEXSAMP0_DEPTH_COMPARE));
    const uint32_t mag = state->mag_filter == VK_FILTER_LINEAR ?
        NV9097_TEXSAMP1_MAG_FILTER_MAG_LINEAR : NV9097_TEXSAMP1_MAG_FILTER_MAG_POINT;
    assert(NVVAL_GET_X(bits[1], NV9097_TEXSAMP1_MAG_FILTER) == mag);
    const int32_t bias_raw = (int32_t)NVVAL_GET_X(bits[1], NV9097_TEXSAMP1_MIP_LOD_BIAS);
    const int32_t bias = (bias_raw & 4096) ? bias_raw - 8192 : bias_raw;
    assert(bias == (int32_t)roundf(state->mip_lod_bias * 256.0f));
    assert(NVVAL_GET_X(bits[2], NV9097_TEXSAMP2_MIN_LOD_CLAMP) == (unsigned)roundf(state->min_lod * 256.0f));
    assert(NVVAL_GET_X(bits[2], NV9097_TEXSAMP2_MAX_LOD_CLAMP) == (unsigned)roundf(state->max_lod * 256.0f));
    assert(memcmp(&bits[4], state->border_color_value.uint32, 4 * sizeof(uint32_t)) == 0);
}

static bool supported_case(unsigned index)
{
    return index <= 7 || (index >= 16 && index <= 26) || (index >= 31 && index <= 34) ||
           (index >= 37 && index <= 40);
}

static void paired_formats(const struct nv_device_info *dev, enum pipe_format format)
{
    struct stela_nvidia_image image = make_image(dev, format);
    for (unsigned i = 0; i < STELA_NVIDIA_SAMPLER_CASES; i++) {
        struct stela_nvidia_sampler_state state = sampler_case(i);
        state.image_view_is_srgb = util_format_is_srgb(format);
        struct stela_nvidia_sampler actual, before;
        memset(&actual, 0xa5, sizeof(actual)); memcpy(&before, &actual, sizeof(actual));
        const bool filtering = state.mag_filter == VK_FILTER_LINEAR || state.min_filter == VK_FILTER_LINEAR ||
                               state.mipmap_mode == VK_SAMPLER_MIPMAP_MODE_LINEAR || state.anisotropy_enable;
        const bool numeric_match = integer_color(state.border_color) == util_format_is_pure_integer(format);
        const int expected = !supported_case(i) ? -95 : !numeric_match ? -22 :
                             filtering && !nil_format_supports_filtering(dev, format) ? -95 : 0;
        const int error = stela_nvidia_sampler_encode(&image, &state, &actual);
        assert(error == expected);
        if (error) {
            assert(memcmp(&actual, &before, sizeof(actual)) == 0);
        } else {
            assert(actual.device == dev && actual.image_owner == &owner);
            assert(memcmp(actual.header.bits, sampler_expected_words[dev->cls_eng3d == MAXWELL_A ? 0 : 1][i],
                          sizeof(actual.header.bits)) == 0);
            decoded_fields(&state, actual.header.bits);
            /* Caller-written layout metadata is never used for format policy. */
            struct stela_nvidia_image candidate = image;
            memset(&candidate.layout, 0xff, sizeof(candidate.layout));
            struct stela_nvidia_sampler guarded;
            assert(stela_nvidia_sampler_encode(&candidate, &state, &guarded) == 0);
            assert(memcmp(guarded.header.bits, actual.header.bits, sizeof(actual.header.bits)) == 0);
        }
    }
}

static void invalid_states_are_atomic(const struct nv_device_info *dev)
{
    const struct stela_nvidia_image image = make_image(dev, PIPE_FORMAT_R8G8B8A8_UNORM);
    for (unsigned fault = 0; fault < 37; fault++) {
        struct stela_nvidia_image candidate = image;
        struct stela_nvidia_sampler_state state = sampler_case(0);
        struct stela_nvidia_sampler out, before;
        memset(&out, 0xa5, sizeof(out)); memcpy(&before, &out, sizeof(out));
        int expected = -22;
        switch (fault) {
        case 0: state.mag_filter = VK_FILTER_CUBIC_EXT; break;
        case 1: state.min_filter = VK_FILTER_MAX_ENUM; break;
        case 2: state.mipmap_mode = VK_SAMPLER_MIPMAP_MODE_MAX_ENUM; break;
        case 3: state.address_mode_u = VK_SAMPLER_ADDRESS_MODE_MAX_ENUM; break;
        case 4: state.address_mode_v = VK_SAMPLER_ADDRESS_MODE_MAX_ENUM; break;
        case 5: state.address_mode_w = VK_SAMPLER_ADDRESS_MODE_MAX_ENUM; break;
        case 6: state.compare_op = VK_COMPARE_OP_MAX_ENUM; break;
        case 7: state.reduction_mode = VK_SAMPLER_REDUCTION_MODE_MAX_ENUM; break;
        case 8: state.mip_lod_bias = NAN; break;
        case 9: state.mip_lod_bias = INFINITY; break;
        case 10: state.mip_lod_bias = -16.01f; break;
        case 11: state.mip_lod_bias = 16.0f; break;
        case 12: state.min_lod = NAN; break;
        case 13: state.min_lod = -1.0f; break;
        case 14: state.min_lod = 9.0f; break;
        case 15: state.max_lod = INFINITY; break;
        case 16: state.max_lod = 16.0f; break;
        case 17: state.max_lod = -1.0f; break;
        case 18: state.max_anisotropy = NAN; break;
        case 19: state.max_anisotropy = 0.0f; break;
        case 20: state.max_anisotropy = 17.0f; break;
        case 21: state.max_anisotropy = 2.0f; break;
        case 22: state.image_view_is_srgb = true; break;
        case 23: state.border_color_value.float32[0] = NAN; break;
        case 24: state.border_color = VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE; break;
        case 25: state.border_color = VK_BORDER_COLOR_MAX_ENUM; break;
        case 26: candidate.owner = NULL; break;
        case 27: candidate.cls_eng3d++; break;
        case 28: candidate.device_type = NV_DEVICE_TYPE_SOC; break;
        case 29: candidate.request.usage = STELA_NVIDIA_IMAGE_STORAGE; expected = -95; break;
        case 30: state.flags = VK_SAMPLER_CREATE_NON_SEAMLESS_CUBE_MAP_BIT_EXT; expected = -95; break;
        case 31: state.border_color_component_mapping.r = VK_COMPONENT_SWIZZLE_R; expected = -95; break;
        case 32: state.compare_enable = true; expected = -95; break;
        case 33: state.unnormalized_coordinates = true; expected = -95; break;
        case 34: state.reduction_mode = VK_SAMPLER_REDUCTION_MODE_MIN; expected = -95; break;
        case 35: candidate.request.format = PIPE_FORMAT_COUNT; break;
        case 36: state.border_color = VK_BORDER_COLOR_INT_TRANSPARENT_BLACK; break;
        }
        assert(stela_nvidia_sampler_encode(&candidate, &state, &out) == expected);
        assert(memcmp(&out, &before, sizeof(out)) == 0);
    }
    struct stela_nvidia_sampler_state state = sampler_case(0);
    struct stela_nvidia_sampler out;
    assert(stela_nvidia_sampler_encode(NULL, &state, &out) == -22);
    assert(stela_nvidia_sampler_encode(&image, NULL, &out) == -22);
    assert(stela_nvidia_sampler_encode(&image, &state, NULL) == -22);
}

static void standard_borders_and_integer_filtering(const struct nv_device_info *dev, enum pipe_format format)
{
    const struct stela_nvidia_image image = make_image(dev, format);
    const VkBorderColor colors[] = {VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK,
        VK_BORDER_COLOR_FLOAT_OPAQUE_BLACK, VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE,
        VK_BORDER_COLOR_INT_TRANSPARENT_BLACK, VK_BORDER_COLOR_INT_OPAQUE_BLACK, VK_BORDER_COLOR_INT_OPAQUE_WHITE};
    const bool image_integer = util_format_is_pure_integer(format);
    for (unsigned color = 0; color < ARRAY_SIZE(colors); color++) {
        struct stela_nvidia_sampler_state state = sampler_case(0);
        state.border_color = colors[color];
        state.image_view_is_srgb = util_format_is_srgb(format);
        const bool integer = color >= 3;
        const uint32_t rgb = color % 3 == 2;
        const uint32_t alpha = color % 3 != 0;
        for (unsigned c = 0; c < 4; c++) {
            const uint32_t value = c == 3 ? alpha : rgb;
            if (integer) state.border_color_value.uint32[c] = value;
            else state.border_color_value.float32[c] = (float)value;
        }
        struct stela_nvidia_sampler out, before;
        memset(&out, 0xa5, sizeof(out)); memcpy(&before, &out, sizeof(out));
        const int error = stela_nvidia_sampler_encode(&image, &state, &out);
        assert(error == (integer == image_integer ? 0 : -22));
        if (error) {
            assert(memcmp(&out, &before, sizeof(out)) == 0);
            continue;
        }
        /* The Vulkan runtime's standard integer borders are signed 0/1, whose
         * payload words are the same for signed and unsigned images. */
        assert(memcmp(&out.header.bits[4], state.border_color_value.uint32, 16) == 0);
        if (integer) {
            for (unsigned filtering = 0; filtering < 4; filtering++) {
                struct stela_nvidia_sampler_state filtered = state;
                if (filtering == 0) filtered.mag_filter = VK_FILTER_LINEAR;
                if (filtering == 1) filtered.min_filter = VK_FILTER_LINEAR;
                if (filtering == 2) filtered.mipmap_mode = VK_SAMPLER_MIPMAP_MODE_LINEAR;
                if (filtering == 3) { filtered.anisotropy_enable = true; filtered.max_anisotropy = 2.0f; }
                struct stela_nvidia_sampler unchanged;
                memcpy(&unchanged, &out, sizeof(out));
                assert(stela_nvidia_sampler_encode(&image, &filtered, &out) == -95);
                assert(memcmp(&out, &unchanged, sizeof(out)) == 0);
            }
            state.border_color_value.uint32[0] = UINT32_MAX;
            struct stela_nvidia_sampler unchanged;
            memcpy(&unchanged, &out, sizeof(out));
            assert(stela_nvidia_sampler_encode(&image, &state, &out) == -22);
            assert(memcmp(&out, &unchanged, sizeof(out)) == 0);
        }
    }
}

int main(void)
{
    const uint16_t classes[] = {MAXWELL_A, MAXWELL_B, PASCAL_A, PASCAL_B, VOLTA_A,
                               TURING_A, AMPERE_A, AMPERE_B, ADA_A};
    const enum pipe_format formats[] = {PIPE_FORMAT_R8G8B8A8_UNORM, PIPE_FORMAT_B8G8R8A8_SRGB,
                                       PIPE_FORMAT_R32_UINT, PIPE_FORMAT_R32_SINT};
    for (unsigned c = 0; c < ARRAY_SIZE(classes); c++) {
        const struct nv_device_info dev = {.type = NV_DEVICE_TYPE_DIS, .cls_eng3d = classes[c]};
        for (unsigned f = 0; f < ARRAY_SIZE(formats); f++) {
            paired_formats(&dev, formats[f]);
            standard_borders_and_integer_filtering(&dev, formats[f]);
        }
        invalid_states_are_atomic(&dev);
    }
    puts("NVIDIA sampler: NVK's recorded headers, decoded fields, 9 classes, paired formats, filter rights and atomic failures passed; hardware_executed=false");
    return 0;
}
