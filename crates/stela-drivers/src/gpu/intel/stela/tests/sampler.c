/* SPDX-License-Identifier: MIT */
#include "../hosted/sampler.h"
#include "intel/dev/intel_device_info.h"
#include "stela/tests/targets/intel.h"
#include "sampler_bits.h" /* Unchanged original gen_bits_header.py output. */
#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static unsigned states, refusals;

static uint32_t field(const uint32_t *words, unsigned start, unsigned bits)
{
    assert(bits && bits <= 32 && (start % 32) + bits <= 32);
    return (words[start / 32] >> (start % 32)) & (UINT32_MAX >> (32 - bits));
}

static void put(uint32_t *words, unsigned start, unsigned bits, int value)
{
    assert(bits && bits <= 32 && (start % 32) + bits <= 32);
    uint32_t mask = UINT32_MAX >> (32 - bits);
    words[start / 32] |= ((uint32_t)value & mask) << (start % 32);
}

static struct stela_intel_image_desc image(void)
{
    return (struct stela_intel_image_desc){
        .dim = ISL_SURF_DIM_2D, .format = ISL_FORMAT_R8G8B8A8_UNORM,
        .width = 127, .height = 67, .depth = 1, .levels = 7, .array_len = 3, .samples = 1,
        .usage = ISL_SURF_USAGE_TEXTURE_BIT, .tiling_flags = ISL_TILING_LINEAR_BIT,
        .backing = STELA_INTEL_IMAGE_UNCOMPRESSED,
    };
}

static struct pipe_sampler_state sampler(void)
{
    return (struct pipe_sampler_state){
        .wrap_s = PIPE_TEX_WRAP_CLAMP_TO_EDGE, .wrap_t = PIPE_TEX_WRAP_CLAMP_TO_EDGE,
        .wrap_r = PIPE_TEX_WRAP_CLAMP_TO_EDGE, .min_img_filter = PIPE_TEX_FILTER_LINEAR,
        .mag_img_filter = PIPE_TEX_FILTER_LINEAR, .min_mip_filter = PIPE_TEX_MIPFILTER_LINEAR,
        .max_lod = 14,
    };
}

/* Test-only independent numeric expectations. Actual production fixed-point
 * packing stays in original util_bitpack_*fixed and the original XML packer. */
static int quantize(double value, double low, double high)
{
    if (value < low) value = low;
    if (value > high) value = high;
    double scaled = value * 256;
    return scaled < 0 ? (int)ceil(scaled - 0.5) : (int)floor(scaled + 0.5);
}

static int wrap(unsigned mode)
{
    /* Texture Coordinate Mode values in original Intel XML. */
    switch (mode) {
    case PIPE_TEX_WRAP_REPEAT: return 0;
    case PIPE_TEX_WRAP_MIRROR_REPEAT: return 1;
    case PIPE_TEX_WRAP_CLAMP_TO_EDGE: return 2;
    case PIPE_TEX_WRAP_MIRROR_CLAMP_TO_EDGE: return 5;
    default: assert(false); return -1;
    }
}

static void check_state(const struct isl_device *dev, const struct stela_intel_image_desc *img,
                         const struct pipe_sampler_state *s)
{
    uint32_t actual[8], expected[4] = {0}; memset(actual, 0xa5, sizeof(actual));
    assert(stela_intel_sampler_state(dev, img, s, actual, sizeof(actual)) == 16);
    assert(SAMPLER_STATE_length(dev->info) == 4);
    unsigned effective_mag = s->min_mip_filter == PIPE_TEX_MIPFILTER_NONE && s->min_lod > 0 ?
        s->min_img_filter : s->mag_img_filter;
    double effective_min = s->min_mip_filter == PIPE_TEX_MIPFILTER_NONE && s->min_lod > 0 ?
        0 : s->min_lod;
    unsigned mip = s->min_mip_filter == PIPE_TEX_MIPFILTER_NONE ? 0 :
        s->min_mip_filter == PIPE_TEX_MIPFILTER_NEAREST ? 1 : 3;
#define READ(name) field(actual, SAMPLER_STATE_##name##_start(dev->info), \
                                SAMPLER_STATE_##name##_bits(dev->info))
#define PUT(name, value) put(expected, SAMPLER_STATE_##name##_start(dev->info), \
                                     SAMPLER_STATE_##name##_bits(dev->info), value)
    assert(READ(MinModeFilter) == s->min_img_filter);
    assert(READ(MagModeFilter) == effective_mag && READ(MipModeFilter) == mip);
    assert(READ(TCXAddressControlMode) == wrap(s->wrap_s));
    assert(READ(TCYAddressControlMode) == wrap(s->wrap_t));
    assert(READ(TCZAddressControlMode) == wrap(s->wrap_r));
    assert(READ(MinLOD) == quantize(effective_min, 0, 14));
    assert(READ(MaxLOD) == quantize(s->max_lod, 0, 14));
    assert(READ(LODPreClampMode) == 2); /* Original CLAMP_MODE_OGL. */
    unsigned bias_bits = SAMPLER_STATE_TextureLODBias_bits(dev->info);
    int bias = READ(TextureLODBias);
    if (bias & (1u << (bias_bits - 1))) bias -= (int)(1u << bias_bits);
    assert(bias == quantize(s->lod_bias, -16, 15));
    assert(READ(UAddressMinFilterRoundingEnable) == s->min_img_filter);
    assert(READ(VAddressMinFilterRoundingEnable) == s->min_img_filter);
    assert(READ(RAddressMinFilterRoundingEnable) == s->min_img_filter);
    /* Original policy bases rounding on requested, not adjusted mag filter. */
    assert(READ(UAddressMagFilterRoundingEnable) == s->mag_img_filter);
    assert(READ(VAddressMagFilterRoundingEnable) == s->mag_img_filter);
    assert(READ(RAddressMagFilterRoundingEnable) == s->mag_img_filter);
    assert(!READ(BorderColorPointer) && !READ(ShadowFunction));
    assert(!READ(SamplerDisable) && !READ(NonnormalizedCoordinateEnable));
    assert(!READ(CubeSurfaceControlMode) && !READ(MaximumAnisotropy) &&
        !READ(AnisotropicAlgorithm));
    if (dev->info->ver > 8) assert(!READ(ReductionType) && !READ(ReductionTypeEnable));
    /* Independently reconstruct the entire packet; all unrequested fields and
     * reserved bits stay zero. No helper or producer bytes form the oracle. */
    PUT(MinModeFilter, s->min_img_filter);
    PUT(MagModeFilter, effective_mag);
    PUT(MipModeFilter, mip);
    PUT(TCXAddressControlMode, wrap(s->wrap_s)); PUT(TCYAddressControlMode, wrap(s->wrap_t));
    PUT(TCZAddressControlMode, wrap(s->wrap_r)); PUT(MinLOD, quantize(effective_min, 0, 14));
    PUT(MaxLOD, quantize(s->max_lod, 0, 14)); PUT(TextureLODBias, quantize(s->lod_bias, -16, 15));
    PUT(LODPreClampMode, 2);
    PUT(UAddressMinFilterRoundingEnable, s->min_img_filter);
    PUT(VAddressMinFilterRoundingEnable, s->min_img_filter);
    PUT(RAddressMinFilterRoundingEnable, s->min_img_filter);
    PUT(UAddressMagFilterRoundingEnable, s->mag_img_filter);
    PUT(VAddressMagFilterRoundingEnable, s->mag_img_filter);
    PUT(RAddressMagFilterRoundingEnable, s->mag_img_filter);
    assert(memcmp(actual, expected, sizeof(expected)) == 0);
    for (unsigned i = 4; i < ARRAY_SIZE(actual); ++i) assert(actual[i] == 0xa5a5a5a5);
#undef READ
#undef PUT
    ++states;
}

static void state_matrix(const struct isl_device *dev)
{
    const unsigned modes[] = {PIPE_TEX_WRAP_REPEAT, PIPE_TEX_WRAP_MIRROR_REPEAT,
        PIPE_TEX_WRAP_CLAMP_TO_EDGE, PIPE_TEX_WRAP_MIRROR_CLAMP_TO_EDGE};
    const float lod[][3] = {{0, 14, 0}, {-FLT_MAX, FLT_MAX, -FLT_MAX}, {0, 1, FLT_MAX},
        {1.0f / 512, 2 + 1.0f / 512, 1.0f / 512}, {1 + 1.0f / 512, 5 + 3.0f / 512, -1.0f / 512},
        {7, 14, -16}, {14, FLT_MAX, 15}, {-0.0f, 0, -0.0f}};
    struct stela_intel_image_desc img = image();
    for (unsigned x = 0; x < ARRAY_SIZE(modes); ++x)
    for (unsigned y = 0; y < ARRAY_SIZE(modes); ++y)
    for (unsigned z = 0; z < ARRAY_SIZE(modes); ++z)
    for (unsigned filters = 0; filters < 4; ++filters)
    for (unsigned mip = 0; mip < 3; ++mip)
    for (unsigned l = 0; l < ARRAY_SIZE(lod); ++l) {
        struct pipe_sampler_state s = sampler();
        s.wrap_s = modes[x]; s.wrap_t = modes[y]; s.wrap_r = modes[z];
        s.min_img_filter = filters & 1; s.mag_img_filter = filters >> 1;
        s.min_mip_filter = mip;
        s.min_lod = lod[l][0];
        s.max_lod = lod[l][1];
        s.lod_bias = lod[l][2];
        s.max_anisotropy = (x + y + z) & 1; /* 0/1 both mean no anisotropy. */
        check_state(dev, &img, &s);
    }
}

static void invalid_states(const struct isl_device *dev)
{
    uint32_t out[8], before[8]; memset(out, 0xa5, sizeof(out)); memcpy(before, out, sizeof(out));
    for (unsigned fault = 0; fault < 26; ++fault) {
        struct stela_intel_image_desc img = image(); struct pipe_sampler_state s = sampler();
        switch (fault) {
        case 0: s.min_lod = NAN; break;
        case 1: s.max_lod = NAN; break;
        case 2: s.lod_bias = NAN; break;
        case 3: s.min_lod = INFINITY; break;
        case 4: s.max_lod = INFINITY; break;
        case 5: s.lod_bias = INFINITY; break;
        case 6: s.min_lod = -INFINITY; break;
        case 7: s.max_lod = -INFINITY; break;
        case 8: s.lod_bias = -INFINITY; break;
        case 9: s.min_lod = 10; s.max_lod = 9; break;
        case 10: s.pad = 1; break;
        case 11: s.min_mip_filter = 3; break;
        case 12: s.max_anisotropy = 2; break;
        case 13: s.compare_mode = PIPE_TEX_COMPARE_R_TO_TEXTURE; break;
        case 14: s.unnormalized_coords = true; break;
        case 15: s.seamless_cube_map = true; break;
        case 16: s.reduction_mode = PIPE_TEX_REDUCTION_MIN; break;
        case 17: s.reduction_mode = PIPE_TEX_REDUCTION_MAX; break;
        case 18: s.reduction_mode = 3; break;
        case 19: s.wrap_s = PIPE_TEX_WRAP_CLAMP; break;
        case 20: s.wrap_t = PIPE_TEX_WRAP_CLAMP_TO_BORDER; break;
        case 21: s.wrap_r = PIPE_TEX_WRAP_MIRROR_CLAMP; break;
        case 22: s.wrap_r = PIPE_TEX_WRAP_MIRROR_CLAMP_TO_BORDER; break;
        case 23: img.usage = ISL_SURF_USAGE_RENDER_TARGET_BIT; break;
        case 24: img.format = ISL_FORMAT_RAW; break;
        case 25: img.dim = ISL_SURF_DIM_3D; break;
        }
        assert(stela_intel_sampler_state(dev, &img, &s, out, sizeof(out)) < 0);
        assert(memcmp(out, before, sizeof(out)) == 0); ++refusals;
    }
    struct stela_intel_image_desc img = image(); struct pipe_sampler_state s = sampler();
    assert(stela_intel_sampler_state(dev, &img, &s, out, 15) == -28);
    assert(stela_intel_sampler_state(dev, &img, &s, (char *)out + 1, sizeof(out) - 1) == -22);
    assert(stela_intel_sampler_state(NULL, &img, &s, out, sizeof(out)) == -22);
    assert(stela_intel_sampler_state(dev, NULL, &s, out, sizeof(out)) == -22);
    assert(stela_intel_sampler_state(dev, &img, NULL, out, sizeof(out)) == -22);
    assert(memcmp(out, before, sizeof(out)) == 0);
    /* Real physical integer formats permit sampling but not linear filtering. */
    img.format = ISL_FORMAT_R32_UINT;
    assert(isl_format_supports_sampling(dev->info, img.format));
    assert(!isl_format_supports_filtering(dev->info, img.format));
    assert(stela_intel_sampler_state(dev, &img, &s, out, sizeof(out)) == -95); ++refusals;
    s.min_img_filter = s.mag_img_filter = PIPE_TEX_FILTER_NEAREST;
    assert(stela_intel_sampler_state(dev, &img, &s, out, sizeof(out)) == -95); ++refusals;
    s.min_mip_filter = PIPE_TEX_MIPFILTER_NEAREST;
    check_state(dev, &img, &s);
    img.format = ISL_FORMAT_R16G16B16A16_FLOAT;
    s = sampler(); check_state(dev, &img, &s);
    /* Alias safety: successful output may overlap the borrowed sampler value. */
    union {struct pipe_sampler_state s; uint32_t words[32];} alias;
    alias.s = s;
    assert(stela_intel_sampler_state(dev, &img, &alias.s, alias.words, sizeof(alias)) == 16);
    uint32_t expected[4];
    assert(stela_intel_sampler_state(dev, &img, &s, expected, sizeof(expected)) == 16);
    assert(memcmp(alias.words, expected, sizeof(expected)) == 0);
    /* Packer output needs u32 alignment, not the generated C struct's ABI
     * alignment (which may be larger due to a 64-bit border offset field). */
    _Alignas(8) uint32_t four_aligned[6]; memset(four_aligned, 0xa5, sizeof(four_aligned));
    assert(stela_intel_sampler_state(dev, &img, &s, four_aligned + 1, 16) == 16);
    assert(memcmp(four_aligned + 1, expected, sizeof(expected)) == 0);
    assert(four_aligned[0] == 0xa5a5a5a5 && four_aligned[5] == 0xa5a5a5a5);
}

static void old_generation_hold(const struct isl_device *dev)
{
    struct stela_intel_image_desc img = image(); struct pipe_sampler_state s = sampler();
    uint32_t out[4] = {1,2,3,4}, before[4]; memcpy(before, out, sizeof(out));
    assert(stela_intel_sampler_state(dev, &img, &s, out, sizeof(out)) == -95);
    assert(memcmp(out, before, sizeof(out)) == 0); ++refusals;
}

int main(void)
{
    const char *platform;
    struct intel_device_info info;
    STELA_INTEL_FOREACH_TARGET(platform, info) {
        struct isl_device dev = {0}; isl_device_init(&dev, &info); dev.requires_padding = true;
        if (info.ver < 8) {
            old_generation_hold(&dev);
            continue;
        }
        state_matrix(&dev); invalid_states(&dev);
    }
    printf("Hosted Intel original Iris sampler: %u independent packet comparisons and %u refusals "
           "passed\n",
        states, refusals);
    return 0;
}
