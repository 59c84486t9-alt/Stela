/* SPDX-License-Identifier: MIT */
#include "../hosted/surface.h"
#include "intel/dev/intel_device_info.h"
#include "intel/genxml/genX_bits.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Decode actual fields using original generated metadata, independently of
 * the surface helper's sizing and pointer calculations. */
static uint64_t field(const uint32_t *words, unsigned start, unsigned bits)
{
    assert(bits && bits <= 64);
    uint64_t value = 0;
    for (unsigned i = 0; i < bits; ++i)
        value |= (uint64_t)((words[(start + i) / 32] >> ((start + i) % 32)) & 1) << i;
    return value;
}

static struct stela_intel_raw_view valid_view(const struct isl_device *dev)
{
    /* Source-only fixture addresses, never a production mapping substitute. */
    return (struct stela_intel_raw_view){
        .gpu_base = 0x400000, .mapped_bytes = 16384, .buffer_bytes = 8192,
        .offset = 256, .bytes = 8191 - 256,
        .address_bits = dev->info->ver < 8 ? 32 : 48, .alignment = 4,
        .access = STELA_INTEL_BUFFER_READ_WRITE,
        .available_access = STELA_INTEL_BUFFER_READ_WRITE,
    };
}

static void decode_raw_view(const struct isl_device *dev, const uint32_t *words,
                            uint64_t expected_address, uint64_t expected_bytes)
{
#define READ_FIELD(name) field(words, RENDER_SURFACE_STATE_##name##_start(dev->info), \
                                    RENDER_SURFACE_STATE_##name##_bits(dev->info))
    assert(READ_FIELD(SurfaceBaseAddress) == expected_address);
    assert(READ_FIELD(SurfaceFormat) == ISL_FORMAT_RAW);
    assert(READ_FIELD(SurfaceType) == 4); /* SURFTYPE_BUFFER in original XML */
    uint64_t width = READ_FIELD(Width), height = READ_FIELD(Height), depth = READ_FIELD(Depth);
    assert(width <= 127);
    uint64_t encoded_bytes = (width | height << 7 | depth << (dev->info->ver >= 7 ? 21 : 20)) + 1;
    uint64_t decoded_bytes = (encoded_bytes & ~UINT64_C(3)) - (encoded_bytes & 3);
    assert(decoded_bytes == expected_bytes);
#undef READ_FIELD
}

static void exact_views_and_original_isl(const struct isl_device *dev)
{
    struct stela_intel_raw_view view = valid_view(dev);
    for (uint64_t bytes = 1; bytes <= 257; ++bytes) {
        for (unsigned external = 0; external < 2; ++external) {
            view.bytes = bytes; view.external = external != 0;
            uint32_t actual[20], expected[20];
            for (unsigned i = 0; i < 20; ++i) actual[i] = expected[i] = 0xa5a5a5a5;
            int encoded = stela_intel_raw_buffer_state(dev, &view, actual, sizeof(actual));
            assert(encoded == dev->ss.size);
            const struct isl_buffer_fill_state_info original = {
                .address = view.gpu_base + view.offset, .size_B = bytes,
                .format = ISL_FORMAT_RAW, .stride_B = 1, .swizzle = ISL_SWIZZLE_IDENTITY,
                .usage = ISL_SURF_USAGE_STORAGE_BIT,
                .mocs = isl_mocs(dev, ISL_SURF_USAGE_STORAGE_BIT, view.external),
            };
            isl_buffer_fill_state_s(dev, expected, &original);
            assert(memcmp(actual, expected, sizeof(actual)) == 0);
            decode_raw_view(dev, actual, view.gpu_base + view.offset, bytes);
            assert(actual[dev->ss.size / 4] == 0xa5a5a5a5);
        }
    }
}

static void invalid_views_leave_output_unchanged(const struct isl_device *dev)
{
    uint32_t state[20], before[20];
    for (unsigned i = 0; i < 20; ++i) state[i] = 0xa5a5a5a5;
    memcpy(before, state, sizeof(state));
    for (unsigned fault = 0; fault < 18; ++fault) {
        struct stela_intel_raw_view view = valid_view(dev);
        switch (fault) {
        case 0: view.bytes = 0; break;
        case 1: view.bytes = UINT64_C(1) << 32; break;
        case 2: view.offset = view.buffer_bytes + 1; break;
        case 3: view.bytes = view.buffer_bytes - view.offset + 1; break;
        case 4: view.mapped_bytes = view.buffer_bytes - 1; break;
        case 5: view.offset++; break;
        case 6: view.alignment = 3; break;
        case 7: view.alignment = 0; break;
        case 8: view.gpu_base++; break;
        case 9: view.access = 0; break;
        case 10: view.access = 4; break;
        case 11: view.available_access = STELA_INTEL_BUFFER_READ; break;
        case 12: view.available_access = 7; break;
        case 13: view.address_bits = 64; break;
        case 14: view.gpu_base = UINT64_MAX - 3; break;
        case 15:
            view.gpu_base = UINT64_C(1) << (view.address_bits - (view.address_bits == 32 ? 0 : 1));
            break;
        case 16: view.bytes = 1; view.offset = 0; view.buffer_bytes = 1; view.mapped_bytes = 7; break;
        case 17:
            view.offset = 0; view.bytes = dev->max_buffer_size - 1;
            view.buffer_bytes = view.bytes; view.mapped_bytes = view.bytes + 16;
            break;
        }
        assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == -22);
        assert(memcmp(state, before, sizeof(state)) == 0);
    }
    struct stela_intel_raw_view view = valid_view(dev);
    assert(stela_intel_raw_buffer_state(dev, &view, state, dev->ss.size - 1) == -28);
    assert(stela_intel_raw_buffer_state(dev, &view, (char *)state + 1, sizeof(state) - 1) == -22);
    assert(memcmp(state, before, sizeof(state)) == 0);
}

static void canonical_and_maximum_boundaries(const struct isl_device *dev)
{
    struct stela_intel_raw_view view = valid_view(dev);
    uint32_t state[20];
    struct stela_intel_raw_limits limits;
    assert(stela_intel_query_raw_limits(dev, &limits) == 0);
    assert(limits.state_bytes == dev->ss.size && limits.gpu_state_alignment == dev->ss.align);
    view.offset = 0;
    view.bytes = limits.max_view_bytes;
    view.buffer_bytes = view.bytes; view.mapped_bytes = view.bytes;
    assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == dev->ss.size);
    decode_raw_view(dev, state, view.gpu_base, view.bytes);
    view.bytes++; view.buffer_bytes++; view.mapped_bytes += 8;
    assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == -22);
    view = valid_view(dev);
    if (dev->info->ver >= 8) {
        view.gpu_base = UINT64_C(0xffff800000400000);
        assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == dev->ss.size);
        decode_raw_view(dev, state, view.gpu_base + view.offset, view.bytes);
        view.gpu_base = (UINT64_C(1) << 47) - view.mapped_bytes;
        assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == dev->ss.size);
        view.gpu_base += 4;
        assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == -22);
        if (dev->info->ver >= 20) {
            view = valid_view(dev);
            view.address_bits = 57;
            view.gpu_base = UINT64_C(0x0012345600400000);
            assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == dev->ss.size);
            decode_raw_view(dev, state, view.gpu_base + view.offset, view.bytes);
            view.gpu_base = UINT64_C(0xff00000000400000);
            assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == dev->ss.size);
            decode_raw_view(dev, state, view.gpu_base + view.offset, view.bytes);
        }
    } else {
        view.gpu_base = (UINT64_C(1) << 32) - view.mapped_bytes;
        assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == dev->ss.size);
        view.gpu_base += 4;
        assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == -22);
        view.gpu_base = 0x400000; view.address_bits = 48;
        assert(stela_intel_raw_buffer_state(dev, &view, state, sizeof(state)) == -22);
    }
}

static void uninitialized_or_unsupported_devices_fail(const struct isl_device *dev)
{
    uint32_t state[20] = {0}, before[20] = {0};
    struct stela_intel_raw_view view = valid_view(dev);
    assert(stela_intel_raw_buffer_state(NULL, &view, state, sizeof(state)) == -22);
    struct isl_device unavailable = {0};
    assert(stela_intel_raw_buffer_state(&unavailable, &view, state, sizeof(state)) == -22);
    unavailable = *dev; unavailable.max_buffer_size = 0;
    assert(stela_intel_raw_buffer_state(&unavailable, &view, state, sizeof(state)) == -22);
    unavailable = *dev; unavailable.ss.size--;
    assert(stela_intel_raw_buffer_state(&unavailable, &view, state, sizeof(state)) == -22);
    struct intel_device_info unknown = *dev->info;
    unknown.verx10 = 100;
    unavailable = *dev; unavailable.info = &unknown;
    assert(stela_intel_raw_buffer_state(&unavailable, &view, state, sizeof(state)) == -95);
    assert(memcmp(state, before, sizeof(state)) == 0);
}

static void formats_follow_real_isl(const struct isl_device *dev)
{
    for (unsigned format = 0; format < ISL_NUM_FORMATS; ++format) {
        struct stela_intel_format_support support;
        if (!isl_format_is_valid((enum isl_format)format)) continue;
        assert(stela_intel_query_format(dev, (enum isl_format)format, &support) == 0);
        assert(support.rendering == isl_format_supports_rendering(dev->info, format));
        assert(support.blending == isl_format_supports_alpha_blending(dev->info, format));
        assert(support.sampling == isl_format_supports_sampling(dev->info, format));
        assert(support.filtering == isl_format_supports_filtering(dev->info, format));
        assert(support.vertex_fetch == isl_format_supports_vertex_fetch(dev->info, format));
        assert(support.typed_read == isl_format_supports_typed_reads(dev->info, format));
        assert(support.typed_write == isl_format_supports_typed_writes(dev->info, format));
        assert(support.typed_atomic == isl_format_supports_typed_atomics(dev->info, format));
        assert(support.raw_buffer_encoder == (format == ISL_FORMAT_RAW));
    }
    struct stela_intel_format_support invalid = {0}, before = invalid;
    assert(stela_intel_query_format(dev, (enum isl_format)-1, &invalid) == -22);
    assert(memcmp(&before, &invalid, sizeof(before)) == 0);
}

int main(void)
{
    const char *platforms[] = {
        "brw", "g4x", "ilk", "snb", "ivb", "byt", "hsw", "bdw", "chv",
        "skl", "bxt", "icl", "tgl", "dg1", "dg2", "mtl", "lnl", "bmg", "ptl", "nvl",
    };
    for (unsigned i = 0; i < sizeof(platforms) / sizeof(platforms[0]); ++i) {
        struct intel_device_info info;
        int pci = intel_device_name_to_pci_device_id(platforms[i]);
        assert(pci >= 0 && intel_get_device_info_for_build(pci, &info));
        struct isl_device dev = {0};
        isl_device_init(&dev, &info);
        exact_views_and_original_isl(&dev);
        invalid_views_leave_output_unchanged(&dev);
        canonical_and_maximum_boundaries(&dev);
        uninitialized_or_unsupported_devices_fail(&dev);
        formats_follow_real_isl(&dev);
        printf("Hosted Intel ISL %s: exact RAW views, bounds, canonical VAs and format queries passed\n", platforms[i]);
    }
    return 0;
}
