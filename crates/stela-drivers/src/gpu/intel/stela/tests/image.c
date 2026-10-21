/* SPDX-License-Identifier: MIT */
#include "../hosted/image.h"
#include "intel/dev/intel_device_info.h"
#include "image_bits.h" /* Original gen_bits_header.py output, test-only. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned layouts, states, refusals;

static uint64_t field(const uint32_t *words, unsigned start, unsigned bits)
{
    assert(bits && bits <= 64);
    uint64_t value = 0;
    for (unsigned i = 0; i < bits; ++i)
        value |= (uint64_t)((words[(start + i) / 32] >> ((start + i) % 32)) & 1) << i;
    return value;
}

static struct stela_intel_image_desc description(void)
{
    return (struct stela_intel_image_desc){
        .dim = ISL_SURF_DIM_2D, .format = ISL_FORMAT_R32_UINT,
        .width = 127, .height = 67, .depth = 1, .levels = 7, .array_len = 3, .samples = 1,
        .usage = ISL_SURF_USAGE_TEXTURE_BIT | ISL_SURF_USAGE_RENDER_TARGET_BIT,
        .tiling_flags = ISL_TILING_LINEAR_BIT,
        .backing = STELA_INTEL_IMAGE_UNCOMPRESSED,
    };
}

static isl_tiling_flags_t color_tilings(void)
{
    return ISL_TILING_LINEAR_BIT | ISL_TILING_X_BIT | ISL_TILING_Y0_BIT |
        ISL_TILING_SKL_Yf_BIT | ISL_TILING_SKL_Ys_BIT | ISL_TILING_ICL_Yf_BIT |
        ISL_TILING_ICL_Ys_BIT | ISL_TILING_4_BIT | ISL_TILING_64_BIT | ISL_TILING_64_XE2_BIT;
}

static struct stela_intel_image_view view_for(const struct stela_intel_image_desc *d,
                                             isl_surf_usage_flags_t role)
{
    return (struct stela_intel_image_view){
        .usage = role, .base_level = d->levels - 1, .levels = 1,
        .base_array_layer = d->array_len - 1, .array_len = 1,
        .access = role == ISL_SURF_USAGE_TEXTURE_BIT ? STELA_INTEL_BUFFER_READ :
                  role == ISL_SURF_USAGE_STORAGE_BIT ? d->storage_access : STELA_INTEL_BUFFER_WRITE,
    };
}

static struct stela_intel_image_mapping mapping_for(const struct isl_device *dev,
                                                   const struct isl_surf *surf)
{
    /* Source-model fixtures only; no physical allocation/mapping claim. */
    return (struct stela_intel_image_mapping){
        .gpu_base = UINT64_C(0x100000000) >> (dev->info->ver < 8 ? 8 : 0),
        .mapped_bytes = surf->size_B + surf->alignment_B,
        .allocation_bytes = surf->size_B + surf->alignment_B,
        .image_offset = surf->alignment_B,
        .address_bits = dev->info->ver < 8 ? 32 : 48,
        .available_access = STELA_INTEL_BUFFER_READ_WRITE,
        .backing = STELA_INTEL_IMAGE_UNCOMPRESSED,
    };
}

static bool original_layout(const struct isl_device *dev, const struct stela_intel_image_desc *d,
                             struct isl_surf *surf)
{
    const struct isl_surf_init_info info = {
        .dim = d->dim, .format = d->format, .width = d->width, .height = d->height,
        .depth = d->depth, .levels = d->levels, .array_len = d->array_len, .samples = d->samples,
        .usage = d->usage | ISL_SURF_USAGE_DISABLE_AUX_BIT, .tiling_flags = d->tiling_flags,
        .min_alignment_B = MAX2(d->min_alignment_B,
            (d->usage & ISL_SURF_USAGE_STORAGE_BIT) ? isl_format_get_layout(d->format)->bpb / 8u : 1u),
        .row_pitch_B = d->row_pitch_B,
    };
    memset(surf, 0, sizeof(*surf));
    return isl_surf_init_s(dev, surf, &info);
}

static void check_layout_bounds(const struct isl_device *dev, const struct isl_surf *surf)
{
    assert(surf->size_B && surf->alignment_B && !(surf->alignment_B & (surf->alignment_B - 1)));
    struct isl_tile_info tile;
    isl_surf_get_tile_info(surf, &tile);
    assert(surf->row_pitch_B >= surf->logical_level0_px.width *
           isl_format_get_layout(surf->format)->bpb / 8u);
    assert(surf->row_pitch_B % tile.phys_extent_B.width == 0);
    assert(surf->usage & ISL_SURF_USAGE_DISABLE_AUX_BIT);
    uint64_t logical_bytes = 0;
    for (unsigned level = 0; level < surf->levels; ++level) {
        logical_bytes += (uint64_t)MAX2(surf->logical_level0_px.width >> level, 1) *
            MAX2(surf->logical_level0_px.height >> level, 1) *
            surf->logical_level0_px.array_len * isl_format_get_layout(surf->format)->bpb / 8u;
        for (unsigned layer = 0; layer < surf->logical_level0_px.array_len; ++layer) {
            uint64_t offset;
            uint32_t x, y;
            /* Original tile-base helper accepts only the first mip in a
             * miptail. The range helper below handles every tail subimage. */
            if (level <= surf->miptail_start_level) {
                isl_surf_get_image_offset_B_tile_sa(surf, level, layer, 0, &offset, &x, &y);
                assert(offset < surf->size_B);
                assert(offset % (tile.phys_extent_B.width * tile.phys_extent_B.height) == 0);
            }
            uint64_t start, end;
            isl_surf_get_image_range_B_tile(surf, level, layer, 0, &start, &end);
            assert(start < end && end <= surf->size_B);
        }
    }
    assert(surf->size_B >= logical_bytes);
    (void)dev;
}

static void check_state(const struct isl_device *dev, const struct stela_intel_image_desc *d,
                        const struct isl_surf *surf, struct stela_intel_image_view view)
{
    struct stela_intel_image_mapping map = mapping_for(dev, surf);
    for (unsigned external = 0; external < 2; ++external) {
        map.external = external;
        uint32_t actual[32], original[32];
        memset(actual, 0xa5, sizeof(actual)); memset(original, 0xa5, sizeof(original));
        assert(stela_intel_image_state(dev, d, &view, &map, actual, sizeof(actual)) == dev->ss.size);
        struct isl_view ov = {.usage = view.usage, .format = d->format,
            .base_level = view.base_level, .levels = view.levels,
            .base_array_layer = view.base_array_layer, .array_len = view.array_len,
            .swizzle = ISL_SWIZZLE_IDENTITY};
        struct isl_surf_fill_state_info state_info = {
            .surf = surf, .view = &ov, .address = map.gpu_base + map.image_offset,
            .mocs = isl_mocs(dev, view.usage, external), .robust_image_access = true,
        };
        isl_surf_fill_state_s(dev, original, &state_info);
        assert(memcmp(actual, original, sizeof(actual)) == 0);
#define READ(name) field(actual, RENDER_SURFACE_STATE_##name##_start(dev->info), \
                                RENDER_SURFACE_STATE_##name##_bits(dev->info))
        assert(READ(SurfaceType) == 1); /* Original XML SURFTYPE_2D. */
        assert(READ(SurfaceFormat) == d->format);
        assert(READ(SurfaceBaseAddress) == map.gpu_base + map.image_offset);
        assert(READ(Width) + 1 == d->width && READ(Height) + 1 == d->height);
        assert(READ(SurfacePitch) + 1 == surf->row_pitch_B);
        assert(READ(MinimumArrayElement) == view.base_array_layer);
        assert(READ(Depth) + 1 == view.array_len);
        assert(READ(SurfaceMinLOD) == view.base_level);
        assert(READ(MIPCountLOD) == (view.usage == ISL_SURF_USAGE_RENDER_TARGET_BIT ?
                                    view.base_level : view.levels - 1));
        if (dev->info->ver >= 8) assert(READ(AuxiliarySurfaceMode) == 0);
        assert(READ(NumberofMultisamples) == 0);
        assert(READ(SurfaceArray) == 1); /* Robust array views retain bounds. */
        if (view.usage != ISL_SURF_USAGE_TEXTURE_BIT)
            assert(READ(RenderTargetViewExtent) + 1 == view.array_len);
#undef READ
        ++states;
    }
}

static void layout_matrix(const struct isl_device *dev)
{
    const enum isl_format formats[] = {ISL_FORMAT_R32_UINT, ISL_FORMAT_R8G8B8A8_UNORM,
        ISL_FORMAT_R16G16B16A16_FLOAT, ISL_FORMAT_R8G8B8A8_UNORM_SRGB};
    const isl_surf_usage_flags_t roles[] = {ISL_SURF_USAGE_TEXTURE_BIT,
        ISL_SURF_USAGE_RENDER_TARGET_BIT, ISL_SURF_USAGE_STORAGE_BIT};
    for (unsigned f = 0; f < ARRAY_SIZE(formats); ++f) {
        for (unsigned r = 0; r < ARRAY_SIZE(roles); ++r) {
            for (unsigned linear = 0; linear < 2; ++linear) {
                struct stela_intel_image_desc d = description();
                d.format = formats[f]; d.usage = roles[r];
                d.storage_access = r == 2 ? STELA_INTEL_BUFFER_READ_WRITE : 0;
                d.tiling_flags = linear ? ISL_TILING_LINEAR_BIT : color_tilings();
                struct isl_surf surf = {0}, original;
                struct stela_intel_format_support fs;
                assert(stela_intel_query_format(dev, d.format, &fs) == 0);
                bool supported = r == 0 ? fs.sampling : r == 1 ? fs.rendering : fs.typed_read && fs.typed_write;
                int result = stela_intel_image_layout(dev, &d, &surf);
                if (!supported) {
                    assert(result == -95); ++refusals; continue;
                }
                assert(result == 0);
                assert(original_layout(dev, &d, &original));
                assert(memcmp(&surf, &original, sizeof(surf)) == 0);
                check_layout_bounds(dev, &surf);
                check_state(dev, &d, &surf, view_for(&d, d.usage));
                if (d.usage == ISL_SURF_USAGE_TEXTURE_BIT) {
                    struct stela_intel_image_view v = view_for(&d, d.usage);
                    v.base_level = 1; v.levels = d.levels - 1;
                    v.base_array_layer = 0; v.array_len = d.array_len;
                    check_state(dev, &d, &surf, v);
                }
                ++layouts;
            }
        }
    }
}

static void explicit_tilings(const struct isl_device *dev)
{
    const isl_tiling_flags_t flags = color_tilings();
    for (unsigned bit = 0; bit < sizeof(flags) * 8; ++bit) {
        if (!(flags & (1u << bit))) continue;
        struct stela_intel_image_desc d = description();
        d.width = 257; d.height = 129; d.levels = 9; d.array_len = 7;
        d.tiling_flags = 1u << bit;
        struct isl_surf original, surf;
        bool supported = original_layout(dev, &d, &original);
        int result = stela_intel_image_layout(dev, &d, &surf);
        if (!supported) { assert(result == -95); ++refusals; continue; }
        assert(result == 0 && memcmp(&original, &surf, sizeof(surf)) == 0);
        assert(surf.tiling == bit);
        check_layout_bounds(dev, &surf);
        check_state(dev, &d, &surf, view_for(&d, ISL_SURF_USAGE_TEXTURE_BIT));
        check_state(dev, &d, &surf, view_for(&d, ISL_SURF_USAGE_RENDER_TARGET_BIT));
        ++layouts;
    }
}

static void invalid_layouts(const struct isl_device *dev)
{
    struct isl_surf out, before;
    memset(&out, 0xa5, sizeof(out)); before = out;
    for (unsigned fault = 0; fault < 24; ++fault) {
        struct stela_intel_image_desc d = description(); d.tiling_flags = color_tilings();
        switch (fault) {
        case 0: d.width = 0; break;
        case 1: d.height = 0; break;
        case 2: d.width = 16385; break;
        case 3: d.height = UINT32_MAX; break;
        case 4: d.array_len = 0; break;
        case 5: d.array_len = 2049; break;
        case 6: d.levels = 0; break;
        case 7: d.levels = 8; break;
        case 8: d.levels = UINT32_MAX; break;
        case 9: d.min_alignment_B = 3; break;
        case 10: d.min_alignment_B = UINT32_C(1) << 31; break;
        case 11: d.dim = ISL_SURF_DIM_3D; break;
        case 12: d.samples = 4; break;
        case 13: d.depth = 2; break;
        case 14: d.usage |= ISL_SURF_USAGE_CUBE_BIT; break;
        case 15: d.tiling_flags = ISL_TILING_HIZ_BIT; break;
        case 16: d.format = ISL_FORMAT_BC1_UNORM; break;
        case 17: d.format = ISL_FORMAT_RAW; break;
        case 18: d.format = (enum isl_format)-1; break;
        case 19: d.backing = 0; break;
        case 20: d.storage_access = STELA_INTEL_BUFFER_READ; break;
        case 21: d.usage = ISL_SURF_USAGE_STORAGE_BIT; d.storage_access = 4; break;
        case 22: d.row_pitch_B = 1; break;
        case 23: d.row_pitch_B = UINT32_MAX; break;
        }
        assert(stela_intel_image_layout(dev, &d, &out) < 0);
        assert(memcmp(&out, &before, sizeof(out)) == 0); ++refusals;
    }
}

static void invalid_views(const struct isl_device *dev)
{
    struct stela_intel_image_desc d = description(); d.tiling_flags = color_tilings();
    struct isl_surf surf; assert(stela_intel_image_layout(dev, &d, &surf) == 0);
    uint32_t out[32], before[32]; memset(out, 0xa5, sizeof(out)); memcpy(before, out, sizeof(out));
    for (unsigned fault = 0; fault < 24; ++fault) {
        struct stela_intel_image_view v = view_for(&d, ISL_SURF_USAGE_TEXTURE_BIT);
        struct stela_intel_image_mapping m = mapping_for(dev, &surf);
        switch (fault) {
        case 0: v.levels = 0; break;
        case 1: v.base_level = d.levels; break;
        case 2: v.levels = UINT32_MAX; break;
        case 3: v.array_len = 0; break;
        case 4: v.base_array_layer = d.array_len; break;
        case 5: v.array_len = UINT32_MAX; break;
        case 6: v.access = STELA_INTEL_BUFFER_WRITE; break;
        case 7: v.access = 0; break;
        case 8: m.available_access = STELA_INTEL_BUFFER_WRITE; break;
        case 9: m.available_access = 7; break;
        case 10: m.mapped_bytes = m.allocation_bytes - 1; break;
        case 11: m.allocation_bytes--; break;
        case 12: m.image_offset = UINT64_MAX; break;
        case 13: m.gpu_base = UINT64_MAX - 16; break;
        case 14: m.gpu_base++; break;
        case 15: m.address_bits = 64; break;
        case 16: m.gpu_base = UINT64_C(1) << (m.address_bits - (m.address_bits == 32 ? 0 : 1)); break;
        case 17: m.backing = 0; break;
        case 18: v.usage = ISL_SURF_USAGE_TEXTURE_BIT | ISL_SURF_USAGE_RENDER_TARGET_BIT; break;
        case 19: v.usage = ISL_SURF_USAGE_STORAGE_BIT; break;
        case 20: v.usage = ISL_SURF_USAGE_RENDER_TARGET_BIT; v.access = STELA_INTEL_BUFFER_WRITE;
                 v.base_level = 0; v.levels = 2; break;
        case 21: m.mapped_bytes = 0; break;
        case 22: m.allocation_bytes = 0; break;
        case 23: m.image_offset = m.allocation_bytes; break;
        }
        assert(stela_intel_image_state(dev, &d, &v, &m, out, sizeof(out)) < 0);
        assert(memcmp(out, before, sizeof(out)) == 0); ++refusals;
    }
    struct stela_intel_image_view v = view_for(&d, ISL_SURF_USAGE_TEXTURE_BIT);
    struct stela_intel_image_mapping m = mapping_for(dev, &surf);
    assert(stela_intel_image_state(dev, &d, &v, &m, out, dev->ss.size - 1) == -28);
    assert(stela_intel_image_state(dev, &d, &v, &m, (char *)out + 1, sizeof(out) - 1) == -22);
    assert(memcmp(out, before, sizeof(out)) == 0);
    /* Both canonical endpoints cannot license crossing the canonical hole. */
    m.gpu_base = m.address_bits == 32 ? UINT64_C(0x100000000) - m.mapped_bytes :
        (UINT64_C(1) << 47) - m.mapped_bytes;
    m.gpu_base &= ~((uint64_t)surf.alignment_B - 1);
    assert(stela_intel_image_state(dev, &d, &v, &m, out, sizeof(out)) == dev->ss.size);
    m.mapped_bytes += surf.alignment_B + 1;
    assert(stela_intel_image_state(dev, &d, &v, &m, out, sizeof(out)) == -22);
    if (dev->info->ver >= 8) {
        m = mapping_for(dev, &surf); m.gpu_base = UINT64_C(0xffff800000400000);
        assert(stela_intel_image_state(dev, &d, &v, &m, out, sizeof(out)) == dev->ss.size);
        if (dev->info->ver >= 20) {
            m.address_bits = 57; m.gpu_base = UINT64_C(0x0012345600400000);
            assert(stela_intel_image_state(dev, &d, &v, &m, out, sizeof(out)) == dev->ss.size);
            m.gpu_base = UINT64_C(0xff00000000400000);
            assert(stela_intel_image_state(dev, &d, &v, &m, out, sizeof(out)) == dev->ss.size);
        }
    }
}

static void dimensional_edges(const struct isl_device *dev)
{
    const unsigned extents[][3] = {{1, 1, 1}, {16384, 1, 1}, {1, 16384, 1},
        {3, 5, 2048}, {257, 129, 7}};
    for (unsigned i = 0; i < ARRAY_SIZE(extents); ++i) {
        struct stela_intel_image_desc d = description(); d.tiling_flags = color_tilings();
        d.width = extents[i][0]; d.height = extents[i][1]; d.array_len = extents[i][2];
        unsigned max_dim = MAX2(d.width, d.height); d.levels = 1;
        while (max_dim >>= 1) ++d.levels;
        struct isl_surf surf; assert(stela_intel_image_layout(dev, &d, &surf) == 0);
        check_layout_bounds(dev, &surf);
        check_state(dev, &d, &surf, view_for(&d, ISL_SURF_USAGE_TEXTURE_BIT));
        check_state(dev, &d, &surf, view_for(&d, ISL_SURF_USAGE_RENDER_TARGET_BIT));
        ++layouts;
    }
    /* Linear caller pitch is exact and sampler overfetch padding is retained. */
    struct stela_intel_image_desc d = description();
    d.usage = ISL_SURF_USAGE_TEXTURE_BIT; d.width = 3; d.height = 1;
    d.levels = d.array_len = 1; d.tiling_flags = ISL_TILING_LINEAR_BIT; d.row_pitch_B = 16;
    struct isl_surf surf; assert(stela_intel_image_layout(dev, &d, &surf) == 0);
    assert(surf.row_pitch_B == 16 && surf.size_B > 16);
    struct stela_intel_image_view v = view_for(&d, d.usage);
    struct stela_intel_image_mapping m = mapping_for(dev, &surf);
    uint32_t state[32]; m.allocation_bytes = m.image_offset + 16;
    assert(stela_intel_image_state(dev, &d, &v, &m, state, sizeof(state)) == -22);
    ++refusals;
    /* The initialized ISL default is not proof of fault-safe scratch mapping. */
    struct isl_device no_padding = *dev; no_padding.requires_padding = false;
    struct isl_surf before = surf;
    assert(stela_intel_image_layout(&no_padding, &d, &surf) == -95);
    assert(memcmp(&surf, &before, sizeof(surf)) == 0); ++refusals;
    /* Storage-only linear access still requires element-size alignment. */
    d.format = ISL_FORMAT_R32_UINT; d.usage = ISL_SURF_USAGE_STORAGE_BIT;
    d.storage_access = STELA_INTEL_BUFFER_READ_WRITE; d.row_pitch_B = 0;
    assert(stela_intel_image_layout(dev, &d, &surf) == 0);
    assert(surf.alignment_B >= 4);
    v = view_for(&d, d.usage); m = mapping_for(dev, &surf);
    m.gpu_base += 1;
    assert(stela_intel_image_state(dev, &d, &v, &m, state, sizeof(state)) == -22); ++refusals;
    m = mapping_for(dev, &surf); m.available_access = STELA_INTEL_BUFFER_READ;
    assert(stela_intel_image_state(dev, &d, &v, &m, state, sizeof(state)) == -22); ++refusals;
    v.access = STELA_INTEL_BUFFER_READ;
    assert(stela_intel_image_state(dev, &d, &v, &m, state, sizeof(state)) == dev->ss.size);
    v.access = STELA_INTEL_BUFFER_WRITE; m.available_access = STELA_INTEL_BUFFER_WRITE;
    assert(stela_intel_image_state(dev, &d, &v, &m, state, sizeof(state)) == dev->ss.size);
}

static void device_refusals(void)
{
    struct stela_intel_image_desc d = description();
    struct isl_surf out, before; memset(&out, 0xa5, sizeof(out)); before = out;
    assert(stela_intel_image_layout(NULL, &d, &out) == -22);
    struct isl_device empty = {0};
    assert(stela_intel_image_layout(&empty, &d, &out) == -22);
    const char *old[] = {"brw", "g4x", "ilk", "snb"};
    for (unsigned i = 0; i < ARRAY_SIZE(old); ++i) {
        struct intel_device_info info;
        int pci = intel_device_name_to_pci_device_id(old[i]);
        assert(pci >= 0 && intel_get_device_info_for_build(pci, &info));
        struct isl_device dev = {0}; isl_device_init(&dev, &info); dev.requires_padding = true;
        assert(stela_intel_image_layout(&dev, &d, &out) == -95);
        assert(memcmp(&out, &before, sizeof(out)) == 0); ++refusals;
    }
}

int main(void)
{
    device_refusals();
    const char *platforms[] = {"ivb", "byt", "hsw", "bdw", "chv", "skl", "bxt",
        "icl", "tgl", "dg1", "dg2", "mtl", "arl", "lnl", "bmg", "ptl", "nvl-u", "nvl"};
    for (unsigned p = 0; p < ARRAY_SIZE(platforms); ++p) {
        struct intel_device_info info;
        int pci = intel_device_name_to_pci_device_id(platforms[p]);
        assert(pci >= 0 && intel_get_device_info_for_build(pci, &info));
        struct isl_device dev = {0}; isl_device_init(&dev, &info);
        /* Original ANV policy without its real scratch-page mapping. */
        dev.requires_padding = true;
        layout_matrix(&dev); explicit_tilings(&dev); invalid_layouts(&dev);
        invalid_views(&dev); dimensional_edges(&dev);
        printf("STELA_INTEL_IMAGE target=%s pci=0x%x verx10=%u layouts=%u states=%u refusals=%u hardware_execution=false\n",
               platforms[p], pci, info.verx10, layouts, states, refusals);
    }
    printf("Hosted Intel image original ISL layout/state and independent bounds: %u layouts, %u states, %u refusals passed\n",
           layouts, states, refusals);
    return 0;
}
