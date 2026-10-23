/* SPDX-License-Identifier: MIT */
#include "image.h"
#include "intel/genxml/genX_bits.h"

static bool fits(uint64_t value, unsigned bits)
{
    return bits && (bits >= 64 || value < (UINT64_C(1) << bits));
}

static bool rights(uint32_t access)
{
    return access && !(access & ~STELA_INTEL_BUFFER_READ_WRITE);
}

static bool canonical(uint64_t address, uint32_t bits)
{
    if (bits == 32) return address <= UINT32_MAX;
    uint64_t mask = (UINT64_C(1) << bits) - 1;
    return (address & ~mask) == ((address & (UINT64_C(1) << (bits - 1))) ? ~mask : 0);
}

static bool mapping_valid(const struct stela_intel_image_mapping *m)
{
    if ((m->address_bits != 32 && m->address_bits != 48 && m->address_bits != 57) ||
        !m->mapped_bytes || !m->allocation_bytes || m->allocation_bytes > m->mapped_bytes ||
        !rights(m->available_access) || !canonical(m->gpu_base, m->address_bits) ||
        m->mapped_bytes - 1 > UINT64_MAX - m->gpu_base)
        return false;
    uint64_t end = m->gpu_base + m->mapped_bytes - 1;
    return canonical(end, m->address_bits) &&
           (m->address_bits == 32 || !((m->gpu_base ^ end) &
                                      (UINT64_C(1) << (m->address_bits - 1))));
}

int stela_intel_image_layout(const struct isl_device *dev,
                             const struct stela_intel_image_desc *input, struct isl_surf *out)
{
    if (!input || !out || !dev || !dev->info || !dev->surf_fill_state_s)
        return -22;
    const struct stela_intel_image_desc d = *input;
    struct stela_intel_format_support support;
    int err = stela_intel_query_format(dev, d.format, &support);
    if (err) return err;
    if (dev->info->ver < 7 || d.dim != ISL_SURF_DIM_2D || d.depth != 1 || d.samples != 1 ||
        d.backing != STELA_INTEL_IMAGE_UNCOMPRESSED)
        return -95;
    const isl_surf_usage_flags_t roles = ISL_SURF_USAGE_TEXTURE_BIT |
        ISL_SURF_USAGE_STORAGE_BIT | ISL_SURF_USAGE_RENDER_TARGET_BIT;
    const isl_tiling_flags_t tilings = ISL_TILING_LINEAR_BIT | ISL_TILING_X_BIT |
        ISL_TILING_Y0_BIT | ISL_TILING_SKL_Yf_BIT | ISL_TILING_SKL_Ys_BIT |
        ISL_TILING_ICL_Yf_BIT | ISL_TILING_ICL_Ys_BIT | ISL_TILING_4_BIT |
        ISL_TILING_64_BIT | ISL_TILING_64_XE2_BIT;
    if (!d.usage || (d.usage & ~roles) || !d.tiling_flags || (d.tiling_flags & ~tilings))
        return -95;
    /* Original ANV selects requires_padding = !has_scratch_page. No owner
     * contract for the alternate fault-safe scratch-page VM exists here. */
    if ((d.usage & ISL_SURF_USAGE_TEXTURE_BIT) && !dev->requires_padding)
        return -95;
    const struct isl_format_layout *fmt = isl_format_get_layout(d.format);
    if (fmt->txc != ISL_TXC_NONE || fmt->bw != 1 || fmt->bh != 1 || fmt->bd != 1 ||
        (fmt->colorspace != ISL_COLORSPACE_LINEAR && fmt->colorspace != ISL_COLORSPACE_SRGB) ||
        (fmt->bpb != 8 && fmt->bpb != 16 && fmt->bpb != 32 && fmt->bpb != 64 && fmt->bpb != 128))
        return -95;
    if (((d.usage & ISL_SURF_USAGE_TEXTURE_BIT) && !support.sampling) ||
        ((d.usage & ISL_SURF_USAGE_RENDER_TARGET_BIT) && !support.rendering))
        return -95;
    if (d.usage & ISL_SURF_USAGE_STORAGE_BIT) {
        if (!rights(d.storage_access)) return -22;
        if (((d.storage_access & STELA_INTEL_BUFFER_READ) && !support.typed_read) ||
            ((d.storage_access & STELA_INTEL_BUFFER_WRITE) && !support.typed_write))
            return -95;
    } else if (d.storage_access) {
        return -22;
    }
    /* Original Iris/Crocus Gen7+ physical limits. Bound arithmetic before
     * assertion-heavy ISL helpers, then also check original XML field widths. */
    if (!d.width || !d.height || d.width > 16384 || d.height > 16384 ||
        !d.array_len || d.array_len > 2048 || !d.levels ||
        (d.min_alignment_B && (d.min_alignment_B & (d.min_alignment_B - 1))) ||
        d.min_alignment_B > (UINT32_C(1) << 30))
        return -22;
    uint32_t max_dim = MAX2(d.width, d.height);
    unsigned max_levels = 1;
    while (max_dim >>= 1) ++max_levels;
    if (d.levels > max_levels ||
        !fits(d.width - 1, RENDER_SURFACE_STATE_Width_bits(dev->info)) ||
        !fits(d.height - 1, RENDER_SURFACE_STATE_Height_bits(dev->info)) ||
        !fits(d.array_len - 1, RENDER_SURFACE_STATE_Depth_bits(dev->info)))
        return -22;
    const struct isl_surf_init_info init = {
        .dim = d.dim, .format = d.format, .width = d.width, .height = d.height,
        .depth = d.depth, .levels = d.levels, .array_len = d.array_len, .samples = d.samples,
        /* isl_calc_base_alignment documents element alignment for typed
         * dataport accesses as well as rendering. Make it an allocation
         * requirement even for a storage-only linear surface. */
        .min_alignment_B = MAX2(d.min_alignment_B,
            (d.usage & ISL_SURF_USAGE_STORAGE_BIT) ? fmt->bpb / 8u : 1u),
        .row_pitch_B = d.row_pitch_B,
        .usage = d.usage | ISL_SURF_USAGE_DISABLE_AUX_BIT, .tiling_flags = d.tiling_flags,
    };
    struct isl_surf surf = {0};
    if (!isl_surf_init_s(dev, &surf, &init)) return -95;
    if (!surf.size_B || !surf.alignment_B || !surf.row_pitch_B ||
        !fits(surf.row_pitch_B - 1, RENDER_SURFACE_STATE_SurfacePitch_bits(dev->info)))
        return -95;
    *out = surf;
    return 0;
}

int stela_intel_image_state(const struct isl_device *dev,
                            const struct stela_intel_image_desc *input,
                            const struct stela_intel_image_view *view_input,
                            const struct stela_intel_image_mapping *mapping_input,
                            void *state, size_t capacity)
{
    if (!input || !view_input || !mapping_input || !state ||
        (uintptr_t)state % _Alignof(uint32_t)) return -22;
    const struct stela_intel_image_desc d = *input;
    const struct stela_intel_image_view v = *view_input;
    const struct stela_intel_image_mapping m = *mapping_input;
    struct isl_surf surf;
    int err = stela_intel_image_layout(dev, &d, &surf);
    if (err) return err;
    if (v.usage != ISL_SURF_USAGE_TEXTURE_BIT && v.usage != ISL_SURF_USAGE_STORAGE_BIT &&
        v.usage != ISL_SURF_USAGE_RENDER_TARGET_BIT) return -95;
    if (!(v.usage & d.usage) || !rights(v.access) ||
        (v.usage == ISL_SURF_USAGE_TEXTURE_BIT && v.access != STELA_INTEL_BUFFER_READ) ||
        (v.usage == ISL_SURF_USAGE_RENDER_TARGET_BIT && !(v.access & STELA_INTEL_BUFFER_WRITE)) ||
        (v.usage == ISL_SURF_USAGE_STORAGE_BIT && (v.access & ~d.storage_access)) ||
        !v.levels || v.base_level >= surf.levels || v.levels > surf.levels - v.base_level ||
        (v.usage != ISL_SURF_USAGE_TEXTURE_BIT && v.levels != 1) ||
        !v.array_len || v.base_array_layer >= surf.logical_level0_px.array_len ||
        v.array_len > surf.logical_level0_px.array_len - v.base_array_layer ||
        !fits(v.base_array_layer, RENDER_SURFACE_STATE_MinimumArrayElement_bits(dev->info)) ||
        !mapping_valid(&m) || (v.access & ~m.available_access) ||
        m.image_offset > m.allocation_bytes || surf.size_B > m.allocation_bytes - m.image_offset ||
        (RENDER_SURFACE_STATE_SurfaceBaseAddress_bits(dev->info) == 32 && m.address_bits != 32))
        return -22;
    if (m.backing != STELA_INTEL_IMAGE_UNCOMPRESSED) return -95;
    const uint64_t address = m.gpu_base + m.image_offset;
    if (address % surf.alignment_B) return -22;
    if (capacity < dev->ss.size) return -28;
    const struct isl_view view = {
        .usage = v.usage, .format = d.format,
        .base_level = v.base_level, .levels = v.levels,
        .base_array_layer = v.base_array_layer, .array_len = v.array_len,
        .swizzle = ISL_SWIZZLE_IDENTITY,
    };
    const struct isl_surf_fill_state_info info = {
        .surf = &surf, .view = &view, .address = address,
        .mocs = isl_mocs(dev, v.usage, m.external),
        .aux_usage = ISL_AUX_USAGE_NONE, .robust_image_access = true,
    };
    isl_surf_fill_state_s(dev, state, &info);
    return dev->ss.size;
}
