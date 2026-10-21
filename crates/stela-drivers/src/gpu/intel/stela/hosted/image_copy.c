/* SPDX-License-Identifier: MIT */
#include "image_copy.h"
#include <limits.h>
#include <string.h>

struct copy_plan {
    struct isl_surf surf;
    struct stela_intel_image_copy_requirements required;
    uint32_t x1, x2, y1, y2;
    uint64_t linear_image_offset;
};

static int prepare(const struct isl_device *dev, const struct stela_intel_image_desc *d,
                    const struct stela_intel_image_rectangle *r, uint32_t pitch,
                    struct copy_plan *p)
{
    int err = stela_intel_image_layout(dev, d, &p->surf);
    if (err) return err;
    switch (p->surf.tiling) {
    case ISL_TILING_LINEAR: case ISL_TILING_X: case ISL_TILING_Y0: case ISL_TILING_4:
        break;
    default: return -95;
    }
    if (r->level >= p->surf.levels || r->layer >= p->surf.logical_level0_px.array_len ||
        !r->width || !r->height || !pitch || pitch > INT32_MAX)
        return -22;
    /* Original Y0/Tile4 routines evaluate 2/3/4 * signed int32 pitch before
     * pointer addition. Bound that actual arithmetic, not just its ABI type. */
    if ((p->surf.tiling == ISL_TILING_Y0 || p->surf.tiling == ISL_TILING_4) && pitch > INT32_MAX / 4)
        return -22;
    uint32_t width = MAX2(d->width >> r->level, 1), height = MAX2(d->height >> r->level, 1);
    if (r->x >= width || r->width > width - r->x ||
        r->y >= height || r->height > height - r->y)
        return -22;
    uint32_t cpp = isl_format_get_layout(d->format)->bpb / 8;
    uint64_t row_bytes = (uint64_t)r->width * cpp;
    if (row_bytes > pitch) return -22;
    uint32_t x0, y0, z0, a0;
    isl_surf_get_image_offset_el(&p->surf, r->level, r->layer, 0, &x0, &y0, &z0, &a0);
    if (z0 || a0) return -95;
    /* Same byte/row coordinate conversion as original Iris tile_extents(). */
    uint64_t x1 = ((uint64_t)x0 + r->x) * cpp, x2 = x1 + row_bytes;
    uint64_t y1 = (uint64_t)y0 + r->y, y2 = y1 + r->height;
    struct isl_tile_info tile;
    isl_surf_get_tile_info(&p->surf, &tile);
    if (x2 > p->surf.row_pitch_B || x2 > UINT32_MAX - tile.phys_extent_B.width ||
        y2 > UINT32_MAX - tile.phys_extent_B.height)
        return -22;
    p->x1 = x1; p->x2 = x2; p->y1 = y1; p->y2 = y2;
    uint64_t start, end;
    uint32_t in_x, in_y, in_z, in_a;
    isl_tiling_get_intratile_range_el(p->surf.tiling, p->surf.dim, p->surf.msaa_layout,
        isl_format_get_layout(d->format)->bpb, p->surf.samples,
        p->surf.row_pitch_B, p->surf.array_pitch_el_rows,
        x0 + r->x, y0 + r->y, 0, 0,
        (struct isl_extent4d){.w = r->width, .h = r->height, .d = 1, .a = 1},
        &start, &end, &in_x, &in_y, &in_z, &in_a);
    if (start >= end || end > p->surf.size_B) return -22;
    p->linear_image_offset = start;
    p->required = (struct stela_intel_image_copy_requirements){
        .image_bytes = p->surf.size_B, .image_cpu_span = p->surf.size_B,
        .row_bytes = row_bytes, .tiling = p->surf.tiling,
        .linear_suffix = (uint64_t)(r->height - 1) * pitch + row_bytes,
    };
    if (p->surf.tiling != ISL_TILING_LINEAR) {
        uint64_t tile_bytes = (uint64_t)tile.phys_extent_B.width * tile.phys_extent_B.height;
        if (tile_bytes > UINT64_MAX - p->surf.size_B) return -22;
        p->required.image_cpu_span += tile_bytes;
        p->required.linear_prefix = x1 % tile.phys_extent_B.width +
                                   (y1 % tile.phys_extent_B.height) * pitch;
        p->required.linear_suffix = (uint64_t)r->height * pitch + row_bytes;
    }
    if (p->required.image_cpu_span > PTRDIFF_MAX || p->required.linear_prefix > PTRDIFF_MAX ||
        p->required.linear_suffix > PTRDIFF_MAX - p->required.linear_prefix)
        return -22;
    return 0;
}

int stela_intel_image_copy_query(const struct isl_device *dev,
                                const struct stela_intel_image_desc *image,
                                const struct stela_intel_image_rectangle *rect,
                                uint32_t pitch, struct stela_intel_image_copy_requirements *out)
{
    if (!image || !rect || !out) return -22;
    const struct stela_intel_image_desc d = *image;
    const struct stela_intel_image_rectangle r = *rect;
    struct copy_plan plan;
    int err = prepare(dev, &d, &r, pitch, &plan);
    if (err) return err;
    *out = plan.required;
    return 0;
}

static bool valid_span(const struct stela_intel_cpu_copy_span *s)
{
    return s->base && s->mapped_bytes && s->allocation_bytes &&
        s->allocation_bytes <= s->mapped_bytes && s->mapped_bytes <= PTRDIFF_MAX &&
        s->mapped_bytes <= UINTPTR_MAX - (uintptr_t)s->base &&
        s->offset <= s->allocation_bytes && s->access &&
        !(s->access & ~STELA_INTEL_BUFFER_READ_WRITE);
}

int stela_intel_image_copy(const struct isl_device *dev,
                           const struct stela_intel_image_desc *image_input,
                           const struct stela_intel_image_rectangle *rect_input,
                           uint32_t pitch,
                           const struct stela_intel_cpu_copy_span *image_input_span,
                           const struct stela_intel_cpu_copy_span *linear_input_span,
                           enum stela_intel_cpu_copy_swizzle swizzle,
                           enum stela_intel_image_copy_direction direction)
{
    if (!image_input || !rect_input || !image_input_span || !linear_input_span) return -22;
    const struct stela_intel_image_desc d = *image_input;
    const struct stela_intel_image_rectangle r = *rect_input;
    const struct stela_intel_cpu_copy_span image = *image_input_span, linear = *linear_input_span;
    struct copy_plan p;
    int err = prepare(dev, &d, &r, pitch, &p);
    if (err) return err;
    if (swizzle != STELA_INTEL_CPU_COPY_NO_BIT6 ||
        image.mapping != STELA_INTEL_CPU_COPY_RAW_WB || linear.mapping != STELA_INTEL_CPU_COPY_RAW_WB)
        return -95;
    if (!valid_span(&image) || !valid_span(&linear) ||
        (direction != STELA_INTEL_IMAGE_UPLOAD && direction != STELA_INTEL_IMAGE_READBACK) ||
        p.required.image_cpu_span > image.allocation_bytes - image.offset ||
        linear.offset < p.required.linear_prefix ||
        p.required.linear_suffix > linear.allocation_bytes - linear.offset)
        return -22;
    uint32_t image_access = direction == STELA_INTEL_IMAGE_UPLOAD ? STELA_INTEL_BUFFER_WRITE :
                                                                    STELA_INTEL_BUFFER_READ;
    uint32_t linear_access = direction == STELA_INTEL_IMAGE_UPLOAD ? STELA_INTEL_BUFFER_READ :
                                                                     STELA_INTEL_BUFFER_WRITE;
    if (!(image.access & image_access) || !(linear.access & linear_access)) return -22;
    uintptr_t image_start = (uintptr_t)image.base, linear_start = (uintptr_t)linear.base;
    if (image_start < linear_start + linear.allocation_bytes &&
        linear_start < image_start + image.allocation_bytes)
        return -22;
    char *image_bytes = (char *)image.base + image.offset;
    char *linear_bytes = (char *)linear.base + linear.offset;
    if (p.surf.tiling == ISL_TILING_LINEAR) {
        for (uint32_t row = 0; row < r.height; ++row) {
            char *i = image_bytes + p.linear_image_offset + (uint64_t)row * p.surf.row_pitch_B;
            char *l = linear_bytes + (uint64_t)row * pitch;
            if (direction == STELA_INTEL_IMAGE_UPLOAD) memcpy(i, l, p.required.row_bytes);
            else memcpy(l, i, p.required.row_bytes);
        }
    } else if (direction == STELA_INTEL_IMAGE_UPLOAD) {
        isl_memcpy_linear_to_tiled(p.x1, p.x2, p.y1, p.y2, image_bytes, linear_bytes,
            p.surf.row_pitch_B, pitch, false, p.surf.tiling, ISL_MEMCPY);
    } else {
        isl_memcpy_tiled_to_linear(p.x1, p.x2, p.y1, p.y2, linear_bytes, image_bytes,
            pitch, p.surf.row_pitch_B, false, p.surf.tiling, ISL_MEMCPY);
    }
    return 0;
}
