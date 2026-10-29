/* SPDX-License-Identifier: MIT */
#include "../hosted/image_copy.h"
#include "intel/dev/intel_device_info.h"
#include "compiler/tests/targets/intel.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned copies, refusals, admitted_layouts;

static struct stela_intel_image_desc description(enum isl_format format, enum isl_tiling tiling)
{
    return (struct stela_intel_image_desc){
        .dim = ISL_SURF_DIM_2D, .format = format,
        .width = 257, .height = 73, .depth = 1, .levels = 9, .array_len = 3, .samples = 1,
        .usage = ISL_SURF_USAGE_TEXTURE_BIT, .tiling_flags = 1u << tiling,
        .backing = STELA_INTEL_IMAGE_UNCOMPRESSED,
    };
}

static struct stela_intel_cpu_copy_span span(void *base, size_t size, size_t offset)
{
    return (struct stela_intel_cpu_copy_span){
        .base = base, .mapped_bytes = size, .allocation_bytes = size, .offset = offset,
        .access = STELA_INTEL_BUFFER_READ_WRITE, .mapping = STELA_INTEL_CPU_COPY_RAW_WB,
    };
}

/* Independent per-byte coordinate oracle: original ISL swizzle metadata is
 * interpreted bit by bit, independently of the retained tiled memcpy's
 * column/cell/span copy algorithms. This runs only in the test, never in the
 * production upload path. It is not an upload/readback roundtrip oracle. */
static size_t coordinate(const struct isl_surf *s, const struct stela_intel_image_rectangle *r,
                          unsigned byte_x, unsigned row)
{
    unsigned cpp = isl_format_get_layout(s->format)->bpb / 8;
    uint32_t x0, y0, z, a;
    isl_surf_get_image_offset_el(s, r->level, r->layer, 0, &x0, &y0, &z, &a);
    assert(!z && !a);
    uint64_t x = (uint64_t)(x0 + r->x) * cpp + byte_x, y = (uint64_t)y0 + r->y + row;
    uint64_t result;
    if (s->tiling == ISL_TILING_LINEAR) {
        result = y * s->row_pitch_B + x;
    } else {
        struct isl_tile_info tile; isl_surf_get_tile_info(s, &tile);
        assert(tile.swiz_count == 12);
        uint64_t tile_bytes = tile.phys_extent_B.width * tile.phys_extent_B.height;
        uint64_t tile_id = (y / tile.phys_extent_B.height) *
            (s->row_pitch_B / tile.phys_extent_B.width) + x / tile.phys_extent_B.width;
        uint64_t values[] = {x % tile.phys_extent_B.width, y % tile.phys_extent_B.height, 0, 0};
        uint64_t offset = 0;
        for (unsigned bit = 0; bit < tile.swiz_count; ++bit) {
            unsigned component = ISL_ADDR_SWIZ_COMPONENT(tile.swiz[bit]);
            unsigned index = ISL_ADDR_SWIZ_INDEX(tile.swiz[bit]);
            assert(component < ARRAY_SIZE(values));
            offset |= ((values[component] >> index) & 1) << bit;
        }
        assert(offset < tile_bytes);
        result = tile_id * tile_bytes + offset;
    }
    assert(result < s->size_B);
    return result;
}

static unsigned char pattern(uint64_t index)
{
    index ^= index >> 11; index *= UINT64_C(0x9e3779b185ebca87);
    index ^= index >> 29; return index ^ (index >> 8) ^ (index >> 16);
}

static void one_rectangle(const struct isl_device *dev, const struct stela_intel_image_desc *d,
                           const struct isl_surf *s, struct stela_intel_image_rectangle r)
{
    unsigned cpp = isl_format_get_layout(d->format)->bpb / 8;
    uint32_t pitch = r.width * cpp + 17; /* Deliberately unaligned ordinary memcpy. */
    struct stela_intel_image_copy_requirements q;
    assert(stela_intel_image_copy_query(dev, d, &r, pitch, &q) == 0);
    assert(q.image_bytes == s->size_B && q.tiling == s->tiling && q.row_bytes == r.width * cpp);
    uint32_t x, y, z, a;
    isl_surf_get_image_offset_el(s, r.level, r.layer, 0, &x, &y, &z, &a);
    assert(!z && !a);
    if (s->tiling == ISL_TILING_LINEAR) {
        assert(q.image_cpu_span == s->size_B && q.linear_prefix == 0);
        assert(q.linear_suffix == (uint64_t)(r.height - 1) * pitch + q.row_bytes);
    } else {
        struct isl_tile_info tile; isl_surf_get_tile_info(s, &tile);
        assert(q.image_cpu_span == s->size_B +
            tile.phys_extent_B.width * tile.phys_extent_B.height);
        assert(q.linear_prefix == ((x + r.x) * cpp) % tile.phys_extent_B.width +
            ((y + r.y) % tile.phys_extent_B.height) * pitch);
        assert(q.linear_suffix == (uint64_t)r.height * pitch + q.row_bytes);
    }
    /* One real allocation includes all prefix/guard bytes; no pointer before
     * an allocation is fabricated. No production allocator is used or added. */
    size_t image_offset = 19, image_size = image_offset + q.image_cpu_span;
    size_t linear_offset = q.linear_prefix, linear_size = linear_offset + q.linear_suffix;
    unsigned char *img = malloc(image_size), *lin = malloc(linear_size);
    unsigned char *expected_img = malloc(image_size), *expected_lin = malloc(linear_size);
    assert(img && lin && expected_img && expected_lin);
    struct stela_intel_cpu_copy_span image = span(img, image_size, image_offset);
    struct stela_intel_cpu_copy_span linear = span(lin, linear_size, linear_offset);
    memset(img, 0xa5, image_size); memset(expected_img, 0xa5, image_size);
    for (size_t i = 0; i < linear_size; ++i) lin[i] = pattern(i + r.level * 13 + r.layer * 107);
    memcpy(expected_lin, lin, linear_size);
    for (unsigned row = 0; row < r.height; ++row)
        for (unsigned byte = 0; byte < q.row_bytes; ++byte)
            expected_img[image_offset + coordinate(s, &r, byte, row)] =
                lin[linear_offset + row * pitch + byte];
    image.access = STELA_INTEL_BUFFER_WRITE; linear.access = STELA_INTEL_BUFFER_READ;
    assert(stela_intel_image_copy(dev, d, &r, pitch, &image, &linear,
        STELA_INTEL_CPU_COPY_NO_BIT6, STELA_INTEL_IMAGE_UPLOAD) == 0);
    assert(memcmp(img, expected_img, image_size) == 0); /* All other image bytes untouched. */
    assert(memcmp(lin, expected_lin, linear_size) == 0); /* Source, including prefix, untouched. */
    ++copies;

    /* Readback input is independently prepared by physical byte index; it is
     * not the upload result. Sentinel checks cover the entire linear span. */
    for (size_t i = 0; i < image_size; ++i) img[i] = pattern(i + 0xace1);
    memcpy(expected_img, img, image_size);
    memset(lin, 0x5a, linear_size); memset(expected_lin, 0x5a, linear_size);
    for (unsigned row = 0; row < r.height; ++row)
        for (unsigned byte = 0; byte < q.row_bytes; ++byte)
            expected_lin[linear_offset + row * pitch + byte] =
                img[image_offset + coordinate(s, &r, byte, row)];
    image.access = STELA_INTEL_BUFFER_READ; linear.access = STELA_INTEL_BUFFER_WRITE;
    assert(stela_intel_image_copy(dev, d, &r, pitch, &image, &linear,
        STELA_INTEL_CPU_COPY_NO_BIT6, STELA_INTEL_IMAGE_READBACK) == 0);
    assert(memcmp(lin, expected_lin, linear_size) == 0);
    assert(memcmp(img, expected_img, image_size) == 0);
    ++copies;
    free(expected_lin); free(expected_img); free(lin); free(img);
}

static void all_rectangles(const struct isl_device *dev, const struct stela_intel_image_desc *d,
                            const struct isl_surf *s)
{
    const struct stela_intel_image_rectangle rectangles[] = {
        {.width=d->width, .height=d->height},
        {.layer=1, .x=1, .y=1, .width=d->width-2, .height=d->height-2},
        {.layer=2, .x=d->width-1, .y=d->height-1, .width=1, .height=1},
        {.level=1, .layer=2, .width=d->width>>1, .height=d->height>>1},
        {.level=2, .layer=1, .x=3, .y=2, .width=(d->width>>2)-3, .height=(d->height>>2)-2},
        {.level=8, .layer=2, .width=1, .height=1},
    };
    for (unsigned i = 0; i < ARRAY_SIZE(rectangles); ++i) one_rectangle(dev, d, s, rectangles[i]);
}

static void invalid_copies(const struct isl_device *dev, const struct stela_intel_image_desc *d)
{
    struct stela_intel_image_rectangle r = {.layer=1, .x=1, .y=1, .width=33, .height=13};
    struct stela_intel_image_copy_requirements q;
    uint32_t pitch = 33 * isl_format_get_layout(d->format)->bpb / 8 + 17;
    assert(stela_intel_image_copy_query(dev, d, &r, pitch, &q) == 0);
    size_t image_size = 16 + q.image_cpu_span, linear_size = q.linear_prefix + q.linear_suffix + 16;
    unsigned char *img = malloc(image_size), *lin = malloc(linear_size);
    unsigned char *before_img = malloc(image_size), *before_lin = malloc(linear_size);
    assert(img && lin && before_img && before_lin);
    memset(img, 0xa5, image_size); memset(lin, 0x5a, linear_size);
    memcpy(before_img, img, image_size); memcpy(before_lin, lin, linear_size);
    const struct stela_intel_cpu_copy_span image = span(img, image_size, 16);
    const struct stela_intel_cpu_copy_span linear = span(lin, linear_size, q.linear_prefix);
    for (unsigned fault = 0; fault < 31; ++fault) {
        struct stela_intel_cpu_copy_span i = image, l = linear;
        enum stela_intel_cpu_copy_swizzle swizzle = STELA_INTEL_CPU_COPY_NO_BIT6;
        enum stela_intel_image_copy_direction direction = STELA_INTEL_IMAGE_UPLOAD;
        switch (fault) {
        case 0: i.base = NULL; break;
        case 1: l.base = NULL; break;
        case 2: i.allocation_bytes = 0; break;
        case 3: l.mapped_bytes = 0; break;
        case 4: i.allocation_bytes = i.mapped_bytes + 1; break;
        case 5: l.allocation_bytes = l.mapped_bytes + 1; break;
        case 6: i.offset = i.allocation_bytes + 1; break;
        case 7: l.offset = l.allocation_bytes + 1; break;
        case 8: i.allocation_bytes = i.offset + q.image_cpu_span - 1; break;
        case 9: l.allocation_bytes = l.offset + q.linear_suffix - 1; break;
        case 10: l.offset = q.linear_prefix ? q.linear_prefix - 1 : l.allocation_bytes + 1; break;
        case 11: i.mapping = 0; break;
        case 12: l.mapping = 0; break;
        case 13: swizzle = 0; break;
        case 14: swizzle = STELA_INTEL_CPU_COPY_BIT6; break;
        case 15: i.access = STELA_INTEL_BUFFER_READ; break;
        case 16: l.access = STELA_INTEL_BUFFER_WRITE; break;
        case 17: i.access = 0; break;
        case 18: l.access = 7; break;
        case 19: direction = 0; break;
        case 20: direction = 3; break;
        case 21: i.base = (void *)(UINTPTR_MAX - 1); break;
        case 22: l.base = (void *)(UINTPTR_MAX - 1); break;
        case 23: i.mapped_bytes = (uint64_t)PTRDIFF_MAX + 1; break;
        case 24: l.mapped_bytes = (uint64_t)PTRDIFF_MAX + 1; break;
        case 25: l.base = i.base; break;
        case 26: direction = STELA_INTEL_IMAGE_READBACK; i.access = STELA_INTEL_BUFFER_WRITE; break;
        case 27: direction = STELA_INTEL_IMAGE_READBACK; l.access = STELA_INTEL_BUFFER_READ; break;
        case 28: i.allocation_bytes = i.offset + q.image_bytes - 1; break;
        case 29: l.offset = UINT64_MAX; break;
        case 30: i.offset = UINT64_MAX; break;
        }
        assert(stela_intel_image_copy(dev, d, &r, pitch, &i, &l, swizzle, direction) < 0);
        assert(memcmp(img, before_img, image_size) == 0 &&
            memcmp(lin, before_lin, linear_size) == 0);
        ++refusals;
    }
    /* Query failures are atomic too, with arithmetic checked before ISL. */
    struct stela_intel_image_copy_requirements out, before;
    memset(&out, 0xa5, sizeof(out)); before = out;
    for (unsigned fault = 0; fault < 12; ++fault) {
        struct stela_intel_image_rectangle bad = r; uint32_t p = pitch;
        switch (fault) {
        case 0: bad.level = d->levels; break;
        case 1: bad.layer = d->array_len; break;
        case 2: bad.width = 0; break;
        case 3: bad.height = 0; break;
        case 4: bad.x = d->width; break;
        case 5: bad.y = d->height; break;
        case 6: bad.width = UINT32_MAX; break;
        case 7: bad.height = UINT32_MAX; break;
        case 8: p = 0; break;
        case 9: p = q.row_bytes - 1; break;
        case 10: p = (uint32_t)INT32_MAX + 1; break;
        case 11: bad.level = UINT32_MAX; break;
        }
        assert(stela_intel_image_copy_query(dev, d, &bad, p, &out) == -22);
        assert(memcmp(&out, &before, sizeof(out)) == 0); ++refusals;
        assert(stela_intel_image_copy(dev, d, &bad, p, &image, &linear,
            STELA_INTEL_CPU_COPY_NO_BIT6, STELA_INTEL_IMAGE_UPLOAD) == -22);
        assert(memcmp(img, before_img, image_size) == 0 &&
            memcmp(lin, before_lin, linear_size) == 0);
    }
    assert(stela_intel_image_copy_query(NULL, d, &r, pitch, &out) == -22);
    assert(stela_intel_image_copy_query(dev, NULL, &r, pitch, &out) == -22);
    assert(stela_intel_image_copy_query(dev, d, NULL, pitch, &out) == -22);
    assert(stela_intel_image_copy_query(dev, d, &r, pitch, NULL) == -22);
    uint32_t arithmetic_pitch = INT32_MAX / 4 + 1;
    if (q.tiling == ISL_TILING_Y0 || q.tiling == ISL_TILING_4) {
        assert(stela_intel_image_copy_query(dev, d, &r, arithmetic_pitch, &out) == -22);
        assert(memcmp(&out, &before, sizeof(out)) == 0); ++refusals;
    } else {
        /* These original routines do not have the signed four-row product. */
        assert(stela_intel_image_copy_query(dev, d, &r, arithmetic_pitch, &out) == 0);
    }
    free(before_lin); free(before_img); free(lin); free(img);
}

static void unsupported_tilings(const struct isl_device *dev)
{
    const enum isl_tiling unsupported[] = {ISL_TILING_SKL_Yf, ISL_TILING_SKL_Ys,
        ISL_TILING_ICL_Yf, ISL_TILING_ICL_Ys, ISL_TILING_64, ISL_TILING_64_XE2};
    for (unsigned t = 0; t < ARRAY_SIZE(unsupported); ++t) {
        struct stela_intel_image_desc d = description(ISL_FORMAT_R8G8B8A8_UNORM, unsupported[t]);
        struct isl_surf s;
        if (stela_intel_image_layout(dev, &d, &s)) continue;
        struct stela_intel_image_rectangle r = {.width=1, .height=1};
        struct stela_intel_image_copy_requirements out, before;
        memset(&out, 0xa5, sizeof(out)); before = out;
        assert(stela_intel_image_copy_query(dev, &d, &r, 16, &out) == -95);
        assert(memcmp(&out, &before, sizeof(out)) == 0); ++refusals;
    }
}

int main(void)
{
    const enum isl_tiling tilings[] = {
        ISL_TILING_LINEAR, ISL_TILING_X, ISL_TILING_Y0, ISL_TILING_4};
    const enum isl_format formats[] = {ISL_FORMAT_R8_UNORM, ISL_FORMAT_R16_UNORM,
        ISL_FORMAT_R8G8B8A8_UNORM, ISL_FORMAT_R16G16B16A16_FLOAT, ISL_FORMAT_R32G32B32A32_FLOAT};
    const char *platform;
    struct intel_device_info info;
    STELA_INTEL_FOREACH_TARGET(platform, info) {
        struct isl_device dev = {0}; isl_device_init(&dev, &info); dev.requires_padding = true;
        for (unsigned t = 0; t < ARRAY_SIZE(tilings); ++t)
        for (unsigned f = 0; f < ARRAY_SIZE(formats); ++f) {
            struct stela_intel_image_desc d = description(formats[f], tilings[t]);
            struct isl_surf s;
            int status = stela_intel_image_layout(&dev, &d, &s);
            if (status) {assert(status == -95); ++refusals; continue;}
            assert(s.tiling == tilings[t]);
            all_rectangles(&dev, &d, &s); invalid_copies(&dev, &d); ++admitted_layouts;
        }
        unsupported_tilings(&dev);
    }
    printf("Hosted Intel image CPU copy: %u layouts, %u independent full-span copies, %u refusals "
           "passed\n",
        admitted_layouts, copies, refusals);
    return 0;
}
