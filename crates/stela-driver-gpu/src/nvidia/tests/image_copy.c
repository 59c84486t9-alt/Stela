/* SPDX-License-Identifier: MIT */
#include "../hosted/image_copy.h"
#include "nouveau/headers/nvidia/classes/clb097.h"
#include "nouveau/headers/nvidia/classes/clb197.h"
#include "nouveau/headers/nvidia/classes/clc097.h"
#include "nouveau/headers/nvidia/classes/clc197.h"
#include "nouveau/headers/nvidia/classes/clc397.h"
#include "nouveau/headers/nvidia/classes/clc597.h"
#include "nouveau/headers/nvidia/classes/clc697.h"
#include "nouveau/headers/nvidia/classes/clc797.h"
#include "nouveau/headers/nvidia/classes/clc997.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned owner = 1, foreign_owner = 2;
enum { GUARD = 32, IMAGE_OFFSET = 37 };

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

/* Independent byte-coordinate oracle: documented block-linear tile/GOB order
 * (nil/tiling.rs), plus the original 16-byte Fermi/Turing GOB coordinate facts
 * (nil/copy.rs CopyGOB{Fermi,Turing2D}::for_each_gob_line). Unlike the original
 * region/chunk iterator, visit every logical byte and compute its destination.
 * The tables are test facts, never a second production tiling implementation.
 */
static size_t tiled_byte(const struct nil_image *image, unsigned level, unsigned layer,
                          unsigned x_byte, unsigned y)
{
    static const uint16_t fermi[2][8] = {
        {0x20, 0x30, 0x00, 0x10, 0xe0, 0xf0, 0xc0, 0xd0},
        {0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0},
    };
    static const uint16_t turing[2][8] = {
        {0x00, 0x10, 0x20, 0x30, 0x80, 0x90, 0xa0, 0xb0},
        {0x40, 0x50, 0x60, 0x70, 0xc0, 0xd0, 0xe0, 0xf0},
    };
    const struct nil_image_level *mip = &image->levels[level];
    assert(mip->tiling.x_log2 == 0 && mip->tiling.z_log2 == 0);
    const unsigned tile_height = 8u << mip->tiling.y_log2;
    const size_t tile_bytes = 512u << mip->tiling.y_log2;
    const size_t tile = (y / tile_height) * (mip->row_stride_B / 64) + x_byte / 64;
    const size_t gob = (y % tile_height) / 8;
    const uint16_t (*segments)[8] = mip->tiling.gob_type == NIL_GOB_TYPE_FERMI_COLOR ? fermi : turing;
    assert(mip->tiling.gob_type == NIL_GOB_TYPE_FERMI_COLOR ||
           mip->tiling.gob_type == NIL_GOB_TYPE_TURING_COLOR2_D);
    return layer * image->array_stride_B + mip->offset_B + tile * tile_bytes + gob * 512 +
           (x_byte % 64 / 32) * 256 + segments[x_byte % 32 / 16][y % 8] + x_byte % 16;
}

static void coordinate_and_original_copy(const struct nv_device_info *dev, enum pipe_format format,
                                         unsigned level, unsigned layer, bool partial)
{
    struct stela_nvidia_image image = make_image(dev, format);
    const struct nil_image original_layout = image.layout;
    struct nil_Extent4D_Pixels level_px = nil_image_level_extent_px(&image.layout, level);
    const size_t element_bytes = util_format_get_blocksize(format);
    struct stela_nvidia_image_region region = {
        .level = level, .layer = layer, .width = level_px.width, .height = level_px.height,
    };
    if (partial && level_px.width > 2 && level_px.height > 2) {
        region.x = 1; region.y = 1;
        region.width = MIN2(67, level_px.width - 1);
        region.height = MIN2(19, level_px.height - 1);
    }
    const size_t row_bytes = region.width * element_bytes;
    const size_t stride = row_bytes + 13;
    const size_t linear_bytes = (region.height - 1) * stride + row_bytes;
    const size_t tiled_bytes = IMAGE_OFFSET + image.layout.size_B + 19;
    uint8_t *tiled = malloc(tiled_bytes + 2 * GUARD);
    uint8_t *expected = malloc(tiled_bytes + 2 * GUARD);
    uint8_t *reference = malloc(tiled_bytes + 2 * GUARD);
    uint8_t *linear = malloc(linear_bytes + 2 * GUARD);
    uint8_t *linear_before = malloc(linear_bytes + 2 * GUARD);
    uint8_t *download = malloc(linear_bytes + 2 * GUARD);
    uint8_t *download_expected = malloc(linear_bytes + 2 * GUARD);
    assert(tiled && expected && reference && linear && linear_before && download && download_expected);
    memset(tiled, 0xa5, tiled_bytes + 2 * GUARD);
    memset(expected, 0xa5, tiled_bytes + 2 * GUARD);
    memset(reference, 0xa5, tiled_bytes + 2 * GUARD);
    memset(linear, 0x7d, linear_bytes + 2 * GUARD);
    memset(download, 0x6b, linear_bytes + 2 * GUARD);
    memset(download_expected, 0x6b, linear_bytes + 2 * GUARD);
    for (unsigned y = 0; y < region.height; ++y) {
        for (unsigned x = 0; x < row_bytes; ++x) {
            const uint8_t value = (uint8_t)(x * 13 + y * 29 + level * 11 + layer * 3);
            linear[GUARD + y * stride + x] = value;
            download_expected[GUARD + y * stride + x] = value;
            const size_t address = tiled_byte(&image.layout, level, layer,
                                               (unsigned)(region.x * element_bytes) + x, region.y + y);
            assert(address < image.layout.size_B);
            expected[GUARD + IMAGE_OFFSET + address] = value;
        }
    }
    memcpy(linear_before, linear, linear_bytes + 2 * GUARD);
    const struct stela_nvidia_image_cpu_view map = {
        .device = dev, .owner = &owner, .pointer = tiled + GUARD,
        .bytes = tiled_bytes, .image_offset = IMAGE_OFFSET,
        .access = STELA_NVIDIA_CPU_READ | STELA_NVIDIA_CPU_WRITE,
    };
    struct stela_nvidia_linear_image src = {linear + GUARD, linear_bytes, stride};
    /* Mutated NIL metadata cannot change the validated production copy. */
    memset(&image.layout, 0xff, sizeof(image.layout));
    assert(stela_nvidia_image_upload(&image, &map, &region, &src) == 0);
    assert(memcmp(tiled, expected, tiled_bytes + 2 * GUARD) == 0);
    assert(memcmp(linear, linear_before, linear_bytes + 2 * GUARD) == 0);
    image.layout = original_layout;

    const uint64_t offset = nil_image_level_layer_offset_B(&image.layout, level, layer);
    assert(offset == layer * image.layout.array_stride_B + image.layout.levels[level].offset_B);
    level_px.array_len = 1;
    const struct nil_Extent4D_Bytes level_B =
        nil_extent4d_px_to_B(level_px, image.layout.format, image.layout.sample_layout);
    const struct nil_Offset4D_Bytes offset_B = {
        .x = (uint32_t)(region.x * element_bytes), .y = region.y,
    };
    const struct nil_Extent4D_Bytes extent_B = {
        .width = (uint32_t)row_bytes, .height = region.height, .depth = 1, .array_len = 1,
    };
    nil_copy_linear_to_tiled(reference + GUARD + IMAGE_OFFSET + offset, level_B,
                              linear + GUARD, stride, 0, offset_B, extent_B,
                              &image.layout.levels[level].tiling);
    assert(memcmp(tiled, reference, tiled_bytes + 2 * GUARD) == 0);

    /* Download from independent coordinate-produced bytes, not upload output. */
    struct stela_nvidia_image_cpu_view read_map = map; read_map.pointer = expected + GUARD;
    const struct stela_nvidia_linear_image dst = {download + GUARD, linear_bytes, stride};
    assert(stela_nvidia_image_download(&image, &read_map, &region, &dst) == 0);
    assert(memcmp(download, download_expected, linear_bytes + 2 * GUARD) == 0);
    assert(memcmp(expected, tiled, tiled_bytes + 2 * GUARD) == 0);
    free(tiled); free(expected); free(reference); free(linear); free(linear_before);
    free(download); free(download_expected);
}

static void invalid_copies_are_atomic(const struct nv_device_info *dev)
{
    const struct stela_nvidia_image image = make_image(dev, PIPE_FORMAT_R8G8B8A8_UNORM);
    const size_t tiled_bytes = IMAGE_OFFSET + image.layout.size_B;
    uint8_t *tiled = malloc(tiled_bytes), *before = malloc(tiled_bytes);
    uint8_t linear[256], linear_before[256];
    assert(tiled && before);
    memset(tiled, 0x39, tiled_bytes); memcpy(before, tiled, tiled_bytes);
    memset(linear, 0x56, sizeof(linear)); memcpy(linear_before, linear, sizeof(linear));
    for (unsigned direction = 0; direction < 2; ++direction) {
        for (unsigned fault = 0; fault < 32; ++fault) {
            const struct nv_device_info foreign_device = *dev;
            struct stela_nvidia_image candidate = image;
            struct stela_nvidia_image_cpu_view map = {
                .device = dev, .owner = &owner, .pointer = tiled, .bytes = tiled_bytes,
                .image_offset = IMAGE_OFFSET, .access = STELA_NVIDIA_CPU_READ | STELA_NVIDIA_CPU_WRITE,
            };
            struct stela_nvidia_image_region region = {
                .level = 1, .layer = 2, .x = 1, .y = 2, .width = 7, .height = 3,
            };
            struct stela_nvidia_linear_image host = {linear, sizeof(linear), 37};
            switch (fault) {
            case 0: map.owner = &foreign_owner; break;
            case 1: map.device = &foreign_device; break;
            case 2: map.bytes--; break;
            case 3: map.image_offset = SIZE_MAX; break;
            case 4: map.pointer = NULL; break;
            case 5: map.pointer = (void *)(UINTPTR_MAX - 7); break;
            case 6: map.bytes = SIZE_MAX; break;
            case 7: map.access = 0; break;
            case 8: map.access = 4; break;
            case 9: map.access = direction ? STELA_NVIDIA_CPU_WRITE : STELA_NVIDIA_CPU_READ; break;
            case 10: region.level = image.request.levels; break;
            case 11: region.layer = image.request.layers; break;
            case 12: region.width = 0; break;
            case 13: region.height = 0; break;
            case 14: region.x = UINT32_MAX; break;
            case 15: region.y = UINT32_MAX; break;
            case 16: region.width = UINT32_MAX; break;
            case 17: region.height = UINT32_MAX; break;
            case 18: host.row_stride = 27; break;
            case 19: host.row_stride = SIZE_MAX; break;
            case 20: host.bytes = 101; break; /* 2*37+28 requires102 */
            case 21: host.pointer = NULL; break;
            case 22: host.pointer = (void *)(UINTPTR_MAX - 100); break;
            case 23: host.pointer = tiled + IMAGE_OFFSET; break;
            case 24: host.pointer = tiled + tiled_bytes - 1; break;
            case 25: host.pointer = tiled; break;
            case 26: host.bytes = 0; break;
            case 27: candidate.cls_eng3d++; break;
            case 28: candidate.device_type = NV_DEVICE_TYPE_SOC; break;
            case 29: candidate.request.width = 0; break;
            case 30: candidate.owner = NULL; break;
            case 31: region.height = 1; host.row_stride = SIZE_MAX; break;
            }
            int error = direction ? stela_nvidia_image_download(&candidate, &map, &region, &host) :
                                    stela_nvidia_image_upload(&candidate, &map, &region, &host);
            assert(error == -22);
            assert(memcmp(tiled, before, tiled_bytes) == 0);
            assert(memcmp(linear, linear_before, sizeof(linear)) == 0);
        }
    }
    /* Span overlap in the reverse address order, without forming an invalid
     * pointer before an allocation. The upload source starts before the view. */
    const size_t alias_bytes = image.layout.size_B + 128;
    uint8_t *alias = malloc(alias_bytes), *alias_before = malloc(alias_bytes);
    assert(alias && alias_before);
    memset(alias, 0xa6, alias_bytes); memcpy(alias_before, alias, alias_bytes);
    const struct stela_nvidia_image_cpu_view map = {
        .device = dev, .owner = &owner, .pointer = alias + 64, .bytes = image.layout.size_B,
        .access = STELA_NVIDIA_CPU_READ | STELA_NVIDIA_CPU_WRITE,
    };
    const struct stela_nvidia_image_region region = {.width = 1, .height = 2};
    const struct stela_nvidia_linear_image host = {alias, 128, 64};
    assert(stela_nvidia_image_upload(&image, &map, &region, &host) == -22);
    assert(stela_nvidia_image_download(&image, &map, &region, &host) == -22);
    assert(memcmp(alias, alias_before, alias_bytes) == 0);
    assert(memcmp(tiled, before, tiled_bytes) == 0);
    assert(stela_nvidia_image_upload(NULL, &map, &region, &host) == -22);
    assert(stela_nvidia_image_upload(&image, NULL, &region, &host) == -22);
    assert(stela_nvidia_image_download(&image, &map, NULL, &host) == -22);
    assert(stela_nvidia_image_download(&image, &map, &region, NULL) == -22);
    free(tiled); free(before); free(alias); free(alias_before);
}

int main(void)
{
    const uint16_t classes[] = {MAXWELL_A, MAXWELL_B, PASCAL_A, PASCAL_B, VOLTA_A,
                               TURING_A, AMPERE_A, AMPERE_B, ADA_A};
    const enum pipe_format formats[] = {PIPE_FORMAT_R8_UNORM, PIPE_FORMAT_R8G8_UNORM,
        PIPE_FORMAT_R8G8B8A8_UNORM, PIPE_FORMAT_R16G16B16A16_FLOAT, PIPE_FORMAT_R32G32B32A32_FLOAT};
    const unsigned levels[] = {0, 3, 7};
    for (unsigned c = 0; c < ARRAY_SIZE(classes); ++c) {
        const struct nv_device_info dev = {.type = NV_DEVICE_TYPE_DIS, .cls_eng3d = classes[c]};
        for (unsigned f = 0; f < ARRAY_SIZE(formats); ++f)
            for (unsigned level = 0; level < ARRAY_SIZE(levels); ++level)
                for (unsigned layer = 0; layer < 3; layer += 2)
                    for (unsigned partial = 0; partial < 2; ++partial)
                        coordinate_and_original_copy(&dev, formats[f], levels[level], layer, partial != 0);
        invalid_copies_are_atomic(&dev);
    }
    puts("NVIDIA NIL CPU copies: 540 original/coordinate/untouched-byte cases, 9 classes, 5 element sizes, mip/layer/stride/alias/rights/overflow failures passed; hardware_executed=false");
    return 0;
}
