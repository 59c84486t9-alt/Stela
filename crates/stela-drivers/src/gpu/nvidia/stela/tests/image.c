/* SPDX-License-Identifier: MIT */
#include "../hosted/image.h"
#include "nouveau/headers/drf.h"
#include "nouveau/headers/nvidia/classes/cl9097.h"
#include "nouveau/headers/nvidia/classes/cla097.h"
#include "nouveau/headers/nvidia/classes/clb097.h"
#include "nouveau/headers/nvidia/classes/clb197.h"
#include "nouveau/headers/nvidia/classes/clc097.h"
#include "nouveau/headers/nvidia/classes/clc197.h"
#include "nouveau/headers/nvidia/classes/clc397.h"
#include "nouveau/headers/nvidia/classes/clc597.h"
#include "nouveau/headers/nvidia/classes/clc697.h"
#include "nouveau/headers/nvidia/classes/clc797.h"
#include "nouveau/headers/nvidia/classes/clc997.h"
#include "nouveau/headers/nvidia/classes/clcb97.h"
#include "nouveau/headers/nvidia/classes/clcd97.h"
#include "nouveau/headers/nvidia/classes/clb097tex.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

/* Source-only fixture identities and addresses. No device open/submission. */
static const unsigned owner = 1, other_owner = 2;

static struct stela_nv_image_request request(enum pipe_format format)
{
    return (struct stela_nv_image_request){
        .format = format, .width = 129, .height = 67, .layers = 5, .levels = 8,
        .usage = STELA_NV_IMAGE_TEXTURE,
    };
}

static struct stela_nv_image_binding binding(const struct stela_nv_image *image)
{
    return (struct stela_nv_image_binding){
        .device = image->device, .owner = image->owner,
        .gpu_base = UINT64_C(0x1240000000), .image_offset = image->layout.align_B,
        .mapped_bytes = image->layout.size_B + image->layout.align_B,
        .address_bits = 48, .available_usage = image->request.usage,
        .pte_kind = image->layout.pte_kind,
    };
}

static struct stela_nv_image_view view(void)
{
    return (struct stela_nv_image_view){
        .base_level = 2, .levels = 3, .base_layer = 1, .layers = 3,
        .usage = STELA_NV_IMAGE_TEXTURE, .array = true,
        .swizzle = {PIPE_SWIZZLE_Z, PIPE_SWIZZLE_Y, PIPE_SWIZZLE_X, PIPE_SWIZZLE_1},
        .min_lod_clamp = 2.5f,
    };
}

static void original_layout_and_tic(const struct nv_device_info *dev, enum pipe_format format)
{
    struct stela_nv_image_request req = request(format);
    const bool storage = nil_format_supports_storage(dev, format);
    if (storage) req.usage |= STELA_NV_IMAGE_STORAGE;
    struct stela_nv_image image;
    assert(stela_nv_image_init(dev, &owner, &req, &image) == 0);
    const struct nil_image_init_info info = {
        .dim = NIL_IMAGE_DIM_2D, .format = nil_format(format),
        .extent_px = {req.width, req.height, 1, req.layers},
        .levels = req.levels, .samples = 1,
        .usage = NIL_IMAGE_USAGE_UNCOMPRESSED_BIT, .modifier = DRM_FORMAT_MOD_INVALID,
    };
    struct nil_image original;
    assert(nil_image_init(dev, &original, &info));
    assert(image.layout.size_B == original.size_B);
    assert(image.layout.align_B == original.align_B);
    assert(image.layout.pte_kind == original.pte_kind);
    assert(image.layout.compressed_pte_kind == 0);
    assert(image.layout.tile_mode == original.tile_mode);
    assert(image.layout.array_stride_B == original.array_stride_B);
    assert(image.layout.size_B >= (uint64_t)req.width * req.height * req.layers *
                                  util_format_get_blocksize(format));
    assert(image.layout.size_B % image.layout.align_B == 0);
    for (unsigned level = 0; level < req.levels; ++level) {
        assert(image.layout.levels[level].offset_B == original.levels[level].offset_B);
        assert(image.layout.levels[level].row_stride_B == original.levels[level].row_stride_B);
        assert(image.layout.levels[level].tiling.gob_type == original.levels[level].tiling.gob_type);
        assert(image.layout.levels[level].tiling.y_log2 == original.levels[level].tiling.y_log2);
        assert(nil_image_level_layer_offset_B(&image.layout, level, 4) +
               nil_image_level_layer_size_B(&image.layout, level) <= image.layout.size_B);
    }
    struct stela_nv_image_binding map = binding(&image);
    for (unsigned access = 0; access < (storage ? 2u : 1u); ++access) {
        struct stela_nv_image_view v = view();
        v.usage = access ? STELA_NV_IMAGE_STORAGE : STELA_NV_IMAGE_TEXTURE;
        struct nil_descriptor actual;
        assert(stela_nv_image_descriptor(&image, &map, &v, &actual) == 0);
        const struct nil_view original_view = {
            .view_type = NIL_VIEW_TYPE_2D_ARRAY,
            .access = access ? NIL_VIEW_ACCESS_STORAGE : NIL_VIEW_ACCESS_TEXTURE,
            .format = original.format, .base_level = v.base_level, .num_levels = v.levels,
            .base_array_layer = v.base_layer, .array_len = v.layers,
            .swizzle = {v.swizzle[0], v.swizzle[1], v.swizzle[2], v.swizzle[3]},
            .min_lod_clamp = v.min_lod_clamp,
        };
        const struct nil_descriptor expected = nil_image_view_descriptor(
            dev, &original, &original_view, map.gpu_base + map.image_offset);
        assert(memcmp(&actual, &expected, sizeof(actual)) == 0);

        /* Decode original NVIDIA field metadata independently of NIL packing. */
        uint64_t address = NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_ADDRESS_BITS31TO9) << 9;
        address |= NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_ADDRESS_BITS47TO32) << 32;
        assert(address == map.gpu_base + map.image_offset +
                          v.base_layer * original.array_stride_B);
        assert(NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_WIDTH_MINUS_ONE) + 1 == req.width);
        assert(NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_HEIGHT_MINUS_ONE) + 1 == req.height);
        assert(NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_DEPTH_MINUS_ONE) + 1 == v.layers);
        assert(NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_RES_VIEW_MIN_MIP_LEVEL) == v.base_level);
        assert(NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_RES_VIEW_MAX_MIP_LEVEL) == v.base_level + v.levels - 1);
        assert(NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_SECTOR_PROMOTION) ==
               NVB097_TEXHEAD_BL_SECTOR_PROMOTION_NO_PROMOTION);
        assert(NVVAL_MW_GET_X(actual.bits, NVB097_TEXHEAD_BL_S_R_G_B_CONVERSION) == util_format_is_srgb(format));
        /* Caller-modified public layout data never reaches original Rust. */
        memset(&image.layout, 0xff, sizeof(image.layout));
        struct nil_descriptor guarded;
        assert(stela_nv_image_descriptor(&image, &map, &v, &guarded) == 0);
        assert(memcmp(&guarded, &expected, sizeof(guarded)) == 0);
        image.layout = original;
    }
}

static void reject_bad_bindings(const struct nv_device_info *dev)
{
    struct stela_nv_image image;
    struct stela_nv_image_request req = request(PIPE_FORMAT_R8G8B8A8_UNORM);
    assert(stela_nv_image_init(dev, &owner, &req, &image) == 0);
    for (unsigned fault = 0; fault < 30; ++fault) {
        const struct nv_device_info foreign_device = *dev;
        struct stela_nv_image candidate = image;
        struct stela_nv_image_binding map = binding(&image);
        struct stela_nv_image_view v = view();
        struct nil_descriptor out, before;
        memset(&out, 0xa5, sizeof(out)); before = out;
        switch (fault) {
        case 0: map.owner = &other_owner; break;
        case 1: map.device = &foreign_device; break;
        case 2: map.mapped_bytes--; break; /* Real rounded tail, not logical pixels */
        case 3: map.image_offset++; break;
        case 4: map.gpu_base++; break;
        case 5: map.pte_kind ^= 1; break;
        case 6: map.address_bits = 49; break;
        case 7: map.address_bits = 0; break;
        case 8: map.gpu_base = (UINT64_C(1) << 48) - image.layout.align_B; break;
        case 9: map.gpu_base = UINT64_MAX - 4095; break;
        case 10: map.image_offset = UINT64_MAX; break;
        case 11: map.mapped_bytes = 0; break;
        case 12: map.available_usage = 0; break;
        case 13: map.available_usage = 8; break;
        case 14: v.base_level = req.levels; break;
        case 15: v.levels = 0; break;
        case 16: v.levels = UINT32_MAX; break;
        case 17: v.base_layer = req.layers; break;
        case 18: v.layers = 0; break;
        case 19: v.layers = UINT32_MAX; break;
        case 20: v.array = false; break;
        case 21: v.swizzle[2] = PIPE_SWIZZLE_NONE; break;
        case 22: v.usage = STELA_NV_IMAGE_STORAGE; break;
        case 23: v.usage = 3; break;
        case 24: v.min_lod_clamp = NAN; break;
        case 25: v.min_lod_clamp = INFINITY; break;
        case 26: v.min_lod_clamp = -1.0f; break;
        case 27: v.min_lod_clamp = 5.0f; break;
        case 28: candidate.cls_eng3d++; break;
        case 29: candidate.device_type = NV_DEVICE_TYPE_SOC; break;
        }
        assert(stela_nv_image_descriptor(&candidate, &map, &v, &out) == -22);
        assert(memcmp(&out, &before, sizeof(out)) == 0);
    }
    struct stela_nv_image_binding map = binding(&image);
    struct stela_nv_image_view v = view();
    struct nil_descriptor out;
    v.layers = 1; v.array = false; v.filtered = true;
    assert(stela_nv_image_descriptor(&image, &map, &v, &out) == 0);
    map.mapped_bytes = image.layout.size_B + map.image_offset;
    /* Full image backing is required even if the view reaches one small mip. */
    v.base_level = req.levels - 1; v.levels = 1;
    assert(stela_nv_image_descriptor(&image, &map, &v, &out) == 0);
    map.mapped_bytes--;
    assert(stela_nv_image_descriptor(&image, &map, &v, &out) == -22);
}

static void reject_bad_requests(const struct nv_device_info *dev)
{
    for (unsigned fault = 0; fault < 19; ++fault) {
        struct stela_nv_image_request req = request(PIPE_FORMAT_R8G8B8A8_UNORM);
        struct nv_device_info info = *dev;
        struct stela_nv_image out, before;
        memset(&out, 0xa5, sizeof(out)); before = out;
        int error = -22;
        switch (fault) {
        case 0: req.width = 0; break;
        case 1: req.height = 0; break;
        case 2: req.layers = 0; break;
        case 3: req.levels = 0; break;
        case 4: req.width = 16385; break;
        case 5: req.height = 16385; break;
        case 6: req.layers = 2049; break;
        case 7: req.levels = 16; break;
        case 8: req.levels = 9; break;
        case 9: req.usage = 0; break;
        case 10: req.usage = 4; break;
        case 11: req.format = PIPE_FORMAT_COUNT; break;
        case 12: req.format = PIPE_FORMAT_NONE; error = -95; break;
        case 13: req.format = PIPE_FORMAT_Z32_FLOAT; error = -95; break;
        case 14: req.format = PIPE_FORMAT_DXT1_RGB; error = -95; break;
        case 15: req.format = PIPE_FORMAT_R8G8B8_UNORM; error = -95; break;
        case 16: req.format = PIPE_FORMAT_R8G8B8A8_SRGB;
                 req.usage = STELA_NV_IMAGE_STORAGE; error = -95; break;
        case 17: info.cls_eng3d = 0xffff; error = -95; break;
        case 18: info.type = NV_DEVICE_TYPE_SOC; error = -95; break;
        }
        assert(stela_nv_image_init(&info, &owner, &req, &out) == error);
        assert(memcmp(&out, &before, sizeof(out)) == 0);
    }
    struct stela_nv_image_request req = request(PIPE_FORMAT_R32_UINT);
    struct stela_nv_image image;
    assert(stela_nv_image_init(dev, &owner, &req, &image) == 0);
    struct stela_nv_image_binding map = binding(&image);
    struct stela_nv_image_view v = view(); v.filtered = true;
    struct nil_descriptor out;
    assert(stela_nv_image_descriptor(&image, &map, &v, &out) == -22);
    assert(stela_nv_image_init(NULL, &owner, &req, &image) == -22);
    assert(stela_nv_image_init(dev, NULL, &req, &image) == -22);
    assert(stela_nv_image_init(dev, &owner, NULL, &image) == -22);
    assert(stela_nv_image_descriptor(NULL, &map, &v, &out) == -22);
    const uint16_t excluded[] = {FERMI_A, KEPLER_A, HOPPER_A, BLACKWELL_A};
    for (unsigned i = 0; i < ARRAY_SIZE(excluded); ++i) {
        struct nv_device_info excluded_device = *dev;
        excluded_device.cls_eng3d = excluded[i];
        assert(stela_nv_image_init(&excluded_device, &owner, &req, &image) == -95);
    }
}

static void format_and_extent_boundaries(const struct nv_device_info *dev)
{
    for (unsigned format = 0; format < PIPE_FORMAT_COUNT; ++format) {
        struct stela_nv_image_request req = request((enum pipe_format)format);
        struct stela_nv_image image;
        int error = stela_nv_image_init(dev, &owner, &req, &image);
        assert(error == 0 || error == -95);
        if (error) continue;
        struct stela_nv_image_binding map = binding(&image);
        struct stela_nv_image_view v = view();
        struct nil_descriptor descriptor;
        assert(stela_nv_image_descriptor(&image, &map, &v, &descriptor) == 0);
    }
    const uint32_t dimensions[] = {1, 2, 10, 11, 21, 22, 42, 43, 85, 86, 127, 128, 16384};
    for (unsigned i = 0; i < ARRAY_SIZE(dimensions); ++i) {
        struct stela_nv_image_request req = {
            .format = PIPE_FORMAT_R32G32B32A32_FLOAT,
            .width = dimensions[i], .height = dimensions[i], .layers = 2048,
            .levels = 1, .usage = STELA_NV_IMAGE_TEXTURE,
        };
        while ((UINT32_C(1) << req.levels) <= dimensions[i]) req.levels++;
        struct stela_nv_image image;
        assert(stela_nv_image_init(dev, &owner, &req, &image) == 0);
        struct stela_nv_image_binding map = binding(&image);
        struct stela_nv_image_view v = view();
        v.base_level = req.levels - 1; v.levels = 1;
        v.base_layer = req.layers - 1; v.layers = 1; v.min_lod_clamp = 0.0f;
        struct nil_descriptor descriptor;
        assert(stela_nv_image_descriptor(&image, &map, &v, &descriptor) == 0);
        const uint64_t limit = UINT64_C(1) << 48;
        map.image_offset = 0; map.mapped_bytes = image.layout.size_B;
        map.gpu_base = limit - map.mapped_bytes;
        assert(stela_nv_image_descriptor(&image, &map, &v, &descriptor) == 0);
        map.mapped_bytes++;
        assert(stela_nv_image_descriptor(&image, &map, &v, &descriptor) == -22);
    }
}

int main(void)
{
    const uint16_t classes[] = {MAXWELL_A, MAXWELL_B, PASCAL_A, PASCAL_B, VOLTA_A,
                               TURING_A, AMPERE_A, AMPERE_B, ADA_A};
    const enum pipe_format formats[] = {PIPE_FORMAT_R8_UNORM, PIPE_FORMAT_R8G8_UNORM,
        PIPE_FORMAT_R8G8B8A8_UNORM, PIPE_FORMAT_B8G8R8A8_SRGB, PIPE_FORMAT_R16G16B16A16_FLOAT,
        PIPE_FORMAT_R32G32B32A32_FLOAT, PIPE_FORMAT_R32_UINT};
    for (unsigned i = 0; i < ARRAY_SIZE(classes); ++i) {
        const struct nv_device_info dev = {.type = NV_DEVICE_TYPE_DIS, .cls_eng3d = classes[i]};
        for (unsigned j = 0; j < ARRAY_SIZE(formats); ++j)
            original_layout_and_tic(&dev, formats[j]);
        reject_bad_bindings(&dev);
        reject_bad_requests(&dev);
        format_and_extent_boundaries(&dev);
    }
    const struct nv_device_info igp = {.type = NV_DEVICE_TYPE_IGP, .cls_eng3d = PASCAL_A};
    original_layout_and_tic(&igp, PIPE_FORMAT_R8G8B8A8_UNORM);
    puts("NVIDIA NIL images: 9 classes, original layouts/TICs, decoded fields, owner/VA/padded-tail/format/range failures passed; hardware_executed=false");
    return 0;
}
