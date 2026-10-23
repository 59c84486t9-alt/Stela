/* SPDX-License-Identifier: MIT */
#include "image.h"
#include "util/u_math.h"
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

static int check_device(const struct nv_device_info *dev)
{
    if (!dev) return -22;
    if (dev->type != NV_DEVICE_TYPE_DIS && dev->type != NV_DEVICE_TYPE_IGP)
        return -95;
    switch (dev->cls_eng3d) {
    case MAXWELL_A: case MAXWELL_B: case PASCAL_A: case PASCAL_B:
    case VOLTA_A: case TURING_A: case AMPERE_A: case AMPERE_B: case ADA_A:
        return 0;
    default:
        return -95;
    }
}

static int make_layout(const struct nv_device_info *dev,
                       const struct stela_nv_image_request *req, struct nil_image *out)
{
    int err = check_device(dev);
    if (err) return err;
    if (!req || !req->width || req->width > 16384 ||
        !req->height || req->height > 16384 || !req->layers || req->layers > 2048 ||
        !req->levels || req->levels > 15 || !req->usage ||
        (req->usage & ~(STELA_NV_IMAGE_TEXTURE | STELA_NV_IMAGE_STORAGE)) ||
        (unsigned)req->format >= PIPE_FORMAT_COUNT)
        return -22;
    uint32_t largest = MAX2(req->width, req->height);
    if (req->levels > util_logbase2(largest) + 1) return -22;

    /* Keep byte/tile arithmetic far inside original u32/u64 intermediates.
     * 16K * 16B rows, 16K rows, <=15 mips and <=2048 layers fit those types.
     * Format and element packing remain the original generated NIL table.
     */
    const struct util_format_description *fmt = util_format_description(req->format);
    if (!fmt || fmt->layout != UTIL_FORMAT_LAYOUT_PLAIN ||
        (fmt->colorspace != UTIL_FORMAT_COLORSPACE_RGB &&
         fmt->colorspace != UTIL_FORMAT_COLORSPACE_SRGB) ||
        fmt->block.width != 1 || fmt->block.height != 1 || fmt->block.depth != 1 ||
        fmt->block.bits < 8 || fmt->block.bits > 128 ||
        (fmt->block.bits & (fmt->block.bits - 1)) ||
        !nil_format_supports_texturing(dev, req->format) ||
        ((req->usage & STELA_NV_IMAGE_STORAGE) &&
         !nil_format_supports_storage(dev, req->format)))
        return -95;

    const struct nil_image_init_info info = {
        .dim = NIL_IMAGE_DIM_2D, .format = nil_format(req->format),
        .extent_px = {req->width, req->height, 1, req->layers},
        .levels = req->levels, .samples = 1,
        .usage = NIL_IMAGE_USAGE_UNCOMPRESSED_BIT,
        .modifier = DRM_FORMAT_MOD_INVALID,
    };
    return nil_image_init(dev, out, &info) ? 0 : -95;
}

int stela_nv_image_init(const struct nv_device_info *dev, const void *owner,
                        const struct stela_nv_image_request *request, struct stela_nv_image *out)
{
    if (!owner || !out || !request) return -22;
    struct stela_nv_image image = {.device = dev, .owner = owner, .request = *request};
    int err = make_layout(dev, &image.request, &image.layout);
    if (err) return err;
    image.cls_eng3d = dev->cls_eng3d;
    image.device_type = dev->type;
    *out = image;
    return 0;
}

int stela_nv_image_descriptor(const struct stela_nv_image *image,
                              const struct stela_nv_image_binding *binding,
                              const struct stela_nv_image_view *input, struct nil_descriptor *out)
{
    if (!image || !binding || !input || !out || !image->owner ||
        binding->device != image->device || binding->owner != image->owner)
        return -22;
    const struct stela_nv_image_binding map = *binding;
    const struct stela_nv_image_view view = *input;
    struct nil_image layout;
    int err = make_layout(image->device, &image->request, &layout);
    if (err) return err;
    if (image->cls_eng3d != image->device->cls_eng3d ||
        image->device_type != image->device->type ||
        !view.levels || view.base_level >= layout.num_levels ||
        view.levels > layout.num_levels - view.base_level ||
        !view.layers || view.base_layer >= layout.extent_px.array_len ||
        view.layers > layout.extent_px.array_len - view.base_layer ||
        (!view.array && view.layers != 1) ||
        (view.usage != STELA_NV_IMAGE_TEXTURE && view.usage != STELA_NV_IMAGE_STORAGE) ||
        (view.usage & ~image->request.usage) ||
        !map.available_usage ||
        (map.available_usage & ~(STELA_NV_IMAGE_TEXTURE | STELA_NV_IMAGE_STORAGE)) ||
        (view.usage & ~map.available_usage) ||
        !isfinite(view.min_lod_clamp) || view.min_lod_clamp < 0.0f ||
        view.min_lod_clamp > (float)(view.base_level + view.levels - 1) ||
        (view.filtered && (view.usage != STELA_NV_IMAGE_TEXTURE ||
                          !nil_format_supports_filtering(image->device, image->request.format))))
        return -22;
    for (unsigned i = 0; i < 4; i++)
        if ((unsigned)view.swizzle[i] > PIPE_SWIZZLE_1) return -22;

    /* NVIDIA TIC encodes an unsigned 48-bit byte address for this generation
     * range. Check the entire mapping and padded image with subtraction, before
     * any address/array arithmetic or original descriptor packing.
     */
    if (!map.address_bits || map.address_bits > 48 || !map.mapped_bytes ||
        map.pte_kind != layout.pte_kind || map.image_offset > map.mapped_bytes ||
        layout.size_B > map.mapped_bytes - map.image_offset)
        return -22;
    const uint64_t limit = (UINT64_C(1) << map.address_bits) - 1;
    if (map.gpu_base > limit || map.mapped_bytes - 1 > limit - map.gpu_base)
        return -22;
    const uint64_t address = map.gpu_base + map.image_offset;
    if (address % layout.align_B) return -22;

    const struct nil_view nil_view = {
        .view_type = view.array ? NIL_VIEW_TYPE_2D_ARRAY : NIL_VIEW_TYPE_2D,
        .access = view.usage == STELA_NV_IMAGE_STORAGE ? NIL_VIEW_ACCESS_STORAGE : NIL_VIEW_ACCESS_TEXTURE,
        .format = layout.format, .base_level = view.base_level, .num_levels = view.levels,
        .base_array_layer = view.base_layer, .array_len = view.layers,
        .swizzle = {view.swizzle[0], view.swizzle[1], view.swizzle[2], view.swizzle[3]},
        .min_lod_clamp = view.min_lod_clamp,
    };
    const struct nil_descriptor descriptor =
        nil_image_view_descriptor(image->device, &layout, &nil_view, address);
    *out = descriptor;
    return 0;
}
