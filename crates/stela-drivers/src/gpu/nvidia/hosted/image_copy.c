/* SPDX-License-Identifier: MIT */
#include "image_copy.h"
#include <stddef.h>

static bool cpu_span(const void *pointer, size_t bytes)
{
    return pointer && bytes && bytes <= PTRDIFF_MAX &&
           bytes - 1 <= UINTPTR_MAX - (uintptr_t)pointer;
}

static int copy_region(const struct stela_nvidia_image *image,
                        const struct stela_nvidia_image_cpu_view *input_mapping,
                        const struct stela_nvidia_image_region *input_region,
                        const struct stela_nvidia_linear_image *input_linear, bool upload)
{
    if (!image || !input_mapping || !input_region || !input_linear || !image->owner ||
        input_mapping->device != image->device || input_mapping->owner != image->owner)
        return -22;
    const struct stela_nvidia_image_cpu_view mapping = *input_mapping;
    const struct stela_nvidia_image_region region = *input_region;
    const struct stela_nvidia_linear_image linear = *input_linear;

    /* As with TIC formation, never trust caller-written NIL layout fields.
     * Reuse the same bounded request validation and original NIL layout path.
     */
    struct stela_nvidia_image rebuilt;
    int err = stela_nvidia_image_init(image->device, image->owner, &image->request, &rebuilt);
    if (err) return err;
    const struct nil_image *layout = &rebuilt.layout;
    if (image->cls_eng3d != rebuilt.cls_eng3d || image->device_type != rebuilt.device_type ||
        !mapping.access || (mapping.access & ~(STELA_NVIDIA_CPU_READ | STELA_NVIDIA_CPU_WRITE)) ||
        !(mapping.access & (upload ? STELA_NVIDIA_CPU_WRITE : STELA_NVIDIA_CPU_READ)) ||
        !cpu_span(mapping.pointer, mapping.bytes) ||
        mapping.image_offset > mapping.bytes ||
        layout->size_B > mapping.bytes - mapping.image_offset ||
        region.level >= layout->num_levels || region.layer >= layout->extent_px.array_len ||
        !region.width || !region.height)
        return -22;
    struct nil_Extent4D_Pixels level_px = nil_image_level_extent_px(layout, region.level);
    if (region.x >= level_px.width || region.width > level_px.width - region.x ||
        region.y >= level_px.height || region.height > level_px.height - region.y)
        return -22;

    const size_t element_bytes = util_format_get_blocksize(image->request.format);
    const size_t row_bytes = region.width * element_bytes;
    /* Dimensions/element sizes are already bounded by image.h, so row_bytes
     * and the pixel-to-byte x conversion fit both size_t and original u32.
     * An arbitrarily large caller pitch still requires checked multiplication.
     */
    if (linear.row_stride < row_bytes ||
        (region.height - 1 && linear.row_stride > (SIZE_MAX - row_bytes) / (region.height - 1)))
        return -22;
    /* Original LinearPointer backs up to level origin using y*pitch, then
     * restores coordinates with wrapping pointer arithmetic. Its integer
     * multiplication must fit even for a one-row rectangle at nonzero y.
     */
    const size_t last_y = region.y + region.height - 1;
    if (last_y && linear.row_stride > SIZE_MAX / last_y) return -22;
    const size_t linear_span = (region.height - 1) * linear.row_stride + row_bytes;
    if (linear_span > linear.bytes || !cpu_span(linear.pointer, linear_span)) return -22;

    const uintptr_t tiled_begin = (uintptr_t)mapping.pointer;
    const uintptr_t linear_begin = (uintptr_t)linear.pointer;
    /* Reject aliases against the whole mapping, not only touched tile sectors.
     * Subtraction avoids an exclusive-end overflow at UINTPTR_MAX.
     */
    if ((linear_begin >= tiled_begin && linear_begin - tiled_begin < mapping.bytes) ||
        (tiled_begin > linear_begin && tiled_begin - linear_begin < linear_span))
        return -22;

    const uint64_t offset = nil_image_level_layer_offset_B(layout, region.level, region.layer);
    const uint64_t level_bytes = nil_image_level_layer_size_B(layout, region.level);
    if (offset > layout->size_B || level_bytes > layout->size_B - offset) return -22;
    const struct nil_tiling *tiling = &layout->levels[region.level].tiling;
    if (tiling->x_log2 != 0 || tiling->z_log2 != 0 ||
        (tiling->gob_type != NIL_GOB_TYPE_FERMI_COLOR &&
         tiling->gob_type != NIL_GOB_TYPE_TURING_COLOR2_D))
        return -95;

    level_px.array_len = 1;
    const struct nil_Extent4D_Bytes level_B =
        nil_extent4d_px_to_B(level_px, layout->format, layout->sample_layout);
    const struct nil_Offset4D_Bytes offset_B = {
        .x = (uint32_t)(region.x * element_bytes), .y = region.y,
    };
    const struct nil_Extent4D_Bytes extent_B = {
        .width = (uint32_t)row_bytes, .height = region.height, .depth = 1, .array_len = 1,
    };
    uint8_t *tiled = (uint8_t *)mapping.pointer + mapping.image_offset + (size_t)offset;
    /* One 2D subresource; the plane stride is intentionally unused, as in the
     * original NVK host-copy path. No layout/packing or copy algorithm is cloned.
     */
    if (upload) {
        nil_copy_linear_to_tiled(tiled, level_B, linear.pointer, linear.row_stride,
                                  0, offset_B, extent_B, tiling);
    } else {
        nil_copy_tiled_to_linear(linear.pointer, linear.row_stride, 0, tiled,
                                  level_B, offset_B, extent_B, tiling);
    }
    return 0;
}

int stela_nvidia_image_upload(const struct stela_nvidia_image *image,
                          const struct stela_nvidia_image_cpu_view *mapping,
                          const struct stela_nvidia_image_region *region,
                          const struct stela_nvidia_linear_image *linear)
{
    return copy_region(image, mapping, region, linear, true);
}

int stela_nvidia_image_download(const struct stela_nvidia_image *image,
                            const struct stela_nvidia_image_cpu_view *mapping,
                            const struct stela_nvidia_image_region *region,
                            const struct stela_nvidia_linear_image *linear)
{
    return copy_region(image, mapping, region, linear, false);
}
