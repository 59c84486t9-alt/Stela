/* SPDX-License-Identifier: MIT */
#include "surface.h"
#include "intel/genxml/genX_bits.h"

static int check_device(const struct isl_device *dev)
{
    if (!dev || !dev->info || !dev->buffer_fill_state_s || !dev->max_buffer_size)
        return -22;
    /* Match the actual retained ISL implementation selection. This guards
     * metadata queries whose normal contract assumes a known generation.
     */
    switch (dev->info->verx10) {
    case 40: case 45: case 50: case 60: case 70: case 75: case 80:
    case 90: case 110: case 120: case 125: case 200: case 300: case 350:
        break;
    default:
        return -95;
    }
    if (dev->ss.size != RENDER_SURFACE_STATE_length(dev->info) * sizeof(uint32_t))
        return -22;
    if ((dev->info->ver < 9 && dev->buffer_length_in_aux_addr) ||
        (dev->buffer_length_in_aux_addr && intel_needs_workaround(dev->info, 14019708328)))
        return -22;
    return 0;
}

static bool canonical(uint64_t address, uint32_t bits)
{
    if (bits == 32) return address <= UINT32_MAX;
    uint64_t mask = (UINT64_C(1) << bits) - 1;
    uint64_t high = address & ~mask;
    return high == ((address & (UINT64_C(1) << (bits - 1))) ? ~mask : 0);
}

/* Keep every byte in one canonical half. Integer addition may not wrap through
 * zero or the canonical hole, even when both endpoints would look valid.
 */
static bool valid_mapping(uint64_t base, uint64_t bytes, uint32_t bits)
{
    if (!bytes || !canonical(base, bits) || bytes - 1 > UINT64_MAX - base)
        return false;
    uint64_t end = base + bytes - 1;
    if (!canonical(end, bits)) return false;
    return bits == 32 || !((base ^ end) & (UINT64_C(1) << (bits - 1)));
}

int stela_intel_raw_buffer_state(const struct isl_device *dev,
                                 const struct stela_intel_raw_view *input,
                                 void *state, size_t capacity)
{
    int err = check_device(dev);
    if (err) return err;
    if (!input || !state || (uintptr_t)state % _Alignof(uint32_t))
        return -22;
    /* Snapshot caller metadata before writing output; input may share storage. */
    const struct stela_intel_raw_view view = *input;
    if ((view.address_bits != 32 && view.address_bits != 48 && view.address_bits != 57) ||
        (RENDER_SURFACE_STATE_SurfaceBaseAddress_bits(dev->info) == 32 && view.address_bits != 32) ||
        !view.alignment || (view.alignment & (view.alignment - 1)) || view.alignment < 4 ||
        !view.access || (view.access & ~STELA_INTEL_BUFFER_READ_WRITE) ||
        !view.available_access || (view.available_access & ~STELA_INTEL_BUFFER_READ_WRITE) ||
        (view.access & ~view.available_access) ||
        !view.bytes || view.bytes > UINT32_MAX || view.buffer_bytes > view.mapped_bytes ||
        view.offset > view.buffer_bytes || view.bytes > view.buffer_bytes - view.offset ||
        view.offset % view.alignment ||
        !valid_mapping(view.gpu_base, view.mapped_bytes, view.address_bits))
        return -22;
    uint64_t address = view.gpu_base + view.offset;
    if (address % view.alignment) return -22;

    /* Exact original ISL RAW size encoding. Refuse its MIN2 clamp beforehand.
     * Dword access granularity additionally requires the whole encoded tail to
     * be mapped, including the size-recovery padding, not just logical bytes.
     */
    uint64_t aligned = (view.bytes + 3) & ~UINT64_C(3);
    uint64_t encoded = aligned + (aligned - view.bytes);
    uint64_t mapped_tail = (encoded + 3) & ~UINT64_C(3);
    if (encoded > dev->max_buffer_size ||
        view.offset > view.mapped_bytes || mapped_tail > view.mapped_bytes - view.offset)
        return -22;
    if (capacity < dev->ss.size) return -28;
    const struct isl_buffer_fill_state_info info = {
        .address = address, .size_B = view.bytes, .format = ISL_FORMAT_RAW,
        .swizzle = ISL_SWIZZLE_IDENTITY, .stride_B = 1,
        .usage = ISL_SURF_USAGE_STORAGE_BIT,
        .mocs = isl_mocs(dev, ISL_SURF_USAGE_STORAGE_BIT, view.external),
    };
    isl_buffer_fill_state_s(dev, state, &info);
    return dev->ss.size;
}

int stela_intel_query_format(const struct isl_device *dev, enum isl_format format,
                             struct stela_intel_format_support *out)
{
    int err = check_device(dev);
    if (err) return err;
    if (!out || (unsigned)format >= ISL_NUM_FORMATS || !isl_format_is_valid(format))
        return -22;
    *out = (struct stela_intel_format_support){
        .rendering = isl_format_supports_rendering(dev->info, format),
        .blending = isl_format_supports_alpha_blending(dev->info, format),
        .sampling = isl_format_supports_sampling(dev->info, format),
        .filtering = isl_format_supports_filtering(dev->info, format),
        .vertex_fetch = isl_format_supports_vertex_fetch(dev->info, format),
        .typed_read = isl_format_supports_typed_reads(dev->info, format),
        .typed_write = isl_format_supports_typed_writes(dev->info, format),
        .typed_atomic = isl_format_supports_typed_atomics(dev->info, format),
        .raw_buffer_encoder = format == ISL_FORMAT_RAW,
        .sample_counts = isl_format_supports_multisampling(dev->info, format) ?
                         isl_device_get_sample_counts(dev) : 0,
    };
    return 0;
}

int stela_intel_query_raw_limits(const struct isl_device *dev, struct stela_intel_raw_limits *out)
{
    int err = check_device(dev);
    if (err) return err;
    if (!out) return -22;
    uint64_t limit = dev->max_buffer_size;
    if (limit > UINT32_MAX) limit = UINT32_MAX;
    /* At the upper size boundary only complete dwords preserve exact size
     * without overflowing ISL's padding encoding or the 32-bit size query. */
    *out = (struct stela_intel_raw_limits){
        .max_view_bytes = limit & ~UINT64_C(3),
        .state_bytes = dev->ss.size, .gpu_state_alignment = dev->ss.align,
        .surface_address_bits = RENDER_SURFACE_STATE_SurfaceBaseAddress_bits(dev->info),
    };
    return 0;
}
