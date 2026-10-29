/* SPDX-License-Identifier: MIT */
#ifndef STELA_VULKAN_BUFFERS_H
#define STELA_VULKAN_BUFFERS_H
#include "air_metadata.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Pure same-process value planning, not a Vulkan/Metal object or IPC ABI.
 * All input arrays are bounded, valid, stable and disjoint from writable
 * output for the complete call. Success copies values, retaining no pointers.
 * Caller-supplied observations do not establish device/layout/resource
 * authority: their actual providers and lifetimes remain separate services. */
#define STELA_VULKAN_BUFFER_METADATA_ENTRY_BYTES 8u
#define STELA_VULKAN_BUFFER_MAX_LAYOUT_BINDINGS (AIR_MAX_ARGUMENTS + 1u)

enum stela_vulkan_buffer_stage {
    STELA_VULKAN_BUFFER_COMPUTE = 1,
    STELA_VULKAN_BUFFER_VERTEX = 2,
    STELA_VULKAN_BUFFER_FRAGMENT = 4,
};
/* A preclassified fact, NOT the numeric VkDescriptorType enum. Only ordinary
 * storage buffers are admitted. Actual layout inspection supplies this value. */
enum stela_vulkan_buffer_descriptor {
    STELA_VULKAN_BUFFER_DESCRIPTOR_STORAGE = 1,
};
enum stela_vulkan_buffer_status {
    STELA_VULKAN_BUFFER_OK,
    STELA_VULKAN_BUFFER_INVALID,
    STELA_VULKAN_BUFFER_UNSUPPORTED,
    STELA_VULKAN_BUFFER_LIMIT,
};

struct stela_vulkan_buffer_limits {
    uint64_t min_offset_alignment;
    uint64_t max_storage_range;
    uint32_t max_bound_sets;
    uint32_t max_storage_descriptors; /* Complete pipeline's ordinary storage arrays. */
    uint32_t max_per_stage_storage_descriptors;
};
struct stela_vulkan_buffer_layout_binding {
    uint32_t set, binding, array_count;
    uint32_t stage_mask; /* stela_vulkan_buffer_stage bits, not VkShaderStageFlags. */
    enum stela_vulkan_buffer_descriptor descriptor;
    uint32_t set_flags, binding_flags; /* Nonzero policies are unsupported here. */
};
struct stela_vulkan_buffer_mapping {
    struct stela_air_buffer buffer; /* Actual selected-entry inspection facts. */
    uint32_t ordinal; /* Dense canonical order, independent of Metal index. */
    enum stela_vulkan_buffer_stage stage;
    uint32_t layout_binding, element;
};
struct stela_vulkan_buffer_request {
    uint32_t count, layout_binding_count;
    const struct stela_vulkan_buffer_mapping *mappings;
    /* Complete ordinary-storage declarations, including all array elements
     * and the reserved metadata binding, not only the used payload entries. */
    const struct stela_vulkan_buffer_layout_binding *layout_bindings;
    uint32_t metadata_binding; /* Index in layout_bindings; array_count must be 1. */
};
/* Pointer-free copied calculation result. Keep immutable while a borrower uses
 * it. Raw C object bytes/padding are NOT a wire encoding or cache identity. */
struct stela_vulkan_buffer_plan {
    uint32_t count, layout_binding_count, metadata_binding, metadata_bytes;
    struct stela_vulkan_buffer_mapping mappings[AIR_MAX_ARGUMENTS];
    struct stela_vulkan_buffer_layout_binding layout_bindings[STELA_VULKAN_BUFFER_MAX_LAYOUT_BINDINGS];
};

struct stela_vulkan_buffer_view {
    uint32_t ordinal;
    uint64_t buffer_bytes, offset, length;
    /* A supplied known alignment of the actual buffer origin, not a CPU/GPU
     * address and not a new alignment grant. The real owner proves it. */
    uint64_t base_alignment;
    enum stela_air_buffer_access available_access;
};
struct stela_vulkan_buffer_geometry {
    uint64_t descriptor_offset, descriptor_range;
    uint32_t prefix, logical_length;
};
/* Values to place beside an actual retained VkBuffer in a real descriptor
 * update. These values contain no handle, object ID, VA or memory authority. */
struct stela_vulkan_buffer_update {
    uint32_t set, binding, element;
    uint64_t offset, range;
};
struct stela_vulkan_buffer_metadata_storage {
    uint64_t buffer_bytes, offset, base_alignment;
};
struct stela_vulkan_buffer_batch {
    struct stela_vulkan_buffer_plan plan;
    struct stela_vulkan_buffer_update payload[AIR_MAX_ARGUMENTS];
    struct stela_vulkan_buffer_update metadata_update;
    uint8_t metadata[AIR_MAX_ARGUMENTS * STELA_VULKAN_BUFFER_METADATA_ENTRY_BYTES];
};

/* Failure changes no output byte. A completely empty request needs no limits
 * and returns an empty plan; it creates no descriptor or metadata resource. */
enum stela_vulkan_buffer_status stela_vulkan_buffer_plan(
    const struct stela_vulkan_buffer_request *, const struct stela_vulkan_buffer_limits *,
    struct stela_vulkan_buffer_plan *);
/* Nonempty exact logical view, <=UINT32_MAX length AND complete descriptor
 * range. Zero length is unsupported; no null descriptor is invented. Optional
 * reflected type_size is not treated as a resource extent or used to enlarge
 * the view. Reflected type_alignment, when present, remains a logical-pointer
 * requirement independently of Vulkan's descriptor-origin alignment. */
enum stela_vulkan_buffer_status stela_vulkan_buffer_view_plan(
    const struct stela_air_buffer *, const struct stela_vulkan_buffer_limits *,
    const struct stela_vulkan_buffer_view *, struct stela_vulkan_buffer_geometry *);
/* Views are in dense ordinal order. Output is committed only after the entire
 * map, payload batch and metadata storage validate. Metadata storage must have
 * an aligned descriptor origin and 4-byte logical alignment. The real owner
 * must separately exclude metadata/payload aliases, retain actual same-device
 * buffers/layouts and ensure visibility/residency/completion-governed reuse.
 * The only serialized bytes here are little-endian (prefix,length) entries. */
enum stela_vulkan_buffer_status stela_vulkan_buffer_batch_plan(
    const struct stela_vulkan_buffer_request *, const struct stela_vulkan_buffer_limits *,
    const struct stela_vulkan_buffer_view *, uint32_t view_count,
    const struct stela_vulkan_buffer_metadata_storage *, struct stela_vulkan_buffer_batch *);
#ifdef __cplusplus
}
#endif
#endif
