/* SPDX-License-Identifier: MIT */
#include "vulkan_buffers.h"
#include <string.h>

_Static_assert(AIR_MAX_ARGUMENTS <= UINT32_MAX / STELA_VULKAN_BUFFER_METADATA_ENTRY_BYTES,
               "bounded metadata byte extent");
_Static_assert(STELA_VULKAN_BUFFER_MAX_LAYOUT_BINDINGS <= UINT64_MAX / UINT32_MAX,
               "complete descriptor counts cannot overflow uint64_t");

static bool power_of_two(uint64_t n)
{
    return n && !(n & (n - 1));
}

static bool access_valid(enum stela_air_buffer_access access)
{
    return access >= STELA_AIR_READ && access <= STELA_AIR_READ_WRITE;
}

static bool stage_valid(enum stela_vulkan_buffer_stage stage)
{
    return stage == STELA_VULKAN_BUFFER_COMPUTE || stage == STELA_VULKAN_BUFFER_VERTEX ||
        stage == STELA_VULKAN_BUFFER_FRAGMENT;
}

static enum stela_vulkan_buffer_status buffer_valid(const struct stela_air_buffer *buffer)
{
    if (!buffer || buffer->argument >= AIR_MAX_ARGUMENTS || buffer->index >= AIR_MAX_ARGUMENTS ||
        !access_valid(buffer->access) ||
        (buffer->type_alignment && !power_of_two(buffer->type_alignment)))
        return STELA_VULKAN_BUFFER_INVALID;
    if ((buffer->address_space != 1 && buffer->address_space != 2) ||
        (buffer->address_space == 2 && buffer->access != STELA_AIR_READ))
        return STELA_VULKAN_BUFFER_UNSUPPORTED;
    return STELA_VULKAN_BUFFER_OK;
}

static bool geometry_limits_valid(const struct stela_vulkan_buffer_limits *limits)
{
    return limits && power_of_two(limits->min_offset_alignment) && limits->max_storage_range;
}

enum stela_vulkan_buffer_status stela_vulkan_buffer_plan(
    const struct stela_vulkan_buffer_request *request, const struct stela_vulkan_buffer_limits *limits,
    struct stela_vulkan_buffer_plan *output)
{
    if (!request || !output || request->count > AIR_MAX_ARGUMENTS ||
        request->layout_binding_count > STELA_VULKAN_BUFFER_MAX_LAYOUT_BINDINGS)
        return STELA_VULKAN_BUFFER_INVALID;
    struct stela_vulkan_buffer_plan result;
    memset(&result, 0, sizeof(result));
    if (!request->count) {
        if (request->layout_binding_count || request->metadata_binding)
            return STELA_VULKAN_BUFFER_INVALID;
        *output = result;
        return STELA_VULKAN_BUFFER_OK;
    }
    if (!request->mappings || !request->layout_bindings || !request->layout_binding_count ||
        request->metadata_binding >= request->layout_binding_count ||
        !geometry_limits_valid(limits) || !limits->max_bound_sets ||
        !limits->max_storage_descriptors || !limits->max_per_stage_storage_descriptors)
        return STELA_VULKAN_BUFFER_INVALID;
    uint64_t total = 0, stage_counts[3] = {0};
    const uint32_t stages[] = {STELA_VULKAN_BUFFER_COMPUTE, STELA_VULKAN_BUFFER_VERTEX,
                               STELA_VULKAN_BUFFER_FRAGMENT};
    const uint32_t stage_mask = STELA_VULKAN_BUFFER_COMPUTE | STELA_VULKAN_BUFFER_VERTEX |
        STELA_VULKAN_BUFFER_FRAGMENT;
    for (uint32_t i = 0; i < request->layout_binding_count; i++) {
        const struct stela_vulkan_buffer_layout_binding *layout = &request->layout_bindings[i];
        if (!layout->array_count || !layout->stage_mask)
            return STELA_VULKAN_BUFFER_INVALID;
        if (layout->descriptor != STELA_VULKAN_BUFFER_DESCRIPTOR_STORAGE || layout->set_flags ||
            layout->binding_flags || (layout->stage_mask & ~stage_mask))
            return STELA_VULKAN_BUFFER_UNSUPPORTED;
        if (layout->set >= limits->max_bound_sets)
            return STELA_VULKAN_BUFFER_LIMIT;
        for (uint32_t j = 0; j < i; j++) {
            const struct stela_vulkan_buffer_layout_binding *other = &request->layout_bindings[j];
            if (layout->set == other->set && layout->binding == other->binding)
                return STELA_VULKAN_BUFFER_INVALID;
        }
        total += layout->array_count;
        if (total > limits->max_storage_descriptors)
            return STELA_VULKAN_BUFFER_LIMIT;
        for (unsigned stage = 0; stage < 3; stage++) {
            if (layout->stage_mask & stages[stage]) {
                stage_counts[stage] += layout->array_count;
                if (stage_counts[stage] > limits->max_per_stage_storage_descriptors)
                    return STELA_VULKAN_BUFFER_LIMIT;
            }
        }
    }
    const struct stela_vulkan_buffer_layout_binding *metadata =
        &request->layout_bindings[request->metadata_binding];
    if (metadata->array_count != 1)
        return STELA_VULKAN_BUFFER_INVALID;
    for (uint32_t i = 0; i < request->count; i++) {
        const struct stela_vulkan_buffer_mapping *row = &request->mappings[i];
        enum stela_vulkan_buffer_status status = buffer_valid(&row->buffer);
        if (status != STELA_VULKAN_BUFFER_OK)
            return status;
        if (row->ordinal != i || !stage_valid(row->stage) ||
            row->layout_binding >= request->layout_binding_count ||
            row->layout_binding == request->metadata_binding)
            return STELA_VULKAN_BUFFER_INVALID;
        const struct stela_vulkan_buffer_layout_binding *layout =
            &request->layout_bindings[row->layout_binding];
        if (row->element >= layout->array_count ||
            !(layout->stage_mask & (uint32_t)row->stage) ||
            !(metadata->stage_mask & (uint32_t)row->stage))
            return STELA_VULKAN_BUFFER_INVALID;
        for (uint32_t j = 0; j < i; j++) {
            const struct stela_vulkan_buffer_mapping *other = &request->mappings[j];
            if ((row->stage == other->stage &&
                 (row->buffer.index == other->buffer.index || row->buffer.argument == other->buffer.argument)) ||
                (row->layout_binding == other->layout_binding && row->element == other->element))
                return STELA_VULKAN_BUFFER_INVALID;
        }
    }
    result.count = request->count;
    result.layout_binding_count = request->layout_binding_count;
    result.metadata_binding = request->metadata_binding;
    result.metadata_bytes = request->count * STELA_VULKAN_BUFFER_METADATA_ENTRY_BYTES;
    if (result.metadata_bytes > limits->max_storage_range)
        return STELA_VULKAN_BUFFER_LIMIT;
    memcpy(result.mappings, request->mappings, request->count * sizeof(result.mappings[0]));
    memcpy(result.layout_bindings, request->layout_bindings,
           request->layout_binding_count * sizeof(result.layout_bindings[0]));
    *output = result;
    return STELA_VULKAN_BUFFER_OK;
}

enum stela_vulkan_buffer_status stela_vulkan_buffer_view_plan(
    const struct stela_air_buffer *buffer, const struct stela_vulkan_buffer_limits *limits,
    const struct stela_vulkan_buffer_view *view, struct stela_vulkan_buffer_geometry *output)
{
    if (!view || !output || !geometry_limits_valid(limits))
        return STELA_VULKAN_BUFFER_INVALID;
    enum stela_vulkan_buffer_status status = buffer_valid(buffer);
    if (status != STELA_VULKAN_BUFFER_OK)
        return status;
    if (!access_valid(view->available_access) || !power_of_two(view->base_alignment))
        return STELA_VULKAN_BUFFER_INVALID;
    if ((buffer->access & ~view->available_access) || !view->length)
        return STELA_VULKAN_BUFFER_UNSUPPORTED;
    uint64_t alignment = buffer->type_alignment ? buffer->type_alignment : 1;
    if (view->base_alignment < alignment || (view->offset & (alignment - 1)))
        return STELA_VULKAN_BUFFER_UNSUPPORTED;
    if (view->offset > view->buffer_bytes || view->length > view->buffer_bytes - view->offset)
        return STELA_VULKAN_BUFFER_INVALID;
    uint64_t descriptor_offset = view->offset & ~(limits->min_offset_alignment - 1);
    uint64_t prefix = view->offset - descriptor_offset;
    /* Bound before adding, independently of native integer wrap and of any
     * provider's larger advertised capacity. A logical length is not padding. */
    if (view->length > UINT32_MAX || prefix > UINT32_MAX ||
        view->length > UINT32_MAX - prefix)
        return STELA_VULKAN_BUFFER_LIMIT;
    uint64_t range = prefix + view->length;
    if (range > limits->max_storage_range || range > view->buffer_bytes - descriptor_offset)
        return STELA_VULKAN_BUFFER_LIMIT;
    const struct stela_vulkan_buffer_geometry result = {
        .descriptor_offset = descriptor_offset, .descriptor_range = range,
        .prefix = (uint32_t)prefix, .logical_length = (uint32_t)view->length,
    };
    *output = result;
    return STELA_VULKAN_BUFFER_OK;
}

static struct stela_vulkan_buffer_update descriptor_update(
    const struct stela_vulkan_buffer_layout_binding *layout, uint32_t element,
    const struct stela_vulkan_buffer_geometry *geometry)
{
    return (struct stela_vulkan_buffer_update){
        .set = layout->set, .binding = layout->binding, .element = element,
        .offset = geometry->descriptor_offset, .range = geometry->descriptor_range,
    };
}

static void write_u32_le(uint8_t *bytes, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++)
        bytes[i] = (uint8_t)(value >> (8 * i));
}

enum stela_vulkan_buffer_status stela_vulkan_buffer_batch_plan(
    const struct stela_vulkan_buffer_request *request, const struct stela_vulkan_buffer_limits *limits,
    const struct stela_vulkan_buffer_view *views, uint32_t view_count,
    const struct stela_vulkan_buffer_metadata_storage *metadata, struct stela_vulkan_buffer_batch *output)
{
    if (!output)
        return STELA_VULKAN_BUFFER_INVALID;
    struct stela_vulkan_buffer_batch result;
    memset(&result, 0, sizeof(result));
    enum stela_vulkan_buffer_status status = stela_vulkan_buffer_plan(request, limits, &result.plan);
    if (status != STELA_VULKAN_BUFFER_OK)
        return status;
    if (view_count != result.plan.count || (view_count && (!views || !metadata)))
        return STELA_VULKAN_BUFFER_INVALID;
    if (!view_count) {
        *output = result;
        return STELA_VULKAN_BUFFER_OK;
    }
    for (uint32_t i = 0; i < view_count; i++) {
        if (views[i].ordinal != i)
            return STELA_VULKAN_BUFFER_INVALID;
        const struct stela_vulkan_buffer_mapping *row = &result.plan.mappings[i];
        struct stela_vulkan_buffer_geometry geometry;
        status = stela_vulkan_buffer_view_plan(&row->buffer, limits, &views[i], &geometry);
        if (status != STELA_VULKAN_BUFFER_OK)
            return status;
        result.payload[i] = descriptor_update(&result.plan.layout_bindings[row->layout_binding],
                                               row->element, &geometry);
        uint8_t *entry = result.metadata + i * STELA_VULKAN_BUFFER_METADATA_ENTRY_BYTES;
        write_u32_le(entry, geometry.prefix);
        write_u32_le(entry + 4, geometry.logical_length);
    }
    /* The metadata shader ABI starts at descriptor offset zero. Unlike a
     * payload view, this owned internal table has no second prefix table. */
    if (metadata->offset & (limits->min_offset_alignment - 1))
        return STELA_VULKAN_BUFFER_UNSUPPORTED;
    const struct stela_air_buffer metadata_buffer = {
        .address_space = 1, .access = STELA_AIR_READ, .type_alignment = 4,
    };
    const struct stela_vulkan_buffer_view metadata_view = {
        .buffer_bytes = metadata->buffer_bytes, .offset = metadata->offset,
        .length = result.plan.metadata_bytes, .base_alignment = metadata->base_alignment,
        .available_access = STELA_AIR_READ,
    };
    struct stela_vulkan_buffer_geometry geometry;
    status = stela_vulkan_buffer_view_plan(&metadata_buffer, limits, &metadata_view, &geometry);
    if (status != STELA_VULKAN_BUFFER_OK)
        return status;
    result.metadata_update = descriptor_update(
        &result.plan.layout_bindings[result.plan.metadata_binding], 0, &geometry);
    *output = result;
    return STELA_VULKAN_BUFFER_OK;
}

#ifdef STELA_VULKAN_BUFFER_TEST
#include <assert.h>
#include <stdio.h>
#ifdef NDEBUG
#error "Vulkan buffer value fixtures require active assertions"
#endif
#if !defined(__SIZEOF_INT128__)
#error "The independent geometry oracle requires a hosted 128-bit integer"
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct fixture {
    struct stela_vulkan_buffer_limits limits;
    struct stela_vulkan_buffer_layout_binding layouts[3];
    struct stela_vulkan_buffer_mapping mappings[3];
    struct stela_vulkan_buffer_view views[3];
    struct stela_vulkan_buffer_metadata_storage metadata;
};

static struct fixture fixture(void)
{
    const struct stela_vulkan_buffer_limits limits = {
        .min_offset_alignment = 256, .max_storage_range = UINT32_MAX,
        .max_bound_sets = 8, .max_storage_descriptors = 64,
        .max_per_stage_storage_descriptors = 32,
    };
    struct fixture f = {.limits = limits};
    f.layouts[0] = (struct stela_vulkan_buffer_layout_binding){
        .set = 2, .binding = 7, .array_count = 3,
        .stage_mask = STELA_VULKAN_BUFFER_VERTEX | STELA_VULKAN_BUFFER_FRAGMENT,
        .descriptor = STELA_VULKAN_BUFFER_DESCRIPTOR_STORAGE,
    };
    f.layouts[1] = (struct stela_vulkan_buffer_layout_binding){
        .set = 0, .binding = 200, .array_count = 2, .stage_mask = STELA_VULKAN_BUFFER_COMPUTE,
        .descriptor = STELA_VULKAN_BUFFER_DESCRIPTOR_STORAGE,
    };
    f.layouts[2] = (struct stela_vulkan_buffer_layout_binding){
        .set = 6, .binding = 1, .array_count = 1,
        .stage_mask = STELA_VULKAN_BUFFER_COMPUTE | STELA_VULKAN_BUFFER_VERTEX |
            STELA_VULKAN_BUFFER_FRAGMENT,
        .descriptor = STELA_VULKAN_BUFFER_DESCRIPTOR_STORAGE,
    };
    for (unsigned i = 0; i < 3; i++) {
        f.mappings[i] = (struct stela_vulkan_buffer_mapping){
            .buffer = {.argument = i == 2 ? 1 : 3, .index = i == 2 ? 9 : 7,
                .address_space = i == 1 ? 2 : 1,
                .access = i == 1 ? STELA_AIR_READ : STELA_AIR_READ_WRITE,
                .type_size = 4, .type_alignment = i == 0 ? 4 : (i == 1 ? 8 : 1)},
            .ordinal = i, .stage = i == 0 ? STELA_VULKAN_BUFFER_VERTEX :
                (i == 1 ? STELA_VULKAN_BUFFER_FRAGMENT : STELA_VULKAN_BUFFER_COMPUTE),
            .layout_binding = i == 2 ? 1 : 0, .element = i == 0 ? 0 : (i == 1 ? 2 : 1),
        };
        f.views[i] = (struct stela_vulkan_buffer_view){
            .ordinal = i, .buffer_bytes = 4096, .offset = i == 0 ? 260 : (i == 1 ? 520 : 7),
            .length = i == 0 ? 64 : (i == 1 ? 33 : 17), .base_alignment = 256,
            .available_access = i == 1 ? STELA_AIR_READ : STELA_AIR_READ_WRITE,
        };
    }
    f.metadata = (struct stela_vulkan_buffer_metadata_storage){
        .buffer_bytes = 8192, .offset = 256, .base_alignment = 256,
    };
    return f;
}

static struct stela_vulkan_buffer_request request(const struct fixture *f)
{
    return (struct stela_vulkan_buffer_request){
        .count = 3, .layout_binding_count = 3, .mappings = f->mappings,
        .layout_bindings = f->layouts, .metadata_binding = 2,
    };
}

static void plan_failure(const struct stela_vulkan_buffer_request *r,
                         const struct stela_vulkan_buffer_limits *limits,
                         enum stela_vulkan_buffer_status expected)
{
    struct stela_vulkan_buffer_plan out, old;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&old, &out, sizeof(old));
    assert(stela_vulkan_buffer_plan(r, limits, &out) == expected);
    assert(!memcmp(&out, &old, sizeof(out)));
}

static void batch_failure(const struct fixture *f, const struct stela_vulkan_buffer_request *r,
                          uint32_t count, enum stela_vulkan_buffer_status expected)
{
    struct stela_vulkan_buffer_batch out, old;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&old, &out, sizeof(old));
    assert(stela_vulkan_buffer_batch_plan(r, &f->limits, f->views, count, &f->metadata, &out) == expected);
    assert(!memcmp(&out, &old, sizeof(out)));
}

static void exact_batch(void)
{
    struct fixture f = fixture();
    struct stela_vulkan_buffer_request r = request(&f);
    struct stela_vulkan_buffer_batch out;
    assert(stela_vulkan_buffer_batch_plan(&r, &f.limits, f.views, 3, &f.metadata, &out) ==
           STELA_VULKAN_BUFFER_OK);
    assert(out.plan.count == 3 && out.plan.layout_binding_count == 3 && out.plan.metadata_bytes == 24);
    assert(out.payload[0].set == 2 && out.payload[0].binding == 7 && out.payload[0].element == 0 &&
           out.payload[0].offset == 256 && out.payload[0].range == 68);
    assert(out.payload[1].set == 2 && out.payload[1].binding == 7 && out.payload[1].element == 2 &&
           out.payload[1].offset == 512 && out.payload[1].range == 41);
    assert(out.payload[2].set == 0 && out.payload[2].binding == 200 && out.payload[2].element == 1 &&
           out.payload[2].offset == 0 && out.payload[2].range == 24);
    assert(out.metadata_update.set == 6 && out.metadata_update.binding == 1 &&
           out.metadata_update.element == 0 && out.metadata_update.offset == 256 &&
           out.metadata_update.range == 24);
    static const uint8_t bytes[] = {
        4, 0, 0, 0, 64, 0, 0, 0, 8, 0, 0, 0, 33, 0, 0, 0, 7, 0, 0, 0, 17, 0, 0, 0,
    };
    assert(!memcmp(out.metadata, bytes, sizeof(bytes)));
    for (size_t i = sizeof(bytes); i < sizeof(out.metadata); i++)
        assert(!out.metadata[i]);
    /* Source edits after return cannot retarget the copied plan. */
    memset(f.layouts, 0, sizeof(f.layouts));
    memset(f.mappings, 0, sizeof(f.mappings));
    assert(out.plan.mappings[0].buffer.index == 7 && out.plan.mappings[1].buffer.address_space == 2);
    assert(out.plan.layout_bindings[0].array_count == 3 && out.plan.layout_bindings[1].binding == 200);
}

static void map_refusals(void)
{
    struct fixture f = fixture();
    struct stela_vulkan_buffer_request r = request(&f);
    struct stela_vulkan_buffer_plan out;
    f.limits.max_storage_descriptors = 6;
    f.limits.max_per_stage_storage_descriptors = 4;
    assert(stela_vulkan_buffer_plan(&r, &f.limits, &out) == STELA_VULKAN_BUFFER_OK);
    f.limits.max_storage_descriptors = 5;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_LIMIT);
    f.limits.max_storage_descriptors = 6;
    f.limits.max_per_stage_storage_descriptors = 3;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_LIMIT);
    f = fixture(); r = request(&f);
    f.limits.max_bound_sets = 6;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_LIMIT);
    f = fixture(); r = request(&f);
    f.limits.max_storage_range = 23;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_LIMIT);
    for (unsigned which = 0; which < 15; which++) {
        f = fixture(); r = request(&f);
        enum stela_vulkan_buffer_status status = STELA_VULKAN_BUFFER_INVALID;
        switch (which) {
        case 0: f.layouts[0].array_count = 0; break;
        case 1: f.layouts[0].stage_mask = 0; break;
        case 2: f.layouts[0].stage_mask |= 8; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 3: f.layouts[0].descriptor = (enum stela_vulkan_buffer_descriptor)0;
                status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 4: f.layouts[0].binding_flags = 1; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 5: f.layouts[0].set_flags = 1; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 6: f.layouts[1].set = 2; f.layouts[1].binding = 7; break;
        case 7: f.layouts[2].array_count = 2; break;
        case 8: f.mappings[0].ordinal = 1; break;
        case 9: f.mappings[0].layout_binding = 3; break;
        case 10: f.mappings[0].layout_binding = 2; break;
        case 11: f.mappings[0].element = 3; break;
        case 12: f.layouts[0].stage_mask = STELA_VULKAN_BUFFER_FRAGMENT; break;
        case 13: f.layouts[2].stage_mask = STELA_VULKAN_BUFFER_COMPUTE; break;
        case 14: f.mappings[1].element = 0; break;
        }
        plan_failure(&r, &f.limits, status);
    }
    for (unsigned which = 0; which < 9; which++) {
        f = fixture(); r = request(&f);
        enum stela_vulkan_buffer_status status = STELA_VULKAN_BUFFER_INVALID;
        switch (which) {
        case 0: f.mappings[1].stage = STELA_VULKAN_BUFFER_VERTEX; break;
        case 1: f.mappings[0].stage = (enum stela_vulkan_buffer_stage)3; break;
        case 2: f.mappings[0].buffer.argument = AIR_MAX_ARGUMENTS; break;
        case 3: f.mappings[0].buffer.index = AIR_MAX_ARGUMENTS; break;
        case 4: f.mappings[0].buffer.access = (enum stela_air_buffer_access)0; break;
        case 5: f.mappings[0].buffer.type_alignment = 3; break;
        case 6: f.mappings[0].buffer.address_space = 3; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 7: f.mappings[1].buffer.access = STELA_AIR_WRITE; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 8: f.mappings[0].buffer.address_space = 0; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        }
        plan_failure(&r, &f.limits, status);
    }
    f = fixture(); r = request(&f);
    r.count = AIR_MAX_ARGUMENTS + 1;
    r.mappings = (const void *)(uintptr_t)1;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_INVALID);
    r = request(&f); r.layout_binding_count = STELA_VULKAN_BUFFER_MAX_LAYOUT_BINDINGS + 1;
    r.layout_bindings = (const void *)(uintptr_t)1;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_INVALID);
    r = request(&f); r.mappings = NULL;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_INVALID);
    r = request(&f); r.layout_bindings = NULL;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_INVALID);
    r = request(&f); r.metadata_binding = 3;
    plan_failure(&r, &f.limits, STELA_VULKAN_BUFFER_INVALID);
    plan_failure(NULL, &f.limits, STELA_VULKAN_BUFFER_INVALID);
    r = request(&f);
    plan_failure(&r, NULL, STELA_VULKAN_BUFFER_INVALID);
    assert(stela_vulkan_buffer_plan(&r, &f.limits, NULL) == STELA_VULKAN_BUFFER_INVALID);
    const struct stela_vulkan_buffer_request empty = {0};
    assert(stela_vulkan_buffer_plan(&empty, NULL, &out) == STELA_VULKAN_BUFFER_OK && !out.count);
}

static void batch_refusals(void)
{
    for (unsigned which = 0; which < 11; which++) {
        struct fixture f = fixture();
        struct stela_vulkan_buffer_request r = request(&f);
        enum stela_vulkan_buffer_status status = STELA_VULKAN_BUFFER_INVALID;
        switch (which) {
        case 0: f.views[2].ordinal = 1; break;
        case 1: f.views[2].length = 0; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 2: f.views[2].offset = 4096; break;
        case 3: f.views[2].available_access = STELA_AIR_READ; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 4: f.views[1].offset = 521; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 5: f.views[1].base_alignment = 4; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 6: f.metadata.offset = 257; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 7: f.metadata.buffer_bytes = 279; break;
        case 8: f.metadata.base_alignment = 2; status = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 9: f.views[2].base_alignment = 3; break;
        case 10: f.views[2].length = UINT64_MAX; break;
        }
        batch_failure(&f, &r, 3, status);
    }
    struct fixture f = fixture();
    struct stela_vulkan_buffer_request r = request(&f);
    batch_failure(&f, &r, 2, STELA_VULKAN_BUFFER_INVALID);
    struct stela_vulkan_buffer_batch out, old;
    memset(&out, 0x65, sizeof(out)); memcpy(&old, &out, sizeof(old));
    assert(stela_vulkan_buffer_batch_plan(&r, &f.limits, NULL, 3, &f.metadata, &out) ==
           STELA_VULKAN_BUFFER_INVALID && !memcmp(&out, &old, sizeof(out)));
    assert(stela_vulkan_buffer_batch_plan(&r, &f.limits, f.views, 3, NULL, &out) ==
           STELA_VULKAN_BUFFER_INVALID && !memcmp(&out, &old, sizeof(out)));
    assert(stela_vulkan_buffer_batch_plan(&r, &f.limits, f.views, 3, &f.metadata, NULL) ==
           STELA_VULKAN_BUFFER_INVALID);
    const struct stela_vulkan_buffer_request empty = {0};
    assert(stela_vulkan_buffer_batch_plan(&empty, NULL, NULL, 0, NULL, &out) == STELA_VULKAN_BUFFER_OK);
    assert(!out.plan.count && !out.plan.metadata_bytes && !out.metadata_update.range);
    f = fixture(); r = request(&f);
    struct stela_vulkan_buffer_batch first, second;
    assert(stela_vulkan_buffer_batch_plan(&r, &f.limits, f.views, 3, &f.metadata, &first) ==
           STELA_VULKAN_BUFFER_OK);
    f.views[0].offset = 268; f.views[0].length = 16;
    assert(stela_vulkan_buffer_batch_plan(&r, &f.limits, f.views, 3, &f.metadata, &second) ==
           STELA_VULKAN_BUFFER_OK);
    assert(first.payload[0].offset == second.payload[0].offset && second.payload[0].range == 28);
    assert(first.plan.mappings[0].element == second.plan.mappings[0].element);
    assert(second.metadata[0] == 12 && second.metadata[4] == 16);
}

/* Independent widened arithmetic uses division/multiplication/full end sums,
 * unlike production's 64-bit masks and subtraction preflights. Policy failures
 * are tested separately; this oracle isolates exact mathematical geometry. */
static void math_case(uint64_t capacity, uint64_t offset, uint64_t length,
                      uint64_t alignment, uint64_t maximum)
{
    const struct stela_air_buffer buffer = {
        .address_space = 1, .access = STELA_AIR_READ_WRITE,
        .type_size = 65536, /* Reflection never enlarges a short real view. */
    };
    const struct stela_vulkan_buffer_limits limits = {
        .min_offset_alignment = alignment, .max_storage_range = maximum,
    };
    const struct stela_vulkan_buffer_view view = {
        .buffer_bytes = capacity, .offset = offset, .length = length, .base_alignment = 1,
        .available_access = STELA_AIR_READ_WRITE,
    };
    unsigned __int128 begin = (unsigned __int128)offset / alignment * alignment;
    unsigned __int128 prefix = (unsigned __int128)offset - begin;
    unsigned __int128 end = (unsigned __int128)offset + length;
    unsigned __int128 range = end - begin;
    enum stela_vulkan_buffer_status expected = STELA_VULKAN_BUFFER_OK;
    if (!length)
        expected = STELA_VULKAN_BUFFER_UNSUPPORTED;
    else if (offset > capacity || end > capacity)
        expected = STELA_VULKAN_BUFFER_INVALID;
    else if (length > UINT32_MAX || prefix > UINT32_MAX || range > UINT32_MAX || range > maximum)
        expected = STELA_VULKAN_BUFFER_LIMIT;
    struct stela_vulkan_buffer_geometry out, old;
    memset(&out, 0xc3, sizeof(out)); memcpy(&old, &out, sizeof(old));
    assert(stela_vulkan_buffer_view_plan(&buffer, &limits, &view, &out) == expected);
    if (expected == STELA_VULKAN_BUFFER_OK) {
        assert(out.descriptor_offset == begin && out.descriptor_range == range);
        assert(out.prefix == prefix && out.logical_length == length);
        assert((unsigned __int128)out.descriptor_offset + out.prefix == offset);
        assert((unsigned __int128)out.descriptor_offset + out.descriptor_range == end);
        assert(out.descriptor_offset % alignment == 0);
    } else {
        assert(!memcmp(&out, &old, sizeof(out)));
    }
}

static void geometry_refusals(void)
{
    for (unsigned which = 0; which < 12; which++) {
        struct stela_air_buffer b = {
            .address_space = 1, .access = STELA_AIR_READ_WRITE, .type_alignment = 4,
        };
        struct stela_vulkan_buffer_limits l = {.min_offset_alignment = 256, .max_storage_range = 4096};
        struct stela_vulkan_buffer_view v = {
            .buffer_bytes = 4096, .offset = 260, .length = 64, .base_alignment = 256,
            .available_access = STELA_AIR_READ_WRITE,
        };
        enum stela_vulkan_buffer_status expected = STELA_VULKAN_BUFFER_INVALID;
        switch (which) {
        case 0: l.min_offset_alignment = 0; break;
        case 1: l.min_offset_alignment = 3; break;
        case 2: l.max_storage_range = 0; break;
        case 3: v.base_alignment = 0; break;
        case 4: v.available_access = (enum stela_air_buffer_access)4; break;
        case 5: v.available_access = STELA_AIR_READ; expected = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 6: v.offset = 262; expected = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 7: v.base_alignment = 2; expected = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 8: b.address_space = 2; expected = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        case 9: b.type_alignment = 3; break;
        case 10: b.index = AIR_MAX_ARGUMENTS; break;
        case 11: v.length = 0; expected = STELA_VULKAN_BUFFER_UNSUPPORTED; break;
        }
        struct stela_vulkan_buffer_geometry out, old;
        memset(&out, 0xa5, sizeof(out)); memcpy(&old, &out, sizeof(old));
        assert(stela_vulkan_buffer_view_plan(&b, &l, &v, &out) == expected);
        assert(!memcmp(&out, &old, sizeof(out)));
    }
    const struct stela_air_buffer b = {.address_space = 1, .access = STELA_AIR_READ};
    const struct stela_vulkan_buffer_limits l = {.min_offset_alignment = 1, .max_storage_range = 16};
    const struct stela_vulkan_buffer_view v = {
        .buffer_bytes = 16, .length = 16, .base_alignment = 1, .available_access = STELA_AIR_READ,
    };
    struct stela_vulkan_buffer_geometry out, old;
    memset(&out, 0x65, sizeof(out)); memcpy(&old, &out, sizeof(old));
    assert(stela_vulkan_buffer_view_plan(NULL, &l, &v, &out) == STELA_VULKAN_BUFFER_INVALID);
    assert(!memcmp(&out, &old, sizeof(out)));
    assert(stela_vulkan_buffer_view_plan(&b, NULL, &v, &out) == STELA_VULKAN_BUFFER_INVALID);
    assert(!memcmp(&out, &old, sizeof(out)));
    assert(stela_vulkan_buffer_view_plan(&b, &l, NULL, &out) == STELA_VULKAN_BUFFER_INVALID);
    assert(!memcmp(&out, &old, sizeof(out)));
    assert(stela_vulkan_buffer_view_plan(&b, &l, &v, NULL) == STELA_VULKAN_BUFFER_INVALID);
}

static void geometry_math(void)
{
    static const uint64_t aligns[] = {1, 2, 4, 8, 16, 64};
    static const uint64_t maxima[] = {1, 7, 31, UINT32_MAX};
    for (uint64_t capacity = 0; capacity <= 24; capacity++) {
        for (uint64_t offset = 0; offset <= capacity + 1; offset++) {
            for (uint64_t length = 0; length <= capacity + 2; length++) {
                for (size_t a = 0; a < ARRAY_SIZE(aligns); a++) {
                    for (size_t m = 0; m < ARRAY_SIZE(maxima); m++)
                        math_case(capacity, offset, length, aligns[a], maxima[m]);
                }
            }
        }
    }
    static const uint64_t edges[] = {
        0, 1, 3, 255, 256, UINT32_MAX - UINT64_C(1), UINT32_MAX,
        UINT32_MAX + UINT64_C(1), UINT64_MAX - 256, UINT64_MAX - 1, UINT64_MAX,
    };
    static const uint64_t wide_aligns[] = {1, 256, UINT64_C(1) << 32, UINT64_C(1) << 63};
    for (size_t c = 0; c < ARRAY_SIZE(edges); c++) {
        for (size_t o = 0; o < ARRAY_SIZE(edges); o++) {
            for (size_t n = 0; n < ARRAY_SIZE(edges); n++) {
                for (size_t a = 0; a < ARRAY_SIZE(wide_aligns); a++)
                    math_case(edges[c], edges[o], edges[n], wide_aligns[a], UINT64_MAX);
            }
        }
    }
    /* Literal byte-position check: select the last aligned byte at or before
     * each origin, then count every backing byte through the logical end. */
    for (uint64_t origin = 0; origin < 64; origin++) {
        uint64_t aligned = 0;
        for (uint64_t byte = 0; byte <= origin; byte++)
            if (byte % 16 == 0)
                aligned = byte;
        uint64_t count = 0;
        for (uint64_t byte = aligned; byte < origin + 7; byte++)
            count++;
        const struct stela_air_buffer b = {.address_space = 1, .access = STELA_AIR_READ};
        const struct stela_vulkan_buffer_limits l = {.min_offset_alignment = 16, .max_storage_range = 128};
        const struct stela_vulkan_buffer_view v = {
            .buffer_bytes = 128, .offset = origin, .length = 7, .base_alignment = 1,
            .available_access = STELA_AIR_READ,
        };
        struct stela_vulkan_buffer_geometry g;
        assert(stela_vulkan_buffer_view_plan(&b, &l, &v, &g) == STELA_VULKAN_BUFFER_OK);
        assert(g.descriptor_offset == aligned && g.descriptor_range == count && g.prefix == origin - aligned);
    }
}

static void full_map_and_multibyte_metadata(void)
{
    struct stela_vulkan_buffer_mapping mappings[AIR_MAX_ARGUMENTS];
    struct stela_vulkan_buffer_view views[AIR_MAX_ARGUMENTS];
    struct stela_vulkan_buffer_layout_binding layouts[] = {
        {.set = 1, .binding = UINT32_MAX, .array_count = AIR_MAX_ARGUMENTS,
         .stage_mask = STELA_VULKAN_BUFFER_COMPUTE, .descriptor = STELA_VULKAN_BUFFER_DESCRIPTOR_STORAGE},
        {.set = 0, .binding = 0, .array_count = 1,
         .stage_mask = STELA_VULKAN_BUFFER_COMPUTE, .descriptor = STELA_VULKAN_BUFFER_DESCRIPTOR_STORAGE},
    };
    for (uint32_t i = 0; i < AIR_MAX_ARGUMENTS; i++) {
        mappings[i] = (struct stela_vulkan_buffer_mapping){
            .buffer = {.argument = i, .index = i, .address_space = 2, .access = STELA_AIR_READ},
            .ordinal = i, .stage = STELA_VULKAN_BUFFER_COMPUTE, .layout_binding = 0, .element = i,
        };
        views[i] = (struct stela_vulkan_buffer_view){
            .ordinal = i, .buffer_bytes = UINT64_MAX, .offset = UINT64_C(0x12345678),
            .length = UINT64_C(0x1020304), .base_alignment = 1, .available_access = STELA_AIR_READ,
        };
    }
    const struct stela_vulkan_buffer_request r = {
        .count = AIR_MAX_ARGUMENTS, .layout_binding_count = 2, .mappings = mappings,
        .layout_bindings = layouts, .metadata_binding = 1,
    };
    const struct stela_vulkan_buffer_limits l = {
        .min_offset_alignment = UINT64_C(1) << 32, .max_storage_range = UINT32_MAX,
        .max_bound_sets = 2, .max_storage_descriptors = AIR_MAX_ARGUMENTS + 1,
        .max_per_stage_storage_descriptors = AIR_MAX_ARGUMENTS + 1,
    };
    const struct stela_vulkan_buffer_metadata_storage meta = {
        .buffer_bytes = 4096, .base_alignment = 4096,
    };
    struct stela_vulkan_buffer_batch batch;
    assert(stela_vulkan_buffer_batch_plan(&r, &l, views, AIR_MAX_ARGUMENTS, &meta, &batch) ==
           STELA_VULKAN_BUFFER_OK);
    assert(batch.plan.metadata_bytes == AIR_MAX_ARGUMENTS * 8 && batch.metadata_update.range == AIR_MAX_ARGUMENTS * 8);
    const uint8_t expected[] = {0x78, 0x56, 0x34, 0x12, 0x04, 0x03, 0x02, 0x01};
    for (unsigned i = 0; i < AIR_MAX_ARGUMENTS; i++) {
        assert(!memcmp(batch.metadata + i * 8, expected, sizeof(expected)));
        assert(batch.payload[i].binding == UINT32_MAX && batch.payload[i].element == i);
    }
}

int main(void)
{
    exact_batch();
    map_refusals();
    batch_refusals();
    geometry_refusals();
    geometry_math();
    full_map_and_multibyte_metadata();
    puts("Vulkan buffer values: exact ranges, logical prefixes, bounded maps, metadata and batch rollback passed");
    return 0;
}
#endif
