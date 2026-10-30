/* SPDX-License-Identifier: MIT */
#include "threadgroup.h"
#include <string.h>

static bool request_valid(const struct stela_metal_threadgroup_request *request)
{
    if (!request) return true;
    if (request->size != sizeof(*request) || request->abi != STELA_METAL_THREADGROUP_ABI ||
        request->reserved || request->count > AIR_MAX_ARGUMENTS || (request->count && !request->rows)) return false;
    for (unsigned i = 0; i < request->count; i++) {
        if (request->rows[i].reserved) return false;
        for (unsigned j = 0; j < i; j++)
            if (request->rows[j].index == request->rows[i].index) return false;
    }
    return true;
}
static const struct stela_metal_threadgroup_request_row *find(
    const struct stela_metal_threadgroup_request *request, unsigned index)
{
    if (request) {
        for (unsigned i = 0; i < request->count; i++)
            if (request->rows[i].index == index) return &request->rows[i];
    }
    return NULL;
}
enum stela_metal_threadgroup_status stela_metal_threadgroup_normalize(
    const struct stela_air_argument_info *arguments, uint32_t argument_count,
    const struct stela_metal_threadgroup_request *request, uint32_t max_bytes,
    struct stela_metal_threadgroup_specialization *output)
{
    if (!output || argument_count > AIR_MAX_ARGUMENTS || (argument_count && !arguments) || !request_valid(request))
        return STELA_METAL_THREADGROUP_INVALID;
    struct stela_metal_threadgroup_specialization result = {0};
    uint64_t total = 0;
    for (unsigned i = 0; i < argument_count; i++) {
        const struct stela_air_argument_info *arg = &arguments[i];
        if (arg->kind != 1 || arg->buffer.address_space != 3) continue;
        const struct stela_air_buffer *b = &arg->buffer;
        if (!arg->plain_buffer_type || !b->type_size || !b->type_alignment ||
            (b->type_alignment & (b->type_alignment - 1)) || b->access < STELA_AIR_READ || b->access > STELA_AIR_READ_WRITE)
            return STELA_METAL_THREADGROUP_UNSUPPORTED;
        for (unsigned j = 0; j < result.count; j++)
            if (result.bindings[j].buffer.index == b->index || result.bindings[j].buffer.argument == b->argument)
                return STELA_METAL_THREADGROUP_INVALID;
        const struct stela_metal_threadgroup_request_row *row = find(request, b->index);
        if (!row || !row->bytes || row->bytes < b->type_size || row->bytes % STELA_METAL_THREADGROUP_ALIGNMENT)
            return STELA_METAL_THREADGROUP_UNSUPPORTED;
        unsigned alignment = b->type_alignment < STELA_METAL_THREADGROUP_ALIGNMENT ?
            STELA_METAL_THREADGROUP_ALIGNMENT : b->type_alignment;
        if (!max_bytes || row->bytes > max_bytes || total > max_bytes - row->bytes || alignment > max_bytes)
            return STELA_METAL_THREADGROUP_LIMIT;
        total += row->bytes;
        result.bindings[result.count++] = (struct stela_metal_threadgroup_binding) {
            .buffer = *b, .bytes = row->bytes, .alignment = alignment,
        };
    }
    if (request && result.count != request->count) return STELA_METAL_THREADGROUP_INVALID;
    *output = result;
    return STELA_METAL_THREADGROUP_OK;
}
bool stela_metal_threadgroup_matches(const struct stela_metal_threadgroup_specialization *compiled,
                                    const struct stela_metal_threadgroup_request *request)
{
    if (!compiled || compiled->count > AIR_MAX_ARGUMENTS || !request_valid(request) ||
        compiled->count != (request ? request->count : 0)) return false;
    for (unsigned i = 0; i < compiled->count; i++) {
        const struct stela_metal_threadgroup_request_row *row = find(request, compiled->bindings[i].buffer.index);
        if (!row || row->bytes != compiled->bindings[i].bytes) return false;
    }
    return true;
}
