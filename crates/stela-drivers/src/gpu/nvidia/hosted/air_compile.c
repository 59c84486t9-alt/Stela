/* SPDX-License-Identifier: MIT */
#include "air_compile.h"
#include "nouveau/compiler/nak_private.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TEXT 4096u
#define MAX_CODE (64u * 1024u * 1024u)
#define CBUF_COUNT 8u
#define CBUF_BYTES 65536u
/* Existing NVK/native compute limits, also checked by compute.c. */
#define MAX_LOCAL_XY 1024u
#define MAX_LOCAL_Z 64u
#define MAX_THREADS 1024u

struct stela_nvidia_air_compilation {
    struct stela_nvidia_air_provenance provenance;
    nir_shader_compiler_options nir_options;
    nir_shader *shader;
    struct nak_shader_bin *bin;
    struct stela_nvidia_air_binding bindings[AIR_MAX_ARGUMENTS];
    uint32_t binding_count, table_bytes;
    void *metadata;
    bool type_reference;
};
static enum stela_nvidia_air_status report(struct stela_nvidia_air_error *error,
    enum stela_nvidia_air_status status, const char *detail)
{
    if (error) {
        error->status = status;
        snprintf(error->detail, sizeof(error->detail), "%s", detail);
    }
    return status;
}
void stela_nvidia_air_destroy(struct stela_nvidia_air_compilation **slot)
{
    if (!slot || !*slot) return;
    struct stela_nvidia_air_compilation *owner = *slot; *slot = NULL;
    if (owner->bin) nak_shader_bin_destroy(owner->bin);
    ralloc_free(owner->shader);
    if (owner->type_reference) glsl_type_singleton_decref();
    free(owner->metadata); free(owner);
}
static bool text_valid(const char *text, size_t bytes)
{
    return bytes <= MAX_TEXT && (!bytes || (text && !memchr(text, 0, bytes)));
}
static char *copy_text(char **cursor, const void *text, size_t bytes)
{
    if (!text) return NULL;
    char *result = *cursor;
    memcpy(result, text, bytes); result[bytes] = 0; *cursor += bytes + 1; return result;
}
static enum stela_nvidia_air_status copy_provenance(struct stela_nvidia_air_compilation *owner,
    const struct stela_metal_library_manifest *manifest,
    const struct stela_metal_function_record *record, unsigned selected,
    struct stela_nvidia_air_error *error)
{
    if (!text_valid((const char *)record->name, record->name_bytes) || !record->name_bytes ||
        !text_valid((const char *)manifest->target, manifest->target_bytes) || !manifest->target_bytes ||
        record->argument_count > AIR_MAX_ARGUMENTS || (record->argument_count && !record->arguments))
        return report(error, STELA_NVIDIA_AIR_INVALID, "Unrepresentable selected entry metadata");
    size_t bytes = record->argument_count * sizeof(struct stela_air_argument_info) +
        (size_t)record->name_bytes + (size_t)manifest->target_bytes + 2;
    for (unsigned i = 0; i < record->argument_count; i++) {
        const struct stela_air_argument_info *arg = &record->arguments[i];
        if (!text_valid(arg->name, arg->name_bytes) || !text_valid(arg->type_name, arg->type_name_bytes))
            return report(error, STELA_NVIDIA_AIR_INVALID, "Unrepresentable argument strings");
        bytes += arg->name_bytes + arg->type_name_bytes + 2;
    }
    /* Bounded before allocation by128 arguments and4096 bytes/string. */
    owner->metadata = malloc(bytes);
    if (!owner->metadata) return report(error, STELA_NVIDIA_AIR_ALLOCATION, "Selected metadata allocation failed");
    struct stela_air_argument_info *args = owner->metadata;
    char *cursor = (char *)(args + record->argument_count);
    struct stela_nvidia_air_provenance *p = &owner->provenance;
    p->input = manifest->input; p->entry = record->entry; p->selected_entry = selected;
    p->entry_flags = record->flags; p->library_flags = manifest->flags; p->compiler_profile = manifest->compiler_profile;
    p->request_language = manifest->request_language; p->request_fast_math = manifest->request_fast_math;
    p->build = manifest->build; p->air_offset = record->air_offset; p->air_bytes = record->air_bytes;
    memcpy(p->air_sha256, record->air_sha256, 32); memcpy(p->source_sha256, manifest->source_sha256, 32);
    p->name = copy_text(&cursor, record->name, (size_t)record->name_bytes);
    p->target = copy_text(&cursor, manifest->target, (size_t)manifest->target_bytes);
    p->argument_count = record->argument_count; p->arguments = args;
    for (unsigned i = 0; i < record->argument_count; i++) {
        args[i] = record->arguments[i];
        args[i].name = copy_text(&cursor, args[i].name, args[i].name_bytes);
        args[i].type_name = copy_text(&cursor, args[i].type_name, args[i].type_name_bytes);
    }
    return STELA_NVIDIA_AIR_OK;
}
static bool same_buffer(const struct stela_air_buffer *a, const struct stela_air_buffer *b)
{
    return a->argument == b->argument && a->index == b->index && a->address_space == b->address_space &&
        a->access == b->access && a->type_size == b->type_size && a->type_alignment == b->type_alignment;
}
static enum stela_nvidia_air_status prepare_bindings(struct stela_nvidia_air_compilation *owner,
    struct stela_nvidia_air_error *error)
{
    for (unsigned i = 0; i < owner->provenance.argument_count; i++) {
        const struct stela_air_argument_info *arg = &owner->provenance.arguments[i];
        if (arg->kind == 2) continue;
        if (arg->kind == 1 && arg->buffer.address_space == 3 && arg->plain_buffer_type) continue;
        if (arg->kind != 1 || arg->buffer.address_space != 1 || !arg->plain_buffer_type)
            return report(error, STELA_NVIDIA_AIR_UNSUPPORTED, "Resource requires an unsupported binding specialization");
        if (!arg->used) continue;
        unsigned offset = owner->binding_count * STELA_NVIDIA_AIR_ROW_BYTES;
        if (owner->binding_count >= AIR_MAX_ARGUMENTS || offset > UINT16_MAX - STELA_NVIDIA_AIR_ROW_BYTES + 1)
            return report(error, STELA_NVIDIA_AIR_LIMIT, "Argument table exceeds original cbuf offset representation");
        owner->bindings[owner->binding_count++] = (struct stela_nvidia_air_binding) {
            .buffer = arg->buffer, .cbuf_offset = offset,
        };
    }
    unsigned bytes = owner->binding_count * STELA_NVIDIA_AIR_ROW_BYTES;
    owner->table_bytes = (bytes + STELA_NVIDIA_AIR_CBUF_ALIGNMENT - 1) & ~(STELA_NVIDIA_AIR_CBUF_ALIGNMENT - 1);
    if (owner->table_bytes > CBUF_BYTES)
        return report(error, STELA_NVIDIA_AIR_LIMIT, "Argument table exceeds QMD constant-buffer extent");
    return STELA_NVIDIA_AIR_OK;
}
static nir_def *bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
    const struct stela_nvidia_air_compilation *owner = data;
    for (unsigned i = 0; i < owner->binding_count; i++) {
        const struct stela_nvidia_air_binding *binding = &owner->bindings[i];
        if (same_buffer(&binding->buffer, buffer))
            return nir_ldc_nv(b, 1, 64, nir_imm_int(b, (int)owner->provenance.options.argument_cbuf),
                nir_imm_int(b, 0), .base = binding->cbuf_offset, .align_mul = 8, .align_offset = 0);
    }
    /* LLVM proves there are no uses of this original parameter. No resource
     * is fabricated for a dead argument; ordinary NIR DCE removes its undef. */
    for (unsigned i = 0; i < owner->provenance.argument_count; i++) {
        const struct stela_air_argument_info *arg = &owner->provenance.arguments[i];
        if (arg->kind == 1 && !arg->used && same_buffer(&arg->buffer, buffer)) return nir_undef(b, 1, 64);
    }
    return NULL;
}
static bool device_valid(const struct nv_device_info *device)
{
    if (device->sm < 20 || !device->max_warps_per_mp || device->max_warps_per_mp > 64 ||
        !device->max_smem_per_wg_kB || !device->sm_smem_size_count ||
        device->sm_smem_size_count > ARRAY_SIZE(device->sm_smem_sizes_kB)) return false;
    for (unsigned i = 0; i < device->sm_smem_size_count; i++) {
        unsigned size = device->sm_smem_sizes_kB[i];
        if (size % 4 || (i && size <= device->sm_smem_sizes_kB[i - 1])) return false;
    }
    return device->max_smem_per_wg_kB <= device->sm_smem_sizes_kB[device->sm_smem_size_count - 1];
}
static bool bind_threadgroup(const struct stela_air_buffer *buffer,
    struct stela_air_threadgroup_view *view, void *data)
{
    const struct stela_nvidia_air_compilation *owner = data;
    const struct stela_metal_threadgroup_specialization *shared = &owner->provenance.threadgroup;
    for (unsigned i = 0; i < shared->count; i++) {
        const struct stela_metal_threadgroup_binding *binding = &shared->bindings[i];
        const struct stela_air_buffer *b = &binding->buffer;
        if (b->argument == buffer->argument && b->index == buffer->index &&
            b->address_space == buffer->address_space && b->access == buffer->access &&
            b->type_size == buffer->type_size && b->type_alignment == buffer->type_alignment) {
            *view = (struct stela_air_threadgroup_view){.size = binding->bytes,
                .alignment = binding->alignment, .available_access = STELA_AIR_READ_WRITE};
            return true;
        }
    }
    return false;
}
enum stela_nvidia_air_status stela_nvidia_air_compile(const struct nv_device_info *device,
    const struct nak_compiler *compiler, const struct stela_metal_assembly *library,
    uint32_t selected, const struct stela_nvidia_air_options *options,
    struct stela_nvidia_air_compilation **output, struct stela_nvidia_air_error *error)
{
    return stela_nvidia_air_compile_specialized(device, compiler, library, selected, options, NULL, output, error);
}
enum stela_nvidia_air_status stela_nvidia_air_compile_specialized(const struct nv_device_info *device,
    const struct nak_compiler *compiler, const struct stela_metal_assembly *library,
    uint32_t selected, const struct stela_nvidia_air_options *options,
    const struct stela_metal_threadgroup_request *request,
    struct stela_nvidia_air_compilation **output, struct stela_nvidia_air_error *error)
{
    if (error) memset(error, 0, sizeof(*error));
    if (!device || !compiler || !library || !options || !output || *output ||
        options->size != sizeof(*options) || options->abi != STELA_NVIDIA_AIR_ABI)
        return report(error, STELA_NVIDIA_AIR_INVALID, "Invalid local compiler ownership/ABI");
    if (!options->max_instructions || !options->max_code_bytes || options->max_code_bytes > MAX_CODE)
        return report(error, STELA_NVIDIA_AIR_LIMIT, "Explicit bounded instruction/code budgets required");
    if (options->argument_cbuf >= CBUF_COUNT || options->record_assembly > 1 ||
        (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT &&
         options->fp_profile != STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41))
        return report(error, STELA_NVIDIA_AIR_UNSUPPORTED, "Unsupported cbuf/diagnostic/FP policy");
    if (!device_valid(device) || compiler->sm != device->sm || compiler->warps_per_sm != device->max_warps_per_mp)
        return report(error, STELA_NVIDIA_AIR_DEVICE, "Actual matching initialized NAK/device facts required");
    const nir_shader_compiler_options *actual_options = nak_nir_options(compiler);
    if (!actual_options || actual_options->cb_data)
        return report(error, STELA_NVIDIA_AIR_UNSUPPORTED, "Borrowed NIR option callback data cannot outlive its compiler");
    uint64_t threads = 1;
    for (unsigned axis = 0; axis < 3; axis++) {
        unsigned count = options->workgroup_size[axis];
        if (!count || count > (axis == 2 ? MAX_LOCAL_Z : MAX_LOCAL_XY) || threads > MAX_THREADS / count)
            return report(error, STELA_NVIDIA_AIR_UNSUPPORTED, "Invalid/unsupported workgroup specialization");
        threads *= count;
    }
    const struct stela_metal_library_manifest *manifest = stela_metal_assembly_manifest(library);
    if (!manifest || manifest->size != sizeof(*manifest) || manifest->abi != STELA_METAL_LIBRARY_ABI ||
        selected >= manifest->entry_count) return report(error, STELA_NVIDIA_AIR_INVALID, "Invalid selected canonical entry");
    const struct stela_metal_function_record *record = &manifest->entries[selected];
    if (record->size != sizeof(*record) || record->abi != STELA_METAL_LIBRARY_ABI ||
        !(record->flags & STELA_METAL_ENTRY_NO_CONSTANTS))
        return report(error, STELA_NVIDIA_AIR_UNSUPPORTED, "Unsupported entry ABI/function constants");
    struct stela_metal_input_view original = {.size = sizeof(original), .abi = STELA_METAL_INPUT_ABI};
    if (stela_metal_assembly_original(library, &original, NULL) != STELA_METAL_ASSEMBLY_OK ||
        record->air_offset > original.length || record->air_bytes > original.length - record->air_offset ||
        !record->air_bytes || record->air_bytes > AIR_MAX_BITCODE_BYTES)
        return report(error, STELA_NVIDIA_AIR_INVALID, "Invalid retained raw AIR span");
    struct stela_metal_threadgroup_specialization threadgroup;
    enum stela_metal_threadgroup_status shared_status = stela_metal_threadgroup_normalize(
        record->arguments, record->argument_count, request, MIN2((unsigned)device->max_smem_per_wg_kB * 1024, UINT16_MAX), &threadgroup);
    if (shared_status != STELA_METAL_THREADGROUP_OK)
        return report(error, shared_status == STELA_METAL_THREADGROUP_INVALID ? STELA_NVIDIA_AIR_INVALID :
            shared_status == STELA_METAL_THREADGROUP_LIMIT ? STELA_NVIDIA_AIR_LIMIT : STELA_NVIDIA_AIR_UNSUPPORTED,
            "Resource requires a supported threadgroup binding specialization");
    struct stela_nvidia_air_compilation *owner = calloc(1, sizeof(*owner));
    if (!owner) return report(error, STELA_NVIDIA_AIR_ALLOCATION, "Compilation owner allocation failed");
    owner->provenance.options = *options; owner->provenance.threadgroup = threadgroup; owner->provenance.device = *device;
    owner->provenance.base_layout = nak_const_offsets_base;
    owner->provenance.graphics_layout = nak_const_offsets_turing_graphics;
    owner->nir_options = *actual_options;
    enum stela_nvidia_air_status status = copy_provenance(owner, manifest, record, selected, error);
    if (!status) status = prepare_bindings(owner, error);
    if (status) { stela_nvidia_air_destroy(&owner); return status; }
    glsl_type_singleton_init_or_ref(); owner->type_reference = true;
    struct stela_air_options air = {
        .workgroup_size = {options->workgroup_size[0], options->workgroup_size[1], options->workgroup_size[2]},
        .max_instructions = options->max_instructions, .bind_buffer = bind_buffer, .binding_data = owner,
        .fp_profile = options->fp_profile,
        /* Original nak_shader_info.cs.smem_size is u16. Never allow an
         * unrepresentable size to reach the original Rust narrowing. */
        .bind_threadgroup = threadgroup.count ? bind_threadgroup : NULL,
        .max_threadgroup_bytes = MIN2((unsigned)device->max_smem_per_wg_kB * 1024, UINT16_MAX),
    };
    struct stela_air_error air_error;
    owner->shader = stela_air_to_nir(original.bytes + record->air_offset, (size_t)record->air_bytes,
        owner->provenance.name, &owner->nir_options, &air, &air_error);
    if (!owner->shader) {
        if (error) error->air = air_error;
        stela_nvidia_air_destroy(&owner);
        return report(error, STELA_NVIDIA_AIR_FRONTEND, "Shared AIR frontend refused selected body/policy");
    }
    nir_validate_shader(owner->shader, "owned AIR argument-table ABI");
    nak_preprocess_nir(owner->shader, compiler);
    /* The original compile function owns its single postprocessing pass. */
    owner->bin = nak_compile_shader(owner->shader, options->record_assembly != 0, compiler, 0, NULL, false);
    owner->provenance.nak_debug_flags = nak_debug_flags(compiler);
    if (!owner->bin || !owner->bin->code || !owner->bin->code_size ||
        owner->bin->info.stage != MESA_SHADER_COMPUTE || owner->bin->info.sm != device->sm ||
        owner->bin->info.cs.smem_size != owner->shader->info.shared_size) {
        stela_nvidia_air_destroy(&owner);
        return report(error, STELA_NVIDIA_AIR_BACKEND, "Original NAK output unavailable/inconsistent");
    }
    if (owner->bin->code_size > options->max_code_bytes) {
        stela_nvidia_air_destroy(&owner);
        return report(error, STELA_NVIDIA_AIR_LIMIT, "Compiled code exceeds caller budget");
    }
    for (unsigned axis = 0; axis < 3; axis++) {
        if (owner->bin->info.cs.local_size[axis] != options->workgroup_size[axis]) {
            stela_nvidia_air_destroy(&owner);
            return report(error, STELA_NVIDIA_AIR_BACKEND, "NAK workgroup specialization differs");
        }
    }
    *output = owner; return report(error, STELA_NVIDIA_AIR_OK, "");
}

static bool within_vm(uint64_t address, uint64_t bytes, unsigned bits)
{
    if (!address || !bytes || !bits || bits > 63) return false;
    uint64_t last = (UINT64_C(1) << bits) - 1;
    return address <= last && bytes - 1 <= last - address;
}
enum stela_nvidia_air_status stela_nvidia_air_pack_arguments(const struct stela_nvidia_air_compilation *owner,
    const struct nv_device_info *device, unsigned va_bits, const struct stela_nvidia_air_buffer_view *views,
    uint32_t count, void *output, size_t bytes)
{
    if (!owner || !device || !device_valid(device) || !va_bits || va_bits > 63)
        return STELA_NVIDIA_AIR_INVALID;
    const struct nv_device_info *compiled = &owner->provenance.device;
    if (device->sm != compiled->sm || device->max_warps_per_mp != compiled->max_warps_per_mp ||
        device->cls_compute != compiled->cls_compute) return STELA_NVIDIA_AIR_DEVICE;
    if (count != owner->binding_count || (count && (!views || !output)) || bytes < owner->table_bytes)
        return STELA_NVIDIA_AIR_BINDING;
    uint64_t addresses[AIR_MAX_ARGUMENTS];
    bool seen[AIR_MAX_ARGUMENTS] = {false};
    for (unsigned i = 0; i < count; i++) {
        const struct stela_nvidia_air_buffer_view *view = &views[i];
        unsigned slot;
        for (slot = 0; slot < owner->binding_count; slot++) {
            const struct stela_air_buffer *buffer = &owner->bindings[slot].buffer;
            if (view->index == buffer->index && view->argument == buffer->argument) break;
        }
        if (slot == owner->binding_count || seen[slot]) return STELA_NVIDIA_AIR_BINDING;
        seen[slot] = true;
        const struct stela_air_buffer *buffer = &owner->bindings[slot].buffer;
        if (view->device != device || !view->owner || !view->bytes ||
            (view->available_access & ~(uint32_t)STELA_AIR_READ_WRITE) ||
            (view->available_access & (unsigned)buffer->access) != (unsigned)buffer->access ||
            view->offset > view->allocation_bytes || view->bytes > view->allocation_bytes - view->offset ||
            !within_vm(view->allocation_va, view->allocation_bytes, va_bits) ||
            view->offset > UINT64_MAX - view->allocation_va || view->bytes < buffer->type_size ||
            !buffer->type_alignment || (view->allocation_va + view->offset) % buffer->type_alignment)
            return STELA_NVIDIA_AIR_BINDING;
        addresses[slot] = view->allocation_va + view->offset;
    }
    /* Every check precedes writes. Slots/count form a bijection; only this
     * dedicated table image (including initialized alignment padding) changes. */
    if (owner->table_bytes) memset(output, 0, owner->table_bytes);
    for (unsigned i = 0; i < count; i++) {
        uint8_t *row = (uint8_t *)output + owner->bindings[i].cbuf_offset;
        for (unsigned byte = 0; byte < STELA_NVIDIA_AIR_ROW_BYTES; byte++) row[byte] = (uint8_t)(addresses[i] >> (8 * byte));
    }
    return STELA_NVIDIA_AIR_OK;
}
const struct nak_shader_bin *stela_nvidia_air_binary(const struct stela_nvidia_air_compilation *owner)
{
    return owner ? owner->bin : NULL;
}
const nir_shader *stela_nvidia_air_nir(const struct stela_nvidia_air_compilation *owner)
{
    return owner ? owner->shader : NULL;
}
const struct stela_nvidia_air_provenance *stela_nvidia_air_provenance(const struct stela_nvidia_air_compilation *owner)
{
    return owner ? &owner->provenance : NULL;
}
const struct stela_nvidia_air_binding *stela_nvidia_air_bindings(const struct stela_nvidia_air_compilation *owner,
    uint32_t *count, uint32_t *table_bytes)
{
    if (count) *count = owner ? owner->binding_count : 0;
    if (table_bytes) *table_bytes = owner ? owner->table_bytes : 0;
    return owner ? owner->bindings : NULL;
}
