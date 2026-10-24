/* SPDX-License-Identifier: MIT */
#include "air_compile.h"
#include "fp_controls.h"
#include "intel/common/intel_compute_slm.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/compiler/gen/gen.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_TEXT 4096u
#define MAX_CODE (64u * 1024u * 1024u)
struct stela_intel_air_compilation {
    struct stela_intel_air_provenance provenance;
    struct stela_intel_air_binary binary;
    nir_shader_compiler_options nir_options;
    nir_shader *shader;
    void *context, *work_context, *metadata;
    struct brw_cs_prog_data brw;
    struct elk_cs_prog_data elk;
    struct stela_intel_air_binding bindings[AIR_MAX_ARGUMENTS];
    uint32_t binding_count;
    bool type_reference;
};
static enum stela_intel_air_status report(struct stela_intel_air_error *error,
    enum stela_intel_air_status status, const char *detail)
{
    if (error) { error->status = status; snprintf(error->detail, sizeof(error->detail), "%s", detail); }
    return status;
}
void stela_intel_air_destroy(struct stela_intel_air_compilation **slot)
{
    if (!slot || !*slot) return;
    struct stela_intel_air_compilation *owner = *slot; *slot = NULL;
    ralloc_free(owner->shader); ralloc_free(owner->work_context); ralloc_free(owner->context);
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
static enum stela_intel_air_status copy_provenance(struct stela_intel_air_compilation *owner,
    const struct stela_metal_library_manifest *manifest,
    const struct stela_metal_function_record *record, unsigned selected,
    struct stela_intel_air_error *error)
{
    if (!text_valid((const char *)record->name, record->name_bytes) || !record->name_bytes ||
        !text_valid((const char *)manifest->target, manifest->target_bytes) || !manifest->target_bytes ||
        record->argument_count > AIR_MAX_ARGUMENTS || (record->argument_count && !record->arguments))
        return report(error, STELA_INTEL_AIR_INVALID, "Unrepresentable selected entry metadata");
    size_t bytes = record->argument_count * sizeof(struct stela_air_argument_info) +
        (size_t)record->name_bytes + (size_t)manifest->target_bytes + 2 +
        owner->provenance.policy.lowered_format_count * sizeof(uint32_t);
    for (unsigned i = 0; i < record->argument_count; i++) {
        const struct stela_air_argument_info *arg = &record->arguments[i];
        if (!text_valid(arg->name, arg->name_bytes) || !text_valid(arg->type_name, arg->type_name_bytes))
            return report(error, STELA_INTEL_AIR_INVALID, "Unrepresentable argument strings");
        bytes += arg->name_bytes + arg->type_name_bytes + 2;
    }
    /* Bounded before allocation by128 arguments and4096 bytes/string. */
    owner->metadata = malloc(bytes);
    if (!owner->metadata) return report(error, STELA_INTEL_AIR_ALLOCATION, "Selected metadata allocation failed");
    struct stela_air_argument_info *args = owner->metadata;
    uint32_t *formats = (uint32_t *)(args + record->argument_count);
    unsigned count = owner->provenance.policy.lowered_format_count;
    if (count) memcpy(formats, owner->provenance.policy.lowered_formats, count * sizeof(*formats));
    owner->provenance.policy.lowered_formats = count ? formats : NULL;
    char *cursor = (char *)(formats + count);
    struct stela_intel_air_provenance *p = &owner->provenance;
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
    return STELA_INTEL_AIR_OK;
}
static bool bind_ssbo(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
    struct stela_intel_air_compilation *owner = data;
    for (unsigned i = 0; i < owner->binding_count; i++) {
        const struct stela_air_buffer *b = &owner->bindings[i].buffer;
        if (b->argument == buffer->argument && b->index == buffer->index &&
            b->address_space == buffer->address_space && b->access == buffer->access &&
            b->type_size == buffer->type_size && b->type_alignment == buffer->type_alignment) {
            *slot = owner->bindings[i].slot; return true;
        }
    }
    return false;
}
static enum stela_intel_air_status prepare_bindings(struct stela_intel_air_compilation *owner,
    struct stela_intel_air_error *error)
{
    for (unsigned i = 0; i < owner->provenance.argument_count; i++) {
        const struct stela_air_argument_info *arg = &owner->provenance.arguments[i];
        if (arg->kind == 2) continue;
        if (arg->kind == 1 && arg->buffer.address_space == 3 && arg->plain_buffer_type) continue;
        if (arg->kind != 1 || arg->buffer.address_space != 1 || !arg->plain_buffer_type)
            return report(error, STELA_INTEL_AIR_UNSUPPORTED, "Unsupported resource binding specialization");
        unsigned slot = owner->binding_count;
        if (slot >= AIR_MAX_ARGUMENTS || slot >= UINT8_MAX)
            return report(error, STELA_INTEL_AIR_LIMIT, "SSBO slot representation exceeded");
        owner->bindings[owner->binding_count++] = (struct stela_intel_air_binding){arg->buffer, slot};
    }
    return STELA_INTEL_AIR_OK;
}
static bool device_valid(const struct intel_device_info *d, bool elk)
{
    if (!d || !d->slice_masks || !d->subslice_total || !d->num_thread_per_eu ||
        !d->max_cs_threads || !d->max_cs_workgroup_threads) return false;
    if (elk) return d->verx10 == 70 || d->verx10 == 75 || d->verx10 == 80;
    switch (d->verx10) {
    case 90: case 110: case 120: case 125: case 200: case 300: case 350: return true;
    default: return false;
    }
}
/* Qualified Gen7 admission is aligned 32-bit shared I/O. Original ELK
 * postprocessing may widen other inputs; do not duplicate it or enter an
 * unqualified byte-scattered path (Gen7.5+). Inspect actual intrinsics after
 * preprocessing/CS lowering, not declared AIR types. */
static bool gen7_shared_io_supported(const struct intel_device_info *device, nir_shader *shader)
{
    if (device->verx10 != 70) return true;
    nir_foreach_function_impl(impl, shader) {
        nir_foreach_block(block, impl) {
            nir_foreach_instr(instr, block) {
                if (instr->type != nir_instr_type_intrinsic) continue;
                nir_intrinsic_instr *in = nir_instr_as_intrinsic(instr);
                unsigned bits;
                if (in->intrinsic == nir_intrinsic_load_shared) bits = in->def.bit_size;
                else if (in->intrinsic == nir_intrinsic_store_shared) bits = nir_src_bit_size(in->src[0]);
                else continue;
                if (bits != 32 || nir_intrinsic_align(in) < 4) return false;
            }
        }
    }
    return true;
}
static bool code_valid(struct stela_intel_air_compilation *owner, const struct elk_compiler *elk)
{
    if (elk) return stela_intel_air_validate_elk(elk, owner->binary.code, owner->binary.executable_bytes);
    gen_decode_params decoded = {.devinfo = &owner->provenance.device, .raw_bytes = owner->binary.code,
        .raw_bytes_size = (int)owner->binary.executable_bytes, .mem_ctx = owner->work_context};
    if (!gen_decode(&decoded)) return false;
    gen_validate_params validation = {.devinfo = &owner->provenance.device, .insts = decoded.insts,
        .num_insts = decoded.num_insts, .mem_ctx = owner->work_context};
    return gen_validate(&validation);
}
static enum stela_intel_air_status capture(struct stela_intel_air_compilation *owner,
    const void *code, const char *message, const struct elk_compiler *elk,
    struct stela_intel_air_error *error)
{
    unsigned bytes = elk ? owner->elk.base.program_size : owner->brw.base.program_size;
    unsigned constants = elk ? owner->elk.base.const_data_size : owner->brw.base.const_data_size;
    unsigned offset = elk ? owner->elk.base.const_data_offset : owner->brw.base.const_data_offset;
    unsigned relocs = elk ? owner->elk.base.num_relocs : owner->brw.base.num_relocs;
    const struct intel_shader_reloc *reloc = elk ? owner->elk.base.relocs : owner->brw.base.relocs;
    mesa_shader_stage stage = elk ? owner->elk.base.stage : owner->brw.base.stage;
    unsigned mask = elk ? owner->elk.prog_mask : owner->brw.prog_mask;
    unsigned shared = elk ? owner->elk.base.total_shared : owner->brw.base.total_shared;
    if (!code || message || !bytes || stage != MESA_SHADER_COMPUTE || !mask || (mask & ~7u) ||
        shared != owner->shader->info.shared_size || (relocs && !reloc) ||
        (offset > bytes || (constants && (!offset || constants > bytes - offset))))
        return report(error, STELA_INTEL_AIR_BACKEND, message ? message : "Original compiler output inconsistent");
    if (bytes > owner->provenance.options.max_code_bytes)
        return report(error, STELA_INTEL_AIR_LIMIT, "Compiled resident code exceeds caller budget");
    unsigned executable = constants ? offset : bytes;
    for (unsigned i = 0; i < 3; i++) {
        unsigned local = elk ? owner->elk.local_size[i] : owner->brw.local_size[i];
        unsigned prog_offset = elk ? owner->elk.prog_offset[i] : owner->brw.prog_offset[i];
        if (local != owner->provenance.options.workgroup_size[i] ||
            ((mask & (1u << i)) && (prog_offset >= executable || (prog_offset & 63))))
            return report(error, STELA_INTEL_AIR_BACKEND, "Invalid original workgroup/SIMD code span");
    }
    for (unsigned i = 0; i < relocs; i++) {
        unsigned span;
        if (reloc[i].type == INTEL_SHADER_RELOC_TYPE_U32) span = 4;
        else if (reloc[i].type == INTEL_SHADER_RELOC_TYPE_MOV_IMM) span = 16;
        else return report(error, STELA_INTEL_AIR_BACKEND, "Unknown original relocation type");
        if (reloc[i].offset % 8 || reloc[i].offset > executable || executable - reloc[i].offset < span)
            return report(error, STELA_INTEL_AIR_BACKEND, "Original relocation exceeds executable span");
    }
    owner->binary = (struct stela_intel_air_binary){.backend = elk ? STELA_INTEL_AIR_ELK : STELA_INTEL_AIR_BRW,
        .code = code, .code_bytes = bytes, .executable_bytes = executable,
        .brw = elk ? NULL : &owner->brw, .elk = elk ? &owner->elk : NULL};
    if (!code_valid(owner, elk)) return report(error, STELA_INTEL_AIR_BACKEND, "Original instruction validator refused code");
    /* Preserve only the original output allocations, not codegen objects
     * containing borrowed ISA/callback pointers from the temporary context. */
    ralloc_steal(owner->context, (void *)code);
    if (reloc) ralloc_steal(owner->context, (void *)reloc);
    if (elk && owner->elk.base.param) ralloc_steal(owner->context, owner->elk.base.param);
    return STELA_INTEL_AIR_OK;
}
static bool bind_threadgroup(const struct stela_air_buffer *buffer,
    struct stela_air_threadgroup_view *view, void *data)
{
    const struct stela_intel_air_compilation *owner = data;
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
enum stela_intel_air_status stela_intel_air_compile(const struct brw_compiler *brw,
    const struct elk_compiler *elk, void *log_data, const struct stela_metal_assembly *library, uint32_t selected,
    const struct stela_intel_air_options *options, struct stela_intel_air_compilation **output,
    struct stela_intel_air_error *error)
{
    return stela_intel_air_compile_specialized(brw, elk, log_data, library, selected, options, NULL, output, error);
}
enum stela_intel_air_status stela_intel_air_compile_specialized(const struct brw_compiler *brw,
    const struct elk_compiler *elk, void *log_data, const struct stela_metal_assembly *library, uint32_t selected,
    const struct stela_intel_air_options *options, const struct stela_metal_threadgroup_request *request,
    struct stela_intel_air_compilation **output,
    struct stela_intel_air_error *error)
{
    if (error) memset(error, 0, sizeof(*error));
    if (!!brw == !!elk || !library || !options || !output || *output ||
        options->size != sizeof(*options) || options->abi != STELA_INTEL_AIR_ABI)
        return report(error, STELA_INTEL_AIR_INVALID, "Invalid local ownership/compiler ABI");
    const struct intel_device_info *device = brw ? brw->devinfo : elk->devinfo;
    if (!device_valid(device, elk != NULL) || (brw && (brw->isa.devinfo != device ||
        !brw->shader_debug_log || !brw->shader_perf_log || brw->num_lowered_storage_formats > ISL_NUM_FORMATS ||
        (brw->num_lowered_storage_formats && !brw->lowered_storage_formats))) ||
        (elk && (elk->isa.devinfo != device || !elk->shader_debug_log || !elk->shader_perf_log ||
        !elk->scalar_stage[MESA_SHADER_COMPUTE] || !elk->nir_options[MESA_SHADER_COMPUTE])))
        return report(error, STELA_INTEL_AIR_DEVICE, "Matching initialized device/ISA/compiler callbacks required");
    const nir_shader_compiler_options *actual_options = brw ? &brw->nir_options[MESA_SHADER_COMPUTE] : elk->nir_options[MESA_SHADER_COMPUTE];
    if (actual_options->cb_data)
        return report(error, STELA_INTEL_AIR_UNSUPPORTED, "Opaque NIR callback payload cannot have independent result ownership");
    /* Original brw_stage_has_packed_dispatch still asserts ver<=30 in this
     * retained path. Do not reach it or infer Gen35 readiness from a device ID. */
    if (device->ver == 35)
        return report(error, STELA_INTEL_AIR_UNSUPPORTED, "Gen35 compiler/dispatch qualification hold");
    if (!options->max_instructions || !options->max_code_bytes || options->max_code_bytes > MAX_CODE)
        return report(error, STELA_INTEL_AIR_LIMIT, "Explicit instruction/resident code budgets required");
    if ((options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT && options->fp_profile != STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41) ||
        (options->subgroup_size && options->subgroup_size != 8 && options->subgroup_size != 16 && options->subgroup_size != 32) ||
        (options->subgroup_size == 8 && device->ver >= 20))
        return report(error, STELA_INTEL_AIR_UNSUPPORTED, "Unsupported FP/subgroup specialization");
    uint64_t threads = 1;
    for (unsigned i = 0; i < 3; i++) {
        unsigned count = options->workgroup_size[i];
        if (!count || count > 1024 || threads > 1024 / count)
            return report(error, STELA_INTEL_AIR_UNSUPPORTED, "Invalid workgroup specialization");
        threads *= count;
    }
    if (threads > (uint64_t)device->max_cs_workgroup_threads * 32)
        return report(error, STELA_INTEL_AIR_UNSUPPORTED, "Workgroup exceeds actual compiler thread capacity");
    const struct stela_metal_library_manifest *manifest = stela_metal_assembly_manifest(library);
    if (!manifest || manifest->size != sizeof(*manifest) || manifest->abi != STELA_METAL_LIBRARY_ABI || selected >= manifest->entry_count)
        return report(error, STELA_INTEL_AIR_INVALID, "Invalid canonical selected entry");
    const struct stela_metal_function_record *record = &manifest->entries[selected];
    if (record->size != sizeof(*record) || record->abi != STELA_METAL_LIBRARY_ABI || !(record->flags & STELA_METAL_ENTRY_NO_CONSTANTS))
        return report(error, STELA_INTEL_AIR_UNSUPPORTED, "Unsupported entry/function constants");
    struct stela_metal_input_view original = {.size = sizeof(original), .abi = STELA_METAL_INPUT_ABI};
    if (stela_metal_assembly_original(library, &original, NULL) != STELA_METAL_ASSEMBLY_OK ||
        record->air_offset > original.length || record->air_bytes > original.length - record->air_offset ||
        !record->air_bytes || record->air_bytes > AIR_MAX_BITCODE_BYTES)
        return report(error, STELA_INTEL_AIR_INVALID, "Invalid retained raw AIR span");
    struct stela_metal_threadgroup_specialization threadgroup;
    enum stela_metal_threadgroup_status shared_status = stela_metal_threadgroup_normalize(
        record->arguments, record->argument_count, request, intel_device_info_get_max_slm_size(device), &threadgroup);
    if (shared_status != STELA_METAL_THREADGROUP_OK)
        return report(error, shared_status == STELA_METAL_THREADGROUP_INVALID ? STELA_INTEL_AIR_INVALID :
            shared_status == STELA_METAL_THREADGROUP_LIMIT ? STELA_INTEL_AIR_LIMIT : STELA_INTEL_AIR_UNSUPPORTED,
            "Resource requires a supported threadgroup binding specialization");
    struct stela_intel_air_compilation *owner = calloc(1, sizeof(*owner));
    if (!owner) return report(error, STELA_INTEL_AIR_ALLOCATION, "Compilation owner allocation failed");
    owner->provenance.options = *options; owner->provenance.threadgroup = threadgroup; owner->provenance.device = *device;
    struct stela_intel_air_policy *policy = &owner->provenance.policy;
    if (brw) {
        policy->precise_trig = brw->precise_trig; policy->lower_dpas = brw->lower_dpas;
        policy->optimistic_simd_heuristic = brw->optimistic_simd_heuristic; policy->spilling_rate = brw->spilling_rate;
        policy->register_file_size = brw->register_file_size; policy->register_pressure_threshold = brw->register_pressure_threshold;
        policy->lowered_format_count = brw->num_lowered_storage_formats; policy->lowered_formats = brw->lowered_storage_formats;
        owner->nir_options = brw->nir_options[MESA_SHADER_COMPUTE];
    } else {
        policy->precise_trig = elk->precise_trig; policy->spilling_rate = elk->spilling_rate;
        policy->scalar_stage = elk->scalar_stage[MESA_SHADER_COMPUTE]; policy->constant_buffer_0_is_relative = elk->constant_buffer_0_is_relative;
        policy->supports_shader_constants = elk->supports_shader_constants; policy->has_negative_rhw_bug = elk->has_negative_rhw_bug;
        owner->nir_options = *elk->nir_options[MESA_SHADER_COMPUTE];
        /* ELK selects 32-bit reversal; its existing postprocess must lower 64-bit reversal.
         * Only this retained owner's copy changes, never the compiler policy. */
        owner->nir_options.lower_int64_options |= nir_lower_bitfield_reverse64;
    }
    memcpy(policy->debug, intel_debug, sizeof(policy->debug)); policy->simd = intel_simd; policy->simd_overridden = intel_simd_overridden;
    enum stela_intel_air_status status = copy_provenance(owner, manifest, record, selected, error);
    if (!status) status = prepare_bindings(owner, error);
    if (!status) {
        owner->context = ralloc_context(NULL);
        if (!owner->context) status = report(error, STELA_INTEL_AIR_ALLOCATION, "Original ralloc context allocation failed");
    }
    if (status) { stela_intel_air_destroy(&owner); return status; }
    glsl_type_singleton_init_or_ref(); owner->type_reference = true;
    struct stela_air_options air = {.workgroup_size = {options->workgroup_size[0], options->workgroup_size[1], options->workgroup_size[2]},
        .max_instructions = options->max_instructions, .fp_profile = options->fp_profile,
        .bind_ssbo = owner->binding_count ? bind_ssbo : NULL, .ssbo_count = owner->binding_count,
        .binding_data = owner, .bind_threadgroup = threadgroup.count ? bind_threadgroup : NULL,
        .max_threadgroup_bytes = intel_device_info_get_max_slm_size(device)};
    struct stela_air_error air_error;
    owner->shader = stela_air_to_nir(original.bytes + record->air_offset, (size_t)record->air_bytes,
        owner->provenance.name, &owner->nir_options, &air, &air_error);
    if (!owner->shader) {
        if (error) error->air = air_error;
        status = report(error, STELA_INTEL_AIR_FRONTEND, "Shared AIR frontend refused selected body/policy");
    } else {
        if (brw) { const struct brw_nir_compiler_opts opts = {0}; brw_preprocess_nir(brw, owner->shader, &opts); }
        else { const struct elk_nir_compiler_opts opts = {0}; elk_preprocess_nir(elk, owner->shader, &opts); }
        const nir_lower_compute_system_values_options sys = {.has_base_workgroup_id = false};
        NIR_PASS(_, owner->shader, nir_lower_compute_system_values, &sys);
        nir_shader_gather_info(owner->shader, nir_shader_get_entrypoint(owner->shader));
        if (stela_intel_fp_controls(device, &owner->shader->info))
            status = report(error, STELA_INTEL_AIR_UNSUPPORTED, "FP controls unsupported by actual hardware contract");
    }
    if (!status) {
        owner->work_context = ralloc_context(NULL);
        if (!owner->work_context) status = report(error, STELA_INTEL_AIR_ALLOCATION, "Original working context allocation failed");
    }
    if (!status) {
        if (options->subgroup_size) owner->shader->info.min_subgroup_size = owner->shader->info.max_subgroup_size = (uint8_t)options->subgroup_size;
        if (brw) {
            struct brw_cs_prog_key key = {0}; brw_nir_lower_cs_intrinsics(owner->shader, device, &owner->brw);
            if (brw_nir_lower_cs_subgroup_id(owner->shader, device, 0)) {
                owner->brw.base.push_sizes[0] = 4; brw_cs_fill_push_const_info(device, &owner->brw, 0);
                owner->brw.base.push_sizes[0] = REG_SIZE;
            } else brw_cs_fill_push_const_info(device, &owner->brw, -1);
            nir_validate_shader(owner->shader, "owned AIR indexed SSBO BRW");
            struct brw_compile_cs_params p = {.base = {.mem_ctx = owner->work_context, .nir = owner->shader,
                .key = &key.base, .prog_data = &owner->brw.base, .log_data = log_data}};
            const void *code = brw_compile(brw, &p.base); status = capture(owner, code, p.base.error_str, NULL, error);
        } else {
            owner->elk.base.param = ralloc_array(owner->context, uint32_t, 0);
            if (!owner->elk.base.param) status = report(error, STELA_INTEL_AIR_ALLOCATION, "Original ELK parameter owner allocation failed");
            else {
                struct elk_cs_prog_key key = {0}; elk_nir_lower_cs_intrinsics(owner->shader, device, &owner->elk);
                if (!gen7_shared_io_supported(device, owner->shader))
                    status = report(error, STELA_INTEL_AIR_UNSUPPORTED, "Gen7 shared access qualification excludes byte-scattered paths");
                else {
                    nir_validate_shader(owner->shader, "owned AIR indexed SSBO ELK");
                    struct elk_compile_cs_params p = {.base = {.mem_ctx = owner->work_context, .nir = owner->shader, .log_data = log_data}, .key = &key, .prog_data = &owner->elk};
                    const void *code = elk_compile_cs(elk, &p); status = capture(owner, code, p.base.error_str, elk, error);
                }
            }
        }
    }
    if (status) { stela_intel_air_destroy(&owner); return status; }
    ralloc_free(owner->work_context); owner->work_context = NULL;
    *output = owner; return report(error, STELA_INTEL_AIR_OK, "");
}
const struct stela_intel_air_binary *stela_intel_air_binary(const struct stela_intel_air_compilation *owner) { return owner ? &owner->binary : NULL; }
const nir_shader *stela_intel_air_nir(const struct stela_intel_air_compilation *owner) { return owner ? owner->shader : NULL; }
const struct stela_intel_air_provenance *stela_intel_air_provenance(const struct stela_intel_air_compilation *owner) { return owner ? &owner->provenance : NULL; }
const struct stela_intel_air_binding *stela_intel_air_bindings(const struct stela_intel_air_compilation *owner, uint32_t *count)
{ if (count) *count = owner ? owner->binding_count : 0; return owner ? owner->bindings : NULL; }
