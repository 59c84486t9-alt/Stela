/* SPDX-License-Identifier: MIT */
#include "air_compile.h"
#include "amd/common/ac_binary.h"
#include "amd/common/nir/ac_nir.h"
#include "amd/compiler/aco_interface.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TEXT 4096u /* Same bounded reflection strings as library assembly. */
#define MAX_CODE (64u * 1024u * 1024u)

struct stela_amd_air_compilation {
   struct stela_amd_compute_binary binary;
   struct stela_amd_air_provenance provenance;
   nir_shader_compiler_options nir_options;
   struct ac_shader_args args;
   struct ac_shader_config config;
   struct stela_amd_air_binding bindings[STELA_AMD_AIR_MAX_BUFFERS];
   uint32_t binding_count;
   void *metadata;
   uint8_t *code;
   bool type_reference, captured;
   enum stela_amd_air_status capture_status;
};

/* Preserve native/packed 16-bit min/max where ACO supports it. Uniform
 * subword scalar operands need the original signed/unsigned legalization. */
static bool
narrow_scalar_minmax(const nir_instr *instr)
{
   if (instr->type != nir_instr_type_alu)
      return false;
   const nir_alu_instr *alu = nir_instr_as_alu(instr);
   return alu->def.num_components == 1 && (alu->def.bit_size == 8 || alu->def.bit_size == 16) &&
      (alu->op == nir_op_imin || alu->op == nir_op_imax ||
       alu->op == nir_op_umin || alu->op == nir_op_umax);
}

static unsigned
lower_minmax_bit_size(const nir_instr *instr, void *data)
{
   return narrow_scalar_minmax(instr) ? ac_nir_lower_bit_size_callback(instr, data) : 0;
}

static enum stela_amd_air_status
report(struct stela_amd_air_error *error, enum stela_amd_air_status status,
       const char *detail)
{
   if (error) {
      error->status = status;
      snprintf(error->detail, sizeof(error->detail), "%s", detail);
   }
   return status;
}

void
stela_amd_air_destroy(struct stela_amd_air_compilation **slot)
{
   if (!slot || !*slot)
      return;
   struct stela_amd_air_compilation *owner = *slot;
   *slot = NULL;
   ralloc_free((void *)owner->binary.shader);
   if (owner->type_reference)
      glsl_type_singleton_decref();
   free(owner->code);
   free(owner->metadata);
   free(owner);
}

static bool
text_valid(const char *text, size_t length)
{
   return length <= MAX_TEXT && (!length || (text && !memchr(text, 0, length)));
}

static char *
copy_text(char **cursor, const void *text, size_t length)
{
   if (!text)
      return NULL;
   char *result = *cursor;
   if (length)
      memcpy(result, text, length);
   result[length] = 0;
   *cursor += length + 1;
   return result;
}

static enum stela_amd_air_status
copy_provenance(struct stela_amd_air_compilation *owner,
                const struct stela_metal_library_manifest *manifest,
                const struct stela_metal_function_record *record, uint32_t selected,
                struct stela_amd_air_error *error)
{
   if (!text_valid((const char *)record->name, record->name_bytes) || !record->name_bytes ||
       !text_valid((const char *)manifest->target, manifest->target_bytes) || !manifest->target_bytes ||
       record->argument_count > AIR_MAX_ARGUMENTS ||
       (record->argument_count && !record->arguments))
      return report(error, STELA_AMD_AIR_INVALID, "Unrepresentable selected entry metadata");
   size_t bytes = record->argument_count * sizeof(struct stela_air_argument_info) +
                  (size_t)record->name_bytes + (size_t)manifest->target_bytes + 2;
   for (unsigned i = 0; i < record->argument_count; i++) {
      const struct stela_air_argument_info *arg = &record->arguments[i];
      if (!text_valid(arg->name, arg->name_bytes) || !text_valid(arg->type_name, arg->type_name_bytes))
         return report(error, STELA_AMD_AIR_INVALID, "Unrepresentable argument strings");
      bytes += arg->name_bytes + arg->type_name_bytes + 2;
   }
   /* All additions are bounded by 128 arguments and 4096 bytes/string. */
   owner->metadata = malloc(bytes);
   if (!owner->metadata)
      return report(error, STELA_AMD_AIR_ALLOCATION, "Selected metadata allocation failed");
   struct stela_air_argument_info *args = owner->metadata;
   char *cursor = (char *)(args + record->argument_count);
   struct stela_amd_air_provenance *p = &owner->provenance;
   p->input = manifest->input;
   p->entry = record->entry;
   p->selected_entry = selected;
   p->entry_flags = record->flags;
   p->library_flags = manifest->flags;
   p->compiler_profile = manifest->compiler_profile;
   p->request_language = manifest->request_language;
   p->request_fast_math = manifest->request_fast_math;
   p->build = manifest->build;
   p->air_offset = record->air_offset;
   p->air_bytes = record->air_bytes;
   memcpy(p->air_sha256, record->air_sha256, 32);
   memcpy(p->source_sha256, manifest->source_sha256, 32);
   p->name = copy_text(&cursor, record->name, (size_t)record->name_bytes);
   p->target = copy_text(&cursor, manifest->target, (size_t)manifest->target_bytes);
   p->argument_count = record->argument_count;
   p->arguments = args;
   for (unsigned i = 0; i < record->argument_count; i++) {
      args[i] = record->arguments[i];
      args[i].name = copy_text(&cursor, args[i].name, args[i].name_bytes);
      args[i].type_name = copy_text(&cursor, args[i].type_name, args[i].type_name_bytes);
   }
   return STELA_AMD_AIR_OK;
}

static enum stela_amd_air_status
prepare_args(struct stela_amd_air_compilation *owner, const struct radeon_info *info,
             struct stela_amd_air_error *error)
{
   for (unsigned i = 0; i < owner->provenance.argument_count; i++) {
      const struct stela_air_argument_info *arg = &owner->provenance.arguments[i];
      if (arg->kind == 2)
         continue; /* Existing AIR frontend validates/lower the actual builtin. */
      if (arg->kind == 1 && arg->buffer.address_space == 3 && arg->plain_buffer_type) continue;
      if (arg->kind != 1 || arg->buffer.address_space != 1 || !arg->plain_buffer_type)
         return report(error, STELA_AMD_AIR_UNSUPPORTED, "Resource requires an unsupported binding specialization");
      if (owner->binding_count == STELA_AMD_AIR_MAX_BUFFERS)
         return report(error, STELA_AMD_AIR_UNSUPPORTED, "More than eight AS1 address pairs");
      struct stela_amd_air_binding *binding = &owner->bindings[owner->binding_count++];
      binding->buffer = arg->buffer;
      ac_add_arg(&owner->args, AC_ARG_SGPR, 2, AC_ARG_CONST_ADDR, &binding->argument);
   }
   for (unsigned axis = 0; axis < 3; axis++) {
      if (info->gfx_level >= GFX12)
         owner->args.workgroup_ids[axis].used = true;
      else
         ac_add_arg(&owner->args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &owner->args.workgroup_ids[axis]);
   }
   if (info->gfx_level < GFX11)
      ac_add_arg(&owner->args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &owner->args.scratch_offset);
   if (info->compiler_info.local_invocation_ids_packed) {
      ac_add_arg(&owner->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &owner->args.local_invocation_ids_packed);
   } else {
      ac_add_arg(&owner->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &owner->args.local_invocation_id_x);
      ac_add_arg(&owner->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &owner->args.local_invocation_id_y);
      ac_add_arg(&owner->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &owner->args.local_invocation_id_z);
   }
   if (owner->args.num_sgprs_used > info->compiler_info.max_sgpr_alloc ||
       owner->args.num_vgprs_used > info->compiler_info.max_vgpr_alloc)
      return report(error, STELA_AMD_AIR_UNSUPPORTED, "Argument layout exceeds actual device register limits");
   return STELA_AMD_AIR_OK;
}

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   struct stela_amd_air_compilation *owner = data;
   for (unsigned i = 0; i < owner->binding_count; i++) {
      const struct stela_amd_air_binding *binding = &owner->bindings[i];
      if (binding->buffer.argument == buffer->argument &&
          binding->buffer.index == buffer->index &&
          binding->buffer.address_space == buffer->address_space &&
          binding->buffer.access == buffer->access &&
          binding->buffer.type_size == buffer->type_size &&
          binding->buffer.type_alignment == buffer->type_alignment)
         return nir_pack_64_2x32(b, ac_nir_load_arg(b, &owner->args, binding->argument));
   }
   return NULL;
}

static bool
compiler_facts_valid(const struct radeon_info *info, unsigned wave)
{
   const struct ac_compiler_info *c = &info->compiler_info;
   unsigned scale = wave == 32 ? 2 : 1;
   /* Original ACO init_program stores these in uint16_t and doubles the
    * physical VGPR count/allocation grain for wave32. Grains are NOT generally
    * powers of two (e.g. SGPR108, VGPR12). Check before those conversions and
    * the allocator's original division/alignment helpers. These are necessary
    * representation checks, not authentication of caller-created device info. */
   return c->max_waves_per_simd && c->max_waves_per_simd <= UINT16_MAX &&
      c->num_simd_per_compute_unit &&
      c->num_physical_sgprs_per_simd && c->num_physical_sgprs_per_simd <= UINT16_MAX &&
      c->num_physical_wave64_vgprs_per_simd && c->num_physical_wave64_vgprs_per_simd <= UINT16_MAX / scale &&
      c->min_sgpr_alloc && c->min_sgpr_alloc <= c->max_sgpr_alloc &&
      c->max_sgpr_alloc <= c->num_physical_sgprs_per_simd &&
      c->sgpr_alloc_granularity && c->sgpr_alloc_granularity <= c->max_sgpr_alloc &&
      c->min_wave64_vgpr_alloc && c->min_wave64_vgpr_alloc <= c->max_vgpr_alloc &&
      c->max_vgpr_alloc <= c->num_physical_wave64_vgprs_per_simd && c->max_vgpr_alloc <= UINT16_MAX &&
      c->wave64_vgpr_alloc_granularity && c->wave64_vgpr_alloc_granularity <= UINT16_MAX / scale &&
      c->wave64_vgpr_encode_granularity && c->wave64_vgpr_encode_granularity <= c->max_vgpr_alloc &&
      c->lds_size_per_workgroup && c->lds_size_per_workgroup <= (info->gfx_level >= GFX7 ? 65536u : 32768u);
}

static void
capture(void **private, const struct ac_shader_config *config,
        const char *ir, unsigned ir_bytes, const char *assembly, unsigned assembly_bytes,
        struct amd_stats *stats, uint32_t executable_bytes, const uint32_t *code,
        uint32_t code_dw, const struct aco_symbol *symbols, unsigned symbol_count,
        const struct ac_shader_debug_info *debug, unsigned debug_count)
{
   (void)ir; (void)ir_bytes; (void)assembly; (void)assembly_bytes; (void)stats;
   (void)symbols; (void)debug; (void)debug_count;
   struct stela_amd_air_compilation *owner = *private;
   if (owner->captured || !config || !code || !code_dw || !executable_bytes ||
       code_dw > UINT32_MAX / 4 || executable_bytes > code_dw * 4 || executable_bytes % 4) {
      owner->capture_status = STELA_AMD_AIR_BACKEND;
      return;
   }
   owner->captured = true;
   if (symbol_count) {
      owner->capture_status = STELA_AMD_AIR_UNSUPPORTED;
      return;
   }
   if (code_dw * 4 > owner->provenance.options.max_code_bytes) {
      owner->capture_status = STELA_AMD_AIR_LIMIT;
      return;
   }
   owner->code = malloc((size_t)code_dw * 4);
   if (!owner->code) {
      owner->capture_status = STELA_AMD_AIR_ALLOCATION;
      return;
   }
   memcpy(owner->code, code, (size_t)code_dw * 4);
   owner->config = *config;
   owner->binary.executable_bytes = executable_bytes;
   owner->binary.code_bytes = code_dw * 4;
}

static bool bind_threadgroup(const struct stela_air_buffer *buffer,
                            struct stela_air_threadgroup_view *view, void *data)
{
   const struct stela_amd_air_compilation *owner = data;
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
enum stela_amd_air_status
stela_amd_air_compile(const struct radeon_info *info, const struct stela_metal_assembly *library,
                     uint32_t selected, const struct stela_amd_air_options *options,
                     struct stela_amd_air_compilation **output, struct stela_amd_air_error *error)
{
   return stela_amd_air_compile_specialized(info, library, selected, options, NULL, output, error);
}
enum stela_amd_air_status
stela_amd_air_compile_specialized(const struct radeon_info *info, const struct stela_metal_assembly *library,
                      uint32_t selected, const struct stela_amd_air_options *options,
                      const struct stela_metal_threadgroup_request *request,
                      struct stela_amd_air_compilation **output, struct stela_amd_air_error *error)
{
   if (error)
      memset(error, 0, sizeof(*error));
   if (!info || !library || !options || !output || *output ||
       options->size != sizeof(*options) || options->abi != STELA_AMD_AIR_ABI)
      return report(error, STELA_AMD_AIR_INVALID, "Invalid local compiler ownership/ABI");
   if (!options->max_instructions || !options->max_code_bytes || options->max_code_bytes > MAX_CODE)
      return report(error, STELA_AMD_AIR_LIMIT, "Explicit nonzero compiler/code budgets required");
   if ((options->wave_size != 32 && options->wave_size != 64) ||
       (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT &&
        options->fp_profile != STELA_AIR_FP_METAL))
      return report(error, STELA_AMD_AIR_UNSUPPORTED, "Unsupported wave/FP profile");
   if (info->family < CHIP_TAHITI || info->family >= CHIP_LAST ||
       ac_get_gfx_level(info->family) != info->gfx_level || !aco_is_gpu_supported(info) ||
       (options->wave_size == 32 && info->gfx_level < GFX10))
      return report(error, STELA_AMD_AIR_UNSUPPORTED, "Target requires a different retained backend");
   struct stela_amd_raw_buffer_facts facts;
   if (stela_amd_query_raw_buffer_facts(info, &facts) != STELA_AMD_BUFFER_OK ||
       !compiler_facts_valid(info, options->wave_size))
      return report(error, STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE, "Actual initialized device/compiler facts required");
   const struct stela_metal_library_manifest *manifest = stela_metal_assembly_manifest(library);
   if (!manifest || selected >= manifest->entry_count)
      return report(error, STELA_AMD_AIR_INVALID, "Selected entry outside canonical library");
   const struct stela_metal_function_record *record = &manifest->entries[selected];
   struct stela_metal_input_view original = {.size = sizeof(original), .abi = STELA_METAL_INPUT_ABI};
   if (stela_metal_assembly_original(library, &original, NULL) != STELA_METAL_ASSEMBLY_OK ||
       record->air_offset > original.length || record->air_bytes > original.length - record->air_offset ||
       !record->air_bytes || record->air_bytes > AIR_MAX_BITCODE_BYTES)
      return report(error, STELA_AMD_AIR_INVALID, "Invalid retained raw AIR span");
   struct stela_metal_threadgroup_specialization threadgroup;
   enum stela_metal_threadgroup_status shared_status = stela_metal_threadgroup_normalize(
       record->arguments, record->argument_count, request, info->compiler_info.lds_size_per_workgroup, &threadgroup);
   if (shared_status != STELA_METAL_THREADGROUP_OK)
       return report(error, shared_status == STELA_METAL_THREADGROUP_INVALID ? STELA_AMD_AIR_INVALID :
           shared_status == STELA_METAL_THREADGROUP_LIMIT ? STELA_AMD_AIR_LIMIT : STELA_AMD_AIR_UNSUPPORTED,
           "Resource requires a supported threadgroup binding specialization");
   struct stela_amd_air_compilation *owner = calloc(1, sizeof(*owner));
   if (!owner)
      return report(error, STELA_AMD_AIR_ALLOCATION, "Compilation owner allocation failed");
   owner->provenance.options = *options; owner->provenance.threadgroup = threadgroup;
   owner->provenance.compiler_info = info->compiler_info;
   owner->provenance.pci_id = info->pci_id;
   owner->provenance.pci_rev_id = info->pci_rev_id;
   owner->provenance.has_graphics = info->has_graphics;
   ac_nir_set_options(&info->compiler_info, false, &owner->nir_options);
   uint64_t threads = 1;
   for (unsigned axis = 0; axis < 3; axis++) {
      unsigned count = options->workgroup_size[axis];
      if (!count || count > owner->nir_options.max_workgroup_invocations ||
          threads > owner->nir_options.max_workgroup_invocations / count) {
         stela_amd_air_destroy(&owner);
         return report(error, STELA_AMD_AIR_UNSUPPORTED, "Invalid/unsupported workgroup specialization");
      }
      threads *= count;
   }
   enum stela_amd_air_status status = copy_provenance(owner, manifest, record, selected, error);
   if (status == STELA_AMD_AIR_OK)
      status = prepare_args(owner, info, error);
   if (status != STELA_AMD_AIR_OK) {
      stela_amd_air_destroy(&owner);
      return status;
   }
   glsl_type_singleton_init_or_ref();
   owner->type_reference = true;
   struct stela_air_options air = {
      .workgroup_size = {options->workgroup_size[0], options->workgroup_size[1], options->workgroup_size[2]},
      .max_instructions = options->max_instructions, .bind_buffer = bind_buffer,
      .binding_data = owner, .fp_profile = options->fp_profile,
      .bind_threadgroup = threadgroup.count ? bind_threadgroup : NULL,
      .max_threadgroup_bytes = info->compiler_info.lds_size_per_workgroup,
   };
   struct stela_air_error air_error;
   nir_shader *shader = stela_air_to_nir(original.bytes + record->air_offset,
      (size_t)record->air_bytes, owner->provenance.name, &owner->nir_options, &air, &air_error);
   if (!shader) {
      if (error)
         error->air = air_error;
      stela_amd_air_destroy(&owner);
      return report(error, STELA_AMD_AIR_FRONTEND, "Shared AIR frontend refused selected body/policy");
   }
   owner->binary = (struct stela_amd_compute_binary) {
      .shader = shader, .args = &owner->args, .config = &owner->config,
      .family = info->family, .gfx_level = info->gfx_level, .wave_size = options->wave_size,
   };
   const ac_nir_lower_intrinsics_to_args_options arg_options = {
      .gfx_level = info->gfx_level, .hw_stage = AC_HW_COMPUTE_SHADER,
      .wave_size = options->wave_size, .workgroup_size = (unsigned)threads,
   };
   ac_nir_lower_intrinsics_to_args(shader, &owner->args, &arg_options);
   ac_nir_lower_global_access(shader, info->gfx_level);
   /* ACO selects the lowered operations, not native NIR integer division.
    * Match RADV's original pass; retain full integer precision and avoid its
    * optional FP16 path on every owned target. */
   nir_lower_idiv(shader, &(nir_lower_idiv_options){.allow_fp16 = false});
   nir_lower_int64(shader);
   bool progress;
   do {
      progress = nir_opt_constant_folding(shader);
      progress |= nir_opt_copy_prop(shader);
      progress |= nir_opt_algebraic(shader);
      progress |= nir_opt_dce(shader);
   } while (progress);
   nir_lower_alu_width(shader, ac_nir_opt_vectorize_cb, &owner->binary.gfx_level);
   bool narrow_minmax = false;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block)
            narrow_minmax |= narrow_scalar_minmax(instr);
      }
   }
   if (narrow_minmax) {
      nir_divergence_analysis(shader);
      nir_lower_bit_size(shader, lower_minmax_bit_size, &owner->binary.gfx_level);
   }
   nir_lower_load_const_to_scalar(shader);
   nir_opt_copy_prop(shader);
   nir_opt_dce(shader);
   nir_shader_gather_info(shader, nir_shader_get_entrypoint(shader));
   nir_validate_shader(shader, "owned AIR to AMD compute ABI");
   const struct aco_compiler_options aco_options = {
      .compiler_info = &info->compiler_info, .family = info->family, .gfx_level = info->gfx_level,
   };
   const struct aco_shader_info aco_info = {
      .hw_stage = AC_HW_COMPUTE_SHADER,
      .lds_size = shader->info.shared_size,
      .wave_size = (uint8_t)options->wave_size,
      .workgroup_size = (unsigned)threads,
   };
   void *private = owner;
   aco_compile_shader(&aco_options, &aco_info, 1, &shader, &owner->args, capture, &private);
   owner->provenance.aco_codegen_flags = aco_get_codegen_flags();
   status = owner->capture_status;
   if (status == STELA_AMD_AIR_OK && (!owner->captured || !owner->code || !owner->config.num_vgprs))
      status = STELA_AMD_AIR_BACKEND;
   if (status != STELA_AMD_AIR_OK) {
      stela_amd_air_destroy(&owner);
      return report(error, status, "Vendor output unavailable, unresolved, over budget or allocation failed");
   }
   *output = owner;
   return report(error, STELA_AMD_AIR_OK, "");
}

const struct stela_amd_compute_binary *
stela_amd_air_binary(const struct stela_amd_air_compilation *owner)
{
   return owner ? &owner->binary : NULL;
}

const uint8_t *
stela_amd_air_code(const struct stela_amd_air_compilation *owner)
{
   return owner ? owner->code : NULL;
}

const struct stela_amd_air_binding *
stela_amd_air_bindings(const struct stela_amd_air_compilation *owner, uint32_t *count)
{
   if (count)
      *count = owner ? owner->binding_count : 0;
   return owner ? owner->bindings : NULL;
}

const struct stela_amd_air_provenance *
stela_amd_air_provenance(const struct stela_amd_air_compilation *owner)
{
   return owner ? &owner->provenance : NULL;
}
