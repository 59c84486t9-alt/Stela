/* SPDX-License-Identifier: MIT */
/* Original AIR input -> shared AIR/NIR frontend -> retained AMD ACO backend.
 * CPU compilation only: no initialized GPU, mappings or submission are claimed.
 */
#include "air_to_nir.h"
#include "air_probe.h"
#include "air_test_fixture.h"
#include "targets/amd.h"
#include "amd/compiler/aco_interface.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_shader_args.h"
#include "amd/common/nir/ac_nir.h"
#if AMD_LLVM_AVAILABLE
#include "amd/llvm/ac_llvm_util.h"
#endif
#include "util/ralloc.h"
#include "../../amd/stela/tests/air_probe_input.h"

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%u: %s\n", __func__, __LINE__, #condition); exit(1); \
} } while (0)

struct binding {
   struct ac_shader_args args;
   struct ac_arg buffer;
   unsigned count;
   unsigned argument;
};

struct binary {
   unsigned code_dw;
   unsigned exec_size;
   struct ac_shader_config config;
   char code_blake3[BLAKE3_HEX_LEN];
   char executable_blake3[BLAKE3_HEX_LEN];
};

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   struct binding *binding = data;
   CHECK(buffer->index == 7 && buffer->address_space == 1);
   CHECK(buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 && buffer->type_alignment == 4);
   binding->count++;
   binding->argument = buffer->argument;
   /* Explicit native fixture ABI: device buffer VA in user SGPRs 0:1. Never
    * replace an AIR resource with a fixed address or a fabricated thread ID. */
   return nir_pack_64_2x32(b, ac_nir_load_arg(b, &binding->args, binding->buffer));
}

static void
capture_binary(void **private, const struct ac_shader_config *config,
               const char *ir, unsigned ir_size, const char *assembly,
               unsigned assembly_size, struct amd_stats *stats,
               uint32_t exec_size, const uint32_t *code, uint32_t code_dw,
               const struct aco_symbol *symbols, unsigned num_symbols,
               const struct ac_shader_debug_info *debug_info, unsigned debug_count)
{
   struct binary *binary = *private;
   CHECK(config && code && code_dw && exec_size && exec_size <= code_dw * sizeof(*code));
   CHECK(!num_symbols); /* No unresolved relocations are accepted by this fixture. */
   binary->code_dw = code_dw;
   binary->exec_size = exec_size;
   binary->config = *config;
   stela_digest(code, (size_t)code_dw * sizeof(*code), binary->code_blake3);
   stela_digest(code, exec_size, binary->executable_blake3);

   if (assembly && assembly_size) {
      if (!assembly[assembly_size - 1])
         assembly_size--;
      fwrite(assembly, 1, assembly_size, stdout);
   }
}

static void
compute_args(struct binding *binding, const struct radeon_info *gpu)
{
   /* Hardware system SGPRs follow enabled user SGPRs. On GFX12+ the retained
    * lowering reads workgroup IDs from the actual architectural TTMP inputs. */
   ac_add_arg(&binding->args, AC_ARG_SGPR, 2, AC_ARG_CONST_ADDR, &binding->buffer);
   for (unsigned axis = 0; axis < 3; axis++) {
      if (gpu->gfx_level >= GFX12)
         binding->args.workgroup_ids[axis].used = true;
      else
         ac_add_arg(&binding->args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &binding->args.workgroup_ids[axis]);
   }
   if (gpu->gfx_level < GFX11)
      ac_add_arg(&binding->args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &binding->args.scratch_offset);
   if (gpu->compiler_info.local_invocation_ids_packed) {
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_ids_packed);
   } else {
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_x);
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_y);
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_z);
   }
}

static struct radeon_info
model(enum radeon_family family)
{
   struct radeon_info gpu = {
      .gfx_level = ac_get_gfx_level(family), .family = family,
      .has_graphics = stela_amd_has_graphics(family),
   };
   ac_fill_compiler_info(&gpu, NULL, false);
   return gpu;
}

static bool
compile_target(LLVMMemoryBufferRef input, const char *entry, const char *input_hash,
               enum radeon_family family, unsigned wave, bool file,
               enum stela_air_fp_profile fp_profile)
{
   struct radeon_info gpu = model(family);
   char target[32];
   stela_amd_target_name(target, family, wave);
   if (!aco_is_gpu_supported(&gpu)) {
      record_held(target, stela_amd_aco_refusal(family));
      return true;
   }
   nir_shader_compiler_options nir_options;
   ac_nir_set_options(&gpu.compiler_info, false, &nir_options);
   struct binding binding = {0};
   compute_args(&binding, &gpu);
   const struct stela_air_options air_options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100,
      .bind_buffer = bind_buffer, .binding_data = &binding, .fp_profile = fp_profile,
   };
   struct stela_air_error error;
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                        entry, &nir_options, &air_options, &error);
   if (!shader) {
      fprintf(stderr, "%s AIR refused: %u %s\n", target, error.kind, error.detail);
      return false;
   }
   CHECK(binding.count == 1 && error.kind == STELA_AIR_OK);
   stela_air_probe_environment_record(target, fp_profile, shader->info.float_controls_execution_mode);
   unsigned loads = 0, stores = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            if (intrinsic->intrinsic == nir_intrinsic_load_global) {
               CHECK(!nir_src_is_const(intrinsic->src[0]));
               loads++;
            } else if (intrinsic->intrinsic == nir_intrinsic_store_global) {
               CHECK(!nir_src_is_const(intrinsic->src[1]));
               if (!file)
                  CHECK(!nir_src_is_const(intrinsic->src[0]));
               stores++;
            }
         }
      }
   }
   CHECK(file ? loads + stores > 0 : loads == 1 && stores == 1);
   CHECK(shader->info.workgroup_size[0] == 32 && shader->info.workgroup_size[1] == 1 &&
         shader->info.workgroup_size[2] == 1);
   /* Reuse AMD's generation-specific system-value lowering rather than
    * implementing packed VGPR or TTMP decoding in the Metal frontend. */
   const ac_nir_lower_intrinsics_to_args_options args_options = {
      .gfx_level = gpu.gfx_level, .hw_stage = AC_HW_COMPUTE_SHADER,
      .wave_size = wave, .workgroup_size = 32,
   };
   ac_nir_lower_intrinsics_to_args(shader, &binding.args, &args_options);
   ac_nir_lower_global_access(shader, gpu.gfx_level);
   nir_lower_int64(shader);
   bool progress;
   do {
      progress = nir_opt_constant_folding(shader);
      progress |= nir_opt_copy_prop(shader);
      progress |= nir_opt_algebraic(shader);
      progress |= nir_opt_dce(shader);
   } while (progress);
   nir_lower_alu_width(shader, ac_nir_opt_vectorize_cb, &gpu.gfx_level);
   nir_lower_load_const_to_scalar(shader);
   nir_opt_copy_prop(shader);
   nir_opt_dce(shader);
   nir_shader_gather_info(shader, nir_shader_get_entrypoint(shader));
   nir_validate_shader(shader, "AIR to AMD compute ABI");
   const struct aco_compiler_options options = {
      .compiler_info = &gpu.compiler_info, .family = family, .gfx_level = gpu.gfx_level,
      .record_asm = true,
   };
   const struct aco_shader_info info = {
      .hw_stage = AC_HW_COMPUTE_SHADER, .wave_size = wave, .workgroup_size = 32,
   };
   struct binary binary = {0};
   void *private = &binary;
   aco_compile_shader(&options, &info, 1, &shader, &binding.args, capture_binary, &private);
   ralloc_free(shader);
   CHECK(binary.code_dw && binary.exec_size && binary.config.num_vgprs);
   printf("AIR kernel %s: user-sgpr=0:1 buffer[7], sgprs=%u vgprs=%u scratch=%u bytes=%u\n",
          target, binary.config.num_sgprs, binary.config.num_vgprs,
          binary.config.scratch_bytes_per_wave, binary.exec_size);
   const uint32_t workgroup_size[] = {32, 1, 1};
   record_compiled(target, binary.exec_size);
   record_object("facts");
   record_str("input_blake3", input_hash);
   record_str("entry", entry);
   record_uint("wave_size", wave);
   record_uints("workgroup_size", workgroup_size, ARRAY_SIZE(workgroup_size));
   record_uint("global_loads", loads);
   record_uint("global_stores", stores);
   record_uint("code_bytes", (uint64_t)binary.code_dw * 4);
   record_uint("executable_bytes", binary.exec_size);
   record_str("code_blake3", binary.code_blake3);
   record_str("executable_blake3", binary.executable_blake3);
   record_uint("buffer_argument", binding.argument);
   record_uint("metal_buffer_index", 7);
   record_str("buffer_abi", "device_va_user_sgpr0_1");
   record_uint("aco_codegen_flags", aco_get_codegen_flags());
   record_bool("aco_optimisations_disabled_option", options.optimisations_disabled);
   record_uint("scratch_bytes_per_wave", binary.config.scratch_bytes_per_wave);
   record_end();

   return true;
}

int
main(int argc, char **argv)
{
#if AMD_LLVM_AVAILABLE
   ac_init_llvm_once();
#endif
   const char *entry = "kernel";
   bool file = false;
   enum stela_air_fp_profile fp_profile;
   if (!stela_air_probe_profile(&argc, argv, &fp_profile))
      return 2;
   stela_air_probe_profile_record(fp_profile);
   LLVMMemoryBufferRef input;
   if (argc == 1) {
      input = stela_air_test_bitcode(stela_air_test_store_body, "");
   } else if (argc == 5 && !strcmp(argv[1], "--input") && !strcmp(argv[3], "--entry") &&
              *argv[4] && strlen(argv[4]) <= 256) {
      input = read_raw_input(argv[2]);
      entry = argv[4];
      file = true;
      if (!input)
         return 1;
   } else {
      fprintf(stderr, "usage: %s [--input raw.bc --entry kernel_name [--fp-profile NAME]]\n", argv[0]);
      return 1;
   }
   char input_hash[BLAKE3_HEX_LEN];
   if (!input_receipt(input, entry, file, input_hash)) {
      LLVMDisposeMemoryBuffer(input);
      return 1;
   }
   for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
      const enum radeon_family family = stela_amd_targets[i];
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2) {
         char target[32];
         stela_amd_target_name(target, family, wave);
         record_expect(target, stela_amd_aco_hold(family));
      }
   }
   glsl_type_singleton_init_or_ref();
   bool ok = true;
   for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
      const enum radeon_family family = stela_amd_targets[i];
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2)
         ok &= compile_target(input, entry, input_hash, family, wave, file, fp_profile);
   }
   LLVMDisposeMemoryBuffer(input);
   glsl_type_singleton_decref();
   return !ok;
}
