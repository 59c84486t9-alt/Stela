/* SPDX-License-Identifier: MIT */
/* Original AIR input -> shared AIR/NIR frontend -> retained AMD ACO backend.
 * CPU compilation only: no initialized GPU, mappings or submission are claimed.
 */
#include "air_to_nir.h"
#include "air_probe_profile.h"
#include "air_test_fixture.h"
#include "probe_report.h"
#include "amd/compiler/aco_interface.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_shader_args.h"
#include "amd/common/nir/ac_nir.h"
#if AMD_LLVM_AVAILABLE
#include "amd/llvm/ac_llvm_util.h"
#endif
#include "util/ralloc.h"
#include "util/mesa-blake3.h"
#include "../../../../amd/tests/air_probe_input.h"
#include <inttypes.h>

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
   blake3_hash hash;
   _mesa_blake3_compute(code, (size_t)code_dw * sizeof(*code), hash);
   _mesa_blake3_format(binary->code_blake3, hash);
   _mesa_blake3_compute(code, exec_size, hash);
   _mesa_blake3_format(binary->executable_blake3, hash);

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

static bool
compile_target(LLVMMemoryBufferRef input, const char *entry, const char *input_hash,
               enum radeon_family family, bool graphics, unsigned wave, bool file,
               enum stela_air_fp_profile fp_profile)
{
   struct radeon_info gpu = {
      .gfx_level = ac_get_gfx_level(family), .family = family, .has_graphics = graphics,
   };
   ac_fill_compiler_info(&gpu, NULL, false);
   char target[64];
   snprintf(target, sizeof(target), "%s.wave%u", ac_get_family_name(family), wave);
   if (!aco_is_gpu_supported(&gpu)) {
      probe_unsupported("air-aco", target, graphics ? "compiler-gfx-level-unsupported" : "requires-cdna-compiler-backend");
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
   printf("STELA_AIR_ENVIRONMENT {\"backend\":\"air-aco\",\"target\":\"%s\",\"fp_profile\":%u,\"nir_float_controls\":%u}\n",
          target, (unsigned)fp_profile, shader->info.float_controls_execution_mode);
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
   printf("STELA_AIR_MEMORY {\"backend\":\"aco\",\"input_blake3\":\"%s\","
          "\"target\":\"%s\",\"global_loads\":%u,\"global_stores\":%u}\n",
          input_hash, target, loads, stores);
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
   probe_compiled("air-aco", target, binary.exec_size);
   printf("STELA_AIR_BINARY {\"backend\":\"aco\",\"input_blake3\":\"%s\",\"entry\":", input_hash);
   json_string(entry);
   printf(",\"target\":\"%s\",\"wave_size\":%u,\"workgroup_size\":[32,1,1],"
          "\"code_bytes\":%zu,\"executable_bytes\":%u,\"code_blake3\":\"%s\","
          "\"executable_blake3\":\"%s\",\"buffer_argument\":%u,\"metal_buffer_index\":7,"
          "\"buffer_abi\":\"device_va_user_sgpr0_1\",\"aco_codegen_flags\":%" PRIu64 ","
          "\"aco_optimisations_disabled_option\":%s,\"scratch_bytes_per_wave\":%u}\n",
          target, wave, (size_t)binary.code_dw * 4, binary.exec_size, binary.code_blake3,
          binary.executable_blake3, binding.argument, aco_get_codegen_flags(),
          options.optimisations_disabled ? "true" : "false", binary.config.scratch_bytes_per_wave);

   return true;
}

int
main(int argc, char **argv)
{
#if AMD_LLVM_AVAILABLE
   ac_init_llvm_once();
#endif
   const struct { enum radeon_family family; bool graphics; } targets[] = {
      {CHIP_TAHITI, true}, {CHIP_BONAIRE, true}, {CHIP_CARRIZO, true},
      {CHIP_RAVEN, true}, {CHIP_NAVI10, true}, {CHIP_REMBRANDT, true},
      {CHIP_NAVI31, true}, {CHIP_STRIX1, true}, {CHIP_GFX1170, true},
      {CHIP_GFX1201, true}, {CHIP_GFX1210, true},
      {CHIP_MI100, false}, {CHIP_MI200, false}, {CHIP_GFX940, false},
   };
   const char *entry = "kernel";
   bool file = false;
   enum stela_air_fp_profile fp_profile;
   if (!stela_air_probe_profile(&argc, argv, &fp_profile))
      return 2;
   stela_air_probe_profile_receipt(fp_profile);
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
   glsl_type_singleton_init_or_ref();

   bool ok = true;
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++) {
      ok &= compile_target(input, entry, input_hash, targets[i].family, targets[i].graphics, 64, file, fp_profile);
      if (ac_get_gfx_level(targets[i].family) >= GFX10)
         ok &= compile_target(input, entry, input_hash, targets[i].family, targets[i].graphics, 32, file, fp_profile);
   }
   LLVMDisposeMemoryBuffer(input);
   glsl_type_singleton_decref();
   return !ok;
}
