/* SPDX-License-Identifier: MIT */
/* CPU model only: immutable synthetic topology/VM facts, real retained ACO
 * compilation, original compiled RadeonSI donors and actual PM4 decoding.
 * No physical device, allocation, mapping or resource residency is created.
 */
#include "../hosted/compute.h"
#include "../hosted/compute_policy.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_shader_util.h"
#include "amd/common/nir/ac_nir.h"
#include "amd/common/sid.h"
#include "amd/compiler/aco_interface.h"
#include "compiler/nir/nir_builder.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#if STELA_AMD_TEST_LLVM
#include "../hosted/llvm_float.h"
#include "amd/llvm/ac_llvm_build.h"
#include "amd/llvm/ac_nir_to_llvm.h"
#include "amd/llvm/ac_shader_abi.h"
#include <llvm-c/Analysis.h>
#include <llvm-c/Object.h>
#endif

/* Minimal donor containers, confined to this test translation unit. Their
 * fields are exactly those read by the retained pure functions. */
struct si_screen { struct radeon_info info; };
struct si_shader_selector { struct si_screen *screen; mesa_shader_stage stage; };
struct si_shader {
   struct si_shader_selector *selector;
   struct ac_shader_config config;
   struct stela_amd_compute_policy info;
   unsigned wave_size;
   unsigned complete_shader_binary_size;
};
unsigned si_get_shader_prefetch_size(struct si_shader *shader);
unsigned si_shader_encode_vgprs(struct si_shader *shader);
unsigned si_shader_encode_sgprs(struct si_shader *shader);
bool si_shader_mem_ordered(struct si_shader *shader);
#include "compute_policy_reference.h"

static struct radeon_info
model(enum radeon_family family, bool graphics)
{
   struct radeon_info info = {
      .family = family, .gfx_level = ac_get_gfx_level(family), .has_graphics = graphics,
      .num_cu = 8, .num_se = 2, .max_se = 2, .spi_cu_en = UINT32_MAX,
      .max_good_cu_per_sa = 4, .max_sa_per_se = 1,
      .virtual_address_max = UINT64_C(0x800000000000),
      .virtual_address_alignment = 4096, .tcc_cache_line_size = 128,
   };
   ac_fill_compiler_info(&info, NULL, false);
   info.instr_prefetch_distance = info.gfx_level >= GFX11 ? 4 : 0;
   return info;
}

static void
test_policy_donors(void)
{
   const enum radeon_family targets[] = {
      CHIP_TAHITI, CHIP_BONAIRE, CHIP_CARRIZO, CHIP_RAVEN, CHIP_MI100,
      CHIP_MI200, CHIP_GFX940, CHIP_NAVI10, CHIP_REMBRANDT, CHIP_NAVI31,
      CHIP_STRIX1, CHIP_GFX1170, CHIP_GFX1201, CHIP_GFX1210,
   };
   unsigned comparisons = 0;
   for (unsigned target = 0; target < ARRAY_SIZE(targets); target++) {
      struct si_screen screen = {.info = model(targets[target], true)};
      struct si_shader_selector selector = {.screen = &screen, .stage = MESA_SHADER_COMPUTE};
      for (unsigned wave = screen.info.gfx_level < GFX10 ? 64 : 32; wave <= 64; wave *= 2) {
         for (unsigned mask = 0; mask < 64; mask++) {
            struct stela_amd_compute_policy state = {
               .stage = MESA_SHADER_COMPUTE, .wave_size = wave, .binary_size = 76,
               .cs_num_user_sgprs = 2 + (mask % 8),
               .uses_sysval_workgroup_id_x = mask & 1,
               .uses_sysval_workgroup_id_y = mask & 2,
               .uses_sysval_workgroup_id_z = mask & 4,
               .uses_sysval_local_invocation_id_y = mask & 8,
               .uses_sysval_local_invocation_id_z = mask & 16,
               .uses_sgpr_tg_size = mask & 32,
               .uses_vmem_sampler_or_bvh = mask & 1,
               .uses_vmem_load_other = mask & 2,
            };
            struct ac_shader_config config = {
               .num_sgprs = 16, .num_vgprs = 8 + 8 * (mask % 4),
               .num_shared_vgprs = screen.info.gfx_level >= GFX10 ? 8 * (mask % 3) : 0,
               .scratch_bytes_per_wave = mask & 4 ? 1024 : 0,
               .lds_size = 512 * (mask % 8), .float_mode = 192,
            };
            struct si_shader donor = {
               .selector = &selector, .config = config, .info = state,
               .wave_size = wave, .complete_shader_binary_size = state.binary_size,
            };
            reference_compute_words(&donor);
            stela_amd_compute_policy(&screen.info, &state, &config);
            assert(config.rsrc1 == donor.config.rsrc1 && config.rsrc2 == donor.config.rsrc2 &&
                   config.rsrc3 == donor.config.rsrc3);
            comparisons++;
         }
      }
   }
   printf("AMD compute: %u compiled pinned-donor resource-word comparisons passed\n", comparisons);
}

struct compiled {
   struct ac_shader_config config;
   unsigned executable_bytes;
   unsigned code_bytes;
};

static void
capture(void **private, const struct ac_shader_config *config,
         const char *ir, unsigned ir_size, const char *assembly,
         unsigned assembly_size, struct amd_stats *stats, uint32_t exec_size,
         const uint32_t *code, uint32_t code_dw, const struct aco_symbol *symbols,
         unsigned num_symbols, const struct ac_shader_debug_info *debug_info, unsigned debug_count)
{
   (void)ir; (void)ir_size; (void)assembly; (void)assembly_size; (void)stats;
   (void)symbols; (void)debug_info; (void)debug_count;
   assert(config && code && code_dw && exec_size && !num_symbols && code_dw <= UINT32_MAX / 4);
   struct compiled *result = *private;
   result->config = *config;
   result->executable_bytes = exec_size;
   result->code_bytes = code_dw * 4;
}

#if STELA_AMD_TEST_LLVM
static void
compile_llvm(nir_shader *shader, const struct ac_shader_args *args,
              const struct radeon_info *info, struct compiled *result)
{
   struct ac_llvm_compiler compiler;
   assert(ac_init_llvm_compiler(&compiler, info->family, AC_TM_CHECK_IR));
   struct ac_llvm_context llvm = {0};
   ac_llvm_context_init(&llvm, &compiler, &info->compiler_info, AC_FLOAT_MODE_DEFAULT,
                        64, false, false);
   struct ac_shader_abi abi = {0};
   struct ac_llvm_pointer main = ac_build_main(args, &llvm, AC_LLVM_AMDGPU_CS,
                                               "compute_model", llvm.voidt, llvm.module);
   ac_llvm_set_workgroup_size(main.value, 32);
   ac_llvm_set_target_features(main.value, &llvm, false);
   assert(stela_amd_llvm_apply_float_controls(llvm.context, main.value, shader) ==
          STELA_AMD_LLVM_FLOAT_OK);
   assert(ac_nir_translate(&llvm, &abi, args, shader));
   LLVMBuildRetVoid(llvm.builder);
   assert(!LLVMVerifyModule(llvm.module, LLVMReturnStatusAction, NULL));
   assert(ac_llvm_optimize_module(compiler.meo, llvm.module));
   assert(!LLVMVerifyModule(llvm.module, LLVMReturnStatusAction, NULL));
   char *elf = NULL;
   size_t elf_size = 0;
   compiler.beo = ac_create_backend_optimizer(compiler.tm);
   assert(ac_compile_module_to_elf(compiler.beo, llvm.module, &elf, &elf_size));
   assert(elf && elf_size);
   LLVMMemoryBufferRef memory = LLVMCreateMemoryBufferWithMemoryRangeCopy(elf, elf_size, "compute-model");
   LLVMBinaryRef binary = LLVMCreateBinary(memory, NULL, NULL);
   assert(binary && LLVMBinaryGetType(binary) == LLVMBinaryTypeELF64L);
   LLVMSectionIteratorRef section = LLVMObjectFileCopySectionIterator(binary);
   bool config_found = false;
   for (; section && !LLVMObjectFileIsSectionIteratorAtEnd(binary, section); LLVMMoveToNextSection(section)) {
      const char *name = LLVMGetSectionName(section);
      if (name && !strcmp(name, ".text")) {
         assert(!result->executable_bytes && LLVMGetSectionSize(section) <= UINT32_MAX);
         result->executable_bytes = LLVMGetSectionSize(section);
         result->code_bytes = result->executable_bytes;
      } else if (name && !strcmp(name, ".AMDGPU.config")) {
         const char *data = LLVMGetSectionContents(section);
         uint64_t size = LLVMGetSectionSize(section);
         assert(!config_found && data && size && size <= elf_size && size % 8 == 0 &&
                (uintptr_t)data % _Alignof(uint32_t) == 0);
         ac_parse_llvm_binary_config(data, size, 64, &info->compiler_info, &result->config);
         assert(stela_amd_llvm_restore_float_controls(shader, &result->config) ==
                STELA_AMD_LLVM_FLOAT_OK);
         config_found = true;
      }
   }
   assert(config_found && result->executable_bytes && result->config.num_vgprs);
   if (section)
      LLVMDisposeSectionIterator(section);
   LLVMDisposeBinary(binary);
   LLVMDisposeMemoryBuffer(memory);
   free(elf);
   ac_llvm_context_dispose(&llvm);
   LLVMDisposeModule(llvm.module);
   LLVMContextDispose(llvm.context);
   ac_destroy_llvm_compiler(&compiler);
}
#endif

static uint32_t
register_word(const uint32_t *words, unsigned count, unsigned reg)
{
   for (unsigned cursor = 0; cursor < count;) {
      const unsigned header = words[cursor], length = ((header >> 16) & 0x3fff) + 2;
      assert(header >> 30 == 3 && length <= count - cursor);
      /* Synthetic model leaves packed register-pair support disabled. */
      assert(((header >> 8) & 255) == PKT3_SET_SH_REG && length >= 3);
      unsigned start = 0xb000 + 4 * words[cursor + 1];
      for (unsigned i = 2; i < length; i++) {
         if (start + 4 * (i - 2) == reg)
            return words[cursor + i];
      }
      cursor += length;
   }
   assert(!"required register absent");
   return 0;
}

static void
test_compiled_target(enum radeon_family family, unsigned wave, bool llvm_backend,
                      unsigned shared_bytes, unsigned float_controls)
{
   struct radeon_info info = model(family, !llvm_backend);
   nir_shader_compiler_options options;
   ac_nir_set_options(&info.compiler_info, llvm_backend, &options);
   struct ac_shader_args args = {0};
   struct ac_arg buffer;
   ac_add_arg(&args, AC_ARG_SGPR, 2, AC_ARG_VALUE, &buffer);
   for (unsigned axis = 0; axis < 3; axis++) {
      if (info.gfx_level >= GFX12)
         args.workgroup_ids[axis].used = true;
      else
         ac_add_arg(&args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &args.workgroup_ids[axis]);
   }
   if (info.gfx_level < GFX11)
      ac_add_arg(&args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &args.scratch_offset);
   if (info.compiler_info.local_invocation_ids_packed) {
      ac_add_arg(&args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &args.local_invocation_ids_packed);
   } else {
      ac_add_arg(&args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &args.local_invocation_id_x);
      ac_add_arg(&args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &args.local_invocation_id_y);
      ac_add_arg(&args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &args.local_invocation_id_z);
   }
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, &options, "compute-policy-fixture");
   b.shader->info.workgroup_size[0] = 32;
   b.shader->info.workgroup_size[1] = b.shader->info.workgroup_size[2] = 1;
   b.shader->info.shared_size = shared_bytes;
   b.shader->info.float_controls_execution_mode = float_controls;
   nir_def *tid = nir_iadd(&b, nir_imul_imm(&b, nir_channel(&b, nir_load_workgroup_id(&b), 0), 32),
                          nir_channel(&b, nir_load_local_invocation_id(&b), 0));
   nir_def *base = nir_pack_64_2x32(&b, ac_nir_load_arg(&b, &args, buffer));
   nir_def *address = nir_iadd(&b, base, nir_imul_imm(&b, nir_u2u64(&b, tid), 4));
   nir_def *value = nir_load_global(&b, 1, 32, address, .align_mul = 4);
   if (shared_bytes) {
      nir_def *offset = nir_imul_imm(&b, tid, 4);
      nir_store_shared(&b, value, offset, .align_mul = 4);
      value = nir_load_shared(&b, 1, 32, offset, .align_mul = 4);
   }
   if (float_controls) {
      nir_def *product = nir_fmul(&b, value, nir_i2f32(&b, tid));
      value = nir_fadd(&b, nir_fsub(&b, product, value), nir_u2f32(&b, tid));
   } else {
      value = nir_iadd_imm(&b, nir_imul_imm(&b, value, 2), 1);
   }
   nir_store_global(&b, value, address, .align_mul = 4);
   const ac_nir_lower_intrinsics_to_args_options arg_options = {
      .gfx_level = info.gfx_level, .hw_stage = AC_HW_COMPUTE_SHADER,
      .wave_size = wave, .workgroup_size = 32, .use_llvm = llvm_backend,
   };
   ac_nir_lower_intrinsics_to_args(b.shader, &args, &arg_options);
   ac_nir_lower_global_access(b.shader, info.gfx_level);
   nir_lower_int64(b.shader);
   nir_lower_alu_width(b.shader, ac_nir_opt_vectorize_cb, &info.gfx_level);
   nir_lower_load_const_to_scalar(b.shader);
   nir_opt_constant_folding(b.shader);
   nir_opt_copy_prop(b.shader);
   nir_opt_dce(b.shader);
   nir_shader_gather_info(b.shader, nir_shader_get_entrypoint(b.shader));
   nir_validate_shader(b.shader, "real ACO pipeline fixture");
   const struct aco_compiler_options compiler_options = {
      .compiler_info = &info.compiler_info, .family = family, .gfx_level = info.gfx_level,
   };
   const struct aco_shader_info shader_info = {
      .hw_stage = AC_HW_COMPUTE_SHADER, .wave_size = wave, .workgroup_size = 32,
      .lds_size = b.shader->info.shared_size,
   };
   struct compiled compiled = {0};
   void *private = &compiled;
   if (llvm_backend) {
#if STELA_AMD_TEST_LLVM
      compile_llvm(b.shader, &args, &info, &compiled);
#else
      assert(!"LLVM test needs the actual selected development kit and compiler library");
#endif
   } else {
      aco_compile_shader(&compiler_options, &shader_info, 1, &b.shader, &args, capture, &private);
   }
   assert(compiled.executable_bytes && compiled.config.num_vgprs);
   const struct stela_amd_compute_binary binary = {
      .shader = b.shader, .args = &args, .config = &compiled.config,
      .family = family, .gfx_level = info.gfx_level,
      .wave_size = wave, .executable_bytes = compiled.executable_bytes,
      .code_bytes = compiled.code_bytes,
   };
   struct stela_amd_buffer_view code = {
      .allocation_va = 0x10000000, .allocation_bytes = 4096,
      .range = 4096, .required_alignment = 256,
   };
   struct stela_amd_compute_binding binding = {
      .argument = buffer, .view = {
         .allocation_va = 0x20000000, .allocation_bytes = 4096,
         .range = 4096, .required_alignment = 4,
      },
   };
   struct stela_amd_compute_pipeline result;
   enum stela_amd_compute_status status =
      stela_amd_build_compute_pipeline(&info, &binary, &code, &binding, 1, &result);
   if (status != STELA_AMD_COMPUTE_OK)
      fprintf(stderr, "model %s wave%u: status%u, SGPR%u/%u VGPR%u/%u LDS%u/%u\n",
              ac_get_family_name(family), wave, status, compiled.config.num_sgprs,
              args.num_sgprs_used, compiled.config.num_vgprs, args.num_vgprs_used,
              compiled.config.lds_size, b.shader->info.shared_size);
   assert(status == STELA_AMD_COMPUTE_OK);
   assert(G_00B848_FLOAT_MODE(result.rsrc1) == compiled.config.float_mode);
   if (float_controls && llvm_backend) {
      const unsigned expected = V_00B028_FP_16_64_DENORMS |
         (float_controls & FLOAT_CONTROLS_DENORM_PRESERVE_FP32 ? V_00B028_FP_32_DENORMS : 0);
      assert(compiled.config.float_mode == expected);
   }
   assert(G_00B84C_USER_SGPR(result.rsrc2) == 2);
   assert(G_00B84C_TGID_X_EN(result.rsrc2) && G_00B84C_TGID_Y_EN(result.rsrc2) &&
          G_00B84C_TGID_Z_EN(result.rsrc2) && G_00B84C_TIDIG_COMP_CNT(result.rsrc2) == 2);
   const unsigned lds_blocks = !shared_bytes ? 0 : info.gfx_level >= GFX10_3 ? 2 : 1;
   assert(!G_00B84C_SCRATCH_EN(result.rsrc2) && G_00B84C_LDS_SIZE(result.rsrc2) == lds_blocks);
   assert(result.user_sgprs[0] == 0x20000000 && result.user_sgprs[1] == 0);
   uint32_t words[256], written;
   assert(stela_amd_compute_pipeline(&info, &result, words, ARRAY_SIZE(words), &written) ==
          STELA_AMD_COMMAND_OK);
   assert(register_word(words, written, R_00B848_COMPUTE_PGM_RSRC1) == result.rsrc1);
   assert(register_word(words, written, R_00B84C_COMPUTE_PGM_RSRC2) == result.rsrc2);
   assert(register_word(words, written, R_00B854_COMPUTE_RESOURCE_LIMITS) == result.resource_limits);
   assert(register_word(words, written, R_00B900_COMPUTE_USER_DATA_0) == result.user_sgprs[0]);

   const struct stela_amd_compute_pipeline preserved = result;
   /* A zero-binding pipeline cannot discard the real shader's address ABI. */
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, NULL, 0, &result) != STELA_AMD_COMPUTE_OK);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, NULL, 1, &result) == STELA_AMD_COMPUTE_INVALID);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   struct stela_amd_compute_binary wrong_target = binary;
   wrong_target.family = CHIP_UNKNOWN;
   assert(stela_amd_build_compute_pipeline(&info, &wrong_target, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_UNSUPPORTED);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   struct radeon_info missing = info;
   missing.num_se = 0;
   assert(stela_amd_build_compute_pipeline(&missing, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   missing = info;
   missing.spi_cu_en = UINT32_C(0xffff0000);
   assert(stela_amd_build_compute_pipeline(&missing, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   struct stela_amd_compute_binding duplicate[] = {binding, binding};
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, duplicate, 2, &result) ==
          STELA_AMD_COMPUTE_INVALID);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   const uint64_t offset = binding.view.offset;
   binding.view.offset = binding.view.allocation_bytes;
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_INVALID);
   binding.view.offset = offset;
   const unsigned original_vgprs = compiled.config.num_vgprs;
   compiled.config.num_vgprs = info.compiler_info.max_vgpr_alloc + 1;
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_UNSUPPORTED);
   compiled.config.num_vgprs = original_vgprs;
   b.shader->info.cs.has_variable_shared_mem = true;
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_UNSUPPORTED);
   b.shader->info.cs.has_variable_shared_mem = false;
   missing = info;
   missing.compiler_info.wave64_vgpr_encode_granularity = UINT32_C(0x80000000);
   assert(stela_amd_build_compute_pipeline(&missing, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   const unsigned scratch = compiled.config.scratch_bytes_per_wave;
   compiled.config.scratch_bytes_per_wave = 1024;
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE);
   compiled.config.scratch_bytes_per_wave = scratch;
   code.range = compiled.executable_bytes - 4;
   assert(stela_amd_build_compute_pipeline(&info, &binary, &code, &binding, 1, &result) ==
          STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE);
   assert(!memcmp(&result, &preserved, sizeof(result)));
   ralloc_free(b.shader);
}

int
main(void)
{
   test_policy_donors();
   glsl_type_singleton_init_or_ref();
   const enum radeon_family targets[] = {
      CHIP_TAHITI, CHIP_BONAIRE, CHIP_CARRIZO, CHIP_RAVEN, CHIP_NAVI10,
      CHIP_REMBRANDT, CHIP_NAVI31, CHIP_STRIX1, CHIP_GFX1170, CHIP_GFX1201,
   };
   unsigned compiled = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++) {
      test_compiled_target(targets[i], 64, false, 0, 0);
      compiled++;
      if (ac_get_gfx_level(targets[i]) >= GFX10) {
         test_compiled_target(targets[i], 32, false, 0, 0);
         compiled++;
      }
   }
   test_compiled_target(CHIP_TAHITI, 64, false, 128, 0);
   test_compiled_target(CHIP_REMBRANDT, 32, false, 128, 0);
   test_compiled_target(CHIP_NAVI31, 64, false, 128, 0);
   test_compiled_target(CHIP_GFX1201, 32, false, 128, 0);
   compiled += 4;
   const unsigned float_modes[] = {
      FLOAT_CONTROLS_DENORM_PRESERVE_FP32 | FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32,
      FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32 | FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32,
   };
   for (unsigned i = 0; i < ARRAY_SIZE(float_modes); i++) {
      test_compiled_target(CHIP_NAVI31, 32, false, 0, float_modes[i]);
      compiled++;
   }
#if STELA_AMD_TEST_LLVM
   ac_init_llvm_once();
   test_compiled_target(CHIP_MI100, 64, true, 0, 0);
   test_compiled_target(CHIP_MI200, 64, true, 0, 0);
   test_compiled_target(CHIP_GFX940, 64, true, 0, 0);
   compiled += 3;
   for (unsigned i = 0; i < ARRAY_SIZE(float_modes); i++) {
      test_compiled_target(CHIP_MI100, 64, true, 0, float_modes[i]);
      test_compiled_target(CHIP_MI200, 64, true, 0, float_modes[i]);
      test_compiled_target(CHIP_GFX940, 64, true, 0, float_modes[i]);
      compiled += 3;
   }
#endif
   glsl_type_singleton_decref();
   printf("AMD compute: %u real compiler config -> retained policy -> decoded PM4 cases passed; synthetic VM/topology only\n", compiled);
   return 0;
}
