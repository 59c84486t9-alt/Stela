/* SPDX-License-Identifier: MIT */
#include "amd/compiler/aco_interface.h"
#include "probe_report.h"
#include "targets/amd.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/nir/ac_nir.h"
#if AMD_LLVM_AVAILABLE
#include "amd/llvm/ac_llvm_util.h"
#endif
#include "compiler/nir/nir_builder.h"
#include "util/ralloc.h"
#include <stdio.h>

struct compile_result {
   unsigned code_dw;
   unsigned exec_size;
};

static void
capture_binary(void **private, const struct ac_shader_config *config,
               const char *ir, unsigned ir_size, const char *assembly,
               unsigned assembly_size, struct amd_stats *stats,
               uint32_t exec_size, const uint32_t *code, uint32_t code_dw,
               const struct aco_symbol *symbols, unsigned num_symbols,
               const struct ac_shader_debug_info *debug_info, unsigned debug_count)
{
   struct compile_result *result = *private;
   if (code && code_dw) {
      result->code_dw = code_dw;
      result->exec_size = exec_size;
   }
   if (assembly && assembly_size) {
      if (assembly[assembly_size - 1] == '\0')
         assembly_size--;
      fwrite(assembly, 1, assembly_size, stdout);
   }
}

static struct radeon_info
model(enum radeon_family family)
{
   struct radeon_info gpu = {
      .gfx_level = ac_get_gfx_level(family),
      .family = family,
      .has_graphics = stela_amd_has_graphics(family),
   };
   ac_fill_compiler_info(&gpu, NULL, false);
   return gpu;
}

/* Synthetic compile targets only: no physical device is initialized. */
static int
compile_store(enum radeon_family family, unsigned wave_size)
{
   enum amd_gfx_level gfx_level = ac_get_gfx_level(family);
   char target[32];
   stela_amd_target_name(target, family, wave_size);
   struct radeon_info gpu = model(family);
   if (!aco_is_gpu_supported(&gpu)) {
      record_held(target, stela_amd_aco_refusal(family));
      return 0;
   }
   nir_shader_compiler_options nir_options;
   ac_nir_set_options(&gpu.compiler_info, false, &nir_options);
   nir_builder b = nir_builder_init_simple_shader(
      MESA_SHADER_COMPUTE, &nir_options, "stela_aco_store_probe");
   b.shader->info.workgroup_size[0] = 1;
   b.shader->info.workgroup_size[1] = 1;
   b.shader->info.workgroup_size[2] = 1;
   nir_def *address = nir_imm_int64(&b, 0x100000);
   nir_def *input = nir_load_global(&b, 1, 32, address, .align_mul = 4);
   nir_store_global(&b, nir_iadd_imm(&b, input, 1), address, .align_mul = 4);
   ac_nir_lower_global_access(b.shader, gfx_level);
   nir_shader_gather_info(b.shader, nir_shader_get_entrypoint(b.shader));
   nir_validate_shader(b.shader, "Stela ACO codegen probe");

   const struct aco_compiler_options options = {
      .compiler_info = &gpu.compiler_info,
      .family = family,
      .gfx_level = gfx_level,
      .record_asm = true,
   };
   const struct aco_shader_info info = {
      .hw_stage = AC_HW_COMPUTE_SHADER,
      .wave_size = wave_size,
      .workgroup_size = 1,
   };
   const struct ac_shader_args args = {0};
   struct compile_result result = {0};
   void *private = &result;
   aco_compile_shader(&options, &info, 1, &b.shader, &args,
                     capture_binary, &private);
   ralloc_free(b.shader);
   printf("%s, wave%u: %u dwords, %u executable bytes\n",
          ac_get_family_name(family), wave_size, result.code_dw, result.exec_size);
   if (result.code_dw && result.exec_size) {
      record_compiled(target, result.exec_size);
      record_end();
   }
   return result.code_dw == 0 || result.exec_size == 0;
}

int
main(void)
{
#if AMD_LLVM_AVAILABLE
   ac_init_llvm_once();
#endif
   /* The upstream compiler alone: every family Mesa's table names from GFX6. */
   for (enum radeon_family family = STELA_AMD_FIRST_FAMILY; family < CHIP_LAST; family++) {
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2) {
         char target[32];
         stela_amd_target_name(target, family, wave);
         record_expect(target, stela_amd_aco_hold(family));
      }
   }
   glsl_type_singleton_init_or_ref();
   int result = 0;
   for (enum radeon_family family = STELA_AMD_FIRST_FAMILY; family < CHIP_LAST; family++) {
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2)
         result |= compile_store(family, wave);
   }
   glsl_type_singleton_decref();
   return result;
}
