/* SPDX-License-Identifier: MIT */
#include "amd/compiler/aco_interface.h"
#include "probe_report.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/nir/ac_nir.h"
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

/* Synthetic compile targets only: no physical device is initialized. */
static int
compile_store(enum radeon_family family, bool has_graphics, unsigned wave_size)
{
   enum amd_gfx_level gfx_level = ac_get_gfx_level(family);
   char target[64];
   snprintf(target, sizeof(target), "%s.wave%u", ac_get_family_name(family), wave_size);
   struct radeon_info gpu = {
      .gfx_level = gfx_level,
      .family = family,
      .has_graphics = has_graphics,
   };
   ac_fill_compiler_info(&gpu, NULL, false);
   if (!aco_is_gpu_supported(&gpu)) {
      probe_unsupported("aco", target, has_graphics ?
                        "compiler-gfx-level-unsupported" : "requires-cdna-compiler-backend");
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
      probe_compiled("aco", target, result.exec_size);
   }
   return result.code_dw == 0 || result.exec_size == 0;
}

int
main(void)
{
   const struct {
      enum radeon_family family;
      bool has_graphics;
   } targets[] = {
      {CHIP_TAHITI, true}, {CHIP_BONAIRE, true}, {CHIP_KABINI, true}, {CHIP_KAVERI, true},
      {CHIP_POLARIS10, true}, {CHIP_CARRIZO, true}, {CHIP_STONEY, true},
      {CHIP_VEGA10, true}, {CHIP_RAVEN, true}, {CHIP_RENOIR, true},
      {CHIP_NAVI10, true}, {CHIP_NAVI21, true}, {CHIP_REMBRANDT, true},
      {CHIP_NAVI31, true}, {CHIP_PHOENIX, true}, {CHIP_STRIX_HALO, true},
      {CHIP_GFX1170, true}, {CHIP_GFX1201, true}, {CHIP_GFX1210, true},
      {CHIP_MI100, false}, {CHIP_MI200, false}, {CHIP_GFX940, false},
   };
   glsl_type_singleton_init_or_ref();
   int result = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++) {
      result |= compile_store(targets[i].family, targets[i].has_graphics, 64);
      if (ac_get_gfx_level(targets[i].family) >= GFX10)
         result |= compile_store(targets[i].family, targets[i].has_graphics, 32);
   }
   glsl_type_singleton_decref();
   return result;
}
