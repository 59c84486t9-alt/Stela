/* SPDX-License-Identifier: MIT */
#include "compiler/nir/nir_builder.h"
#include "probe_report.h"
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#include "util/ralloc.h"
#include <stdio.h>

/* Compile a shader with an observable store. This checks the linked C/Rust
 * compiler path across the NVIDIA generations used by the native kernel core.
 * No GPU is accessed, and these synthetic compile targets are not device info
 * that may be used to initialize physical hardware.
 */
static int
compile_store(unsigned sm)
{
   const struct nv_device_info dev = {
      .sm = sm,
      .max_warps_per_mp = 32,
   };
   const struct nak_constant_offset_info layout = {
      .sample_info_cb = 0,
      .sample_locations_offset = 0,
      .sample_masks_offset = 256,
      .printf_cb = 0,
      .printf_buffer_offset = 512,
   };
   struct nak_compiler *nak = nak_compiler_create(&dev, &layout, &layout);
   if (!nak)
      return 1;

   nir_builder b = nir_builder_init_simple_shader(
      MESA_SHADER_COMPUTE, nak_nir_options(nak), "stela_codegen_probe");
   b.shader->info.workgroup_size[0] = 32;
   b.shader->info.workgroup_size[1] = 1;
   b.shader->info.workgroup_size[2] = 1;
   nir_def *index = nir_load_local_invocation_index(&b);
   nir_def *value = nir_iadd_imm(&b, nir_imul_imm(&b, index, 2), 1);
   nir_def *offset = nir_u2u64(&b, nir_imul_imm(&b, index, 4));
   nir_def *address = nir_iadd(&b, nir_imm_int64(&b, 0x100000), offset);
   nir_store_global(&b, value, address, .align_mul = 4);
   nir_validate_shader(b.shader, "Stela code generation probe");

   const nir_lower_compute_system_values_options system_values = {
      .lower_local_invocation_index = true,
   };
   nir_lower_compute_system_values(b.shader, &system_values);
   nak_preprocess_nir(b.shader, nak);
   /* nak_compile_shader runs the retained postprocessing itself. */
   struct nak_shader_bin *bin =
      nak_compile_shader(b.shader, true, nak, 0, NULL, false);
   int result = 0;
   if (!bin || !bin->code || !bin->code_size ||
       bin->info.stage != MESA_SHADER_COMPUTE || bin->info.sm != sm ||
       bin->info.num_instrs < 2) {
      fprintf(stderr, "SM%u failed to compile the store shader\n", sm);
      result = 1;
   } else {
      char target[16];
      snprintf(target, sizeof(target), "sm%u", sm);
      probe_compiled("nak", target, bin->code_size);
      printf("SM%u: %u bytes, %u instructions\n", sm, bin->code_size,
             bin->info.num_instrs);
      if (bin->asm_str)
         puts(bin->asm_str);
   }
   if (bin)
      nak_shader_bin_destroy(bin);
   ralloc_free(b.shader);
   nak_compiler_destroy(nak);
   return result;
}

int
main(void)
{
   const unsigned models[] = {75, 80, 86, 89, 90, 100, 120};
   glsl_type_singleton_init_or_ref();
   int result = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(models); i++)
      result |= compile_store(models[i]);
   glsl_type_singleton_decref();
   return result;
}
