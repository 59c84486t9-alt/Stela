/* SPDX-License-Identifier: MIT */
#include "compiler/nir/nir_builder.h"
#include "probe_report.h"
#include "targets/nvidia.h"
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <string.h>

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
   struct nak_compiler *nak = nak_compiler_create(&dev);
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
      stela_nvidia_target_name(target, sm);
      record_compiled(target, bin->code_size);
      record_end();
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

/* The access a shader's raw buffer loads end with, after nir_opt_access:
 * a load of buffer memory the shader never writes may be reordered, and
 * NAK reads it through the incoherent cache; once the shader stores to any
 * buffer, or for a coherent or relaxed atomic load, it stays in order. */
static int
check_global_load_access(unsigned sm, bool store, enum gl_access_qualifier load_access,
                         enum gl_access_qualifier expected)
{
   const struct nv_device_info dev = {.sm = sm, .max_warps_per_mp = 32};
   struct nak_compiler *nak = nak_compiler_create(&dev);
   if (!nak)
      return 1;
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, nak_nir_options(nak),
                                                  "stela_access_probe");
   b.shader->info.workgroup_size[0] = 32;
   b.shader->info.workgroup_size[1] = 1;
   b.shader->info.workgroup_size[2] = 1;
   b.shader->info.shared_size = 128;
   nir_def *index = nir_load_local_invocation_index(&b);
   nir_def *address = nir_iadd(&b, nir_imm_int64(&b, 0x100000), nir_u2u64(&b, nir_imul_imm(&b, index, 4)));
   nir_def *value = nir_load_global(&b, 1, 32, address, .align_mul = 4, .access = load_access);
   if (store)
      nir_store_global(&b, value, nir_iadd_imm(&b, address, 0x1000), .align_mul = 4);
   nir_store_shared(&b, value, nir_imul_imm(&b, index, 4), .align_mul = 4);
   const nir_opt_access_options options = {.is_vulkan = true};
   nir_opt_access(b.shader, &options);
   enum gl_access_qualifier access = 0;
   nir_foreach_function_impl(impl, b.shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic &&
                nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_load_global)
               access = nir_intrinsic_access(nir_instr_as_intrinsic(instr));
         }
      }
   }
   const nir_lower_compute_system_values_options system_values = {
      .lower_local_invocation_index = true,
   };
   nir_lower_compute_system_values(b.shader, &system_values);
   nak_preprocess_nir(b.shader, nak);
   struct nak_shader_bin *bin = nak_compile_shader(b.shader, true, nak, 0, NULL, false);
   bool incoherent = bin && bin->asm_str && strstr(bin->asm_str, ".constant");
   int result = 0;
   if (!bin || access != expected || incoherent != !!(expected & ACCESS_CAN_REORDER)) {
      fprintf(stderr, "SM%u: load access %#x (expected %#x), incoherent read %d\n", sm, access,
              expected, incoherent);
      result = 1;
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
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nvidia_sms); i++) {
      char target[16];
      stela_nvidia_target_name(target, stela_nvidia_sms[i]);
      record_expect(target, NULL);
   }
   glsl_type_singleton_init_or_ref();
   int result = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nvidia_sms); i++) {
      unsigned sm = stela_nvidia_sms[i];
      result |= compile_store(sm);
      result |= check_global_load_access(sm, false, 0, ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER);
      result |= check_global_load_access(sm, true, 0, 0);
      result |= check_global_load_access(sm, false, ACCESS_COHERENT, ACCESS_COHERENT);
      result |= check_global_load_access(sm, false, ACCESS_ATOMIC | ACCESS_COHERENT,
                                         ACCESS_ATOMIC | ACCESS_COHERENT);
   }
   glsl_type_singleton_decref();
   return result;
}
