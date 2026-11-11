/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The backend's internal compute kernels compile through NAK for every
 * NVIDIA target: NAK refuses ALU operations it has no lowering for only
 * when it compiles, which on a device is when the backend starts. The
 * Vulkan driver's descriptor and push-constant lowering is stood in for by
 * bindless images and a global argument address; no device is opened. */
#include "../metal_abi.h"
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#include "targets/nvidia.h"
#include "compiler/glsl_types.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

/* What the Vulkan driver's lowering leaves of the kernel's bindings. */
static bool
stand_in_bindings(nir_builder *b, nir_intrinsic_instr *intrin, void *data)
{
   (void)data;
   b->cursor = nir_before_instr(&intrin->instr);
   switch (intrin->intrinsic) {
   case nir_intrinsic_load_push_constant: {
      nir_def *address = nir_iadd_imm(b, nir_u2u64(b, intrin->src[0].ssa),
                                      0x100000 + nir_intrinsic_base(intrin));
      nir_def *value = nir_load_global_constant(b, intrin->def.num_components,
                                                intrin->def.bit_size, address,
                                                .align_mul = 4);
      nir_def_replace(&intrin->def, value);
      return true;
   }
   case nir_intrinsic_image_deref_load:
   case nir_intrinsic_image_deref_store:
   case nir_intrinsic_image_deref_size:
   case nir_intrinsic_image_deref_samples:
   case nir_intrinsic_image_deref_atomic:
   case nir_intrinsic_image_deref_atomic_swap: {
      nir_deref_instr *deref = nir_src_as_deref(intrin->src[0]);
      nir_def *handle = deref->deref_type == nir_deref_type_array
                           ? nir_u2u32(b, deref->arr.index.ssa) : nir_imm_int(b, 0);
      nir_rewrite_image_intrinsic(intrin, handle, nir_image_intrinsic_type_bindless);
      return true;
   }
   default:
      return false;
   }
}

static void
compiles(nir_shader *(*build)(const nir_shader_compiler_options *), const char *name)
{
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nvidia_sms); i++) {
      const struct nv_device_info device = {.sm = stela_nvidia_sms[i], .max_warps_per_mp = 32};
      struct nak_compiler *compiler = nak_compiler_create(&device);
      CHECK(compiler);
      nir_shader *nir = build(nak_nir_options(compiler));
      CHECK(nir);
      nir_shader_intrinsics_pass(nir, stand_in_bindings, nir_metadata_control_flow, NULL);
      nir_opt_dce(nir);
      nir_remove_dead_derefs(nir);
      nir_remove_dead_variables(nir, nir_var_image | nir_var_uniform, NULL);
      /* Dispatches start at workgroup zero, as the driver's do. */
      const nir_lower_compute_system_values_options system_values = {0};
      nir_lower_compute_system_values(nir, &system_values);
      nir_validate_shader(nir, name);
      nak_preprocess_nir(nir, compiler);
      struct nak_shader_bin *bin = nak_compile_shader(nir, false, compiler, 0, NULL, false);
      CHECK(bin && bin->code && bin->code_size && bin->info.stage == MESA_SHADER_COMPUTE);
      printf("%s SM%u: %u instructions\n", name, stela_nvidia_sms[i], bin->info.num_instrs);
      nak_shader_bin_destroy(bin);
      ralloc_free(nir);
      nak_compiler_destroy(compiler);
   }
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   compiles(stela_metal_accumulate_kernel, "accumulate");
   compiles(stela_metal_select_kernel, "select");
   compiles(stela_metal_resolve_draws_kernel, "resolve draws");
   compiles(stela_metal_resolve_dispatches_kernel, "resolve dispatches");
   compiles(stela_metal_store_texels_kernel, "store texels");
   compiles(stela_metal_load_texels_kernel, "load texels");
   compiles(stela_metal_average_samples_kernel, "average samples");
   compiles(stela_metal_decode_etc_kernel, "decode etc");
   compiles(stela_metal_decode_pvrtc_kernel, "decode pvrtc");
   compiles(stela_metal_decode_astc_kernel, "decode astc");
   compiles(stela_metal_reorder_blocks_kernel, "reorder blocks");
   puts("metal abi kernels compile through NAK");
   glsl_type_singleton_decref();
   return 0;
}
