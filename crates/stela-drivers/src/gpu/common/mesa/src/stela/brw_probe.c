/* SPDX-License-Identifier: MIT */
#include "compiler/nir/nir_builder.h"
#include "intel_probe.h"
#include "probe_report.h"
#include "intel/compiler/intel_gfx_ver_enum.h"
#include "intel/compiler/brw/brw_compiler.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/gen/gen.h"
#include "intel/dev/intel_device_info.h"
#include "util/ralloc.h"
#include <stdarg.h>
#include <stdio.h>

static void
compiler_log(void *data, unsigned *id, const char *format, ...)
{
   va_list arguments;
   va_start(arguments, format);
   vfprintf(stderr, format, arguments);
   va_end(arguments);
}

/* Static compile targets never open a device or initialize physical hardware. */
static int
compile_store(const char *platform)
{
   struct intel_device_info device;
   int pci_id = intel_device_name_to_pci_device_id(platform);
   if (pci_id < 0 || !intel_get_device_info_for_build(pci_id, &device))
      return 1;
   if (device.ver == 35) {
      /* The imported backend explicitly requires dispatch qualification on
       * this generation. Preserve that gate; an ISA table is not proof of
       * shader execution support.
       */
      if (gfx_ver_from_devinfo(&device) != XE3P)
         return 1;
      probe_unsupported("brw", platform, "requires-dispatch-packing-qualification");
      return 0;
   }
   void *context = ralloc_context(NULL);
   struct brw_compiler *compiler = brw_compiler_create(context, &device);
   compiler->shader_debug_log = compiler_log;
   compiler->shader_perf_log = compiler_log;
   nir_builder b = nir_builder_init_simple_shader(
      MESA_SHADER_COMPUTE, &compiler->nir_options[MESA_SHADER_COMPUTE],
      "stela_brw_store_probe");
   b.shader->info.workgroup_size[0] = 16;
   b.shader->info.workgroup_size[1] = 1;
   b.shader->info.workgroup_size[2] = 1;
   nir_def *address = nir_imm_int64(&b, 0x100000);
   nir_def *input = nir_load_global(&b, 1, 32, address, .align_mul = 4);
   nir_store_global(&b, nir_iadd_imm(&b, input, 1), address, .align_mul = 4);
   const struct brw_nir_compiler_opts options = {0};
   brw_preprocess_nir(compiler, b.shader, &options);
   nir_shader_gather_info(b.shader, nir_shader_get_entrypoint(b.shader));
   struct brw_cs_prog_key key = {0};
   struct brw_cs_prog_data data = {0};
   b.shader->info.min_subgroup_size = 16;
   b.shader->info.max_subgroup_size = 16;
   brw_nir_lower_cs_intrinsics(b.shader, &device, &data);
   nir_validate_shader(b.shader, "Stela BRW codegen probe");
   struct brw_compile_cs_params parameters = {
      .base = {
         .mem_ctx = context,
         .nir = b.shader,
         .key = &key.base,
         .prog_data = &data.base,
      },
   };
   const unsigned *code = brw_compile(compiler, &parameters.base);
   int failed = !code || !data.base.program_size || parameters.base.error_str;
   unsigned sends = 0;
   if (!failed)
      failed = !validate_intel_code(&device, context, code,
                                    data.base.program_size, platform, &sends);
   if (failed)
      fprintf(stderr, "%s codegen failed: %s\n", platform,
              parameters.base.error_str ? parameters.base.error_str : "no code");
   else {
      probe_compiled("brw", platform, data.base.program_size);
      printf("%s, PCI %04x, ver %u.%u: %u bytes, %u sends, validated\n",
             platform, pci_id, device.ver, device.verx10 % 10,
             data.base.program_size, sends);
   }
   ralloc_free(b.shader);
   ralloc_free(context);
   return failed;
}

int
main(void)
{
   struct intel_device_info unsupported;
   if (intel_get_device_info_for_build(0, &unsupported)) {
      fprintf(stderr, "an unknown PCI ID was accepted as a compile target\n");
      return 1;
   }
   const char *platforms[] = {
      "skl", "bxt", "kbl", "glk", "icl", "ehl", "tgl", "rkl", "dg1",
      "adl", "dg2", "mtl", "arl", "lnl", "bmg", "ptl", "nvl-u", "nvl",
   };
   glsl_type_singleton_init_or_ref();
   int result = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(platforms); i++)
      result |= compile_store(platforms[i]);
   glsl_type_singleton_decref();
   return result;
}
