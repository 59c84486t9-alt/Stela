/* SPDX-License-Identifier: MIT */
#include "compiler/nir/nir_builder.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/compiler/elk/elk_eu.h"
#include "intel/dev/intel_device_info.h"
#include "intel/dev/intel_debug.h"
#include "probe_report.h"
#include "util/ralloc.h"
#include <stdarg.h>
#include <stdio.h>

static bool
validate_code(const struct elk_isa_info *isa, const void *code, unsigned bytes,
              unsigned *sends)
{
   *sends = 0;
   unsigned offset = 0;
   while (offset < bytes) {
      elk_inst instruction = {0};
      if (bytes - offset < sizeof(elk_compact_inst))
         return false;
      memcpy(&instruction, (const char *)code + offset, sizeof(elk_compact_inst));
      bool compact = elk_inst_cmpt_control(isa->devinfo, &instruction);
      unsigned size = compact ? sizeof(elk_compact_inst) : sizeof(elk_inst);
      if (bytes - offset < size)
         return false;
      if (compact) {
         elk_compact_inst encoded;
         memcpy(&encoded, (const char *)code + offset, sizeof(encoded));
         elk_uncompact_instruction(isa, &instruction, &encoded);
      } else {
         memcpy(&instruction, (const char *)code + offset, sizeof(instruction));
      }
      if (!elk_validate_instruction(isa, &instruction, offset, size, NULL))
         return false;
      enum elk_opcode opcode = elk_inst_opcode(isa, &instruction);
      *sends += opcode == ELK_OPCODE_SEND || opcode == ELK_OPCODE_SENDC;
      offset += size;
   }
   /* Load, store and end-of-thread must all survive compilation. */
   return *sends >= 3;
}

static void
compiler_log(void *data, unsigned *id, const char *format, ...)
{
   va_list arguments;
   va_start(arguments, format);
   vfprintf(stderr, format, arguments);
   va_end(arguments);
}

static int
compile_store(const char *platform)
{
   struct intel_device_info device;
   int pci_id = intel_device_name_to_pci_device_id(platform);
   if (pci_id < 0 || !intel_get_device_info_for_build(pci_id, &device))
      return 1;
   void *context = ralloc_context(NULL);
   struct elk_compiler *compiler = elk_compiler_create(context, &device);
   compiler->shader_debug_log = compiler_log;
   compiler->shader_perf_log = compiler_log;
   nir_builder b = nir_builder_init_simple_shader(
      MESA_SHADER_COMPUTE, compiler->nir_options[MESA_SHADER_COMPUTE],
      "stela_elk_store_probe");
   b.shader->info.workgroup_size[0] = 16;
   b.shader->info.workgroup_size[1] = 1;
   b.shader->info.workgroup_size[2] = 1;
   b.shader->info.num_ssbos = 1;
   nir_def *buffer = nir_imm_int(&b, 0);
   nir_def *offset = nir_imm_int(&b, 0);
   nir_def *input = nir_load_ssbo(&b, 1, 32, buffer, offset, .align_mul = 4);
   nir_store_ssbo(&b, nir_iadd_imm(&b, input, 1), buffer, offset, .align_mul = 4);
   const struct elk_nir_compiler_opts options = {0};
   elk_preprocess_nir(compiler, b.shader, &options);
   nir_shader_gather_info(b.shader, nir_shader_get_entrypoint(b.shader));
   struct elk_cs_prog_key key = {0};
   struct elk_cs_prog_data data = {0};
   b.shader->info.min_subgroup_size = 16;
   b.shader->info.max_subgroup_size = 16;
   elk_nir_lower_cs_intrinsics(b.shader, &device, &data);
   nir_validate_shader(b.shader, "Stela ELK codegen probe");
   struct elk_compile_cs_params parameters = {
      .base = {.mem_ctx = context, .nir = b.shader},
      .key = &key,
      .prog_data = &data,
   };
   const unsigned *code = elk_compile_cs(compiler, &parameters);
   unsigned sends = 0;
   bool valid = code && data.base.program_size && !parameters.base.error_str;
   if (valid)
      valid = validate_code(&compiler->isa, code, data.base.program_size, &sends);
   if (valid) {
      probe_compiled("elk", platform, data.base.program_size);
      printf("%s, PCI %04x: %u bytes, %u sends, validated\n", platform,
             pci_id, data.base.program_size, sends);
   } else {
      fprintf(stderr, "%s ELK codegen failed: %s\n", platform,
              parameters.base.error_str ? parameters.base.error_str : "invalid code");
   }
   ralloc_free(b.shader);
   ralloc_free(context);
   return !valid;
}

int
main(void)
{
   const char *platforms[] = {"ivb", "byt", "hsw", "bdw", "chv"};
   process_intel_debug_variable();
   glsl_type_singleton_init_or_ref();
   int failed = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(platforms); i++)
      failed |= compile_store(platforms[i]);
   glsl_type_singleton_decref();
   return failed;
}
