/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "compiler/tests/targets/intel.h"
#include "air_probe_input.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/compiler/elk/elk_eu.h"
#include "intel/dev/intel_device_info.h"
#include "intel/dev/intel_debug.h"
#include "util/ralloc.h"
#include <stdarg.h>

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static void
compiler_log(void *data, unsigned *id, const char *format, ...)
{
   (void)data; (void)id;
   va_list arguments;
   va_start(arguments, format);
   vfprintf(stderr, format, arguments);
   va_end(arguments);
}

static bool
bind_ssbo(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
   unsigned *bindings = data;
   if (buffer->index != 7 || buffer->address_space != 1 ||
       buffer->access != STELA_AIR_READ_WRITE || buffer->type_size != 4 ||
       buffer->type_alignment != 4 || bindings[0])
      return false;
   bindings[1] = buffer->argument;
   /* Fixture binding table maps Metal index 7 to explicit slot 0. No physical
    * VA or runtime resource is constructed. Runtime surfaces must describe the
    * exact validated Metal view, not an inferred address or rounded byte size.
    */
   *slot = 0;
   (*bindings)++;
   return true;
}

/* Same compact/uncompact traversal as compiler/tests/elk.c. Instruction
 * legality is checked by the original complete ELK validator first. */
static unsigned
count_sends(const struct elk_isa_info *isa, const void *code, unsigned bytes)
{
   unsigned sends = 0;
   for (unsigned offset = 0; offset < bytes;) {
      elk_inst instruction = {0};
      CHECK(bytes - offset >= sizeof(elk_compact_inst));
      memcpy(&instruction, (const char *)code + offset, sizeof(elk_compact_inst));
      bool compact = elk_inst_cmpt_control(isa->devinfo, &instruction);
      unsigned size = compact ? sizeof(elk_compact_inst) : sizeof(elk_inst);
      CHECK(bytes - offset >= size);
      if (compact) {
         elk_compact_inst encoded;
         memcpy(&encoded, (const char *)code + offset, sizeof(encoded));
         elk_uncompact_instruction(isa, &instruction, &encoded);
      } else {
         memcpy(&instruction, (const char *)code + offset, sizeof(instruction));
      }
      enum elk_opcode opcode = elk_inst_opcode(isa, &instruction);
      sends += opcode == ELK_OPCODE_SEND || opcode == ELK_OPCODE_SENDC;
      offset += size;
   }
   return sends;
}

static int
compile_air(const char *platform, const struct intel_device_info *device,
            LLVMMemoryBufferRef input, const char *entry, bool fixture,
            enum stela_air_fp_profile fp_profile)
{
   void *context = ralloc_context(NULL);
   struct elk_compiler *compiler = elk_compiler_create(context, device);
   CHECK(compiler);
   compiler->shader_debug_log = compiler_log;
   compiler->shader_perf_log = compiler_log;
   unsigned bindings[2] = {0};
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100,
      .bind_ssbo = bind_ssbo, .ssbo_count = 1, .binding_data = bindings,
      .fp_profile = fp_profile,
   };
   struct stela_air_error error;
   nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                     entry, compiler->nir_options[MESA_SHADER_COMPUTE],
                                     &options, &error);
   if (!nir)
      fprintf(stderr, "%s AIR lowering failed: %s\n", platform, error.detail);
   if (!nir || bindings[0] != 1 || error.kind != STELA_AIR_OK || nir->info.num_ssbos != 1) {
      ralloc_free(nir);
      ralloc_free(context);
      return 1;
   }
   stela_air_probe_environment_record(platform, fp_profile,
                                      nir->info.float_controls_execution_mode);
   const struct elk_nir_compiler_opts compiler_options = {0};
   elk_preprocess_nir(compiler, nir, &compiler_options);
   nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
   struct elk_cs_prog_key key = {0};
   struct elk_cs_prog_data data = {0};
   nir->info.min_subgroup_size = 16;
   nir->info.max_subgroup_size = 16;
   elk_nir_lower_cs_intrinsics(nir, device, &data);
   nir_validate_shader(nir, "Stela AIR indexed SSBO to ELK offline fixture");
   struct elk_compile_cs_params parameters = {
      .base = {.mem_ctx = context, .nir = nir}, .key = &key, .prog_data = &data,
   };
   const unsigned *code = elk_compile_cs(compiler, &parameters);
   bool valid = code && data.base.program_size && !parameters.base.error_str;
   if (valid)
      valid = elk_validate_instructions(&compiler->isa, code, 0, data.base.program_size, NULL);
   unsigned sends = valid ? count_sends(&compiler->isa, code, data.base.program_size) : 0;
   /* Dynamic view-size query, load, store, and EOT must survive compilation. */
   valid = valid && sends >= 4;
   if (valid) {
      CHECK(data.base.nr_params &&
            data.base.param[data.base.nr_params - 1] == ELK_PARAM_BUILTIN_SUBGROUP_ID);
      const uint32_t workgroup[] = {32, 1, 1};
      record_compiled(platform, data.base.program_size);
      record_object("facts");
      record_uint("pci_id", device->pci_device_id);
      record_str("entry", entry);
      record_blake3("input_blake3", LLVMGetBufferStart(input), LLVMGetBufferSize(input));
      record_blake3("code_blake3", code, data.base.program_size);
      record_str("input_kind", fixture ? "source_fixture" : "raw_input");
      record_uint("input_bytes", LLVMGetBufferSize(input));
      record_uint("buffer_argument", bindings[1]);
      record_str("buffer_access", "read_write");
      record_uint("buffer_type_bytes", 4);
      record_uint("buffer_alignment", 4);
      record_uint("max_instructions", 100);
      record_uints("workgroup", workgroup, ARRAY_SIZE(workgroup));
      record_uint("buffer_index", 7);
      record_uint("ssbo_slot", 0);
      record_uint("ssbo_count", 1);
      record_uint("subgroup", 16);
      record_uint("per_thread_push_bytes", data.push.per_thread.size);
      record_uint("cross_thread_push_bytes", data.push.cross_thread.size);
      record_end();
      printf("AIR indexed SSBO->ELK %s PCI %04x: %u bytes, %u sends, validated\n",
             platform, device->pci_device_id, data.base.program_size, sends);
   } else {
      fprintf(stderr, "%s AIR ELK failed: %s, sends=%u\n", platform,
              parameters.base.error_str ? parameters.base.error_str : "no valid code", sends);
   }
   ralloc_free(nir);
   ralloc_free(context);
   return !valid;
}

int main(int argc, char **argv)
{
   const char *entry = "kernel";
   enum stela_air_fp_profile fp_profile;
   if (!stela_air_probe_profile(&argc, argv, &fp_profile))
      return 2;
   stela_air_probe_profile_record(fp_profile);
   LLVMMemoryBufferRef input = stela_intel_air_probe_input(argc, argv, &entry);
   if (!input) {
      fprintf(stderr,
              "usage: %s [--input RAW_AIR_BITCODE --entry IDENTIFIER [--fp-profile NAME]] (4 "
              "bytes..16 MiB)\n",
              argv[0]);
      return 2;
   }
   struct intel_device_info device;
   const char *platform;
   STELA_INTEL_FOREACH_TARGET(platform, device) {
      if (stela_intel_elk(&device))
         record_expect(platform, NULL);
   }
   process_intel_debug_variable();
   glsl_type_singleton_init_or_ref();
   int result = 0;
   STELA_INTEL_FOREACH_TARGET(platform, device) {
      if (stela_intel_elk(&device))
         result |= compile_air(platform, &device, input, entry, argc == 1, fp_profile);
   }
   LLVMDisposeMemoryBuffer(input);
   glsl_type_singleton_decref();
   return result;
}
