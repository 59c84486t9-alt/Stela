/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "air_probe_profile.h"
#include "air_probe_input.h"
#include "stela/probe_report.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/compiler/elk/elk_eu.h"
#include "intel/dev/intel_device_info.h"
#include "intel/dev/intel_debug.h"
#include "util/ralloc.h"
#include "util/blake3/blake3.h"
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

static void
digest(const void *bytes, size_t size, char out[2 * BLAKE3_OUT_LEN + 1])
{
   blake3_hasher hasher;
   uint8_t hash[BLAKE3_OUT_LEN];
   blake3_hasher_init(&hasher);
   blake3_hasher_update(&hasher, bytes, size);
   blake3_hasher_finalize(&hasher, hash, sizeof(hash));
   static const char hex[] = "0123456789abcdef";
   for (unsigned i = 0; i < sizeof(hash); ++i) {
      out[2 * i] = hex[hash[i] >> 4]; out[2 * i + 1] = hex[hash[i] & 15];
   }
   out[2 * BLAKE3_OUT_LEN] = 0;
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

/* Same compact/uncompact traversal as the retained elk_probe.c. Instruction
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
compile_air(const char *platform, LLVMMemoryBufferRef input, const char *entry, bool fixture,
            enum stela_air_fp_profile fp_profile)
{
   struct intel_device_info device;
   int pci_id = intel_device_name_to_pci_device_id(platform);
   CHECK(pci_id >= 0 && intel_get_device_info_for_build(pci_id, &device));
   CHECK(device.kmd_type == INTEL_KMD_TYPE_INVALID);
   void *context = ralloc_context(NULL);
   struct elk_compiler *compiler = elk_compiler_create(context, &device);
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
   printf("STELA_AIR_ENVIRONMENT {\"backend\":\"air-elk\",\"target\":\"%s\",\"fp_profile\":%u,\"nir_float_controls\":%u}\n",
          platform, (unsigned)fp_profile, nir->info.float_controls_execution_mode);
   const struct elk_nir_compiler_opts compiler_options = {0};
   elk_preprocess_nir(compiler, nir, &compiler_options);
   nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
   struct elk_cs_prog_key key = {0};
   struct elk_cs_prog_data data = {0};
   nir->info.min_subgroup_size = 16;
   nir->info.max_subgroup_size = 16;
   elk_nir_lower_cs_intrinsics(nir, &device, &data);
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
      CHECK(data.base.nr_params && data.base.param[data.base.nr_params - 1] == ELK_PARAM_BUILTIN_SUBGROUP_ID);
      char input_hash[2 * BLAKE3_OUT_LEN + 1], code_hash[2 * BLAKE3_OUT_LEN + 1];
      digest(LLVMGetBufferStart(input), LLVMGetBufferSize(input), input_hash);
      digest(code, data.base.program_size, code_hash);
      probe_compiled("air-elk", platform, data.base.program_size);
      printf("STELA_AIR_INTEL_OUTPUT {\"target\":\"%s\",\"pci_id\":%u,\"entry\":\"%s\","
             "\"input_blake3\":\"%s\",\"code_blake3\":\"%s\","
             "\"input_kind\":\"%s\",\"input_bytes\":%zu,\"buffer_argument\":%u,\"buffer_access\":\"read_write\","
             "\"buffer_type_bytes\":4,\"buffer_alignment\":4,\"max_instructions\":100,"
             "\"workgroup\":[32,1,1],\"buffer_index\":7,\"ssbo_slot\":0,"
             "\"ssbo_count\":1,\"subgroup\":16,\"per_thread_push_bytes\":%u,"
             "\"cross_thread_push_bytes\":%u}\n",
             platform, pci_id, entry, input_hash, code_hash,
             fixture ? "source_fixture" : "raw_input", LLVMGetBufferSize(input),
             bindings[1], data.push.per_thread.size,
             data.push.cross_thread.size);
      printf("AIR indexed SSBO->ELK %s PCI %04x: %u bytes, %u sends, validated\n",
             platform, pci_id, data.base.program_size, sends);
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
   const char *platforms[] = {"ivb", "byt", "hsw", "bdw", "chv"};
   const char *entry = "kernel";
   enum stela_air_fp_profile fp_profile;
   if (!stela_air_probe_profile(&argc, argv, &fp_profile))
      return 2;
   stela_air_probe_profile_receipt(fp_profile);
   LLVMMemoryBufferRef input = stela_intel_air_probe_input(argc, argv, &entry);
   if (!input) {
      fprintf(stderr, "usage: %s [--input RAW_AIR_BITCODE --entry IDENTIFIER [--fp-profile NAME]] (4 bytes..16 MiB)\n", argv[0]);
      return 2;
   }
   process_intel_debug_variable();
   glsl_type_singleton_init_or_ref();
   int result = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(platforms); ++i)
      result |= compile_air(platforms[i], input, entry, argc == 1, fp_profile);
   LLVMDisposeMemoryBuffer(input);
   glsl_type_singleton_decref();
   return result;
}
