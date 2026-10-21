/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "air_probe_input.h"
#include "stela/intel_probe.h"
#include "stela/probe_report.h"
#include "intel/compiler/intel_gfx_ver_enum.h"
#include "intel/compiler/brw/brw_compiler.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/dev/intel_device_info.h"
#include "util/ralloc.h"
#include "util/blake3/blake3.h"
#include <stdarg.h>

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static void
compiler_log(void *data, unsigned *id, const char *format, ...)
{
   (void)data;
   (void)id;
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
      out[2 * i] = hex[hash[i] >> 4];
      out[2 * i + 1] = hex[hash[i] & 15];
   }
   out[2 * BLAKE3_OUT_LEN] = 0;
}

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   unsigned *bindings = data;
   if (buffer->index != 7 || buffer->address_space != 1 ||
       buffer->access != STELA_AIR_READ_WRITE || buffer->type_size != 4 ||
       buffer->type_alignment != 4 || bindings[0])
      return NULL;
   bindings[1] = buffer->argument;
   (*bindings)++;
   /* Offline compile fixture only. No production resource ABI, runtime buffer,
    * GPU allocation or resource residency is established by this address. */
   return nir_imm_int64(b, 0x100000);
}

static int
compile_air(const char *platform, LLVMMemoryBufferRef input, const char *entry, bool fixture)
{
   struct intel_device_info device;
   int pci_id = intel_device_name_to_pci_device_id(platform);
   CHECK(pci_id >= 0 && intel_get_device_info_for_build(pci_id, &device));
   CHECK(device.kmd_type == INTEL_KMD_TYPE_INVALID);
   if (device.ver == 35) {
      CHECK(gfx_ver_from_devinfo(&device) == XE3P);
      probe_unsupported("air-brw", platform, "requires-dispatch-packing-qualification");
      return 0;
   }
   void *context = ralloc_context(NULL);
   struct brw_compiler *compiler = brw_compiler_create(context, &device);
   CHECK(compiler);
   compiler->shader_debug_log = compiler_log;
   compiler->shader_perf_log = compiler_log;
   unsigned bindings[2] = {0};
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100,
      .bind_buffer = bind_buffer, .binding_data = bindings,
   };
   struct stela_air_error error;
   nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                     entry, &compiler->nir_options[MESA_SHADER_COMPUTE],
                                     &options, &error);
   if (!nir)
      fprintf(stderr, "%s AIR lowering failed: %s\n", platform, error.detail);
   if (!nir || bindings[0] != 1 || error.kind != STELA_AIR_OK) {
      ralloc_free(nir);
      ralloc_free(context);
      return 1;
   }
   CHECK(nir->info.workgroup_size[0] == 32 && nir->info.workgroup_size[1] == 1 &&
         nir->info.workgroup_size[2] == 1);
   const struct brw_nir_compiler_opts compiler_options = {0};
   brw_preprocess_nir(compiler, nir, &compiler_options);
   nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
   struct brw_cs_prog_key key = {0};
   struct brw_cs_prog_data data = {0};
   nir->info.min_subgroup_size = 16;
   nir->info.max_subgroup_size = 16;
   brw_nir_lower_cs_intrinsics(nir, &device, &data);
   /* Follow Iris's existing pre-12.5 subgroup payload contract rather than
    * inventing a thread-ID substitute. Runtime dispatch must supply this
    * per-thread push value; offline compilation does not provide it. */
   if (brw_nir_lower_cs_subgroup_id(nir, &device, 0)) {
      data.base.push_sizes[0] = 4;
      brw_cs_fill_push_const_info(&device, &data, 0);
      data.base.push_sizes[0] = REG_SIZE;
   } else {
      brw_cs_fill_push_const_info(&device, &data, -1);
   }
   nir_validate_shader(nir, "Stela AIR to BRW offline compile fixture");
   struct brw_compile_cs_params parameters = {
      .base = {.mem_ctx = context, .nir = nir, .key = &key.base, .prog_data = &data.base},
   };
   const unsigned *code = brw_compile(compiler, &parameters.base);
   int failed = !code || !data.base.program_size || parameters.base.error_str;
   unsigned sends = 0;
   if (!failed)
      failed = !validate_intel_code(&device, context, code, data.base.program_size, platform, &sends);
   if (failed)
      fprintf(stderr, "%s AIR codegen failed: %s\n", platform,
              parameters.base.error_str ? parameters.base.error_str : "no valid code");
   else {
      char input_hash[2 * BLAKE3_OUT_LEN + 1], code_hash[2 * BLAKE3_OUT_LEN + 1];
      digest(LLVMGetBufferStart(input), LLVMGetBufferSize(input), input_hash);
      digest(code, data.base.program_size, code_hash);
      probe_compiled("air-brw", platform, data.base.program_size);
      printf("STELA_AIR_INTEL_OUTPUT {\"target\":\"%s\",\"pci_id\":%u,\"entry\":\"%s\","
             "\"input_blake3\":\"%s\",\"code_blake3\":\"%s\","
             "\"input_kind\":\"%s\",\"input_bytes\":%zu,\"buffer_argument\":%u,\"buffer_access\":\"read_write\","
             "\"buffer_type_bytes\":4,\"buffer_alignment\":4,\"max_instructions\":100,"
             "\"workgroup\":[32,1,1],\"buffer_index\":7,\"fixture_va\":1048576,"
             "\"ssbo_count\":0,\"subgroup\":16,\"per_thread_push_bytes\":%u,"
             "\"cross_thread_push_bytes\":%u}\n",
             platform, pci_id, entry, input_hash, code_hash,
             fixture ? "source_fixture" : "raw_input", LLVMGetBufferSize(input),
             bindings[1], data.push.per_thread.size,
             data.push.cross_thread.size);
      printf("AIR bitcode->NIR->BRW %s PCI %04x: %u bytes, %u sends, validated\n",
             platform, pci_id, data.base.program_size, sends);
   }
   ralloc_free(nir);
   ralloc_free(context);
   return failed;
}

int
main(int argc, char **argv)
{
   /* This fixture tests the retained BRW global-address path. Older ELK's
    * SSBO resource model needs a deliberate binding/lowering contract first.
    */
   const char *platforms[] = {
      "skl", "bxt", "kbl", "glk", "icl", "ehl", "tgl", "rkl", "dg1",
      "adl", "dg2", "mtl", "arl", "lnl", "bmg", "ptl", "nvl-u", "nvl",
   };
   const char *entry = "kernel";
   LLVMMemoryBufferRef input = stela_intel_air_probe_input(argc, argv, &entry);
   if (!input) {
      fprintf(stderr, "usage: %s [--input RAW_AIR_BITCODE --entry IDENTIFIER] (4 bytes..16 MiB)\n", argv[0]);
      return 2;
   }
   glsl_type_singleton_init_or_ref();
   int result = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(platforms); ++i)
      result |= compile_air(platforms[i], input, entry, argc == 1);
   LLVMDisposeMemoryBuffer(input);
   glsl_type_singleton_decref();
   return result;
}
