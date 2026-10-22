/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "air_probe_input.h"
#include "stela/tests/intel_probe.h"
#include "stela/tests/targets/intel.h"
#include "intel/compiler/brw/brw_compiler.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/dev/intel_device_info.h"
#include "util/ralloc.h"
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
compile_air(const char *platform, const struct intel_device_info *device,
            LLVMMemoryBufferRef input, const char *entry, bool fixture,
            enum stela_air_fp_profile fp_profile)
{
   const char *hold = stela_intel_hold(device);
   if (hold) {
      record_held(platform, hold);
      return 0;
   }
   void *context = ralloc_context(NULL);
   struct brw_compiler *compiler = brw_compiler_create(context, device);
   CHECK(compiler);
   compiler->shader_debug_log = compiler_log;
   compiler->shader_perf_log = compiler_log;
   unsigned bindings[2] = {0};
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100,
      .bind_buffer = bind_buffer, .binding_data = bindings, .fp_profile = fp_profile,
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
   stela_air_probe_environment_record(platform, fp_profile,
                                      nir->info.float_controls_execution_mode);
   const struct brw_nir_compiler_opts compiler_options = {0};
   brw_preprocess_nir(compiler, nir, &compiler_options);
   nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
   struct brw_cs_prog_key key = {0};
   struct brw_cs_prog_data data = {0};
   nir->info.min_subgroup_size = 16;
   nir->info.max_subgroup_size = 16;
   brw_nir_lower_cs_intrinsics(nir, device, &data);
   /* Follow Iris's existing pre-12.5 subgroup payload contract rather than
    * inventing a thread-ID substitute. Runtime dispatch must supply this
    * per-thread push value; offline compilation does not provide it. */
   if (brw_nir_lower_cs_subgroup_id(nir, device, 0)) {
      data.base.push_sizes[0] = 4;
      brw_cs_fill_push_const_info(device, &data, 0);
      data.base.push_sizes[0] = REG_SIZE;
   } else {
      brw_cs_fill_push_const_info(device, &data, -1);
   }
   nir_validate_shader(nir, "Stela AIR to BRW offline compile fixture");
   struct brw_compile_cs_params parameters = {
      .base = {.mem_ctx = context, .nir = nir, .key = &key.base, .prog_data = &data.base},
   };
   const unsigned *code = brw_compile(compiler, &parameters.base);
   int failed = !code || !data.base.program_size || parameters.base.error_str;
   unsigned sends = 0;
   if (!failed)
      failed = !validate_intel_code(device, context, code, data.base.program_size, platform, &sends);
   if (failed)
      fprintf(stderr, "%s AIR codegen failed: %s\n", platform,
              parameters.base.error_str ? parameters.base.error_str : "no valid code");
   else {
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
      record_uint("fixture_va", 0x100000);
      record_uint("ssbo_count", 0);
      record_uint("subgroup", 16);
      record_uint("per_thread_push_bytes", data.push.per_thread.size);
      record_uint("cross_thread_push_bytes", data.push.cross_thread.size);
      record_end();
      printf("AIR bitcode->NIR->BRW %s PCI %04x: %u bytes, %u sends, validated\n",
             platform, device->pci_device_id, data.base.program_size, sends);
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
   const char *entry = "kernel";
   enum stela_air_fp_profile fp_profile;
   if (!stela_air_probe_profile(&argc, argv, &fp_profile))
      return 2;
   stela_air_probe_profile_record(fp_profile);
   LLVMMemoryBufferRef input = stela_intel_air_probe_input(argc, argv, &entry);
   if (!input) {
      fprintf(stderr, "usage: %s [--input RAW_AIR_BITCODE --entry IDENTIFIER [--fp-profile NAME]] (4 bytes..16 MiB)\n", argv[0]);
      return 2;
   }
   struct intel_device_info device;
   const char *platform;
   STELA_INTEL_FOREACH_TARGET(platform, device) {
      if (!stela_intel_elk(&device))
         record_expect(platform, stela_intel_hold(&device));
   }
   glsl_type_singleton_init_or_ref();
   int result = 0;
   STELA_INTEL_FOREACH_TARGET(platform, device) {
      if (!stela_intel_elk(&device))
         result |= compile_air(platform, &device, input, entry, argc == 1, fp_profile);
   }
   LLVMDisposeMemoryBuffer(input);
   glsl_type_singleton_decref();
   return result;
}
