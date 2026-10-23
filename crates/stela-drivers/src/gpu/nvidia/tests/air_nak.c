/* SPDX-License-Identifier: MIT */
/* Offline, original-input compiler qualification. No device is opened. */
#include "air_to_nir.h"
#include "../../compiler/tests/air_probe.h"
#include "../../compiler/tests/air_test_fixture.h"
#include "../../compiler/tests/targets/nvidia.h"
#include "nouveau/compiler/nak.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   unsigned *bindings = data;
   /* LLVM argument order is intentionally not part of this mapping. */
   CHECK(buffer->index == 7 && buffer->address_space == 1 &&
         buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 &&
         buffer->type_alignment == 4);
   (*bindings)++;
   return nir_imm_int64(b, 0x100000); /* Fixture VA, not a production binding. */
}

static void
compile_input(const void *input, size_t size, const char *entry, const char *input_hash,
              unsigned sm, enum stela_air_fp_profile fp_profile)
{
   char target[16];
   stela_nv_target_name(target, sm);
   const struct nv_device_info device = {.sm = sm, .max_warps_per_mp = 32};
   struct nak_compiler *compiler = nak_compiler_create(&device);
   CHECK(compiler);
   unsigned bindings = 0;
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 256,
      .bind_buffer = bind_buffer, .binding_data = &bindings, .fp_profile = fp_profile,
   };
   struct stela_air_error error;
   nir_shader *nir = stela_air_to_nir(input, size, entry,
      nak_nir_options(compiler), &options, &error);
   if (!nir)
      fprintf(stderr, "AIR input refused (%u): %s\n", error.kind, error.detail);
   CHECK(nir && bindings == 1);
   stela_air_probe_environment_record(target, fp_profile, nir->info.float_controls_execution_mode);
   nir_validate_shader(nir, "original AIR input");
   nak_preprocess_nir(nir, compiler);
   /* nak_compile_shader runs the retained postprocessing itself. */
   struct nak_shader_bin *bin = nak_compile_shader(nir, true, compiler, 0, NULL, false);
   CHECK(bin && bin->code && bin->code_size && bin->info.num_instrs > 2 &&
         bin->info.sm == sm && bin->info.stage == MESA_SHADER_COMPUTE);
   char code_hash[BLAKE3_HEX_LEN];
   stela_digest(bin->code, bin->code_size, code_hash);
   const uint32_t workgroup[] = {32, 1, 1};
   record_compiled(target, bin->code_size);
   record_object("facts");
   record_str("entry", entry);
   record_uints("workgroup", workgroup, ARRAY_SIZE(workgroup));
   record_uint("buffer_index", 7);
   record_uint("max_instructions", 256);
   record_str("binding", "fixture-global64");
   record_uint("fixture_va", 0x100000);
   record_uint("instructions", bin->info.num_instrs);
   record_str("input_blake3", input_hash);
   record_str("code_blake3", code_hash);
   record_end();
   nak_shader_bin_destroy(bin);
   ralloc_free(nir);
   nak_compiler_destroy(compiler);
}

/* Bound before allocation, and retain the exact bytes without reassembly,
 * metadata edits or optimization through a different LLVM module. */
static void *
read_input(const char *path, size_t *size)
{
   FILE *stream = fopen(path, "rb");
   CHECK(stream && !fseek(stream, 0, SEEK_END));
   long length = ftell(stream);
   CHECK(length > 0 && length <= 64 * 1024 * 1024 && !fseek(stream, 0, SEEK_SET));
   void *bytes = malloc(length);
   CHECK(bytes && fread(bytes, 1, length, stream) == (size_t)length);
   CHECK(fgetc(stream) == EOF && !ferror(stream));
   CHECK(!fclose(stream));
   *size = (size_t)length;
   return bytes;
}

int
main(int argc, char **argv)
{
   enum stela_air_fp_profile fp_profile;
   if (!stela_air_probe_profile(&argc, argv, &fp_profile))
      goto usage;
   const bool file = argc > 1;
   const char *entry = "kernel";
   if (file) {
      if (argc != 5 || strcmp(argv[1], "--input") || strcmp(argv[3], "--entry"))
         goto usage;
      entry = argv[4];
      if (!*entry || strlen(entry) > 255)
         goto usage;
   }
   stela_air_probe_profile_record(fp_profile);
   size_t size;
   void *bytes;
   LLVMMemoryBufferRef fixture = NULL;
   if (file) {
      bytes = read_input(argv[2], &size);
   } else {
      fixture = stela_air_test_bitcode(stela_air_test_store_body, "");
      bytes = (void *)LLVMGetBufferStart(fixture);
      size = LLVMGetBufferSize(fixture);
   }
   char input_hash[BLAKE3_HEX_LEN];
   stela_digest(bytes, size, input_hash);
   stela_air_probe_input_record(file, size, input_hash, entry);
   record_end();
   char target[16];
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nv_sms); i++) {
      stela_nv_target_name(target, stela_nv_sms[i]);
      record_expect(target, NULL);
   }
   glsl_type_singleton_init_or_ref();
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nv_sms); i++)
      compile_input(bytes, size, entry, input_hash, stela_nv_sms[i], fp_profile);
   glsl_type_singleton_decref();
   if (fixture)
      LLVMDisposeMemoryBuffer(fixture);
   else
      free(bytes);
   return 0;
usage:
   fprintf(stderr, "usage: %s [--input raw-original.bc --entry NAME [--fp-profile NAME]]\n", argv[0]);
   return 2;
}
