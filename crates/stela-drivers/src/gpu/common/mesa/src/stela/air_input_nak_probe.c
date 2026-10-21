/* SPDX-License-Identifier: MIT */
/* Offline, original-input compiler qualification. No device is opened. */
#include "air_to_nir.h"
#include "air_probe_profile.h"
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#include "util/mesa-blake3.h"
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
print_digest(const void *data, size_t size)
{
   blake3_hash digest;
   _mesa_blake3_compute(data, size, digest);
   for (unsigned i = 0; i < sizeof(digest); i++)
      printf("%02x", digest[i]);
}

static void
compile_input(const void *input, size_t size, const char *entry, unsigned sm,
              enum stela_air_fp_profile fp_profile)
{
   const struct nv_device_info device = {.sm = sm, .max_warps_per_mp = 32};
   const struct nak_constant_offset_info layout = {
      .sample_info_cb = 0, .sample_locations_offset = 0,
      .sample_masks_offset = 256, .printf_cb = 0, .printf_buffer_offset = 512,
   };
   struct nak_compiler *compiler = nak_compiler_create(&device, &layout, &layout);
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
   printf("STELA_AIR_ENVIRONMENT {\"backend\":\"air-nak\",\"target\":\"sm%u\",\"fp_profile\":%u,\"nir_float_controls\":%u}\n",
          sm, (unsigned)fp_profile, nir->info.float_controls_execution_mode);
   nir_validate_shader(nir, "original AIR input");
   nak_preprocess_nir(nir, compiler);
   /* nak_compile_shader runs the retained postprocessing itself. */
   struct nak_shader_bin *bin = nak_compile_shader(nir, true, compiler, 0, NULL, false);
   CHECK(bin && bin->code && bin->code_size && bin->info.num_instrs > 2 &&
         bin->info.sm == sm && bin->info.stage == MESA_SHADER_COMPUTE);
   printf("STELA_GPU_TARGET {\"backend\":\"air-nak\",\"target\":\"sm%u\","
          "\"state\":\"compiled\",\"input_kind\":\"raw_input\",\"entry\":\"%s\","
          "\"workgroup\":[32,1,1],\"buffer_index\":7,\"max_instructions\":256,"
          "\"binding\":\"fixture-global64\",\"fixture_va\":1048576,"
          "\"bytes\":%u,\"instructions\":%u,\"input_bytes\":%zu,\"input_blake3\":\"",
          sm, entry, bin->code_size, bin->info.num_instrs, size);
   print_digest(input, size);
   printf("\",\"code_blake3\":\"");
   print_digest(bin->code, bin->code_size);
   puts("\"}");
   nak_shader_bin_destroy(bin);
   ralloc_free(nir);
   nak_compiler_destroy(compiler);
}

int
main(int argc, char **argv)
{
   const char *entry = NULL, *files[32];
   unsigned file_count = 0;
   enum stela_air_fp_profile fp_profile;
   if (!stela_air_probe_profile(&argc, argv, &fp_profile))
      goto usage;
   for (int i = 1; i < argc; i++) {
      if (!strcmp(argv[i], "--entry") && !entry && i + 1 < argc)
         entry = argv[++i];
      else if (!strcmp(argv[i], "--input") && file_count < ARRAY_SIZE(files) && i + 1 < argc)
         files[file_count++] = argv[++i];
      else
         goto usage;
   }
   if (!entry || !*entry || strlen(entry) > 255 || !file_count)
      goto usage;
   /* Keep the receipt's identifier unambiguous without introducing a separate
    * escaping format. This offline fixture CLI accepts ordinary LLVM names. */
   for (const char *c = entry; *c; c++) {
      if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
            (*c >= '0' && *c <= '9') || *c == '_' || *c == '.' || *c == '$'))
         goto usage;
   }
   stela_air_probe_profile_receipt(fp_profile);
   glsl_type_singleton_init_or_ref();
   for (unsigned file = 0; file < file_count; file++) {
      /* Bound before allocation, and retain the exact bytes without reassembly,
       * metadata edits or optimization through a different LLVM module. */
      FILE *stream = fopen(files[file], "rb");
      CHECK(stream && !fseek(stream, 0, SEEK_END));
      long length = ftell(stream);
      CHECK(length > 0 && length <= 64 * 1024 * 1024 && !fseek(stream, 0, SEEK_SET));
      void *bytes = malloc(length);
      CHECK(bytes && fread(bytes, 1, length, stream) == (size_t)length);
      CHECK(fgetc(stream) == EOF && !ferror(stream));
      CHECK(!fclose(stream));
      printf("STELA_AIR_INPUT {\"origin\":\"raw_input_file\",\"bytes\":%ld,"
             "\"entry\":\"%s\",\"blake3\":\"", length, entry);
      print_digest(bytes, length);
      puts("\"}");
      const unsigned targets[] = {75, 80, 86, 87, 89, 90, 100, 104, 120};
      for (unsigned i = 0; i < ARRAY_SIZE(targets); i++)
         compile_input(bytes, length, entry, targets[i], fp_profile);
      free(bytes);
   }
   glsl_type_singleton_decref();
   return 0;
usage:
      fprintf(stderr, "usage: %s --entry NAME --input raw-original.bc [--input ... up to 32 files] [--fp-profile NAME]\n", argv[0]);
      return 2;
}
