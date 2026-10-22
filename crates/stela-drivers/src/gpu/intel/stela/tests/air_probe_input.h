/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_AIR_PROBE_INPUT_H
#define STELA_INTEL_AIR_PROBE_INPUT_H

#include "stela/tests/air_test_fixture.h"
#include "util/mesa-blake3.h"

/* Raw AIR is already selected by the production archive reader. Preserve the
 * original bounded bytes; never rewrite metadata or unwrap another container.
 * Bound entry names to identifiers so output records stay unambiguous JSON. */
static inline LLVMMemoryBufferRef
stela_intel_air_probe_input(int argc, char **argv, const char **entry)
{
   if (argc == 1)
      return stela_air_test_bitcode(stela_air_test_store_body, "");
   if (argc != 5 || strcmp(argv[1], "--input") || strcmp(argv[3], "--entry"))
      return NULL;
   *entry = argv[4];
   size_t length = strlen(*entry);
   if (!length || length > 127)
      return NULL;
   for (size_t i = 0; i < length; ++i) {
      char c = (*entry)[i];
      if (!(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (i && c >= '0' && c <= '9')))
         return NULL;
   }
   FILE *file = fopen(argv[2], "rb");
   if (!file)
      return NULL;
   const size_t limit = 16 * 1024 * 1024;
   char *bytes = malloc(limit + 1);
   if (!bytes) {
      fclose(file);
      return NULL;
   }
   size_t size = fread(bytes, 1, limit + 1, file);
   bool valid = size >= 4 && size <= limit && !ferror(file) &&
                !memcmp(bytes, "BC\xc0\xde", 4);
   fclose(file);
   LLVMMemoryBufferRef input = valid ?
      LLVMCreateMemoryBufferWithMemoryRangeCopy(bytes, size, "unaltered-air-input") : NULL;
   if (input) {
      blake3_hash hash;
      char hex[BLAKE3_OUT_LEN * 2 + 1];
      _mesa_blake3_compute(bytes, size, hash);
      _mesa_blake3_format(hex, hash);
      printf("STELA_AIR_INPUT {\"origin\":\"raw_input_file\",\"bytes\":%zu,"
             "\"blake3\":\"%s\",\"entry\":\"%s\"}\n", size, hex, *entry);
   }
   free(bytes);
   return input;
}

#endif
