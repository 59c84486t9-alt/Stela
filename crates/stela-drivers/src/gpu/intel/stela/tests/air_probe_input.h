/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_AIR_PROBE_INPUT_H
#define STELA_INTEL_AIR_PROBE_INPUT_H

#include "compiler/tests/air_probe.h"
#include "compiler/tests/air_test_fixture.h"

static inline void
stela_intel_air_probe_input_record(bool file, const void *bytes, size_t size, const char *entry)
{
   char hex[BLAKE3_HEX_LEN];
   stela_digest(bytes, size, hex);
   stela_air_probe_input_record(file, size, hex, entry);
   record_end();
}

/* Raw AIR is already selected by the production archive reader. Preserve the
 * original bounded bytes; never rewrite metadata or unwrap another container.
 * Bound entry names to identifiers, as the production entry lookup does. */
static inline LLVMMemoryBufferRef
stela_intel_air_probe_input(int argc, char **argv, const char **entry)
{
   if (argc == 1) {
      LLVMMemoryBufferRef fixture = stela_air_test_bitcode(stela_air_test_store_body, "");
      stela_intel_air_probe_input_record(false, LLVMGetBufferStart(fixture),
                                         LLVMGetBufferSize(fixture), *entry);
      return fixture;
   }
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
   if (input)
      stela_intel_air_probe_input_record(true, bytes, size, *entry);
   free(bytes);
   return input;
}

#endif
