/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_AIR_PROBE_INPUT_H
#define STELA_AMD_AIR_PROBE_INPUT_H

/* Shared hosted AMD compiler-test input handling. Not a production loader or
 * hostile-input sandbox; the production AIR reader owns wrapper/archive choice.
 */
#include "stela/tests/air_probe.h"
#include "util/macros.h"
#include <llvm-c/BitReader.h>
#include <llvm-c/Core.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static LLVMMemoryBufferRef
read_raw_input(const char *path)
{
   FILE *file = fopen(path, "rb");
   if (!file) {
      fprintf(stderr, "cannot open AIR input\n");
      return NULL;
   }
   long size = -1;
   if (!fseek(file, 0, SEEK_END))
      size = ftell(file);
   if (size < 4 || size > 64 * 1024 * 1024 || fseek(file, 0, SEEK_SET)) {
      fprintf(stderr, "AIR input must contain 4..64MiB of raw bitcode\n");
      fclose(file);
      return NULL;
   }
   char *bytes = malloc(size);
   if (!bytes) {
      fclose(file);
      return NULL;
   }
   const bool read = fread(bytes, 1, size, file) == (size_t)size &&
                     fgetc(file) == EOF && !ferror(file);
   const bool closed = fclose(file) == 0;
   LLVMMemoryBufferRef result = NULL;
   if (read && closed && !memcmp(bytes, "BC\xc0\xde", 4))
      result = LLVMCreateMemoryBufferWithMemoryRangeCopy(bytes, size, "raw-air-input");
   else
      fprintf(stderr, "AIR input changed, could not be read, or is not raw bitcode\n");
   free(bytes);
   return result;
}

static bool
input_receipt_options(LLVMMemoryBufferRef input, const char *entry, bool file,
                      char input_hash[BLAKE3_HEX_LEN], const unsigned workgroup[3],
                      unsigned instruction_budget)
{
   stela_digest(LLVMGetBufferStart(input), LLVMGetBufferSize(input), input_hash);
   LLVMContextRef context = LLVMContextCreate();
   LLVMModuleRef module = NULL;
   if (LLVMParseBitcodeInContext2(context, input, &module)) {
      fprintf(stderr, "LLVM refused AIR input while reading provenance\n");
      if (module)
         LLVMDisposeModule(module);
      LLVMContextDispose(context);
      return false;
   }
   const char *metadata[] = {"air.version", "air.language_version", "air.compile_options",
                             "llvm.ident", "llvm.module.flags"};
   for (unsigned i = 0; i < ARRAY_SIZE(metadata); i++) {
      if (LLVMGetNamedMetadataNumOperands(module, metadata[i]) > 256) {
         fprintf(stderr, "AIR input metadata receipt budget exceeded\n");
         LLVMDisposeModule(module);
         LLVMContextDispose(context);
         return false;
      }
   }
   unsigned major, minor, patch;
   LLVMGetVersion(&major, &minor, &patch);
   const uint32_t llvm_version[] = {major, minor, patch};
   /* Names and metadata are verified-but-untrusted bytes; records escape them. */
   stela_air_probe_input_record(file, LLVMGetBufferSize(input), input_hash, entry);
   record_object("facts");
   record_uints("workgroup_size", workgroup, 3);
   record_uint("instruction_budget", instruction_budget);
   record_uints("llvm_version", llvm_version, ARRAY_SIZE(llvm_version));
   record_str("target", LLVMGetTarget(module));
   record_str("mesa_version", PACKAGE_VERSION);
   record_object("metadata");
   for (unsigned i = 0; i < ARRAY_SIZE(metadata); i++) {
      record_array(metadata[i]);
      LLVMValueRef nodes[256];
      unsigned count = LLVMGetNamedMetadataNumOperands(module, metadata[i]);
      LLVMGetNamedMetadataOperands(module, metadata[i], nodes);
      for (unsigned n = 0; n < count; n++) {
         char *text = LLVMPrintValueToString(nodes[n]);
         /* LLVM's standalone metadata printer prefixes its process-local
          * object address. Keep the complete metadata expression, excluding
          * that diagnostic decoration so receipts reproduce across runs. */
         const char *expression = text;
         if (!strncmp(text, "<0x", 3)) {
            const char *end = strchr(text, '>');
            if (end && !strncmp(end, "> = ", 4))
               expression = end + 4;
         }
         record_item(expression);
         LLVMDisposeMessage(text);
      }
      record_close();
   }
   record_end();
   LLVMDisposeModule(module);
   LLVMContextDispose(context);
   return true;
}

static bool
input_receipt(LLVMMemoryBufferRef input, const char *entry, bool file,
              char input_hash[BLAKE3_HEX_LEN])
{
   const unsigned workgroup[3] = {32, 1, 1};
   return input_receipt_options(input, entry, file, input_hash, workgroup, 100);
}

#endif
