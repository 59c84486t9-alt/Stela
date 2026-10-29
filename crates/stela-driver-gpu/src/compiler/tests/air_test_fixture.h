/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_TEST_FIXTURE_H
#define STELA_AIR_TEST_FIXTURE_H
#include "llvm-c/BitWriter.h"
#include "llvm-c/Core.h"
#include "llvm-c/IRReader.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STELA_AIR_FIXTURE_CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "AIR test fixture: %s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

/* Original LLVM IR fixture, not Apple shader bytes. The AIR metadata encoding
 * follows the independently observed AIR 2.8 contract. LLVM writes real bitcode;
 * tests never substitute byte framing for valid shader IR. */
static const char *stela_air_test_prefix =
   "target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
   "target triple = \"air64_v28-apple-macosx26.7.0\"\n"
   "define void @kernel(i32 %tid, ptr addrspace(1) %out) {\n";
static const char *stela_air_test_metadata =
   "}\n"
   "!air.version = !{!0}\n"
   "!air.language_version = !{!1}\n"
   "!air.kernel = !{!2}\n"
   "!air.compile_options = !{!8,!9,!10}\n"
   "!0 = !{i32 2, i32 8, i32 0}\n"
   "!1 = !{!\"Metal\", i32 4, i32 0, i32 0}\n"
   "!2 = !{ptr @kernel, !3, !4}\n"
   "!3 = !{}\n"
   "!4 = !{!5,!6}\n"
   "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"tid\"}\n"
   "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 7, i32 1, !\"air.read_write\","
           "!\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
           "!\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"output\"}\n"
   "!8 = !{!\"air.compile.denorms_disable\"}\n"
   "!9 = !{!\"air.compile.fast_math_enable\"}\n"
   "!10 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";
static const char *stela_air_test_store_body =
   "%index = zext i32 %tid to i64\n"
   "%address = getelementptr i32, ptr addrspace(1) %out, i64 %index\n"
   "%input = load i32, ptr addrspace(1) %address, align 4\n"
   "%twice = mul i32 %input, 2\n"
   "%value = add i32 %twice, 1\n"
   "store i32 %value, ptr addrspace(1) %address, align 4\n"
   "ret void\n";

static inline LLVMMemoryBufferRef
stela_air_test_custom_bitcode(const char *prefix, const char *body,
                             const char *metadata, const char *extra)
{
   size_t bytes = strlen(prefix) + strlen(body) + strlen(metadata) + strlen(extra) + 1;
   char *text = malloc(bytes);
   STELA_AIR_FIXTURE_CHECK(text);
   snprintf(text, bytes, "%s%s%s%s", prefix, body, metadata, extra);
   LLVMContextRef context = LLVMContextCreate();
   LLVMMemoryBufferRef input = LLVMCreateMemoryBufferWithMemoryRangeCopy(text, bytes - 1, "original-air-test");
   LLVMModuleRef module = NULL;
   char *message = NULL;
   bool invalid = LLVMParseIRInContext(context, input, &module, &message);
   if (invalid)
      fprintf(stderr, "%s\n", message);
   STELA_AIR_FIXTURE_CHECK(!invalid);
   LLVMDisposeMessage(message);
   LLVMMemoryBufferRef output = LLVMWriteBitcodeToMemoryBuffer(module);
   /* LLVM's writer wraps Darwin-target bitcode. The production Rust archive
    * reader removes this framing; isolate only the test writer's payload. */
   const unsigned char *encoded = (const unsigned char *)LLVMGetBufferStart(output);
   if (LLVMGetBufferSize(output) >= 20 && !memcmp(encoded, "\xde\xc0\x17\x0b", 4)) {
      uint32_t offset = 0, length = 0;
      for (unsigned i = 0; i < 4; i++) {
         offset |= (uint32_t)encoded[8 + i] << (i * 8);
         length |= (uint32_t)encoded[12 + i] << (i * 8);
      }
      STELA_AIR_FIXTURE_CHECK(offset <= LLVMGetBufferSize(output) && length <= LLVMGetBufferSize(output) - offset);
      LLVMMemoryBufferRef raw = LLVMCreateMemoryBufferWithMemoryRangeCopy((const char *)encoded + offset, length, "raw-air-test");
      LLVMDisposeMemoryBuffer(output);
      output = raw;
   }
   LLVMDisposeModule(module);
   LLVMContextDispose(context);
   free(text);
   return output;
}

static inline LLVMMemoryBufferRef
stela_air_test_bitcode(const char *body, const char *extra)
{
   return stela_air_test_custom_bitcode(stela_air_test_prefix, body,
                                       stela_air_test_metadata, extra);
}

#undef STELA_AIR_FIXTURE_CHECK
#endif
