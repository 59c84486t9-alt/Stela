/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_PERMUTATION_TESTS_H
#define STELA_AIR_PERMUTATION_TESTS_H

#include <inttypes.h>
#include <stdarg.h>

/* Independent bit-linear and byte-linear numeric oracles; no host endian
 * loads, compiler builtin or reuse of the production halfword recipe. */
static uint64_t
permutation_reference(unsigned operation, unsigned bits, uint64_t value)
{
   uint64_t result = 0;
   if (operation == 0) {
      for (unsigned bit = 0; bit < bits; bit++)
         result |= ((value >> bit) & 1) << (bits - bit - 1);
   } else {
      unsigned bytes = bits / 8;
      for (unsigned byte = 0; byte < bytes; byte++)
         result |= ((value >> (byte * 8)) & UINT64_C(0xff)) << ((bytes - byte - 1) * 8);
   }
   return result;
}

static void
permutation_text(char *text, size_t capacity, size_t *length, const char *format, ...)
{
   va_list args;
   va_start(args, format);
   int written = vsnprintf(text + *length, capacity - *length, format, args);
   va_end(args);
   CHECK(written >= 0 && (size_t)written < capacity - *length);
   *length += (size_t)written;
}

static nir_shader *
permutation_translate(const char *body, const char *declarations)
{
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, declarations);
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, 1000, &error);
   if (!nir)
      fprintf(stderr, "integer permutation fixture: %s\n%s\n", error.detail, body);
   CHECK(nir && error.kind == STELA_AIR_OK);
   LLVMDisposeMemoryBuffer(input);
   return nir;
}

static void
permutation_values(unsigned bits, unsigned lanes, const uint64_t values[4])
{
   static const char *const operations[] = {"bitreverse", "bswap"};
   unsigned count = bits == 8 ? 1 : 2;
   char body[4096], declarations[512], type[32], suffix[32];
   size_t length = 0, decl_length = 0;
   if (lanes == 1) {
      snprintf(type, sizeof(type), "i%u", bits);
      snprintf(suffix, sizeof(suffix), "i%u", bits);
   } else {
      snprintf(type, sizeof(type), "<%u x i%u>", lanes, bits);
      snprintf(suffix, sizeof(suffix), "v%ui%u", lanes, bits);
   }
   for (unsigned operation = 0; operation < count; operation++) {
      permutation_text(declarations, sizeof(declarations), &decl_length,
         "declare %s @llvm.%s.%s(%s)\n", type, operations[operation], suffix, type);
      permutation_text(body, sizeof(body), &length, "%%v%u = call %s @llvm.%s.%s(%s ",
         operation, type, operations[operation], suffix, type);
      if (lanes > 1)
         permutation_text(body, sizeof(body), &length, "<");
      for (unsigned lane = 0; lane < lanes; lane++) {
         if (lane)
            permutation_text(body, sizeof(body), &length, ", ");
         if (lanes > 1)
            permutation_text(body, sizeof(body), &length, "i%u ", bits);
         permutation_text(body, sizeof(body), &length, "%" PRIu64, values[lane]);
      }
      if (lanes > 1)
         permutation_text(body, sizeof(body), &length, ">");
      permutation_text(body, sizeof(body), &length,
         ")\n%%round%u = call %s @llvm.%s.%s(%s %%v%u)\n"
         "%%p%u = getelementptr i8, ptr addrspace(1) %%out, i64 %u\n"
         "%%q%u = getelementptr i8, ptr addrspace(1) %%out, i64 %u\n"
         "store %s %%v%u, ptr addrspace(1) %%p%u, align 1\n"
         "store %s %%round%u, ptr addrspace(1) %%q%u, align 1\n",
         operation, type, operations[operation], suffix, type, operation,
         operation, operation * 64, operation, operation * 64 + 32,
         type, operation, operation, type, operation, operation);
   }
   permutation_text(body, sizeof(body), &length, "ret void\n");
   nir_shader *nir = permutation_translate(body, declarations);
   nir_opt_dce(nir);
   struct air_effect_store trace[4];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == count * 2);
   for (unsigned operation = 0; operation < count; operation++) {
      for (unsigned pass = 0; pass < 2; pass++) {
         struct air_effect_store *store = &trace[operation * 2 + pass];
         CHECK(!store->ssbo && store->address == 0x100000 + operation * 64 + pass * 32);
         CHECK(store->bits == bits && store->components == lanes);
         for (unsigned lane = 0; lane < lanes; lane++) {
            uint64_t expected = pass ? values[lane] : permutation_reference(operation, bits, values[lane]);
            CHECK(nir_const_value_as_uint(store->values[lane], bits) == expected);
         }
      }
   }
   ralloc_free(nir);
}

static void
permutation_guarded(void)
{
   const char *body =
      "%zero = icmp eq i32 %tid, 0\nbr i1 %zero, label %skip, label %permute\n"
      "skip:\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\n"
      "permute:\n%reverse = call i32 @llvm.bitreverse.i32(i32 %tid)\n"
      "%swap = call i32 @llvm.bswap.i32(i32 %tid)\n"
      "%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %reverse, ptr addrspace(1) %out, align 4\n"
      "store i32 %swap, ptr addrspace(1) %p, align 4\nret void\n";
   const char *declarations = "declare i32 @llvm.bitreverse.i32(i32)\n"
                              "declare i32 @llvm.bswap.i32(i32)\n";
   const uint32_t inputs[] = {0, 1, UINT32_C(0x80000000), UINT32_C(0x01234567)};
   for (unsigned i = 0; i < ARRAY_SIZE(inputs); i++) {
      nir_shader *nir = permutation_translate(body, declarations);
      specialize_invocation(nir, inputs[i]);
      uint64_t addresses[] = {0x100000, 0x100004};
      uint32_t expected[] = {inputs[i] ? (uint32_t)permutation_reference(0, 32, inputs[i]) : 99,
                             (uint32_t)permutation_reference(1, 32, inputs[i])};
      check_executed_stores(nir, addresses, expected, inputs[i] ? 2 : 1);
      ralloc_free(nir);
   }
}

static void
permutation_loop(void)
{
   nir_shader *nir = permutation_translate(
      "entry:\nbr label %loop\nloop:\n"
      "%i = phi i32 [0, %entry], [%next, %loop]\n"
      "%v = phi i64 [81985529216486895, %entry], [%updated, %loop]\n"
      "%reverse = call i64 @llvm.bitreverse.i64(i64 %v)\n"
      "%swap = call i64 @llvm.bswap.i64(i64 %v)\n"
      "%p = getelementptr i8, ptr addrspace(1) %out, i64 8\n"
      "store i64 %reverse, ptr addrspace(1) %out, align 4\n"
      "store i64 %swap, ptr addrspace(1) %p, align 4\n"
      "%updated = xor i64 %reverse, %swap\n%next = add i32 %i, 1\n"
      "%more = icmp ult i32 %next, 7\nbr i1 %more, label %loop, label %exit\n"
      "exit:\nret void\n",
      "declare i64 @llvm.bitreverse.i64(i64)\n"
      "declare i64 @llvm.bswap.i64(i64)\n");
   nir_opt_dce(nir);
   struct air_effect_store trace[14];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   uint64_t value = UINT64_C(0x0123456789abcdef);
   for (unsigned iteration = 0; iteration < 7; iteration++) {
      uint64_t reverse = permutation_reference(0, 64, value);
      uint64_t swap = permutation_reference(1, 64, value);
      for (unsigned operation = 0; operation < 2; operation++) {
         struct air_effect_store *store = &trace[iteration * 2 + operation];
         CHECK(!store->ssbo && store->bits == 64 && store->components == 1);
         CHECK(store->address == 0x100000 + operation * 8);
         CHECK(store->values[0].u64 == (operation ? swap : reverse));
      }
      value = reverse ^ swap;
   }
   ralloc_free(nir);
}

/* Classify original textual malformed inputs independently, then assert the
 * rejection at the actual decoded boundary. LLVM can enforce immarg itself;
 * such a verifier refusal is never reported as exercising our call checker. */
static void
permutation_refusal(const char *body, const char *extra, enum stela_air_error_kind valid_error)
{
   size_t bytes = strlen(stela_air_test_prefix) + strlen(body) +
                  strlen(stela_air_test_metadata) + strlen(extra) + 1;
   char *source = malloc(bytes);
   CHECK(source);
   snprintf(source, bytes, "%s%s%s%s", stela_air_test_prefix, body, stela_air_test_metadata, extra);
   LLVMContextRef context = LLVMContextCreate();
   LLVMMemoryBufferRef input = LLVMCreateMemoryBufferWithMemoryRangeCopy(source, bytes - 1, "permutation-refusal");
   LLVMModuleRef module = NULL;
   char *message = NULL;
   CHECK(!LLVMParseIRInContext(context, input, &module, &message));
   LLVMDisposeMessage(message); message = NULL;
   bool invalid = LLVMVerifyModule(module, LLVMReturnStatusAction, &message);
   if (invalid)
      CHECK(message && message[0]);
   LLVMDisposeMessage(message);
   LLVMDisposeModule(module); LLVMContextDispose(context); free(source);
   expect_refusal(body, extra, 100, invalid ? STELA_AIR_VERIFY : valid_error);
}

static void
integer_permutation_tests(void)
{
   const unsigned widths[] = {8, 16, 32, 64};
   for (unsigned w = 0; w < ARRAY_SIZE(widths); w++) {
      unsigned bits = widths[w];
      uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
      const uint64_t cases[] = {0, mask, mask - 1, 1, UINT64_C(1) << (bits - 1),
         UINT64_C(0x0123456789abcdef) & mask, UINT64_C(0x80000000000000ff) & mask,
         UINT64_C(0x55aa00ff80402010) & mask};
      for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
         const uint64_t values[4] = {cases[i]};
         permutation_values(bits, 1, values);
      }
      for (unsigned bit = 0; bit < bits; bit++) {
         const uint64_t values[4] = {UINT64_C(1) << bit};
         permutation_values(bits, 1, values);
      }
      const uint64_t values[4] = {0, mask, UINT64_C(0x0123456789abcdef) & mask,
                                  UINT64_C(0x80000000000000ff) & mask};
      for (unsigned lanes = 2; lanes <= 4; lanes++)
         permutation_values(bits, lanes, values);
   }
   for (unsigned value = 0; value < 256; value++) {
      const uint64_t values[4] = {value};
      permutation_values(8, 1, values);
   }
   permutation_guarded();
   permutation_loop();
   const char *operations[] = {"bitreverse", "bswap"};
   for (unsigned operation = 0; operation < ARRAY_SIZE(operations); operation++) {
      const char *types[] = {"i1", "i24", "i48", "<1 x i32>", "<5 x i32>", "<vscale x 2 x i32>"};
      const char *suffixes[] = {"i1", "i24", "i48", "v1i32", "v5i32", "nxv2i32"};
      for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
         char body[512], declaration[256];
         snprintf(body, sizeof(body), "%%v = call %s @llvm.%s.%s(%s zeroinitializer)\nret void\n",
            types[i], operations[operation], suffixes[i], types[i]);
         snprintf(declaration, sizeof(declaration), "declare %s @llvm.%s.%s(%s)\n",
            types[i], operations[operation], suffixes[i], types[i]);
         permutation_refusal(body, declaration, STELA_AIR_TYPE);
      }
      const char *bad_values[] = {"poison", "undef"};
      for (unsigned i = 0; i < ARRAY_SIZE(bad_values); i++) {
         char body[256], declaration[128];
         snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 %s)\nret void\n",
            operations[operation], bad_values[i]);
         snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32)\n", operations[operation]);
         expect_refusal(body, declaration, 100, STELA_AIR_INSTRUCTION);
      }
   }
   permutation_refusal("%v = call i8 @llvm.bswap.i8(i8 1)\nret void\n",
                        "declare i8 @llvm.bswap.i8(i8)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call <2 x i8> @llvm.bswap.v2i8(<2 x i8> zeroinitializer)\nret void\n",
                        "declare <2 x i8> @llvm.bswap.v2i8(<2 x i8>)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call fastcc i32 @llvm.bitreverse.i32(i32 1)\nret void\n",
                        "declare fastcc i32 @llvm.bitreverse.i32(i32)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call i32 @llvm.bswap.i32(i32 1)\nret void\n",
                        "declare fastcc i32 @llvm.bswap.i32(i32)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call i32 @llvm.bitreverse.i32(i32 1) [\"stela.permutation.refusal\"(i32 7)]\nret void\n",
                        "declare i32 @llvm.bitreverse.i32(i32)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call i32 @llvm.bswap.i32(i32 1)\nret void\n",
                        "define i32 @llvm.bswap.i32(i32 %v) { ret i32 %v }\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call i32 (i32, ...) @llvm.bitreverse.i32(i32 1)\nret void\n",
                        "declare i32 @llvm.bitreverse.i32(i32, ...)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call i32 @llvm.bswap.i32(i32 1, i32 2)\nret void\n",
                        "declare i32 @llvm.bswap.i32(i32, i32)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call i64 @llvm.bitreverse.i32(i64 1)\nret void\n",
                        "declare i32 @llvm.bitreverse.i32(i32)\n", STELA_AIR_TYPE);
   permutation_refusal("%v = call float @llvm.bswap.f32(float 1.0)\nret void\n",
                        "declare float @llvm.bswap.f32(float)\n", STELA_AIR_TYPE);
   expect_refusal("%v = call i32 @user.llvm.bitreverse.i32(i32 1)\nret void\n",
                   "declare i32 @user.llvm.bitreverse.i32(i32)\n", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("%v = freeze i32 1\n%c = call i32 @llvm.bswap.i32(i32 %v)\nret void\n",
                   "declare i32 @llvm.bswap.i32(i32)\n", 100, STELA_AIR_INSTRUCTION);
}

#endif
