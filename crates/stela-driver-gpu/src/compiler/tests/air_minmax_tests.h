/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_MINMAX_TESTS_H
#define STELA_AIR_MINMAX_TESTS_H

#include <inttypes.h>
#include <stdarg.h>

/* Compare individual bits in significance order. Signed ordering first uses
 * the sign bit; no host signed cast, min/max builtin or NIR recipe is reused. */
static bool
minmax_less(unsigned bits, bool signed_order, uint64_t a, uint64_t b)
{
   unsigned sign_a = (a >> (bits - 1)) & 1;
   unsigned sign_b = (b >> (bits - 1)) & 1;
   if (signed_order && sign_a != sign_b)
      return sign_a;
   for (unsigned remaining = bits; remaining; remaining--) {
      unsigned bit_a = (a >> (remaining - 1)) & 1;
      unsigned bit_b = (b >> (remaining - 1)) & 1;
      if (bit_a != bit_b)
         return bit_b;
   }
   return false;
}

static uint64_t
minmax_reference(unsigned operation, unsigned bits, uint64_t a, uint64_t b)
{
   bool a_less_b = minmax_less(bits, operation < 2, a, b);
   return operation & 1 ? (a_less_b ? b : a) : (a_less_b ? a : b);
}

static void
minmax_text(char *text, size_t capacity, size_t *length, const char *format, ...)
{
   va_list args;
   va_start(args, format);
   int written = vsnprintf(text + *length, capacity - *length, format, args);
   va_end(args);
   CHECK(written >= 0 && (size_t)written < capacity - *length);
   *length += (size_t)written;
}

static nir_shader *
minmax_translate(const char *body, const char *declarations)
{
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, declarations);
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, 1000, &error);
   if (!nir)
      fprintf(stderr, "integer minmax fixture: %s\n%s\n", error.detail, body);
   CHECK(nir && error.kind == STELA_AIR_OK);
   LLVMDisposeMemoryBuffer(input);
   return nir;
}

static void
minmax_literal(char *text, size_t capacity, size_t *length, unsigned bits,
               unsigned lanes, const uint64_t values[4])
{
   if (lanes > 1)
      minmax_text(text, capacity, length, "<");
   for (unsigned lane = 0; lane < lanes; lane++) {
      if (lane)
         minmax_text(text, capacity, length, ", ");
      if (lanes > 1)
         minmax_text(text, capacity, length, "i%u ", bits);
      minmax_text(text, capacity, length, "%" PRIu64, values[lane]);
   }
   if (lanes > 1)
      minmax_text(text, capacity, length, ">");
}

static void
minmax_values(unsigned bits, unsigned lanes, const uint64_t a[4], const uint64_t b[4])
{
   const char *operations[] = {"smin", "smax", "umin", "umax"};
   char body[8192], declarations[1024], type[32], suffix[32];
   size_t length = 0, decl_length = 0;
   if (lanes == 1) {
      snprintf(type, sizeof(type), "i%u", bits);
      snprintf(suffix, sizeof(suffix), "i%u", bits);
   } else {
      snprintf(type, sizeof(type), "<%u x i%u>", lanes, bits);
      snprintf(suffix, sizeof(suffix), "v%ui%u", lanes, bits);
   }
   for (unsigned operation = 0; operation < ARRAY_SIZE(operations); operation++) {
      minmax_text(declarations, sizeof(declarations), &decl_length,
         "declare %s @llvm.%s.%s(%s, %s)\n", type, operations[operation], suffix, type, type);
      for (unsigned pass = 0; pass < 2; pass++) {
         minmax_text(body, sizeof(body), &length, "%%v%u_%u = call %s @llvm.%s.%s(%s ",
            operation, pass, type, operations[operation], suffix, type);
         minmax_literal(body, sizeof(body), &length, bits, lanes, pass ? b : a);
         minmax_text(body, sizeof(body), &length, ", %s ", type);
         minmax_literal(body, sizeof(body), &length, bits, lanes, pass ? a : b);
         minmax_text(body, sizeof(body), &length,
            ")\n%%p%u_%u = getelementptr i8, ptr addrspace(1) %%out, i64 %u\n"
            "store %s %%v%u_%u, ptr addrspace(1) %%p%u_%u, align 1\n",
            operation, pass, operation * 64 + pass * 32, type, operation, pass, operation, pass);
      }
   }
   minmax_text(body, sizeof(body), &length, "ret void\n");
   nir_shader *nir = minmax_translate(body, declarations);
   nir_opt_dce(nir);
   struct air_effect_store trace[8];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   for (unsigned operation = 0; operation < ARRAY_SIZE(operations); operation++) {
      for (unsigned pass = 0; pass < 2; pass++) {
         const struct air_effect_store *store = &trace[operation * 2 + pass];
         CHECK(!store->ssbo && store->address == 0x100000 + operation * 64 + pass * 32);
         CHECK(store->bits == bits && store->components == lanes);
         for (unsigned lane = 0; lane < lanes; lane++)
            CHECK(nir_const_value_as_uint(store->values[lane], bits) ==
                  minmax_reference(operation, bits, a[lane], b[lane]));
      }
   }
   ralloc_free(nir);
}

static void
minmax_guarded(void)
{
   const char *body =
      "%zero = icmp eq i32 %tid, 0\nbr i1 %zero, label %skip, label %choose\n"
      "skip:\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\n"
      "choose:\n%smin = call i32 @llvm.smin.i32(i32 %tid, i32 2147483647)\n"
      "%smax = call i32 @llvm.smax.i32(i32 %tid, i32 2147483647)\n"
      "%umin = call i32 @llvm.umin.i32(i32 %tid, i32 2147483647)\n"
      "%umax = call i32 @llvm.umax.i32(i32 %tid, i32 2147483647)\n"
      "%p1 = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "%p2 = getelementptr i32, ptr addrspace(1) %out, i32 2\n"
      "%p3 = getelementptr i32, ptr addrspace(1) %out, i32 3\n"
      "store i32 %smin, ptr addrspace(1) %out, align 4\n"
      "store i32 %smax, ptr addrspace(1) %p1, align 4\n"
      "store i32 %umin, ptr addrspace(1) %p2, align 4\n"
      "store i32 %umax, ptr addrspace(1) %p3, align 4\nret void\n";
   const char *declarations = "declare i32 @llvm.smin.i32(i32, i32)\n"
      "declare i32 @llvm.smax.i32(i32, i32)\n"
      "declare i32 @llvm.umin.i32(i32, i32)\n"
      "declare i32 @llvm.umax.i32(i32, i32)\n";
   const uint32_t values[] = {0, 1, UINT32_C(0x80000000), UINT32_MAX};
   for (unsigned i = 0; i < ARRAY_SIZE(values); i++) {
      nir_shader *nir = minmax_translate(body, declarations);
      specialize_invocation(nir, values[i]);
      uint64_t addresses[] = {0x100000, 0x100004, 0x100008, 0x10000c};
      uint32_t expected[4];
      for (unsigned operation = 0; operation < ARRAY_SIZE(expected); operation++)
         expected[operation] = minmax_reference(operation, 32, values[i], UINT32_C(0x7fffffff));
      if (!values[i])
         expected[0] = 99;
      check_executed_stores(nir, addresses, expected, values[i] ? 4 : 1);
      ralloc_free(nir);
   }
}

static void
minmax_loop(void)
{
   nir_shader *nir = minmax_translate(
      "entry:\nbr label %loop\nloop:\n"
      "%i = phi i32 [0, %entry], [%next, %loop]\n"
      "%a = phi i64 [9223372036854775808, %entry], [%a_next, %loop]\n"
      "%b = phi i64 [9223372036854775807, %entry], [%b_next, %loop]\n"
      "%smin = call i64 @llvm.smin.i64(i64 %a, i64 %b)\n"
      "%smax = call i64 @llvm.smax.i64(i64 %a, i64 %b)\n"
      "%umin = call i64 @llvm.umin.i64(i64 %a, i64 %b)\n"
      "%umax = call i64 @llvm.umax.i64(i64 %a, i64 %b)\n"
      "%p1 = getelementptr i8, ptr addrspace(1) %out, i64 8\n"
      "%p2 = getelementptr i8, ptr addrspace(1) %out, i64 16\n"
      "%p3 = getelementptr i8, ptr addrspace(1) %out, i64 24\n"
      "store i64 %smin, ptr addrspace(1) %out, align 4\n"
      "store i64 %smax, ptr addrspace(1) %p1, align 4\n"
      "store i64 %umin, ptr addrspace(1) %p2, align 4\n"
      "store i64 %umax, ptr addrspace(1) %p3, align 4\n"
      "%a_next = xor i64 %a, 9223372036854775808\n"
      "%b_next = add i64 %b, 4294967297\n%next = add i32 %i, 1\n"
      "%more = icmp ult i32 %next, 7\nbr i1 %more, label %loop, label %exit\n"
      "exit:\nret void\n",
      "declare i64 @llvm.smin.i64(i64, i64)\n"
      "declare i64 @llvm.smax.i64(i64, i64)\n"
      "declare i64 @llvm.umin.i64(i64, i64)\n"
      "declare i64 @llvm.umax.i64(i64, i64)\n");
   nir_opt_dce(nir);
   struct air_effect_store trace[28];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   uint64_t a = UINT64_C(0x8000000000000000), b = UINT64_C(0x7fffffffffffffff);
   for (unsigned iteration = 0; iteration < 7; iteration++) {
      for (unsigned operation = 0; operation < 4; operation++) {
         const struct air_effect_store *store = &trace[iteration * 4 + operation];
         CHECK(!store->ssbo && store->bits == 64 && store->components == 1);
         CHECK(store->address == 0x100000 + operation * 8);
         CHECK(store->values[0].u64 == minmax_reference(operation, 64, a, b));
      }
      a ^= UINT64_C(0x8000000000000000);
      b += UINT64_C(0x100000001);
   }
   ralloc_free(nir);
}

/* Keep original textual verifier classification separate from the decoded
 * frontend refusal. Reader repair/upgrade behavior is not presumed. */
static void
minmax_refusal(const char *body, const char *extra, enum stela_air_error_kind valid_error)
{
   size_t bytes = strlen(stela_air_test_prefix) + strlen(body) +
                  strlen(stela_air_test_metadata) + strlen(extra) + 1;
   char *source = malloc(bytes);
   CHECK(source);
   snprintf(source, bytes, "%s%s%s%s", stela_air_test_prefix, body, stela_air_test_metadata, extra);
   LLVMContextRef context = LLVMContextCreate();
   LLVMMemoryBufferRef input = LLVMCreateMemoryBufferWithMemoryRangeCopy(source, bytes - 1, "minmax-refusal");
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
integer_minmax_tests(void)
{
   const unsigned widths[] = {8, 16, 32, 64};
   for (unsigned w = 0; w < ARRAY_SIZE(widths); w++) {
      unsigned bits = widths[w];
      uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
      uint64_t sign = UINT64_C(1) << (bits - 1);
      uint64_t x = UINT64_C(0x0123456789abcdef) & mask;
      uint64_t y = UINT64_C(0xfedcba9876543210) & mask;
      const uint64_t pairs[][2] = {{0, 0}, {mask, mask}, {0, mask}, {mask, 0},
         {sign, sign - 1}, {sign - 1, sign}, {sign, mask}, {mask, sign},
         {1, mask}, {mask - 1, mask}, {x, y}, {y, x}};
      for (unsigned i = 0; i < ARRAY_SIZE(pairs); i++) {
         const uint64_t a[4] = {pairs[i][0]}, b[4] = {pairs[i][1]};
         minmax_values(bits, 1, a, b);
      }
      const uint64_t a[4] = {0, sign, mask, x}, b[4] = {mask, sign - 1, 1, y};
      for (unsigned lanes = 2; lanes <= 4; lanes++)
         minmax_values(bits, lanes, a, b);
   }
   /* Exhaust every i8 value in each operand of a permutation of the domain;
    * this is 256 distinct pairs, not the full 65,536-pair Cartesian product. */
   for (unsigned value = 0; value < 256; value++) {
      const uint64_t a[4] = {value}, b[4] = {(value * 73 + 19) & 255};
      minmax_values(8, 1, a, b);
   }
   minmax_guarded();
   minmax_loop();
   const char *operations[] = {"smin", "smax", "umin", "umax"};
   for (unsigned operation = 0; operation < ARRAY_SIZE(operations); operation++) {
      const char *types[] = {"i1", "i24", "i128", "<1 x i32>", "<5 x i32>", "<vscale x 2 x i32>", "float"};
      const char *suffixes[] = {"i1", "i24", "i128", "v1i32", "v5i32", "nxv2i32", "f32"};
      for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
         char body[512], declaration[256];
         snprintf(body, sizeof(body), "%%v = call %s @llvm.%s.%s(%s zeroinitializer, %s zeroinitializer)\nret void\n",
            types[i], operations[operation], suffixes[i], types[i], types[i]);
         snprintf(declaration, sizeof(declaration), "declare %s @llvm.%s.%s(%s, %s)\n",
            types[i], operations[operation], suffixes[i], types[i], types[i]);
         minmax_refusal(body, declaration, STELA_AIR_TYPE);
      }
      char body[512], declaration[256];
      snprintf(body, sizeof(body), "%%v = call fastcc i32 @llvm.%s.i32(i32 1, i32 2)\nret void\n", operations[operation]);
      snprintf(declaration, sizeof(declaration), "declare fastcc i32 @llvm.%s.i32(i32, i32)\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i32 2)\nret void\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "define i32 @llvm.%s.i32(i32 %%a, i32 %%b) { ret i32 %%a }\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32, ...)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 (i32, i32, ...) @llvm.%s.i32(i32 1, i32 2)\nret void\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i32 2) [\"stela.minmax.refusal\"(i32 7)]\nret void\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1)\nret void\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i16)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i16 2)\nret void\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call fastcc i32 @llvm.%s.i32(i32 1, i32 2)\nret void\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(body, sizeof(body), "%%v = call i64 @llvm.%s.i32(i64 1, i64 2)\nret void\n", operations[operation]);
      minmax_refusal(body, declaration, STELA_AIR_TYPE);
   }
   expect_refusal("%v = call i32 @user.llvm.smin.i32(i32 1, i32 2)\nret void\n",
      "declare i32 @user.llvm.smin.i32(i32, i32)\n", 100, STELA_AIR_INSTRUCTION);
}

#endif
