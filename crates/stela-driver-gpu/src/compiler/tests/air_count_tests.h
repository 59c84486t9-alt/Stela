/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_COUNT_TESTS_H
#define STELA_AIR_COUNT_TESTS_H

#include <inttypes.h>
#include <stdarg.h>

/* Independent bit-by-bit reference; no host CLZ/CTZ UB or NIR evaluator reuse. */
static unsigned
count_reference(unsigned operation, unsigned bits, uint64_t value)
{
   unsigned count = 0;
   if (!operation) {
      for (unsigned bit = 0; bit < bits; bit++)
         count += (unsigned)((value >> bit) & 1);
   } else {
      for (unsigned bit = 0; bit < bits; bit++) {
         unsigned index = operation == 1 ? bits - bit - 1 : bit;
         if ((value >> index) & 1)
            break;
         count++;
      }
   }
   return count;
}

static void
count_text(char *text, size_t capacity, size_t *length, const char *format, ...)
{
   va_list args;
   va_start(args, format);
   int written = vsnprintf(text + *length, capacity - *length, format, args);
   va_end(args);
   CHECK(written >= 0 && (size_t)written < capacity - *length);
   *length += (size_t)written;
}

static nir_shader *
count_translate(const char *body, const char *declarations)
{
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, declarations);
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, 1000, &error);
   if (!nir)
      fprintf(stderr, "integer count fixture: %s\n%s\n", error.detail, body);
   CHECK(nir && error.kind == STELA_AIR_OK);
   LLVMDisposeMemoryBuffer(input);
   return nir;
}

static void
count_values(unsigned bits, unsigned lanes, const uint64_t values[4], bool poison_zero)
{
   static const char *const ops[] = {"ctpop", "ctlz", "cttz"};
   char body[4096], declarations[1024], type[32], suffix[32];
   size_t length = 0, decl_length = 0;
   if (lanes == 1) {
      snprintf(type, sizeof(type), "i%u", bits);
      snprintf(suffix, sizeof(suffix), "i%u", bits);
   } else {
      snprintf(type, sizeof(type), "<%u x i%u>", lanes, bits);
      snprintf(suffix, sizeof(suffix), "v%ui%u", lanes, bits);
   }
   for (unsigned op = 0; op < ARRAY_SIZE(ops); op++) {
      count_text(declarations, sizeof(declarations), &decl_length,
                 "declare %s @llvm.%s.%s(%s%s)\n", type, ops[op], suffix,
                 type, op ? ", i1" : "");
      count_text(body, sizeof(body), &length, "%%v%u = call %s @llvm.%s.%s(%s ",
                 op, type, ops[op], suffix, type);
      if (lanes > 1)
         count_text(body, sizeof(body), &length, "<");
      for (unsigned lane = 0; lane < lanes; lane++) {
         if (lane)
            count_text(body, sizeof(body), &length, ", ");
         if (lanes > 1)
            count_text(body, sizeof(body), &length, "i%u ", bits);
         count_text(body, sizeof(body), &length, "%" PRIu64, values[lane]);
         CHECK(!poison_zero || values[lane]);
      }
      if (lanes > 1)
         count_text(body, sizeof(body), &length, ">");
      if (op)
         count_text(body, sizeof(body), &length, ", i1 %s", poison_zero ? "true" : "false");
      count_text(body, sizeof(body), &length,
         ")\n%%p%u = getelementptr i8, ptr addrspace(1) %%out, i64 %u\n"
         "store %s %%v%u, ptr addrspace(1) %%p%u, align 1\n", op, op * 32, type, op, op);
   }
   count_text(body, sizeof(body), &length, "ret void\n");
   nir_shader *nir = count_translate(body, declarations);
   nir_opt_dce(nir);
   struct air_effect_store trace[3];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   for (unsigned op = 0; op < ARRAY_SIZE(ops); op++) {
      CHECK(!trace[op].ssbo && trace[op].address == 0x100000 + op * 32);
      CHECK(trace[op].bits == bits && trace[op].components == lanes);
      for (unsigned lane = 0; lane < lanes; lane++)
         CHECK(nir_const_value_as_uint(trace[op].values[lane], bits) ==
               count_reference(op, bits, values[lane]));
   }
   ralloc_free(nir);
}

static void
count_guarded(void)
{
   const char *body =
      "%zero = icmp eq i32 %tid, 0\nbr i1 %zero, label %skip, label %count\n"
      "skip:\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\n"
      "count:\n%l = call i32 @llvm.ctlz.i32(i32 %tid, i1 true)\n"
      "%r = call i32 @llvm.cttz.i32(i32 %tid, i1 true)\n"
      "%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %l, ptr addrspace(1) %out, align 4\n"
      "store i32 %r, ptr addrspace(1) %p, align 4\nret void\n";
   const char *decl = "declare i32 @llvm.ctlz.i32(i32, i1)\n"
                      "declare i32 @llvm.cttz.i32(i32, i1)\n";
   const uint32_t inputs[] = {0, 1, 2, 3, UINT32_C(0x80000000)};
   for (unsigned i = 0; i < ARRAY_SIZE(inputs); i++) {
      nir_shader *nir = count_translate(body, decl);
      specialize_invocation(nir, inputs[i]);
      uint64_t addresses[] = {0x100000, 0x100004};
      uint32_t expected[] = {inputs[i] ? count_reference(1, 32, inputs[i]) : 99,
                             count_reference(2, 32, inputs[i])};
      check_executed_stores(nir, addresses, expected, inputs[i] ? 2 : 1);
      ralloc_free(nir);
   }
}

static void
count_loop(void)
{
   nir_shader *nir = count_translate(
      "entry:\nbr label %loop\nloop:\n"
      "%i = phi i32 [0, %entry], [%next, %loop]\n"
      "%v = phi i64 [9223372036854775808, %entry], [%shift, %loop]\n"
      "%pop = call i64 @llvm.ctpop.i64(i64 %v)\n"
      "%leading = call i64 @llvm.ctlz.i64(i64 %v, i1 false)\n"
      "%trailing = call i64 @llvm.cttz.i64(i64 %v, i1 false)\n"
      "%p1 = getelementptr i8, ptr addrspace(1) %out, i64 8\n"
      "%p2 = getelementptr i8, ptr addrspace(1) %out, i64 16\n"
      "store i64 %pop, ptr addrspace(1) %out, align 4\n"
      "store i64 %leading, ptr addrspace(1) %p1, align 4\n"
      "store i64 %trailing, ptr addrspace(1) %p2, align 4\n"
      "%shift = lshr i64 %v, 13\n%next = add i32 %i, 1\n"
      "%more = icmp ult i32 %next, 6\nbr i1 %more, label %loop, label %exit\n"
      "exit:\nret void\n",
      "declare i64 @llvm.ctpop.i64(i64)\n"
      "declare i64 @llvm.ctlz.i64(i64, i1)\n"
      "declare i64 @llvm.cttz.i64(i64, i1)\n");
   nir_opt_dce(nir);
   struct air_effect_store trace[18];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   uint64_t value = UINT64_C(1) << 63;
   for (unsigned iteration = 0; iteration < 6; iteration++) {
      for (unsigned op = 0; op < 3; op++) {
         struct air_effect_store *store = &trace[iteration * 3 + op];
         CHECK(!store->ssbo && store->bits == 64 && store->components == 1);
         CHECK(store->address == 0x100000 + op * 8);
         CHECK(store->values[0].u64 == count_reference(op, 64, value));
      }
      value >>= 13;
   }
   ralloc_free(nir);
}

/* Classify original textual malformed inputs independently, then assert the
 * rejection at the actual decoded boundary. LLVM can enforce immarg itself;
 * such a verifier refusal is never reported as exercising our call checker. */
static void
count_refusal(const char *body, const char *extra, enum stela_air_error_kind valid_error)
{
   size_t bytes = strlen(stela_air_test_prefix) + strlen(body) +
                  strlen(stela_air_test_metadata) + strlen(extra) + 1;
   char *source = malloc(bytes);
   CHECK(source);
   snprintf(source, bytes, "%s%s%s%s", stela_air_test_prefix, body, stela_air_test_metadata, extra);
   LLVMContextRef context = LLVMContextCreate();
   LLVMMemoryBufferRef input = LLVMCreateMemoryBufferWithMemoryRangeCopy(source, bytes - 1, "count-refusal");
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
integer_count_tests(void)
{
   const unsigned widths[] = {8, 16, 32, 64};
   for (unsigned w = 0; w < ARRAY_SIZE(widths); w++) {
      unsigned bits = widths[w];
      uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
      const uint64_t cases[] = {0, mask, mask - 1, (UINT64_C(1) << (bits - 1)),
                               UINT64_C(0xaaaaaaaaaaaaaaaa) & mask,
                               UINT64_C(0x5555555555555555) & mask};
      for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
         const uint64_t values[4] = {cases[i]};
         count_values(bits, 1, values, false);
         if (cases[i])
            count_values(bits, 1, values, true);
      }
      for (unsigned bit = 0; bit < bits; bit++) {
         const uint64_t values[4] = {UINT64_C(1) << bit};
         count_values(bits, 1, values, false);
         count_values(bits, 1, values, true);
      }
      const uint64_t values[4] = {0, mask, UINT64_C(1) << (bits - 1), 1};
      const uint64_t nonzero[4] = {1, mask, UINT64_C(1) << (bits - 1), mask - 1};
      for (unsigned lanes = 2; lanes <= 4; lanes++) {
         count_values(bits, lanes, values, false);
         count_values(bits, lanes, nonzero, true);
      }
   }
   count_guarded();
   count_loop();
   const char *ops[] = {"ctpop", "ctlz", "cttz"};
   for (unsigned op = 0; op < ARRAY_SIZE(ops); op++) {
      const char *types[] = {"i1", "i24", "<1 x i32>", "<5 x i32>", "<vscale x 2 x i32>"};
      const char *suffixes[] = {"i1", "i24", "v1i32", "v5i32", "nxv2i32"};
      for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
         char body[512], decl[256];
         snprintf(body, sizeof(body), "%%v = call %s @llvm.%s.%s(%s zeroinitializer%s)\nret void\n",
                  types[i], ops[op], suffixes[i], types[i], op ? ", i1 false" : "");
         snprintf(decl, sizeof(decl), "declare %s @llvm.%s.%s(%s%s)\n",
                  types[i], ops[op], suffixes[i], types[i], op ? ", i1" : "");
         expect_refusal(body, decl, 100, STELA_AIR_TYPE);
      }
   }
   count_refusal("%flag = icmp eq i32 %tid, 0\n%v = call i32 @llvm.ctlz.i32(i32 1, i1 %flag)\nret void\n",
                  "declare i32 @llvm.ctlz.i32(i32, i1)\n", STELA_AIR_INSTRUCTION);
   count_refusal("%v = call i32 @llvm.cttz.i32(i32 1, i1 poison)\nret void\n",
                  "declare i32 @llvm.cttz.i32(i32, i1)\n", STELA_AIR_INSTRUCTION);
   count_refusal("%v = call fastcc i32 @llvm.ctpop.i32(i32 1)\nret void\n",
                  "declare fastcc i32 @llvm.ctpop.i32(i32)\n", STELA_AIR_TYPE);
   count_refusal("%v = call fastcc i32 @llvm.ctpop.i32(i32 1)\nret void\n",
                  "declare i32 @llvm.ctpop.i32(i32)\n", STELA_AIR_TYPE);
   count_refusal("%v = call i32 @llvm.ctpop.i32(i32 1) [\"stela.count.refusal\"(i32 7)]\nret void\n",
                  "declare i32 @llvm.ctpop.i32(i32)\n", STELA_AIR_TYPE);
   count_refusal("%v = call i32 @llvm.ctpop.i32(i32 1)\nret void\n",
                  "define i32 @llvm.ctpop.i32(i32 %v) { ret i32 %v }\n", STELA_AIR_TYPE);
   count_refusal("%v = call i32 (i32, ...) @llvm.ctpop.i32(i32 1)\nret void\n",
                  "declare i32 @llvm.ctpop.i32(i32, ...)\n", STELA_AIR_TYPE);
   count_refusal("%v = call i32 @llvm.ctpop.i32(i32 1, i32 2)\nret void\n",
                  "declare i32 @llvm.ctpop.i32(i32, i32)\n", STELA_AIR_TYPE);
   count_refusal("%v = call i64 @llvm.ctpop.i32(i64 1)\nret void\n",
                  "declare i32 @llvm.ctpop.i32(i32)\n", STELA_AIR_TYPE);
   count_refusal("%v = call float @llvm.ctpop.f32(float 1.0)\nret void\n",
                  "declare float @llvm.ctpop.f32(float)\n", STELA_AIR_TYPE);
   count_refusal("%v = call <2 x i32> @llvm.ctlz.v2i32(<2 x i32> zeroinitializer, <2 x i1> zeroinitializer)\nret void\n",
                  "declare <2 x i32> @llvm.ctlz.v2i32(<2 x i32>, <2 x i1>)\n", STELA_AIR_TYPE);
   count_refusal("%v = call i32 @llvm.ctpop.i32(i16 1)\nret void\n",
                  "declare i32 @llvm.ctpop.i32(i16)\n", STELA_AIR_TYPE);
   expect_refusal("%v = call i32 @user.llvm.ctpop.i32(i32 1)\nret void\n",
                  "declare i32 @user.llvm.ctpop.i32(i32)\n", 100, STELA_AIR_INSTRUCTION);
}

#endif
