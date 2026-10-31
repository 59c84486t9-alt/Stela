/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_FUNNEL_TESTS_H
#define STELA_AIR_FUNNEL_TESTS_H

#include <inttypes.h>
#include <stdarg.h>
#include "air_funnel_fixture.h"

/* Read one bit from the mathematical 2N-bit concatenation, rather than
 * reusing shifts/OR, native rotates, NIR operations or a host 128-bit type. */
static uint64_t
funnel_reference(bool left, unsigned bits, uint64_t a, uint64_t b, uint64_t amount)
{
   unsigned k = amount % bits;
   uint64_t result = 0;
   for (unsigned bit = 0; bit < bits; bit++) {
      unsigned source = left ? bits + bit - k : bit + k;
      unsigned value = source < bits ? (b >> source) & 1 : (a >> (source - bits)) & 1;
      result |= (uint64_t)value << bit;
   }
   return result;
}

static void
funnel_text(char *text, size_t capacity, size_t *length, const char *format, ...)
{
   va_list args;
   va_start(args, format);
   int written = vsnprintf(text + *length, capacity - *length, format, args);
   va_end(args);
   CHECK(written >= 0 && (size_t)written < capacity - *length);
   *length += (size_t)written;
}

static const nir_shader_compiler_options funnel_options[] = {
   {0}, {.has_shfr32 = true},
   {.has_rotate8 = true, .has_rotate16 = true, .has_rotate32 = true},
   {.has_shfr32 = true, .has_rotate8 = true, .has_rotate16 = true, .has_rotate32 = true},
};

static nir_shader *
funnel_translate(const char *body, const char *declarations, unsigned mode)
{
   CHECK(mode < ARRAY_SIZE(funnel_options));
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, declarations);
   struct stela_air_error error;
   nir_shader *nir = translate(input, &funnel_options[mode], 1000, &error);
   if (!nir)
      fprintf(stderr, "integer funnel fixture: %s\n%s\n", error.detail, body);
   CHECK(nir && error.kind == STELA_AIR_OK);
   LLVMDisposeMemoryBuffer(input);
   return nir;
}

static void
funnel_literal(char *text, size_t capacity, size_t *length, unsigned bits,
               unsigned lanes, const uint64_t values[4])
{
   if (lanes > 1)
      funnel_text(text, capacity, length, "<");
   for (unsigned lane = 0; lane < lanes; lane++) {
      if (lane)
         funnel_text(text, capacity, length, ", ");
      if (lanes > 1)
         funnel_text(text, capacity, length, "i%u ", bits);
      funnel_text(text, capacity, length, "%" PRIu64, values[lane]);
   }
   if (lanes > 1)
      funnel_text(text, capacity, length, ">");
}

static void
funnel_values(unsigned bits, unsigned lanes, const uint64_t a[4], const uint64_t b[4],
              const uint64_t c[4], unsigned mode)
{
   char body[8192], declarations[512], type[32], suffix[32];
   size_t length = 0;
   if (lanes == 1) {
      snprintf(type, sizeof(type), "i%u", bits);
      snprintf(suffix, sizeof(suffix), "i%u", bits);
   } else {
      snprintf(type, sizeof(type), "<%u x i%u>", lanes, bits);
      snprintf(suffix, sizeof(suffix), "v%ui%u", lanes, bits);
   }
   snprintf(declarations, sizeof(declarations),
      "declare %s @llvm.fshl.%s(%s, %s, %s)\n"
      "declare %s @llvm.fshr.%s(%s, %s, %s)\n",
      type, suffix, type, type, type, type, suffix, type, type, type);
   const uint64_t *inputs[] = {a, b, c};
   const char *names[] = {"a", "b", "c"};
   for (unsigned input = 0; input < ARRAY_SIZE(inputs); input++) {
      funnel_text(body, sizeof(body), &length, "%%%s = add %s zeroinitializer, ", names[input], type);
      funnel_literal(body, sizeof(body), &length, bits, lanes, inputs[input]);
      funnel_text(body, sizeof(body), &length, "\n");
   }
   const unsigned lhs[] = {0, 1, 0, 1}, rhs[] = {1, 0, 0, 1};
   for (unsigned operation = 0; operation < 2; operation++) {
      for (unsigned pass = 0; pass < 4; pass++) {
         unsigned slot = operation * 4 + pass;
         funnel_text(body, sizeof(body), &length,
            "%%v%u = call %s @llvm.%s.%s(%s %%%s, %s %%%s, %s %%c)\n"
            "%%p%u = getelementptr i8, ptr addrspace(1) %%out, i64 %u\n"
            "store %s %%v%u, ptr addrspace(1) %%p%u, align 1\n",
            slot, type, operation ? "fshr" : "fshl", suffix, type, names[lhs[pass]],
            type, names[rhs[pass]], type, slot, slot * 32, type, slot, slot);
      }
   }
   funnel_text(body, sizeof(body), &length, "ret void\n");
   nir_shader *nir = funnel_translate(body, declarations, mode);
   nir_opt_dce(nir);
   struct air_effect_store trace[8];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   for (unsigned operation = 0; operation < 2; operation++) {
      for (unsigned pass = 0; pass < 4; pass++) {
         const struct air_effect_store *store = &trace[operation * 4 + pass];
         CHECK(!store->ssbo && store->address == 0x100000 + (operation * 4 + pass) * 32);
         CHECK(store->bits == bits && store->components == lanes);
         for (unsigned lane = 0; lane < lanes; lane++)
            CHECK(nir_const_value_as_uint(store->values[lane], bits) ==
                  funnel_reference(!operation, bits, inputs[lhs[pass]][lane], inputs[rhs[pass]][lane], c[lane]));
      }
   }
   ralloc_free(nir);
}

static unsigned
funnel_op_count(nir_shader *nir, nir_op operation)
{
   unsigned count = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_alu)
               continue;
            nir_alu_instr *alu = nir_instr_as_alu(instr);
            if (alu->op == nir_op_ishl || alu->op == nir_op_ushr || alu->op == nir_op_shfr ||
                alu->op == nir_op_urol || alu->op == nir_op_uror) {
               unsigned count_source = nir_op_infos[alu->op].num_inputs - 1;
               CHECK(alu->src[count_source].src.ssa->bit_size == 32);
            }
            count += alu->op == operation;
         }
      }
   }
   return count;
}

static void
funnel_dynamic(unsigned bits, unsigned mode)
{
   char body[4096], declarations[512];
   size_t length = 0;
   if (bits < 32)
      funnel_text(body, sizeof(body), &length, "%%count = trunc i32 %%tid to i%u\n", bits);
   else if (bits > 32)
      funnel_text(body, sizeof(body), &length, "%%count = zext i32 %%tid to i%u\n", bits);
   else
      funnel_text(body, sizeof(body), &length, "%%count = add i32 %%tid, 0\n");
   funnel_text(body, sizeof(body), &length,
      "%%a = xor i%u %%count, 37\n%%b = xor i%u %%count, 218\n", bits, bits);
   const char *lhs[] = {"a", "a", "a", "b"}, *rhs[] = {"b", "b", "a", "b"};
   for (unsigned i = 0; i < 4; i++)
      funnel_text(body, sizeof(body), &length,
         "%%v%u = call i%u @llvm.%s.i%u(i%u %%%s, i%u %%%s, i%u %%count)\n"
         "%%p%u = getelementptr i8, ptr addrspace(1) %%out, i64 %u\n"
         "store i%u %%v%u, ptr addrspace(1) %%p%u, align 1\n",
         i, bits, i == 0 || i == 2 ? "fshl" : "fshr", bits, bits, lhs[i], bits, rhs[i], bits,
         i, i * 8, bits, i, i);
   funnel_text(body, sizeof(body), &length, "ret void\n");
   snprintf(declarations, sizeof(declarations),
      "declare i%u @llvm.fshl.i%u(i%u, i%u, i%u)\n"
      "declare i%u @llvm.fshr.i%u(i%u, i%u, i%u)\n",
      bits, bits, bits, bits, bits, bits, bits, bits, bits, bits);
   const uint32_t amounts[] = {0, 1, bits - 1, bits, bits + 1, bits * 2, UINT32_MAX};
   for (unsigned case_index = 0; case_index < ARRAY_SIZE(amounts); case_index++) {
      nir_shader *nir = funnel_translate(body, declarations, mode);
      bool rotate = bits < 64 && mode >= 2;
      bool shfr = bits == 32 && (mode == 1 || mode == 3);
      CHECK(funnel_op_count(nir, nir_op_shfr) == (shfr ? (rotate ? 2 : 4) : 0));
      CHECK(funnel_op_count(nir, nir_op_urol) == (rotate ? 1 : 0));
      CHECK(funnel_op_count(nir, nir_op_uror) == (rotate ? 1 : 0));
      specialize_invocation(nir, amounts[case_index]);
      nir_opt_dce(nir);
      struct air_effect_store trace[4];
      struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
      CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
      uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
      uint64_t count = amounts[case_index] & mask, a = count ^ 37, b = count ^ 218;
      const uint64_t expected[] = {
         funnel_reference(true, bits, a, b, count), funnel_reference(false, bits, a, b, count),
         funnel_reference(true, bits, a, a, count), funnel_reference(false, bits, b, b, count),
      };
      for (unsigned i = 0; i < ARRAY_SIZE(trace); i++) {
         CHECK(!trace[i].ssbo && trace[i].address == 0x100000 + i * 8);
         CHECK(trace[i].components == 1 && trace[i].bits == bits);
         CHECK(nir_const_value_as_uint(trace[i].values[0], bits) == expected[i]);
      }
      ralloc_free(nir);
   }
}

static void
funnel_guarded(void)
{
   const char *body =
      "%zero = icmp eq i32 %tid, 0\nbr i1 %zero, label %skip, label %choose\n"
      "skip:\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\nchoose:\n"
      "%left = call i32 @llvm.fshl.i32(i32 19088743, i32 2309737967, i32 %tid)\n"
      "%right = call i32 @llvm.fshr.i32(i32 19088743, i32 2309737967, i32 %tid)\n"
      "%p1 = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %left, ptr addrspace(1) %out, align 4\n"
      "store i32 %right, ptr addrspace(1) %p1, align 4\nret void\n";
   const char *declarations = "declare i32 @llvm.fshl.i32(i32, i32, i32)\n"
      "declare i32 @llvm.fshr.i32(i32, i32, i32)\n";
   const uint32_t amounts[] = {0, 1, 31, 32, 33, 64, UINT32_MAX};
   for (unsigned i = 0; i < ARRAY_SIZE(amounts); i++) {
      nir_shader *nir = funnel_translate(body, declarations, 1);
      specialize_invocation(nir, amounts[i]);
      uint64_t addresses[] = {0x100000, 0x100004};
      uint32_t expected[] = {
         amounts[i] ? funnel_reference(true, 32, 19088743, 2309737967, amounts[i]) : 99,
         funnel_reference(false, 32, 19088743, 2309737967, amounts[i]),
      };
      check_executed_stores(nir, addresses, expected, amounts[i] ? 2 : 1);
      ralloc_free(nir);
   }
}

static void
funnel_loop(void)
{
   const char *body =
      "entry:\nbr label %loop\nloop:\n"
      "%i = phi i32 [0, %entry], [%next, %loop]\n"
      "%a = phi i64 [81985529216486895, %entry], [%a_next, %loop]\n"
      "%b = phi i64 [18364758544493064720, %entry], [%b_next, %loop]\n"
      "%c = phi i64 [9223372036854775808, %entry], [%c_next, %loop]\n"
      "%left = call i64 @llvm.fshl.i64(i64 %a, i64 %b, i64 %c)\n"
      "%right = call i64 @llvm.fshr.i64(i64 %a, i64 %b, i64 %c)\n"
      "%p1 = getelementptr i8, ptr addrspace(1) %out, i64 8\n"
      "store i64 %left, ptr addrspace(1) %out, align 4\n"
      "store i64 %right, ptr addrspace(1) %p1, align 4\n"
      "%a_next = xor i64 %a, 9223372036854775808\n"
      "%b_next = add i64 %b, 4294967297\n%c_next = add i64 %c, 65\n"
      "%next = add i32 %i, 1\n%more = icmp ult i32 %next, 7\n"
      "br i1 %more, label %loop, label %exit\nexit:\nret void\n";
   nir_shader *nir = funnel_translate(body,
      "declare i64 @llvm.fshl.i64(i64, i64, i64)\n"
      "declare i64 @llvm.fshr.i64(i64, i64, i64)\n", 0);
   nir_opt_dce(nir);
   struct air_effect_store trace[14];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   uint64_t a = UINT64_C(0x0123456789abcdef), b = UINT64_C(0xfedcba9876543210);
   uint64_t c = UINT64_C(0x8000000000000000);
   for (unsigned iteration = 0; iteration < 7; iteration++) {
      for (unsigned operation = 0; operation < 2; operation++) {
         const struct air_effect_store *store = &trace[iteration * 2 + operation];
         CHECK(!store->ssbo && store->bits == 64 && store->components == 1);
         CHECK(store->address == 0x100000 + operation * 8);
         CHECK(store->values[0].u64 == funnel_reference(!operation, 64, a, b, c));
      }
      a ^= UINT64_C(0x8000000000000000);
      b += UINT64_C(0x100000001);
      c += 65;
   }
   ralloc_free(nir);
}

static void
funnel_unknown_buffers(void)
{
   for (unsigned i = 0; i < ARRAY_SIZE(stela_air_funnel_fixtures); i++) {
      for (unsigned mode = 0; mode < ARRAY_SIZE(funnel_options); mode++) {
         nir_shader *nir = funnel_translate(stela_air_funnel_fixtures[i].body,
                                           stela_air_funnel_fixtures[i].declarations, mode);
         unsigned loads = 0, stores = 0;
         nir_foreach_function_impl(impl, nir) {
            nir_foreach_block(block, impl) {
               nir_foreach_instr(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_op op = nir_instr_as_intrinsic(instr)->intrinsic;
                  loads += op == nir_intrinsic_load_global;
                  stores += op == nir_intrinsic_store_global;
               }
            }
         }
         CHECK(loads == 3 && stores == 4);
         struct air_effect_store trace[4];
         struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
         CHECK(run.status == AIR_EFFECT_UNSUPPORTED && !run.stores);
         ralloc_free(nir);
      }
   }
}

/* Classify LLVM verifier refusals separately; malformed intrinsic IR need not
 * reach the frontend, and LLVM reader repair is not presumed. */
static void
funnel_refusal(const char *body, const char *extra, enum stela_air_error_kind valid_error)
{
   size_t bytes = strlen(stela_air_test_prefix) + strlen(body) +
                  strlen(stela_air_test_metadata) + strlen(extra) + 1;
   char *source = malloc(bytes);
   CHECK(source);
   snprintf(source, bytes, "%s%s%s%s", stela_air_test_prefix, body, stela_air_test_metadata, extra);
   LLVMContextRef context = LLVMContextCreate();
   LLVMMemoryBufferRef input = LLVMCreateMemoryBufferWithMemoryRangeCopy(source, bytes - 1, "funnel-refusal");
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
funnel_refusals(void)
{
   const char *operations[] = {"fshl", "fshr"};
   for (unsigned operation = 0; operation < ARRAY_SIZE(operations); operation++) {
      const char *types[] = {"i1", "i24", "i128", "<1 x i32>", "<5 x i32>", "<vscale x 2 x i32>", "float"};
      const char *suffixes[] = {"i1", "i24", "i128", "v1i32", "v5i32", "nxv2i32", "f32"};
      for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
         char body[768], declaration[384];
         snprintf(body, sizeof(body), "%%v = call %s @llvm.%s.%s(%s zeroinitializer, %s zeroinitializer, %s zeroinitializer)\nret void\n",
            types[i], operations[operation], suffixes[i], types[i], types[i], types[i]);
         snprintf(declaration, sizeof(declaration), "declare %s @llvm.%s.%s(%s, %s, %s)\n",
            types[i], operations[operation], suffixes[i], types[i], types[i], types[i]);
         funnel_refusal(body, declaration, STELA_AIR_TYPE);
      }
      char body[768], declaration[384];
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32, i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call fastcc i32 @llvm.%s.i32(i32 1, i32 2, i32 0)\nret void\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i32 2, i32 0)\nret void\n", operations[operation]);
      snprintf(declaration, sizeof(declaration), "declare fastcc i32 @llvm.%s.i32(i32, i32, i32)\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(body, sizeof(body), "%%v = call fastcc i32 @llvm.%s.i32(i32 1, i32 2, i32 0)\nret void\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i32 2, i32 0)\nret void\n", operations[operation]);
      snprintf(declaration, sizeof(declaration), "define i32 @llvm.%s.i32(i32 %%a, i32 %%b, i32 %%c) { ret i32 %%a }\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32, i32, ...)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 (i32, i32, i32, ...) @llvm.%s.i32(i32 1, i32 2, i32 0)\nret void\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32, i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i32 2, i32 0) [\"stela.funnel.refusal\"(i32 7)]\nret void\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i32 2)\nret void\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32, i32, i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(i32 1, i32 2, i32 0, i32 0)\nret void\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
      for (unsigned argument = 0; argument < 3; argument++) {
         const char *types[] = {"i32", "i32", "i32"};
         types[argument] = "i16";
         snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(%s, %s, %s)\n",
            operations[operation], types[0], types[1], types[2]);
         snprintf(body, sizeof(body), "%%v = call i32 @llvm.%s.i32(%s 1, %s 2, %s 0)\nret void\n",
            operations[operation], types[0], types[1], types[2]);
         funnel_refusal(body, declaration, STELA_AIR_TYPE);
      }
      snprintf(declaration, sizeof(declaration), "declare i32 @llvm.%s.i32(i32, i32, i32)\n", operations[operation]);
      snprintf(body, sizeof(body), "%%v = call i64 @llvm.%s.i32(i64 1, i64 2, i64 0)\nret void\n", operations[operation]);
      funnel_refusal(body, declaration, STELA_AIR_TYPE);
   }
   expect_refusal("%v = call i32 @user.llvm.fshl.i32(i32 1, i32 2, i32 0)\nret void\n",
      "declare i32 @user.llvm.fshl.i32(i32, i32, i32)\n", 100, STELA_AIR_INSTRUCTION);
   funnel_refusal("%v = call i32 @user.alias(i32 1, i32 2, i32 0)\nret void\n",
      "define i32 @user.target(i32 %a, i32 %b, i32 %c) { ret i32 %a }\n"
      "@user.alias = alias i32 (i32, i32, i32), ptr @user.target\n", STELA_AIR_TARGET);
   funnel_refusal("%fn = select i1 true, ptr @llvm.fshr.i32, ptr @llvm.fshr.i32\n"
      "%v = call i32 %fn(i32 1, i32 2, i32 0)\nret void\n",
      "declare i32 @llvm.fshr.i32(i32, i32, i32)\n", STELA_AIR_INSTRUCTION);
}

/* A test clone receives exactly the three scalar input values for this tuple.
 * Validate each original load's full address and width before replacing it;
 * this is finite fixture specialization, not an invented memory oracle. */
static void
funnel_isolated_inputs(nir_shader *nir, unsigned bits, uint64_t a, uint64_t b, uint64_t c)
{
   const uint64_t inputs[] = {a, b, c};
   unsigned seen = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr_safe(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *load = nir_instr_as_intrinsic(instr);
            if (load->intrinsic != nir_intrinsic_load_global)
               continue;
            CHECK(load->def.num_components == 1 && load->def.bit_size == bits);
            CHECK(load->src[0].ssa->num_components == 1 && load->src[0].ssa->bit_size == 64);
            CHECK(nir_src_is_const(load->src[0]));
            uint64_t address = nir_src_as_uint(load->src[0]);
            CHECK(address == 0x100000 || address == 0x100020 || address == 0x100040);
            unsigned slot = (address - 0x100000) / 32;
            CHECK(!(seen & (1u << slot)));
            seen |= 1u << slot;
            nir_builder builder = nir_builder_at(nir_before_instr(instr));
            nir_def *value = nir_imm_intN_t(&builder, inputs[slot], bits);
            CHECK(value);
            nir_def_rewrite_uses(&load->def, value);
            nir_instr_remove(instr);
         }
      }
   }
   CHECK(seen == 7);
   nir_opt_dce(nir);
}

static void
funnel_isolated_bits(void)
{
   const unsigned widths[] = {8, 16, 32, 64};
   unsigned templates = 0, tuples = 0, effects = 0;
   for (unsigned w = 0; w < ARRAY_SIZE(widths); w++) {
      unsigned bits = widths[w], width_tuples = 0;
      uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
      const uint64_t amounts[] = {0, 1, bits - 1, bits, bits + 1, bits * 2 - 1,
                                  bits * 2, mask, UINT64_C(1) << (bits - 1)};
      /* The shared fixture table orders each scalar then its three vectors.
       * Explicit checks keep this indexing assumption observable. */
      const unsigned scalar_fixture = w * 4;
      for (unsigned mode = 0; mode < ARRAY_SIZE(funnel_options); mode++) {
         nir_shader *original = funnel_translate(stela_air_funnel_fixtures[scalar_fixture].body,
            stela_air_funnel_fixtures[scalar_fixture].declarations, mode);
         while (nir_opt_constant_folding(original)) {}
         nir_opt_dce(original);
         templates++;
         for (unsigned bit = 0; bit < bits; bit++) {
            for (unsigned half = 0; half < 2; half++) {
               uint64_t isolated = UINT64_C(1) << bit;
               uint64_t a = half ? 0 : isolated, b = half ? isolated : 0;
               for (unsigned i = 0; i < ARRAY_SIZE(amounts); i++) {
                  nir_shader *nir = nir_shader_clone(NULL, original);
                  CHECK(nir);
                  funnel_isolated_inputs(nir, bits, a, b, amounts[i]);
                  struct air_effect_store trace[4];
                  struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
                  CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
                  const uint64_t expected[] = {
                     funnel_reference(true, bits, a, b, amounts[i]),
                     funnel_reference(false, bits, a, b, amounts[i]),
                     funnel_reference(true, bits, a, a, amounts[i]),
                     funnel_reference(false, bits, b, b, amounts[i]),
                  };
                  for (unsigned output = 0; output < ARRAY_SIZE(trace); output++) {
                     CHECK(!trace[output].ssbo && trace[output].address == 0x100060 + output * 32);
                     CHECK(trace[output].bits == bits && trace[output].components == 1);
                     CHECK(nir_const_value_as_uint(trace[output].values[0], bits) == expected[output]);
                  }
                  width_tuples++;
                  effects += run.stores;
                  ralloc_free(nir);
               }
            }
         }
         ralloc_free(original);
      }
      CHECK(width_tuples == bits * 2 * ARRAY_SIZE(amounts) * ARRAY_SIZE(funnel_options));
      tuples += width_tuples;
   }
   /* 120 bit positions * 2 halves * 9 source counts * 4 option sets.
    * Four stores per tuple include both directions and equal-input rotates. */
   CHECK(templates == 16 && tuples == 8640 && effects == 34560);
}

static void
integer_funnel_tests(void)
{
   const unsigned widths[] = {8, 16, 32, 64};
   for (unsigned w = 0; w < ARRAY_SIZE(widths); w++) {
      unsigned bits = widths[w];
      uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
      const uint64_t a[4] = {UINT64_C(0x0123456789abcdef) & mask, 0, mask, 1};
      const uint64_t b[4] = {UINT64_C(0xfedcba9876543210) & mask, mask, 0, UINT64_C(1) << (bits - 1)};
      const uint64_t amounts[] = {0, 1, bits - 1, bits, bits + 1, bits * 2 - 1, bits * 2, mask,
                                  UINT64_C(1) << (bits - 1)};
      for (unsigned mode = 0; mode < ARRAY_SIZE(funnel_options); mode++) {
         for (unsigned lanes = 1; lanes <= 4; lanes++) {
            for (unsigned i = 0; i < ARRAY_SIZE(amounts); i++) {
               uint64_t c[4];
               for (unsigned lane = 0; lane < 4; lane++)
                  c[lane] = amounts[(i + lane) % ARRAY_SIZE(amounts)];
               funnel_values(bits, lanes, a, b, c, mode);
            }
         }
         funnel_dynamic(bits, mode);
      }
   }
   /* All i8 amounts, on four lane-distinct asymmetric input pairs. This is not an
    * exhaustive 2^24 input Cartesian product. */
   for (unsigned amount = 0; amount < 256; amount++) {
      const uint64_t a[4] = {0xa5, 0, 0xff, 0x81}, b[4] = {0x3c, 0xff, 0, 0x18};
      const uint64_t c[4] = {amount, (amount + 1) & 255, (amount + 7) & 255, (amount + 128) & 255};
      funnel_values(8, 4, a, b, c, 0);
   }
   funnel_guarded();
   funnel_loop();
   funnel_unknown_buffers();
   funnel_refusals();
   funnel_isolated_bits();
}

#endif
