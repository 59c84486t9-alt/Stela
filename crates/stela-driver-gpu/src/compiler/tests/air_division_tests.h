/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_DIVISION_TESTS_H
#define STELA_AIR_DIVISION_TESTS_H

#include <inttypes.h>
#include <stdarg.h>

enum division_domain { DIVISION_DEFINED, DIVISION_UB, DIVISION_POISON };

/* Independent unsigned-magnitude reference avoids C signed overflow and tests
 * the exact full-width integer result rather than repeating NIR op selection. */
static enum division_domain
division_reference(unsigned bits, uint64_t a, uint64_t b, bool signed_op,
                   bool exact, uint64_t *quotient, uint64_t *remainder)
{
   uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
   uint64_t sign = UINT64_C(1) << (bits - 1);
   a &= mask;
   b &= mask;
   if (!b || (signed_op && a == sign && b == mask))
      return DIVISION_UB; /* Pinned LLVM specifies this for srem as well. */
   bool aneg = signed_op && (a & sign), bneg = signed_op && (b & sign);
   uint64_t am = aneg ? (-a & mask) : a, bm = bneg ? (-b & mask) : b;
   uint64_t q = am / bm, r = am % bm;
   if (exact && r)
      return DIVISION_POISON;
   *quotient = (aneg != bneg ? -q : q) & mask;
   *remainder = (aneg ? -r : r) & mask;
   return DIVISION_DEFINED;
}

static void
division_text(char *text, size_t capacity, size_t *length, const char *format, ...)
{
   va_list args;
   va_start(args, format);
   int written = vsnprintf(text + *length, capacity - *length, format, args);
   va_end(args);
   CHECK(written >= 0 && (size_t)written < capacity - *length);
   *length += written;
}

static void
division_values(unsigned bits, unsigned lanes, const uint64_t a[4],
                const uint64_t b[4], bool exact)
{
   const char *ops[] = {"udiv", "sdiv", "urem", "srem"};
   uint64_t expected[4][4] = {{0}};
   char body[8192], type[32];
   size_t length = 0;
   if (lanes == 1)
      snprintf(type, sizeof(type), "i%u", bits);
   else
      snprintf(type, sizeof(type), "<%u x i%u>", lanes, bits);
   for (unsigned op = 0; op < ARRAY_SIZE(ops); op++) {
      division_text(body, sizeof(body), &length, "%%v%u = %s %s%s ", op,
                    ops[op], exact && op < 2 ? "exact " : "", type);
      for (unsigned operand = 0; operand < 2; operand++) {
         if (lanes > 1)
            division_text(body, sizeof(body), &length, "<");
         for (unsigned lane = 0; lane < lanes; lane++) {
            if (lane)
               division_text(body, sizeof(body), &length, ", ");
            if (lanes > 1)
               division_text(body, sizeof(body), &length, "i%u ", bits);
            division_text(body, sizeof(body), &length, "%" PRIu64,
                          operand ? b[lane] : a[lane]);
         }
         division_text(body, sizeof(body), &length,
                       lanes > 1 ? (operand ? ">\n" : ">, ") : (operand ? "\n" : ", "));
      }
      division_text(body, sizeof(body), &length,
         "%%p%u = getelementptr i8, ptr addrspace(1) %%out, i64 %u\n"
         "store %s %%v%u, ptr addrspace(1) %%p%u, align 1\n", op, op * 32, type, op, op);
      for (unsigned lane = 0; lane < lanes; lane++) {
         uint64_t q, r;
         CHECK(division_reference(bits, a[lane], b[lane], op & 1, exact && op < 2,
                                  &q, &r) == DIVISION_DEFINED);
         expected[op][lane] = op < 2 ? q : r;
      }
   }
   division_text(body, sizeof(body), &length, "ret void\n");
   nir_shader *nir = translate_body(body);
   nir_opt_dce(nir); /* Preserve the division ALU for the existing evaluator. */
   struct air_effect_store trace[4];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == 4);
   for (unsigned i = 0; i < 4; i++) {
      CHECK(!trace[i].ssbo && trace[i].address == 0x100000 + i * 32);
      CHECK(trace[i].bits == bits && trace[i].components == lanes);
      for (unsigned lane = 0; lane < lanes; lane++)
         CHECK(nir_const_value_as_uint(trace[i].values[lane], bits) == expected[i][lane]);
   }
   ralloc_free(nir);
}

static void
division_guarded(void)
{
   const char *body =
      "%d = sub i32 %tid, 1\n%zero = icmp eq i32 %d, 0\n"
      "%overflow = icmp eq i32 %d, -1\n%bad = or i1 %zero, %overflow\n"
      "br i1 %bad, label %skip, label %divide\n"
      "skip:\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\n"
      "divide:\n%q = sdiv i32 -2147483648, %d\n%r = srem i32 -2147483648, %d\n"
      "%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %q, ptr addrspace(1) %out, align 4\n"
      "store i32 %r, ptr addrspace(1) %p, align 4\nret void\n";
   for (unsigned tid = 0; tid < 5; tid++) {
      uint64_t q = 99, r = 0;
      if (tid > 1)
         CHECK(division_reference(32, UINT64_C(2147483648), tid - 1, true, false,
                                  &q, &r) == DIVISION_DEFINED);
      uint64_t addresses[] = {0x100000, 0x100004};
      uint32_t values[] = {q, r};
      nir_shader *nir = translate_body(body);
      specialize_invocation(nir, tid);
      check_executed_stores(nir, addresses, values, tid > 1 ? 2 : 1);
      ralloc_free(nir);
   }
}

static void
division_loop(void)
{
   nir_shader *nir = translate_body(
      "entry:\nbr label %loop\nloop:\n"
      "%i = phi i32 [0, %entry], [%next, %loop]\n"
      "%u = phi i64 [18446744073709551615, %entry], [%uq, %loop]\n"
      "%s = phi i64 [9223372036854775809, %entry], [%sq, %loop]\n"
      "%uq = udiv i64 %u, 3\n%sq = sdiv i64 %s, -3\n"
      "%ur = urem i64 %u, 3\n%sr = srem i64 %s, -3\n"
      "%p1 = getelementptr i8, ptr addrspace(1) %out, i64 8\n"
      "%p2 = getelementptr i8, ptr addrspace(1) %out, i64 16\n"
      "%p3 = getelementptr i8, ptr addrspace(1) %out, i64 24\n"
      "store i64 %uq, ptr addrspace(1) %out, align 4\n"
      "store i64 %sq, ptr addrspace(1) %p1, align 4\n"
      "store i64 %ur, ptr addrspace(1) %p2, align 4\n"
      "store i64 %sr, ptr addrspace(1) %p3, align 4\n"
      "%next = add i32 %i, 1\n%more = icmp ult i32 %next, 5\n"
      "br i1 %more, label %loop, label %exit\nexit:\nret void\n");
   nir_opt_dce(nir); /* Retain the loop, simultaneous PHIs and all four ALUs. */
   struct air_effect_store trace[20];
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == ARRAY_SIZE(trace));
   uint64_t u = UINT64_MAX, s = UINT64_C(9223372036854775809);
   for (unsigned iteration = 0; iteration < 5; iteration++) {
      uint64_t expected[4];
      CHECK(division_reference(64, u, 3, false, false, &expected[0], &expected[2]) == DIVISION_DEFINED);
      CHECK(division_reference(64, s, UINT64_MAX - 2, true, false, &expected[1], &expected[3]) == DIVISION_DEFINED);
      for (unsigned i = 0; i < 4; i++) {
         struct air_effect_store *store = &trace[iteration * 4 + i];
         CHECK(!store->ssbo && store->bits == 64 && store->components == 1);
         CHECK(store->address == 0x100000 + i * 8 && store->values[0].u64 == expected[i]);
      }
      u = expected[0];
      s = expected[1];
   }
   ralloc_free(nir);
}

static void
integer_division_tests(void)
{
   const unsigned widths[] = {8, 16, 32, 64};
   const char *ops[] = {"udiv", "sdiv", "urem", "srem"};
   for (unsigned width = 0; width < ARRAY_SIZE(widths); width++) {
      unsigned bits = widths[width];
      uint64_t sign = UINT64_C(1) << (bits - 1);
      uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
      const uint64_t cases[][2] = {
         {mask, 3}, {0, 5}, {sign, 1}, {sign, 2}, {sign + 1, mask},
         {sign + 1, mask - 2}, {mask - 6, 3}, {7, mask - 2},
         {mask - 6, mask - 2}, {mask, 1}, {sign - 1, mask},
         {(UINT64_C(1) << (bits - 2)) + 1, 7},
      };
      for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
         const uint64_t a[4] = {cases[i][0]}, b[4] = {cases[i][1]};
         division_values(bits, 1, a, b, false);
      }
      const uint64_t a[4] = {mask - 6, 7, sign, mask};
      const uint64_t b[4] = {3, mask - 2, 2, mask - 2};
      for (unsigned lanes = 2; lanes <= 4; lanes++)
         division_values(bits, lanes, a, b, false);
      const uint64_t exact_a[4] = {sign}, exact_b[4] = {2};
      division_values(bits, 1, exact_a, exact_b, true);
      /* Domain classification only: never execute or demand a numerical result
       * for LLVM UB or exact's poison cases, nor substitute Mesa's zero fold. */
      uint64_t q, r;
      CHECK(division_reference(bits, 1, 0, false, false, &q, &r) == DIVISION_UB);
      CHECK(division_reference(bits, sign, mask, true, false, &q, &r) == DIVISION_UB);
      CHECK(division_reference(bits, 7, 3, false, true, &q, &r) == DIVISION_POISON);
      CHECK(division_reference(bits, mask - 6, 3, true, true, &q, &r) == DIVISION_POISON);
   }
   division_guarded();
   division_loop();
   for (unsigned op = 0; op < ARRAY_SIZE(ops); op++) {
      char body[256];
      snprintf(body, sizeof(body), "%%v = %s i1 true, true\nret void\n", ops[op]);
      expect_refusal(body, "", 100, STELA_AIR_TYPE);
      snprintf(body, sizeof(body), "%%v = %s i24 7, 3\nret void\n", ops[op]);
      expect_refusal(body, "", 100, STELA_AIR_TYPE);
      snprintf(body, sizeof(body), "%%v = %s <5 x i32> <i32 7, i32 7, i32 7, i32 7, i32 7>, "
               "<i32 3, i32 3, i32 3, i32 3, i32 3>\nret void\n", ops[op]);
      expect_refusal(body, "", 100, STELA_AIR_TYPE);
   }
}

#endif
