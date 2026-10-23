/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_DIVISION_FIXTURE_H
#define STELA_AIR_DIVISION_FIXTURE_H

/* Authored IR, never Apple output. One real unknown buffer value and a dynamic
 * positive divisor keep all four integer operations in the backend intake.
 * The scalar divisor is 1..32 at every admitted width, excluding LLVM's UB
 * cases. Vector divisors are fixed positive values and inputs stay unknown.
 * Existing AIR fixture metadata guarantees 4-byte base alignment, not 8. */
#define STELA_AIR_DIVISION_BODY(type, conversion, alignment) \
   "%masked = and i32 %tid, 31\n" \
   "%nonzero = add i32 %masked, 1\n" conversion \
   "%input = load " type ", ptr addrspace(1) %out, align " alignment "\n" \
   "%uq = udiv " type " %input, %den\n" \
   "%sq = sdiv " type " %input, %den\n" \
   "%ur = urem " type " %input, %den\n" \
   "%sr = srem " type " %input, %den\n" \
   "%q = xor " type " %uq, %sq\n" \
   "%r = xor " type " %ur, %sr\n" \
   "%value = xor " type " %q, %r\n" \
   "store " type " %value, ptr addrspace(1) %out, align " alignment "\nret void\n"

static const struct {
   const char *name, *body;
} stela_air_division_fixtures[] = {
   {"integer-divrem8", STELA_AIR_DIVISION_BODY("i8", "%den = trunc i32 %nonzero to i8\n", "1")},
   {"integer-divrem16", STELA_AIR_DIVISION_BODY("i16", "%den = trunc i32 %nonzero to i16\n", "2")},
   {"integer-divrem32", STELA_AIR_DIVISION_BODY("i32", "%den = add i32 %nonzero, 0\n", "4")},
   {"integer-divrem64", STELA_AIR_DIVISION_BODY("i64", "%den = zext i32 %nonzero to i64\n", "4")},
   {"integer-divrem8x2", STELA_AIR_DIVISION_BODY("<2 x i8>",
      "%den = add <2 x i8> <i8 0, i8 0>, <i8 3, i8 5>\n", "1")},
   {"integer-divrem16x3", STELA_AIR_DIVISION_BODY("<3 x i16>",
      "%den = add <3 x i16> <i16 0, i16 0, i16 0>, <i16 3, i16 5, i16 7>\n", "2")},
   {"integer-divrem32x4", STELA_AIR_DIVISION_BODY("<4 x i32>",
      "%den = add <4 x i32> <i32 0, i32 0, i32 0, i32 0>, <i32 3, i32 5, i32 7, i32 11>\n", "4")},
   {"integer-divrem64x3", STELA_AIR_DIVISION_BODY("<3 x i64>",
      "%den = add <3 x i64> <i64 0, i64 0, i64 0>, <i64 3, i64 5, i64 7>\n", "4")},
};

#undef STELA_AIR_DIVISION_BODY
#endif
