/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_FUNNEL_FIXTURE_H
#define STELA_AIR_FUNNEL_FIXTURE_H

/* Authored IR: three unknown input regions are captured before any store.
 * Each region is 32 bytes, including a full i64x4 payload. The actual buffer
 * base guarantees four-byte alignment, so i64 accesses do not claim eight. */
#define STELA_AIR_FUNNEL_DECL(type, suffix) \
   "declare " type " @llvm.fshl." suffix "(" type ", " type ", " type ")\n" \
   "declare " type " @llvm.fshr." suffix "(" type ", " type ", " type ")\n"
#define STELA_AIR_FUNNEL_INPUT(type, alignment) \
   "%input_b = getelementptr i8, ptr addrspace(1) %out, i64 32\n" \
   "%input_c = getelementptr i8, ptr addrspace(1) %out, i64 64\n" \
   "%a = load " type ", ptr addrspace(1) %out, align " alignment "\n" \
   "%b = load " type ", ptr addrspace(1) %input_b, align " alignment "\n" \
   "%c = load " type ", ptr addrspace(1) %input_c, align " alignment "\n"
#define STELA_AIR_FUNNEL_OUTPUT(type, suffix, alignment, count) \
   "%left = call " type " @llvm.fshl." suffix "(" type " %a, " type " %b, " type " " count ")\n" \
   "%right = call " type " @llvm.fshr." suffix "(" type " %a, " type " %b, " type " " count ")\n" \
   "%rol = call " type " @llvm.fshl." suffix "(" type " %a, " type " %a, " type " " count ")\n" \
   "%ror = call " type " @llvm.fshr." suffix "(" type " %b, " type " %b, " type " " count ")\n" \
   "%p0 = getelementptr i8, ptr addrspace(1) %out, i64 96\n" \
   "%p1 = getelementptr i8, ptr addrspace(1) %out, i64 128\n" \
   "%p2 = getelementptr i8, ptr addrspace(1) %out, i64 160\n" \
   "%p3 = getelementptr i8, ptr addrspace(1) %out, i64 192\n" \
   "store " type " %left, ptr addrspace(1) %p0, align " alignment "\n" \
   "store " type " %right, ptr addrspace(1) %p1, align " alignment "\n" \
   "store " type " %rol, ptr addrspace(1) %p2, align " alignment "\n" \
   "store " type " %ror, ptr addrspace(1) %p3, align " alignment "\nret void\n"
#define STELA_AIR_FUNNEL_FIXTURE(name, type, suffix, alignment) \
   {name, STELA_AIR_FUNNEL_INPUT(type, alignment) \
      STELA_AIR_FUNNEL_OUTPUT(type, suffix, alignment, "%c"), STELA_AIR_FUNNEL_DECL(type, suffix)}

static const struct {
   const char *name, *body, *declarations;
} stela_air_funnel_fixtures[] = {
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel8", "i8", "i8", "1"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel8x2", "<2 x i8>", "v2i8", "1"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel8x3", "<3 x i8>", "v3i8", "1"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel8x4", "<4 x i8>", "v4i8", "1"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel16", "i16", "i16", "2"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel16x2", "<2 x i16>", "v2i16", "2"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel16x3", "<3 x i16>", "v3i16", "2"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel16x4", "<4 x i16>", "v4i16", "2"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel32", "i32", "i32", "4"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel32x2", "<2 x i32>", "v2i32", "4"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel32x3", "<3 x i32>", "v3i32", "4"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel32x4", "<4 x i32>", "v4i32", "4"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel64", "i64", "i64", "4"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel64x2", "<2 x i64>", "v2i64", "4"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel64x3", "<3 x i64>", "v3i64", "4"),
   STELA_AIR_FUNNEL_FIXTURE("integer-funnel64x4", "<4 x i64>", "v4i64", "4"),
   {"integer-funnel32-divergent", STELA_AIR_FUNNEL_INPUT("i32", "4")
      "%mixed = xor i32 %c, %tid\n"
      STELA_AIR_FUNNEL_OUTPUT("i32", "i32", "4", "%mixed"), STELA_AIR_FUNNEL_DECL("i32", "i32")},
};

#undef STELA_AIR_FUNNEL_DECL
#undef STELA_AIR_FUNNEL_INPUT
#undef STELA_AIR_FUNNEL_OUTPUT
#undef STELA_AIR_FUNNEL_FIXTURE
#endif
