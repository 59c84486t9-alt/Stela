/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_MINMAX_FIXTURE_H
#define STELA_AIR_MINMAX_FIXTURE_H

/* Authored AIR-shaped IR, never Apple output. Both input regions are loaded
 * before the four independent results are stored in disjoint 32-byte regions.
 * Each full i64x4 payload fits; all i64 accesses use the actual four-byte base
 * alignment. These dynamic inputs must reach the real owned vendor compilers. */
#define STELA_AIR_MINMAX_DECL(type, suffix) \
   "declare " type " @llvm.smin." suffix "(" type ", " type ")\n" \
   "declare " type " @llvm.smax." suffix "(" type ", " type ")\n" \
   "declare " type " @llvm.umin." suffix "(" type ", " type ")\n" \
   "declare " type " @llvm.umax." suffix "(" type ", " type ")\n"
#define STELA_AIR_MINMAX_INPUT(type, alignment) \
   "%input_b = getelementptr i8, ptr addrspace(1) %out, i64 32\n" \
   "%a = load " type ", ptr addrspace(1) %out, align " alignment "\n" \
   "%b = load " type ", ptr addrspace(1) %input_b, align " alignment "\n"
#define STELA_AIR_MINMAX_OUTPUT(type, suffix, alignment, lhs) \
   "%smin = call " type " @llvm.smin." suffix "(" type " " lhs ", " type " %b)\n" \
   "%smax = call " type " @llvm.smax." suffix "(" type " " lhs ", " type " %b)\n" \
   "%umin = call " type " @llvm.umin." suffix "(" type " " lhs ", " type " %b)\n" \
   "%umax = call " type " @llvm.umax." suffix "(" type " " lhs ", " type " %b)\n" \
   "%p0 = getelementptr i8, ptr addrspace(1) %out, i64 64\n" \
   "%p1 = getelementptr i8, ptr addrspace(1) %out, i64 96\n" \
   "%p2 = getelementptr i8, ptr addrspace(1) %out, i64 128\n" \
   "%p3 = getelementptr i8, ptr addrspace(1) %out, i64 160\n" \
   "store " type " %smin, ptr addrspace(1) %p0, align " alignment "\n" \
   "store " type " %smax, ptr addrspace(1) %p1, align " alignment "\n" \
   "store " type " %umin, ptr addrspace(1) %p2, align " alignment "\n" \
   "store " type " %umax, ptr addrspace(1) %p3, align " alignment "\nret void\n"
#define STELA_AIR_MINMAX_FIXTURE(name, type, suffix, alignment) \
   {name, STELA_AIR_MINMAX_INPUT(type, alignment) \
      STELA_AIR_MINMAX_OUTPUT(type, suffix, alignment, "%a"), \
      STELA_AIR_MINMAX_DECL(type, suffix)}

static const struct {
   const char *name, *body, *declarations;
} stela_air_minmax_fixtures[] = {
   STELA_AIR_MINMAX_FIXTURE("integer-minmax8", "i8", "i8", "1"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax16", "i16", "i16", "2"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax32", "i32", "i32", "4"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax64", "i64", "i64", "4"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax8x2", "<2 x i8>", "v2i8", "1"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax8x3", "<3 x i8>", "v3i8", "1"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax8x4", "<4 x i8>", "v4i8", "1"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax16x2", "<2 x i16>", "v2i16", "2"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax16x3", "<3 x i16>", "v3i16", "2"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax16x4", "<4 x i16>", "v4i16", "2"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax32x2", "<2 x i32>", "v2i32", "4"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax32x3", "<3 x i32>", "v3i32", "4"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax32x4", "<4 x i32>", "v4i32", "4"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax64x2", "<2 x i64>", "v2i64", "4"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax64x3", "<3 x i64>", "v3i64", "4"),
   STELA_AIR_MINMAX_FIXTURE("integer-minmax64x4", "<4 x i64>", "v4i64", "4"),
   {"integer-minmax16-divergent", STELA_AIR_MINMAX_INPUT("i16", "2")
      "%lane = trunc i32 %tid to i16\n%mixed = xor i16 %a, %lane\n"
      STELA_AIR_MINMAX_OUTPUT("i16", "i16", "2", "%mixed"),
      STELA_AIR_MINMAX_DECL("i16", "i16")},
};

#undef STELA_AIR_MINMAX_DECL
#undef STELA_AIR_MINMAX_INPUT
#undef STELA_AIR_MINMAX_OUTPUT
#undef STELA_AIR_MINMAX_FIXTURE
#endif
