/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_COUNT_FIXTURE_H
#define STELA_AIR_COUNT_FIXTURE_H

/* Authored AIR-shaped IR, never Apple output. Unknown live buffer loads keep
 * all three operations in real backend intake. Both zero-poison flags are
 * tested: the true variants force one interior bit, excluding poison in every lane
 * while both leading and trailing results still depend on the loaded value.
 * The fixture's actual base alignment is four bytes, including i64 loads. */
#define STELA_AIR_COUNT_BODY(type, suffix, forced_bit, alignment) \
   "%input = load " type ", ptr addrspace(1) %out, align " alignment "\n" \
   "%nonzero = or " type " %input, " forced_bit "\n" \
   "%pop = call " type " @llvm.ctpop." suffix "(" type " %input)\n" \
   "%lz = call " type " @llvm.ctlz." suffix "(" type " %input, i1 false)\n" \
   "%tz = call " type " @llvm.cttz." suffix "(" type " %input, i1 false)\n" \
   "%lzn = call " type " @llvm.ctlz." suffix "(" type " %nonzero, i1 true)\n" \
   "%tzn = call " type " @llvm.cttz." suffix "(" type " %nonzero, i1 true)\n" \
   "%p1 = getelementptr i8, ptr addrspace(1) %out, i64 32\n" \
   "%p2 = getelementptr i8, ptr addrspace(1) %out, i64 64\n" \
   "%p3 = getelementptr i8, ptr addrspace(1) %out, i64 96\n" \
   "%p4 = getelementptr i8, ptr addrspace(1) %out, i64 128\n" \
   "store " type " %pop, ptr addrspace(1) %out, align " alignment "\n" \
   "store " type " %lz, ptr addrspace(1) %p1, align " alignment "\n" \
   "store " type " %tz, ptr addrspace(1) %p2, align " alignment "\n" \
   "store " type " %lzn, ptr addrspace(1) %p3, align " alignment "\n" \
   "store " type " %tzn, ptr addrspace(1) %p4, align " alignment "\nret void\n"
#define STELA_AIR_COUNT_DECL(type, suffix) \
   "declare " type " @llvm.ctpop." suffix "(" type ")\n" \
   "declare " type " @llvm.ctlz." suffix "(" type ", i1)\n" \
   "declare " type " @llvm.cttz." suffix "(" type ", i1)\n"

static const struct {
   const char *name, *body, *declarations;
} stela_air_count_fixtures[] = {
   {"integer-count8", STELA_AIR_COUNT_BODY("i8", "i8", "16", "1"),
      STELA_AIR_COUNT_DECL("i8", "i8")},
   {"integer-count16", STELA_AIR_COUNT_BODY("i16", "i16", "256", "2"),
      STELA_AIR_COUNT_DECL("i16", "i16")},
   {"integer-count32", STELA_AIR_COUNT_BODY("i32", "i32", "65536", "4"),
      STELA_AIR_COUNT_DECL("i32", "i32")},
   {"integer-count64", STELA_AIR_COUNT_BODY("i64", "i64", "4294967296", "4"),
      STELA_AIR_COUNT_DECL("i64", "i64")},
   {"integer-count8x2", STELA_AIR_COUNT_BODY("<2 x i8>", "v2i8", "<i8 16, i8 16>", "1"),
      STELA_AIR_COUNT_DECL("<2 x i8>", "v2i8")},
   {"integer-count16x3", STELA_AIR_COUNT_BODY("<3 x i16>", "v3i16", "<i16 256, i16 256, i16 256>", "2"),
      STELA_AIR_COUNT_DECL("<3 x i16>", "v3i16")},
   {"integer-count32x4", STELA_AIR_COUNT_BODY("<4 x i32>", "v4i32", "<i32 65536, i32 65536, i32 65536, i32 65536>", "4"),
      STELA_AIR_COUNT_DECL("<4 x i32>", "v4i32")},
   {"integer-count64x3", STELA_AIR_COUNT_BODY("<3 x i64>", "v3i64", "<i64 4294967296, i64 4294967296, i64 4294967296>", "4"),
      STELA_AIR_COUNT_DECL("<3 x i64>", "v3i64")},
};

#undef STELA_AIR_COUNT_BODY
#undef STELA_AIR_COUNT_DECL
#endif
