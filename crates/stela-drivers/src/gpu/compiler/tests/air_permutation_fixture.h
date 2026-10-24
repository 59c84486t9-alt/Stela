/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_PERMUTATION_FIXTURE_H
#define STELA_AIR_PERMUTATION_FIXTURE_H

/* Authored AIR-shaped IR, never Apple output. Unknown buffer input retains
 * each supported permutation independently; storing both avoids cancellation.
 * i8 byte swap has no valid LLVM contract and is deliberately not emitted.
 * Base alignment is four bytes, including every i64 scalar/vector access. */
#define STELA_AIR_REVERSE_BODY(type, suffix, alignment) \
   "%input = load " type ", ptr addrspace(1) %out, align " alignment "\n" \
   "%reverse = call " type " @llvm.bitreverse." suffix "(" type " %input)\n" \
   "store " type " %reverse, ptr addrspace(1) %out, align " alignment "\n"
#define STELA_AIR_SWAP_BODY(type, suffix, alignment) \
   "%swap = call " type " @llvm.bswap." suffix "(" type " %input)\n" \
   "%p = getelementptr i8, ptr addrspace(1) %out, i64 32\n" \
   "store " type " %swap, ptr addrspace(1) %p, align " alignment "\n"
#define STELA_AIR_REVERSE_DECL(type, suffix) \
   "declare " type " @llvm.bitreverse." suffix "(" type ")\n"
#define STELA_AIR_SWAP_DECL(type, suffix) \
   "declare " type " @llvm.bswap." suffix "(" type ")\n"

static const struct {
   const char *name, *body, *declarations;
} stela_air_permutation_fixtures[] = {
   {"integer-permutation8", STELA_AIR_REVERSE_BODY("i8", "i8", "1") "ret void\n",
      STELA_AIR_REVERSE_DECL("i8", "i8")},
   {"integer-permutation16", STELA_AIR_REVERSE_BODY("i16", "i16", "2")
      STELA_AIR_SWAP_BODY("i16", "i16", "2") "ret void\n",
      STELA_AIR_REVERSE_DECL("i16", "i16") STELA_AIR_SWAP_DECL("i16", "i16")},
   {"integer-permutation32", STELA_AIR_REVERSE_BODY("i32", "i32", "4")
      STELA_AIR_SWAP_BODY("i32", "i32", "4") "ret void\n",
      STELA_AIR_REVERSE_DECL("i32", "i32") STELA_AIR_SWAP_DECL("i32", "i32")},
   {"integer-permutation64", STELA_AIR_REVERSE_BODY("i64", "i64", "4")
      STELA_AIR_SWAP_BODY("i64", "i64", "4") "ret void\n",
      STELA_AIR_REVERSE_DECL("i64", "i64") STELA_AIR_SWAP_DECL("i64", "i64")},
   {"integer-permutation8x2", STELA_AIR_REVERSE_BODY("<2 x i8>", "v2i8", "1") "ret void\n",
      STELA_AIR_REVERSE_DECL("<2 x i8>", "v2i8")},
   {"integer-permutation16x3", STELA_AIR_REVERSE_BODY("<3 x i16>", "v3i16", "2")
      STELA_AIR_SWAP_BODY("<3 x i16>", "v3i16", "2") "ret void\n",
      STELA_AIR_REVERSE_DECL("<3 x i16>", "v3i16") STELA_AIR_SWAP_DECL("<3 x i16>", "v3i16")},
   {"integer-permutation32x4", STELA_AIR_REVERSE_BODY("<4 x i32>", "v4i32", "4")
      STELA_AIR_SWAP_BODY("<4 x i32>", "v4i32", "4") "ret void\n",
      STELA_AIR_REVERSE_DECL("<4 x i32>", "v4i32") STELA_AIR_SWAP_DECL("<4 x i32>", "v4i32")},
   {"integer-permutation64x3", STELA_AIR_REVERSE_BODY("<3 x i64>", "v3i64", "4")
      STELA_AIR_SWAP_BODY("<3 x i64>", "v3i64", "4") "ret void\n",
      STELA_AIR_REVERSE_DECL("<3 x i64>", "v3i64") STELA_AIR_SWAP_DECL("<3 x i64>", "v3i64")},
};

#undef STELA_AIR_REVERSE_BODY
#undef STELA_AIR_SWAP_BODY
#undef STELA_AIR_REVERSE_DECL
#undef STELA_AIR_SWAP_DECL
#endif
