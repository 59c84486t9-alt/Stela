/*
 * Copyright (C) 2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef UTIL_BITPACK_UINT_H
#define UTIL_BITPACK_UINT_H

/* Shared integer-only packing primitives. The includer supplies the same scalar
 * types, attributes, assertion and validation hooks as bitpack_helpers.h.
 */
ALWAYS_INLINE static uint64_t
util_bitpack_ones(uint32_t start, uint32_t end)
{
   return (UINT64_MAX >> (64 - (end - start + 1))) << start;
}

ALWAYS_INLINE static uint64_t
util_bitpack_uint(uint64_t v, uint32_t start, UNUSED uint32_t end)
{
   util_bitpack_validate_value(v);

#ifndef NDEBUG
   const int bits = end - start + 1;
   if (bits < 64) {
      const uint64_t max = u_uintN_max(bits);
      assert(v <= max);
   }
#endif

   return v << start;
}

ALWAYS_INLINE static uint64_t
util_bitpack_uint_nonzero(uint64_t v, uint32_t start, uint32_t end)
{
   assert(v != 0ull);
   return util_bitpack_uint(v, start, end);
}

#endif
