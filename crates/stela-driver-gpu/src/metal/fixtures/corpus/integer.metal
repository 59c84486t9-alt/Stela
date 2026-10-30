// SPDX-License-Identifier: MIT
// Integer arithmetic and bit functions over every integer width.
#include <metal_stdlib>
using namespace metal;

template <typename T>
static T bits(T x, T y)
{
    T r = x * y + x / (y | 1) + x % (y | 1) + (x << 3) + (x >> 2);
    r += clz(x) + ctz(y) + popcount(x) + reverse_bits(y) + rotate(x, y);
    r += mulhi(x, y) + madhi(x, y, r) + madsat(x, y, r);
    r += addsat(x, y) + subsat(x, y) + hadd(x, y) + rhadd(x, y) + T(absdiff(x, y));
    r += min(x, y) + max(x, y) + clamp(x, y, r) + min3(x, y, r) + max3(x, y, r) + median3(x, y, r);
    r += extract_bits(x, 3, 5) + insert_bits(x, y, 2, 7);
    return r;
}

kernel void integers(device int4 *i32 [[buffer(0)]], device uint4 *u32 [[buffer(1)]],
                     device short4 *i16 [[buffer(2)]], device ushort4 *u16 [[buffer(3)]],
                     device char4 *i8 [[buffer(4)]], device uchar4 *u8 [[buffer(5)]],
                     device long2 *i64 [[buffer(6)]], device ulong2 *u64 [[buffer(7)]],
                     uint tid [[thread_position_in_grid]])
{
    i32[tid] = bits(i32[tid], i32[tid + 1]) + abs(i32[tid]);
    u32[tid] = bits(u32[tid], u32[tid + 1]) + mul24(u32[tid], u32[tid + 2]) +
               mad24(u32[tid], u32[tid + 1], u32[tid + 2]);
    i16[tid] = bits(i16[tid], i16[tid + 1]);
    u16[tid] = bits(u16[tid], u16[tid + 1]);
    i8[tid] = bits(i8[tid], i8[tid + 1]);
    u8[tid] = bits(u8[tid], u8[tid + 1]);
    long2 a = i64[tid], b = i64[tid + 1];
    i64[tid] = a * b + a / (b | 1) + (a << 7) + popcount(a) + clz(b) + mulhi(a, b);
    ulong2 c = u64[tid], d = u64[tid + 1];
    u64[tid] = c * d + c % (d | 1) + (c >> 9) + ctz(c) + max(c, d) + rotate(c, d);
}
