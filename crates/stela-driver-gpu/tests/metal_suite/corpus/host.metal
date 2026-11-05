// SPDX-License-Identifier: MIT
// The shaders host cases run: drawing into drawables, reading and writing
// IOSurface planes, archived pipelines, ordered and concurrent counting,
// and stamping a buffer past 4 GiB.
#include <metal_stdlib>
using namespace metal;

struct Position {
    float4 position [[position]];
};

// The left half of the target, as a strip.
vertex Position vert_left_half(uint v [[vertex_id]])
{
    return {float4(v & 1 ? 0.0f : -1.0f, v & 2 ? 1.0f : -1.0f, 0.0f, 1.0f)};
}

fragment float4 frag_constant(constant float4 &color [[buffer(0)]])
{
    return color;
}

struct Tinted {
    float4 position [[position]];
    float4 tint [[user(tint)]];
};

// Reads a varying the vertex function never writes: linking fails.
fragment float4 frag_unwritten_input(Tinted in [[stage_in]])
{
    return in.tint;
}

kernel void surface_invert(texture2d<float, access::read> src [[texture(0)]],
                           texture2d<float, access::write> dst [[texture(1)]],
                           uint2 p [[thread_position_in_grid]])
{
    float4 v = src.read(p);
    dst.write(float4(1.0f - v.rgb, v.a), p);
}

// Luma with the chroma pair of each 2x2 block, as bytes of one word.
kernel void surface_planes(texture2d<float, access::read> luma [[texture(0)]],
                           texture2d<float, access::read> chroma [[texture(1)]],
                           device uint *out [[buffer(0)]],
                           uint2 p [[thread_position_in_grid]], uint2 n [[threads_per_grid]])
{
    float y = luma.read(p).r;
    float2 uv = chroma.read(p / 2).rg;
    out[p.y * n.x + p.x] = uint(rint(y * 255.0f)) | uint(rint(uv.x * 255.0f)) << 8 | uint(rint(uv.y * 255.0f)) << 16;
}

kernel void archived(device uint *data [[buffer(0)]], constant uint &unused [[buffer(1)]], uint i [[thread_position_in_grid]])
{
    data[i] = data[i] * 3u + 1u;
}

kernel void not_archived(device uint *data [[buffer(0)]], uint i [[thread_position_in_grid]])
{
    data[i] = 0u;
}

kernel void append_digit(device uint *value [[buffer(0)]], constant uint &digit [[buffer(1)]])
{
    value[0] = value[0] * 10u + digit;
}

kernel void bump(device uint *counts [[buffer(0)]], constant uint &slot [[buffer(1)]])
{
    counts[slot] += 1u;
}

kernel void bump_atomic(device atomic_uint *counts [[buffer(0)]], constant uint &slot [[buffer(1)]])
{
    atomic_fetch_add_explicit(&counts[slot], 1u, memory_order_relaxed);
}

kernel void stamp(device uint *big [[buffer(0)]], constant uint &first [[buffer(1)]], uint i [[thread_position_in_grid]])
{
    big[first + i] = first + i;
}

// Each thread's hash of its position, reduced in threadgroup memory and
// then once per group into a sum, an xor, a count and the largest y.
kernel void grid_hash(device atomic_uint *sums [[buffer(0)]], threadgroup atomic_uint *local [[threadgroup(0)]],
                      uint3 p [[thread_position_in_grid]], uint l [[thread_index_in_threadgroup]])
{
    if (l < 4)
        atomic_store_explicit(&local[l], 0u, memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint h = (p.x * 0x9E3779B1u) ^ (p.y * 0x85EBCA77u) ^ (p.z * 0xC2B2AE3Du);
    atomic_fetch_add_explicit(&local[0], h, memory_order_relaxed);
    atomic_fetch_xor_explicit(&local[1], h, memory_order_relaxed);
    atomic_fetch_add_explicit(&local[2], 1u, memory_order_relaxed);
    atomic_fetch_max_explicit(&local[3], p.y + p.z, memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (l == 0)
        atomic_fetch_add_explicit(&sums[0], atomic_load_explicit(&local[0], memory_order_relaxed), memory_order_relaxed);
    if (l == 1)
        atomic_fetch_xor_explicit(&sums[1], atomic_load_explicit(&local[1], memory_order_relaxed), memory_order_relaxed);
    if (l == 2)
        atomic_fetch_add_explicit(&sums[2], atomic_load_explicit(&local[2], memory_order_relaxed), memory_order_relaxed);
    if (l == 3)
        atomic_fetch_max_explicit(&sums[3], atomic_load_explicit(&local[3], memory_order_relaxed), memory_order_relaxed);
}
