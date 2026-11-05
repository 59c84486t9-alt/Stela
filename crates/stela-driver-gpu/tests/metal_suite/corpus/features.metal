// SPDX-License-Identifier: MIT
// Compute features the other sources leave out, chosen by which AIR
// intrinsics macOS's own shaders call (`metal-suite coverage`): vector
// relational reductions, device atomic stores behind a fence, threadgroup
// atomic bitwise operations, SIMD-group barriers, the remaining quad-group
// functions, null textures, pixel storage types, uniform values, diagonal
// SIMD-group matrices and bfloat vectors.
#include <metal_stdlib>
using namespace metal;

// all and any over boolean vectors of each width, 8 words per thread.
kernel void relational(device const int4 *in [[buffer(0)]], device uint *out [[buffer(1)]],
                       uint i [[thread_position_in_grid]])
{
    int4 v = in[i];
    device uint *o = out + i * 8;
    o[0] = all(v > 0);
    o[1] = any(v > 0);
    o[2] = all(v.xy == v.zw);
    o[3] = any(v.xyz < -5);
    o[4] = all(v.xyz != int3(0));
    o[5] = any(bool4(v & 1));
    o[6] = all(bool2(v.xy));
    o[7] = any(bool3(v.yzw)) ? 7u : 9u;
}

// Each thread stores its data plainly, fences, then publishes a flag
// with an atomic store; the flag and data are read back through atomic
// and plain loads.
kernel void atomic_store_fence(device const uint *in [[buffer(0)]], device uint *data [[buffer(1)]],
                               device atomic_uint *flags [[buffer(2)]], device atomic_int *signed_flags [[buffer(3)]],
                               device uint *out [[buffer(4)]], uint i [[thread_position_in_grid]])
{
    uint v = in[i];
    data[i] = v * 5u + 3u;
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, thread_scope_device);
    atomic_store_explicit(&flags[i], v ^ 0x5a5a5a5au, memory_order_relaxed);
    atomic_store_explicit(&signed_flags[i], -int(v % 1000), memory_order_relaxed);
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, thread_scope_device);
    out[i * 2] = atomic_load_explicit(&flags[i], memory_order_relaxed) + data[i];
    out[i * 2 + 1] = uint(atomic_load_explicit(&signed_flags[i], memory_order_relaxed));
}

// Threadgroup atomic or, and and xor over every thread of a group.
kernel void atomics_threadgroup_bits(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                                     uint id [[thread_position_in_grid]], uint local [[thread_index_in_threadgroup]],
                                     uint group [[threadgroup_position_in_grid]])
{
    threadgroup atomic_uint bits[3];
    if (local == 0) {
        atomic_store_explicit(&bits[0], 0u, memory_order_relaxed);
        atomic_store_explicit(&bits[1], 0xFFFFFFFFu, memory_order_relaxed);
        atomic_store_explicit(&bits[2], 0u, memory_order_relaxed);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint v = in[id];
    atomic_fetch_or_explicit(&bits[0], v & (0x01010101u << (local % 8)), memory_order_relaxed);
    atomic_fetch_and_explicit(&bits[1], v | 0x0F0F0F0Fu, memory_order_relaxed);
    atomic_fetch_xor_explicit(&bits[2], v, memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (local < 3)
        out[group * 3 + local] = atomic_load_explicit(&bits[local], memory_order_relaxed);
}

// A SIMD-group barrier orders threadgroup memory within a SIMD group:
// each thread reads what another lane of its group wrote.
kernel void simdgroup_exchange(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                               uint id [[thread_position_in_grid]], uint local [[thread_index_in_threadgroup]],
                               uint lane [[thread_index_in_simdgroup]])
{
    threadgroup uint scratch[64];
    scratch[local] = in[id] * 3u + 1u;
    simdgroup_barrier(mem_flags::mem_threadgroup);
    out[id] = scratch[local - lane + (lane + 13) % 32];
}

#ifndef SKIP_quad_more
// The quad-group functions quad_functions leaves out, 20 words per thread.
kernel void quad_more(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                      uint id [[thread_position_in_grid]])
{
    uint v = in[id];
    int s = int(v) - 300;
    device uint *o = out + id * 20;
    o[0] = quad_shuffle_up(v, 1);
    o[1] = quad_shuffle_down(v, 2);
    o[2] = quad_shuffle_rotate_up(v, 1);
    o[3] = quad_shuffle_rotate_down(v, 3);
    o[4] = quad_shuffle_and_fill_up(v, v + 1000, 1);
    o[5] = quad_shuffle_and_fill_down(v, v + 1000, 2);
    o[6] = quad_and(v | 0xF0u);
    o[7] = quad_or(v & 0x30u);
    o[8] = quad_xor(v);
    o[9] = quad_product(v % 5 + 1);
    o[10] = quad_prefix_exclusive_sum(v);
    o[11] = quad_prefix_inclusive_product(v % 3 + 1);
    o[12] = quad_prefix_exclusive_product(v % 3 + 1);
    o[13] = quad_broadcast_first(v);
    o[14] = uint(quad_all(v < 500)) | uint(quad_any(v > 550)) << 1 | uint(quad_is_first()) << 2;
    o[15] = uint(static_cast<quad_vote::vote_t>(quad_active_threads_mask()));
    o[16] = uint(quad_sum(s));
    o[17] = uint(quad_min(s));
    o[18] = as_type<uint>(quad_sum(float(v % 64) * 0.25f));
    o[19] = as_type<uint>(quad_max(float(s) * 0.5f));
}
#endif

#ifndef SKIP_null_textures
// Textures chosen at run time between a bound one and a null one.
kernel void null_textures(texture2d<float> bound [[texture(0)]], texture2d_array<float> layers [[texture(1)]],
                          texturecube<float> cube [[texture(2)]], texture3d<float> volume [[texture(3)]],
                          device const uint *pick [[buffer(0)]], device uint *out [[buffer(1)]],
                          uint i [[thread_position_in_grid]])
{
    bool use = pick[i] != 0;
    texture2d<float> a = use ? bound : texture2d<float>();
    texture2d_array<float> b = use ? layers : texture2d_array<float>();
    texturecube<float> c = use ? cube : texturecube<float>();
    texture3d<float> d = use ? volume : texture3d<float>();
    depth2d<float> e = depth2d<float>();
    out[i * 2] = uint(is_null_texture(a)) | uint(is_null_texture(b)) << 1 | uint(is_null_texture(c)) << 2 |
                 uint(is_null_texture(d)) << 3 | uint(is_null_texture(e)) << 4;
    out[i * 2 + 1] = is_null_texture(a) ? 0xFFFFu : uint(a.read(uint2(i % 4, 0)).x * 255.0f + 0.5f);
}
#endif

#ifndef SKIP_pixel_unpack
// Pixel storage types in device memory read as floats.
kernel void pixel_unpack(device const rgba8unorm<float4> *a [[buffer(0)]], device const srgba8unorm<float4> *b [[buffer(1)]],
                         device const rgb10a2<float4> *c [[buffer(2)]], device const rg11b10f<float3> *d [[buffer(3)]],
                         device const rgb9e5<float3> *e [[buffer(4)]], device const rg16snorm<float2> *f [[buffer(5)]],
                         device float4 *oa [[buffer(6)]], device float4 *ob [[buffer(7)]], device float4 *oc [[buffer(8)]],
                         device float4 *od [[buffer(9)]], device float4 *oe [[buffer(10)]], device float4 *of [[buffer(11)]],
                         uint i [[thread_position_in_grid]])
{
    oa[i] = a[i];
    ob[i] = b[i];
    oc[i] = c[i];
    od[i] = float4(float3(d[i]), 0.0f);
    oe[i] = float4(float3(e[i]), 0.0f);
    of[i] = float4(float2(f[i]), 0.0f, 0.0f);
}
#endif

#ifndef SKIP_pixel_pack
// Floats stored through pixel storage types.
kernel void pixel_pack(device const float4 *in [[buffer(0)]], device rgba8unorm<float4> *a [[buffer(1)]],
                       device srgba8unorm<float4> *b [[buffer(2)]], device rgb10a2<float4> *c [[buffer(3)]],
                       device rg11b10f<float3> *d [[buffer(4)]], device rgb9e5<float3> *e [[buffer(5)]],
                       device rg16snorm<float2> *f [[buffer(6)]], uint i [[thread_position_in_grid]])
{
    float4 v = in[i * 6];
    a[i] = v;
    b[i] = in[i * 6 + 1];
    c[i] = in[i * 6 + 2];
    d[i] = in[i * 6 + 3].xyz;
    e[i] = in[i * 6 + 4].xyz;
    f[i] = in[i * 6 + 5].xy;
}
#endif

#ifndef SKIP_uniform_values
// A value every thread holds alike, declared so.
kernel void uniform_values(device const uint *in [[buffer(0)]], constant uint &k [[buffer(1)]],
                           device uint *out [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    uniform<uint> u = make_uniform(k * 2u);
    uint sum = 0;
    for (uint j = 0; j < u; j++)
        sum += in[(i + j) % 64];
    out[i] = sum;
}
#endif

#ifndef SKIP_simdgroup_diagonal
// A diagonal SIMD-group matrix times a loaded one, and a filled matrix.
kernel void simdgroup_diagonal(device const float *b [[buffer(0)]], device float *out [[buffer(1)]])
{
    simdgroup_float8x8 d = simdgroup_float8x8(2.5f);
    simdgroup_float8x8 m, r;
    simdgroup_load(m, b, 8);
    simdgroup_multiply(r, d, m);
    simdgroup_store(r, out, 8);
    simdgroup_float8x8 filled = make_filled_simdgroup_matrix<float, 8, 8>(-1.5f);
    simdgroup_store(filled, out + 64, 8);
}
#endif

#ifndef SKIP_bfloat_vectors
// bfloat vectors: narrowed from float, widened back and converted to half.
kernel void bfloat_vectors(device const float4 *in [[buffer(0)]], device ushort4 *narrow [[buffer(1)]],
                           device float4 *wide [[buffer(2)]], device half4 *halves [[buffer(3)]],
                           device ushort2 *pairs [[buffer(4)]], uint i [[thread_position_in_grid]])
{
    bfloat4 b = bfloat4(in[i]);
    narrow[i] = as_type<ushort4>(b);
    wide[i] = float4(b);
    halves[i] = half4(b);
    pairs[i] = as_type<ushort2>(bfloat2(in[i].zw));
}
#endif

// Quad-group indices of a thread within its threadgroup.
kernel void quadgroup_ids(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]],
                          ushort quad [[quadgroup_index_in_threadgroup]],
                          ushort quads [[quadgroups_per_threadgroup]],
                          ushort lane [[thread_index_in_quadgroup]])
{ out[i] = uint(quad) << 16 | uint(quads) << 8 | uint(lane); }
