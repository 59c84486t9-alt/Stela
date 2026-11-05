// SPDX-License-Identifier: MIT
// Compute: dispatch builtins, threadgroup memory and barriers, device and
// threadgroup atomics, SIMD-group and quad-group functions, SIMD-group
// matrices, memory layouts and control flow. Every result is a function of
// the thread's indices and its inputs, so the host computes each exactly.
#include <metal_stdlib>
using namespace metal;

// Every position builtin of a thread, 16 words per thread.
kernel void builtins(device uint *out [[buffer(0)]],
                     uint3 grid_pos [[thread_position_in_grid]],
                     uint3 group_pos [[threadgroup_position_in_grid]],
                     uint3 local_pos [[thread_position_in_threadgroup]],
                     uint3 group_size [[threads_per_threadgroup]],
                     uint3 groups [[threadgroups_per_grid]],
                     uint3 grid_size [[threads_per_grid]],
                     uint local_index [[thread_index_in_threadgroup]],
                     uint simd_lane [[thread_index_in_simdgroup]],
                     uint simd_group [[simdgroup_index_in_threadgroup]],
                     uint simd_size [[threads_per_simdgroup]],
                     uint simd_groups [[simdgroups_per_threadgroup]])
{
    uint id = (grid_pos.z * grid_size.y + grid_pos.y) * grid_size.x + grid_pos.x;
    device uint *o = out + id * 16;
    o[0] = grid_pos.x; o[1] = grid_pos.y; o[2] = grid_pos.z;
    o[3] = group_pos.x; o[4] = group_pos.y; o[5] = group_pos.z;
    o[6] = local_pos.x; o[7] = local_pos.y; o[8] = local_pos.z;
    o[9] = group_size.x * 10000 + group_size.y * 100 + group_size.z;
    o[10] = groups.x * 10000 + groups.y * 100 + groups.z;
    o[11] = grid_size.x * 10000 + grid_size.y * 100 + grid_size.z;
    o[12] = local_index;
    o[13] = simd_lane + simd_group * simd_size;
    o[14] = simd_size;
    o[15] = simd_groups;
}

// A tree reduction through threadgroup memory with barriers: each group's
// sum, and every partial the tree computed.
kernel void reduce_threadgroup(device const uint *in [[buffer(0)]], device uint *sums [[buffer(1)]],
                               device uint *partials [[buffer(2)]],
                               threadgroup uint *scratch [[threadgroup(0)]],
                               uint id [[thread_position_in_grid]], uint local [[thread_index_in_threadgroup]],
                               uint group [[threadgroup_position_in_grid]], uint size [[threads_per_threadgroup]])
{
    scratch[local] = in[id];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint stride = size / 2; stride > 0; stride /= 2) {
        if (local < stride)
            scratch[local] += scratch[local + stride];
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    partials[id] = scratch[local];
    if (local == 0)
        sums[group] = scratch[0];
}

// A static threadgroup array of float4 written transposed and read back,
// with a barrier between: every thread reads another thread's write.
kernel void threadgroup_transpose(device const float4 *in [[buffer(0)]], device float4 *out [[buffer(1)]],
                                  uint2 local [[thread_position_in_threadgroup]],
                                  uint2 group [[threadgroup_position_in_grid]])
{
    threadgroup float4 tile[16][17];
    uint2 base = group * 16;
    tile[local.y][local.x] = in[(base.y + local.y) * 64 + base.x + local.x];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    out[(base.y + local.y) * 64 + base.x + local.x] = tile[local.x][local.y] * 2.0f + float4(local.x, local.y, 0, 1);
}

// Device atomics of every operation on int and uint: each thread applies
// its value to one of 8 counters; the counters' final values are exact.
kernel void atomics_device(device const uint *in [[buffer(0)]], device atomic_uint *u [[buffer(1)]],
                           device atomic_int *s [[buffer(2)]], uint id [[thread_position_in_grid]])
{
    uint v = in[id];
    uint slot = id % 8;
    atomic_fetch_add_explicit(&u[slot * 8 + 0], v, memory_order_relaxed);
    atomic_fetch_sub_explicit(&u[slot * 8 + 1], v, memory_order_relaxed);
    atomic_fetch_and_explicit(&u[slot * 8 + 2], v | 0x0f0f0f0fu, memory_order_relaxed);
    atomic_fetch_or_explicit(&u[slot * 8 + 3], v & 0x10101010u, memory_order_relaxed);
    atomic_fetch_xor_explicit(&u[slot * 8 + 4], v, memory_order_relaxed);
    atomic_fetch_min_explicit(&u[slot * 8 + 5], v, memory_order_relaxed);
    atomic_fetch_max_explicit(&u[slot * 8 + 6], v, memory_order_relaxed);
    // A maximum through compare-and-exchange.
    uint expected = atomic_load_explicit(&u[slot * 8 + 7], memory_order_relaxed);
    while (expected < v && !atomic_compare_exchange_weak_explicit(&u[slot * 8 + 7], &expected, v,
                                                                   memory_order_relaxed, memory_order_relaxed)) {
    }
    int w = int(v) - int(0x80000000u);
    atomic_fetch_add_explicit(&s[slot * 4 + 0], w >> 8, memory_order_relaxed);
    atomic_fetch_min_explicit(&s[slot * 4 + 1], w, memory_order_relaxed);
    atomic_fetch_max_explicit(&s[slot * 4 + 2], w, memory_order_relaxed);
    atomic_fetch_sub_explicit(&s[slot * 4 + 3], w >> 8, memory_order_relaxed);
}

// The values fetch-add returned: a permutation of the prefix sums, so
// sorted they are exact.
kernel void atomics_returns(device atomic_uint *counter [[buffer(0)]], device uint *seen [[buffer(1)]],
                            uint id [[thread_position_in_grid]])
{
    seen[id] = atomic_fetch_add_explicit(counter, (id % 5) + 1, memory_order_relaxed) * 8 + (id % 5);
}

// Exchange returns every value once: the old values and the final value
// together are the inputs and the initial value.
kernel void atomics_exchange(device atomic_uint *cell [[buffer(0)]], device uint *seen [[buffer(1)]],
                             uint id [[thread_position_in_grid]])
{
    seen[id] = atomic_exchange_explicit(cell, id + 1, memory_order_relaxed);
}

// Threadgroup atomics: a histogram of each group's values, then copied out.
kernel void atomics_threadgroup(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                                uint id [[thread_position_in_grid]], uint local [[thread_index_in_threadgroup]],
                                uint group [[threadgroup_position_in_grid]])
{
    threadgroup atomic_uint bins[16];
    threadgroup atomic_int extremes[2];
    if (local < 16)
        atomic_store_explicit(&bins[local], 0, memory_order_relaxed);
    if (local == 0) {
        atomic_store_explicit(&extremes[0], INT_MAX, memory_order_relaxed);
        atomic_store_explicit(&extremes[1], INT_MIN, memory_order_relaxed);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint v = in[id];
    atomic_fetch_add_explicit(&bins[v % 16], 1, memory_order_relaxed);
    atomic_fetch_min_explicit(&extremes[0], int(v) - 1000, memory_order_relaxed);
    atomic_fetch_max_explicit(&extremes[1], int(v) - 1000, memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (local < 16)
        out[group * 18 + local] = atomic_load_explicit(&bins[local], memory_order_relaxed);
    if (local < 2)
        out[group * 18 + 16 + local] = uint(atomic_load_explicit(&extremes[local], memory_order_relaxed));
}

#ifndef SKIP_atomics_float
// Float atomic add (Metal 3): sums of small integers, exact in any order.
kernel void atomics_float(device const float *in [[buffer(0)]], device atomic_float *sums [[buffer(1)]],
                          uint id [[thread_position_in_grid]])
{
    atomic_fetch_add_explicit(&sums[id % 4], in[id], memory_order_relaxed);
}
#endif

// SIMD-group functions over a full group, 24 words per thread.
kernel void simd_functions(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                           uint id [[thread_position_in_grid]], uint lane [[thread_index_in_simdgroup]])
{
    uint v = in[id];
    int s = int(v) - 50;
    float f = float(v % 64);
    device uint *o = out + id * 24;
    o[0] = simd_sum(v);
    o[1] = simd_product(v % 3 + 1);
    o[2] = simd_min(v);
    o[3] = simd_max(v);
    o[4] = simd_and(v | 0xf0u);
    o[5] = simd_or(v & 0x30u);
    o[6] = simd_xor(v);
    o[7] = simd_prefix_inclusive_sum(v);
    o[8] = simd_prefix_exclusive_sum(v);
    o[9] = simd_prefix_exclusive_product(v % 2 + 1);
    o[10] = simd_shuffle(v, (lane * 7 + 3) % 32);
    o[11] = simd_shuffle_up(v, 3);
    o[12] = simd_shuffle_down(v, 5);
    o[13] = simd_shuffle_xor(v, 9);
    o[14] = simd_broadcast(v, 17);
    o[15] = simd_broadcast_first(v);
    o[16] = uint(uint64_t(simd_ballot((v & 1) != 0)));
    o[17] = uint(simd_all(v < 1000)) | uint(simd_any(v == in[id - lane])) << 1 | uint(simd_is_first()) << 2;
    o[18] = as_type<uint>(simd_sum(f));
    o[19] = as_type<uint>(simd_prefix_inclusive_sum(f));
    o[20] = as_type<uint>(simd_max(f));
    o[21] = uint(simd_min(s));
    o[22] = uint(simd_sum(s));
    o[23] = uint(simd_prefix_inclusive_product(s % 2 == 0 ? 1 : -1));
}

#ifndef SKIP_simd_rotate
kernel void simd_rotate(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                        uint id [[thread_position_in_grid]])
{
    uint v = in[id];
    out[id * 4 + 0] = simd_shuffle_rotate_up(v, 5);
    out[id * 4 + 1] = simd_shuffle_rotate_down(v, 11);
    out[id * 4 + 2] = simd_shuffle_and_fill_up(v, v + 1000, 4);
    out[id * 4 + 3] = simd_shuffle_and_fill_down(v, v + 1000, 6);
}
#endif

// SIMD-group functions in divergent control flow: only every third lane
// takes part, so reductions and ballots see a partial group.
kernel void simd_divergent(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                           uint id [[thread_position_in_grid]], uint lane [[thread_index_in_simdgroup]])
{
    uint v = in[id];
    device uint *o = out + id * 6;
    o[0] = o[1] = o[2] = o[3] = o[4] = o[5] = 0xdeadbeefu;
    if (lane % 3 == 0) {
        o[0] = simd_sum(v);
        o[1] = simd_prefix_exclusive_sum(v);
        o[2] = uint(static_cast<simd_vote::vote_t>(simd_ballot(true)));
        o[3] = uint(static_cast<simd_vote::vote_t>(simd_active_threads_mask()));
        o[4] = simd_broadcast_first(v);
        o[5] = simd_max(v);
    }
}

// Quad-group functions, 8 words per thread.
kernel void quad_functions(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                           uint id [[thread_position_in_grid]], uint lane [[thread_index_in_quadgroup]])
{
    uint v = in[id];
    device uint *o = out + id * 8;
    o[0] = quad_sum(v);
    o[1] = quad_min(v);
    o[2] = quad_max(v);
    o[3] = quad_prefix_inclusive_sum(v);
    o[4] = quad_shuffle(v, (lane + 1) % 4);
    o[5] = quad_shuffle_xor(v, 2);
    o[6] = quad_broadcast(v, 3);
    o[7] = uint(static_cast<quad_vote::vote_t>(quad_ballot((v & 1) != 0))) | lane << 8;
}

#ifndef SKIP_simdgroup_matrix
// An 8x8 SIMD-group matrix product, A * B + C, in float and half.
kernel void simdgroup_matrix(device const float *a [[buffer(0)]], device const float *b [[buffer(1)]],
                             device float *out [[buffer(2)]], device half *out_half [[buffer(3)]],
                             device const half *ah [[buffer(4)]], device const half *bh [[buffer(5)]])
{
    simdgroup_float8x8 ma, mb, mc;
    simdgroup_load(ma, a, 8);
    simdgroup_load(mb, b, 8);
    simdgroup_load(mc, a, 8, ulong2(0, 0), true);
    simdgroup_multiply_accumulate(mc, ma, mb, mc);
    simdgroup_store(mc, out, 8);
    simdgroup_half8x8 ha, hb, hc;
    simdgroup_load(ha, ah, 8);
    simdgroup_load(hb, bh, 8);
    simdgroup_multiply(hc, ha, hb);
    simdgroup_store(hc, out_half, 8);
}
#endif

struct Mixed {
    char c;
    short s;
    float3 v;     // 16-byte aligned, 16 bytes
    packed_float3 p;
    half h;
    uchar4 u;
    float2x2 m;
};

// Device memory of mixed layouts: a struct with padding, packed vectors,
// byte and short arrays, constant and program-scope data and a thread
// array indexed at run time.
constant float table[8] = {1.5f, -2.0f, 3.25f, 0.0f, -7.0f, 11.0f, 0.125f, 1e10f};

kernel void memory_layouts(device const Mixed *in [[buffer(0)]], device Mixed *out [[buffer(1)]],
                           device const uchar *bytes [[buffer(2)]], device ushort *shorts [[buffer(3)]],
                           constant float4 &k [[buffer(4)]], device float *scalars [[buffer(5)]],
                           uint id [[thread_position_in_grid]])
{
    Mixed m = in[id];
    m.c = char(m.c * 3 + 1);
    m.s = short(m.s - id);
    m.v = m.v.zxy * k.x;
    m.p = packed_float3(float3(m.p) + float3(m.v));
    m.h = m.h * half(2);
    m.u = m.u.wzyx + uchar4(id);
    m.m = transpose(m.m);
    out[id] = m;
    shorts[id] = ushort(bytes[id * 3]) | ushort(bytes[id * 3 + 1]) << 8;
    float local[16];
    for (uint i = 0; i < 16; i++)
        local[i] = float(i * id) + table[i % 8];
    scalars[id] = local[id % 16] + local[(id * 7) % 16] * k.y + table[id % 8];
}

// Control flow: nested loops with break and continue, a switch, early
// return and a value-dependent while loop.
static uint collatz(uint n)
{
    uint steps = 0;
    while (n != 1 && steps < 500) {
        n = (n & 1) ? n * 3 + 1 : n / 2;
        steps++;
    }
    return steps;
}

kernel void control_flow(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                         uint id [[thread_position_in_grid]])
{
    uint v = in[id];
    if (v % 17 == 0) {
        out[id * 4] = 0xffffffffu;
        out[id * 4 + 1] = out[id * 4 + 2] = out[id * 4 + 3] = 0;
        return;
    }
    uint acc = 0;
    for (uint i = 0; i < v % 13; i++) {
        if (i == 7)
            break;
        for (uint j = 0; j < 5; j++) {
            if ((i + j) % 3 == 0)
                continue;
            acc += i * j + 1;
        }
    }
    uint s;
    switch (v % 6) {
    case 0: s = 10; break;
    case 1: s = acc; break;
    case 2:
    case 3: s = acc * 2 + v; break;
    default: s = 99;
    }
    out[id * 4] = acc;
    out[id * 4 + 1] = s;
    out[id * 4 + 2] = collatz(v % 1000 + 1);
    out[id * 4 + 3] = v > 500 ? (v < 700 ? 1u : 2u) : 3u;
}
