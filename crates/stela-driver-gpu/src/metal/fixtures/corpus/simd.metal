// SPDX-License-Identifier: MIT
// SIMD-group, quad-group and threadgroup collectives, and SIMD-group
// matrices.
#include <metal_stdlib>
using namespace metal;

kernel void simdgroups(device float *data [[buffer(0)]], device uint *bits [[buffer(1)]],
                       uint tid [[thread_position_in_grid]], uint lane [[thread_index_in_simdgroup]],
                       uint simd [[simdgroup_index_in_threadgroup]],
                       uint width [[threads_per_simdgroup]], uint quad_lane [[thread_index_in_quadgroup]])
{
    float x = data[tid];
    float r = simd_sum(x) + simd_product(x) + simd_min(x) + simd_max(x);
    r += simd_prefix_exclusive_sum(x) + simd_prefix_inclusive_sum(x) + simd_prefix_exclusive_product(x);
    r += simd_shuffle(x, lane ^ 1) + simd_shuffle_xor(x, 2) + simd_shuffle_up(x, 1) + simd_shuffle_down(x, 1);
    r += simd_shuffle_rotate_down(x, 3) + simd_shuffle_and_fill_up(x, r, 2) + simd_broadcast(x, 0);
    r += simd_broadcast_first(x) + float(simd_is_first());
    simd_vote vote = simd_ballot(x > 0.0f);
    uint u = uint(static_cast<simd_vote::vote_t>(vote)) + uint(simd_all(x > 0.0f)) + uint(simd_any(x < 0.0f));
    uint b = bits[tid];
    u += simd_and(b) + simd_or(b) + simd_xor(b) + simd_sum(b) + simd_max(b);
    r += quad_sum(x) + quad_shuffle(x, quad_lane ^ 1) + quad_shuffle_xor(x, 1) + quad_broadcast(x, 0);
    r += quad_prefix_exclusive_sum(x) + quad_min(x) + float(quad_all(x > 0.0f));
    simdgroup_barrier(mem_flags::mem_none);
    threadgroup_barrier(mem_flags::mem_device | mem_flags::mem_threadgroup);
    data[tid] = r + float(simd) + float(width);
    bits[tid] = u;
}

kernel void simd_matrices(device const float *a [[buffer(0)]], device const half *b [[buffer(1)]],
                          device float *c [[buffer(2)]])
{
    simdgroup_float8x8 x, y, z = make_filled_simdgroup_matrix<float, 8, 8>(1.0f);
    simdgroup_load(x, a, 8);
    simdgroup_load(y, a + 64, 8, ulong2(0), true);
    simdgroup_multiply_accumulate(z, x, y, z);
    simdgroup_multiply(z, z, x);
    simdgroup_half8x8 h;
    simdgroup_load(h, b, 8);
    simdgroup_float8x8 w;
    simdgroup_multiply(w, h, h);
    simdgroup_store(z, c, 8);
    simdgroup_store(w, c + 64, 8);
}
