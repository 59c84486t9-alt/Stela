// SPDX-License-Identifier: MIT
// Atomic operations on device and threadgroup memory.
#include <metal_stdlib>
using namespace metal;

kernel void atomics(device atomic_int *ints [[buffer(0)]], device atomic_uint *uints [[buffer(1)]],
                    device atomic_float *floats [[buffer(2)]], device atomic_ulong *longs [[buffer(3)]],
                    device int *out [[buffer(4)]], uint tid [[thread_position_in_grid]],
                    uint lid [[thread_index_in_threadgroup]])
{
    threadgroup atomic_int shared[64];
    atomic_store_explicit(&shared[lid], int(tid), memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    int r = atomic_fetch_add_explicit(&ints[0], 1, memory_order_relaxed);
    r += atomic_fetch_sub_explicit(&ints[1], 2, memory_order_relaxed);
    r += atomic_fetch_min_explicit(&ints[2], r, memory_order_relaxed);
    r += atomic_fetch_max_explicit(&ints[3], r, memory_order_relaxed);
    r += atomic_fetch_and_explicit(&ints[4], r, memory_order_relaxed);
    r += atomic_fetch_or_explicit(&ints[5], r, memory_order_relaxed);
    r += atomic_fetch_xor_explicit(&ints[6], r, memory_order_relaxed);
    r += atomic_exchange_explicit(&ints[7], r, memory_order_relaxed);
    int expected = r;
    atomic_compare_exchange_weak_explicit(&ints[8], &expected, r + 1, memory_order_relaxed,
                                          memory_order_relaxed);
    r += expected + atomic_load_explicit(&ints[9], memory_order_relaxed);
    uint u = atomic_fetch_add_explicit(&uints[0], 3u, memory_order_relaxed);
    u += atomic_fetch_min_explicit(&uints[1], u, memory_order_relaxed);
    u += atomic_fetch_max_explicit(&uints[2], u, memory_order_relaxed);
    float f = atomic_fetch_add_explicit(&floats[0], 1.5f, memory_order_relaxed);
    f += atomic_exchange_explicit(&floats[1], f, memory_order_relaxed);
    atomic_max_explicit(&longs[0], ulong(tid), memory_order_relaxed);
    atomic_min_explicit(&longs[1], ulong(tid), memory_order_relaxed);
    r += atomic_fetch_add_explicit(&shared[(lid + 1) & 63], r, memory_order_relaxed);
    r += atomic_fetch_max_explicit(&shared[(lid + 2) & 63], r, memory_order_relaxed);
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, thread_scope_device);
    out[tid] = r + int(u) + int(f);
}
