#include <metal_stdlib>
using namespace metal;

kernel void stela_threadgroup_static(device uint *data [[buffer(7)]],
                                    uint tid [[thread_position_in_grid]]) {
    threadgroup uint scratch[32];
    uint lane = tid & 31u;
    scratch[lane] = data[tid];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    data[tid] = scratch[(lane + 1u) & 31u];
}

kernel void stela_threadgroup_dynamic(device uint *data [[buffer(7)]],
                                     threadgroup uint *scratch [[threadgroup(3)]],
                                     uint tid [[thread_position_in_grid]]) {
    uint lane = tid & 31u;
    scratch[lane] = data[tid];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    data[tid] = scratch[(lane + 1u) & 31u];
}
