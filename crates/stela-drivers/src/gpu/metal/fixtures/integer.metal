#include <metal_stdlib>
using namespace metal;
kernel void stela_integer(device uint *data [[buffer(7)]], uint tid [[thread_position_in_grid]]) { data[tid] = data[tid] * 2u + 1u; }
