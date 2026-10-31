// SPDX-License-Identifier: MIT
// Function constants, visible functions and function tables, and
// kernels with stage-in.
#include <metal_stdlib>
using namespace metal;

constant bool use_tint [[function_constant(0)]];
constant float scale [[function_constant(1)]];
constant int iterations = is_function_constant_defined(scale) ? 4 : 1;
constant float3 offset [[function_constant(2)]];

[[visible]] float shade(float x, float y)
{
    return x * y + scale;
}

[[visible]] float blend(float x, float y)
{
    return mix(x, y, 0.5f);
}

kernel void constants(device float *data [[buffer(0)]], uint tid [[thread_position_in_grid]],
                      device float *tint [[buffer(1), function_constant(use_tint)]])
{
    float x = data[tid];
    for (int i = 0; i < iterations; i++)
        x = x * scale + offset.x;
    if (use_tint)
        x += tint[tid];
    data[tid] = x;
}

kernel void tables(device float *data [[buffer(0)]],
                   visible_function_table<float(float, float)> functions [[buffer(1)]],
                   uint tid [[thread_position_in_grid]])
{
    float x = data[tid];
    data[tid] = functions[tid % 2](x, data[tid + 1]);
}

struct Attributes {
    float4 position [[attribute(0)]];
    uint index [[attribute(1)]];
};

kernel void staged(Attributes in [[stage_in]], device float4 *out [[buffer(0)]],
                   uint tid [[thread_position_in_grid]])
{
    out[tid] = in.position + float4(in.index);
}
