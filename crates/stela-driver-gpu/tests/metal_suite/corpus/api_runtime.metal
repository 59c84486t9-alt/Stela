// Compiled by the device at run time: SCALE and OFFSET come from the
// compile options' macros, and the language version from their version.
#include <metal_stdlib>
using namespace metal;

#ifndef OFFSET
#define OFFSET 7u
#endif

kernel void runtime_scale(device uint *data [[buffer(0)]], uint i [[thread_position_in_grid]])
{
    data[i] = data[i] * SCALE + OFFSET + __METAL_VERSION__;
}

// Floats narrowed to half as the compile options' conversion rounding
// mode rounds them.
kernel void runtime_narrow(device const float *in [[buffer(0)]], device half *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{
    out[i] = half(in[i]);
}

// Each thread's threadgroup size and index, under a size the compile
// options require.
kernel void runtime_group(device uint4 *out [[buffer(0)]], uint3 n [[threads_per_threadgroup]],
                          uint3 l [[thread_position_in_threadgroup]], uint3 i [[thread_position_in_grid]])
{
    out[i.x] = uint4(n, l.x);
}
