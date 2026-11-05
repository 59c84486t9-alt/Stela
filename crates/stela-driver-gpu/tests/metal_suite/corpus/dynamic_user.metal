// SPDX-License-Identifier: MIT
// Functions that call into the dynamic library dynamic.metal builds, from
// a kernel and from a fragment function.
#include <metal_stdlib>
using namespace metal;

extern float dyn_scale(float x);
extern float4 dyn_tint(float4 c);

kernel void use_dynamic(device const float *in [[buffer(0)]], device float *out [[buffer(1)]],
                        uint i [[thread_position_in_grid]])
{ out[i] = dyn_scale(in[i]); }

struct Pixel {
    float4 position [[position]];
};

vertex Pixel vert_full(uint v [[vertex_id]])
{ return {float4(v & 1 ? 1.0f : -1.0f, v & 2 ? 1.0f : -1.0f, 0.0f, 1.0f)}; }

fragment float4 frag_dynamic(constant float4 &color [[buffer(0)]])
{ return dyn_tint(color); }
