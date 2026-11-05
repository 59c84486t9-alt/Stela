// SPDX-License-Identifier: MIT
// How functions receive what they use beyond plain buffers: function
// constants, argument buffers (Tier 2: structs of pointers, resource IDs
// and arrays of them, nested), visible function tables and stitched
// functions.
#include <metal_stdlib>
using namespace metal;

constant int c_int [[function_constant(0)]];
constant float c_float [[function_constant(1)]];
constant bool c_bool [[function_constant(2)]];
constant uint c_uint [[function_constant(3)]];
constant half c_half [[function_constant(4)]];
constant bool c_extra [[function_constant(5)]];
constant short c_short [[function_constant(6)]];
constant float4 c_vector [[function_constant(7)]];
constant int c_named [[function_constant(8)]];
// A constant derived from others, and one whose definition is queried.
constant int c_derived = c_int * 3 + 1;
constant bool c_defined = is_function_constant_defined(c_named);

kernel void constants(device uint *out [[buffer(0)]],
                      device const uint *extra [[buffer(1), function_constant(c_extra)]])
{
    out[0] = uint(c_int);
    out[1] = as_type<uint>(c_float);
    out[2] = c_bool ? 1u : 0u;
    out[3] = c_uint;
    out[4] = uint(as_type<ushort>(c_half));
    out[5] = c_extra ? extra[0] : 0xDEADu;
    out[6] = uint(int(c_short));
    out[7] = uint(c_derived);
    out[8] = c_defined ? uint(c_named) : 0xFFFFFFFFu;
    for (uint k = 0; k < 4; k++)
        out[9 + k] = as_type<uint>(c_vector[k]);
}

// Constants select code: a loop bound and a branch the compiler removes.
kernel void constant_branches(device const float *in [[buffer(0)]], device float *out [[buffer(1)]],
                              uint i [[thread_position_in_grid]])
{
    float v = in[i];
    for (int k = 0; k < c_int; k++)
        v = v * 0.5f + 1.0f;
    if (c_bool)
        v = -v;
    out[i] = v;
}

struct Inner {
    device const uint *values;
    uint scale;
};

struct Arguments {
    device const float *values;
    texture2d<float> image;
    sampler linear;
    device uint *counter;
    array<texture2d<float>, 3> layers;
    constant Inner *inner;
    uint count;
};

// Reads through every kind of entry: a buffer pointer, a texture and a
// sampler, a texture array, a nested argument struct and an inline
// value, and writes through a pointer.
kernel void argument_buffer(constant Arguments &args [[buffer(0)]], device float4 *out [[buffer(1)]],
                            uint i [[thread_position_in_grid]])
{
    float v = args.values[i];
    float2 at = float2((float(i % 4) + 0.5f) / 4.0f, 0.5f);
    float4 sampled = args.image.sample(args.linear, at, level(0));
    float4 layer = args.layers[i % 3].read(uint2(i % 4, 0));
    uint inner = args.inner->values[i % 8] * args.inner->scale;
    atomic_fetch_add_explicit((device atomic_uint *)args.counter, 1u, memory_order_relaxed);
    out[i * 2] = sampled + float4(v);
    out[i * 2 + 1] = float4(layer.x, float(inner), float(args.count), layer.w);
}

// An array of argument structs, indexed per thread.
struct Item {
    device const float *source;
    float bias;
};

kernel void argument_array(constant Item *items [[buffer(0)]], device float *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{
    constant Item &item = items[i % 4];
    out[i] = item.source[i] + item.bias;
}

#ifndef SKIP_visible_table
[[visible]] float twice(float x)
{
    return x * 2.0f;
}

[[visible]] float square(float x)
{
    return x * x;
}

[[visible]] float negate_plus(float x)
{
    return 1.0f - x;
}

kernel void visible_table(device const float *in [[buffer(0)]],
                          visible_function_table<float(float)> table [[buffer(1)]],
                          device float *out [[buffer(2)]], device const uint *which [[buffer(3)]],
                          uint i [[thread_position_in_grid]])
{
    out[i] = table[which[i]](in[i]);
}

// The same table called from a fragment function, one input per pixel of
// an 8-pixel-wide target.
struct VisiblePixel {
    float4 position [[position]];
};

vertex VisiblePixel vert_visible(uint v [[vertex_id]])
{ return {float4(v & 1 ? 1.0f : -1.0f, v & 2 ? 1.0f : -1.0f, 0.0f, 1.0f)}; }

fragment float4 frag_visible(VisiblePixel p [[stage_in]], device const float *in [[buffer(0)]],
                             visible_function_table<float(float)> table [[buffer(1)]],
                             device const uint *which [[buffer(3)]])
{
    uint i = uint(p.position.y) * 8 + uint(p.position.x);
    return float4(table[which[i]](in[i]), 0.0f, 0.0f, 1.0f);
}
#endif

#ifndef SKIP_stitched_call
[[stitchable]] float stitch_mul(float a, float b)
{
    return a * b;
}

[[stitchable]] float stitch_add(float a, float b)
{
    return a + b;
}

kernel void stitched_call(device const float *in [[buffer(0)]],
                          visible_function_table<float(float, float)> table [[buffer(1)]],
                          device float *out [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    out[i] = table[0](in[2 * i], in[2 * i + 1]);
}
#endif
