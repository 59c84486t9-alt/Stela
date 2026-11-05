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

// The other scalar and vector types a constant can have.
constant char k_char [[function_constant(20)]];
constant uchar k_uchar [[function_constant(21)]];
constant ushort k_ushort [[function_constant(22)]];
constant int2 k_int2 [[function_constant(23)]];
constant uint4 k_uint4 [[function_constant(24)]];
constant half4 k_half4 [[function_constant(25)]];
constant float2 k_float2 [[function_constant(26)]];
constant long k_long [[function_constant(27)]];
constant ulong k_ulong [[function_constant(28)]];
constant int4 k_int4 [[function_constant(29)]];

kernel void constants_more(device uint *out [[buffer(0)]])
{
    out[0] = uint(int(k_char));
    out[1] = k_uchar;
    out[2] = k_ushort;
    out[3] = uint(k_int2.x);
    out[4] = uint(k_int2.y);
    for (uint k = 0; k < 4; k++) {
        out[5 + k] = k_uint4[k];
        out[9 + k] = as_type<ushort>(k_half4[k]);
    }
    out[13] = as_type<uint>(k_float2.x);
    out[14] = as_type<uint>(k_float2.y);
    out[15] = uint(as_type<ulong>(k_long));
    out[16] = uint(as_type<ulong>(k_long) >> 32);
    out[17] = uint(k_ulong);
    out[18] = uint(k_ulong >> 32);
    for (uint k = 0; k < 4; k++)
        out[19 + k] = uint(k_int4[k]);
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

// Three constants of one type, set together from one array.
constant uint c_range0 [[function_constant(40)]];
constant uint c_range1 [[function_constant(41)]];
constant uint c_range2 [[function_constant(42)]];

kernel void constant_range(device uint *out [[buffer(0)]])
{
    out[0] = c_range0;
    out[1] = c_range1;
    out[2] = c_range2;
}

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

#ifndef SKIP_visible_pair
// Two tables at consecutive indices, the second applied to the first's
// result: which[i] % 3 picks from the first, which[i] / 3 the second.
static float through_pair(float x, uint w, visible_function_table<float(float)> a,
                          visible_function_table<float(float)> b)
{
    return b[w / 3](a[w % 3](x));
}

kernel void visible_pair(device const float *in [[buffer(0)]], visible_function_table<float(float)> a [[buffer(1)]],
                         visible_function_table<float(float)> b [[buffer(2)]], device float *out [[buffer(3)]],
                         device const uint *which [[buffer(4)]], uint i [[thread_position_in_grid]])
{
    out[i] = through_pair(in[i], which[i], a, b);
}

// A table's size and emptiness, a null table's, and an array's of no
// elements and of two.
kernel void table_extents(visible_function_table<float(float)> a [[buffer(1)]], device uint *out [[buffer(3)]])
{
    visible_function_table<float(float)> none;
    array<uint, 0> nothing;
    array<uint, 2> pair = {1u, 2u};
    out[0] = a.size();
    out[1] = a.empty();
    out[2] = none.size();
    out[3] = none.empty();
    out[4] = nothing.empty();
    out[5] = pair.empty();
}

// The pair reached through an argument buffer instead of bound slots.
struct PairTables {
    visible_function_table<float(float)> a [[id(0)]];
    visible_function_table<float(float)> b [[id(1)]];
};

kernel void tabled_pair(device const float *in [[buffer(0)]], constant PairTables &t [[buffer(1)]],
                        device float *out [[buffer(3)]], device const uint *which [[buffer(4)]],
                        uint i [[thread_position_in_grid]])
{
    out[i] = through_pair(in[i], which[i], t.a, t.b);
}

// The pair from a vertex function, one point per pixel of an 8x8 target
// carrying its value, and from a fragment function per pixel.
struct VisibleValue {
    float4 position [[position]];
    float size [[point_size]];
    float value [[flat]];
};

vertex VisibleValue vert_visible_pair(device const float *in [[buffer(0)]],
                                      visible_function_table<float(float)> a [[buffer(1)]],
                                      visible_function_table<float(float)> b [[buffer(2)]],
                                      device const uint *which [[buffer(4)]], uint v [[vertex_id]])
{
    float2 p = (float2(v % 8, v / 8) + 0.5f) / 4.0f;
    return {float4(p.x - 1.0f, 1.0f - p.y, 0.0f, 1.0f), 1.0f, through_pair(in[v], which[v], a, b)};
}

fragment float4 frag_visible_value(VisibleValue p [[stage_in]])
{
    return float4(p.value, 0.0f, 0.0f, 1.0f);
}

struct PairPixel {
    float4 position [[position]];
};

vertex PairPixel vert_pair_quad(uint v [[vertex_id]])
{ return {float4(v & 1 ? 1.0f : -1.0f, v & 2 ? 1.0f : -1.0f, 0.0f, 1.0f)}; }

fragment float4 frag_visible_pair(PairPixel p [[stage_in]], device const float *in [[buffer(0)]],
                                  visible_function_table<float(float)> a [[buffer(1)]],
                                  visible_function_table<float(float)> b [[buffer(2)]],
                                  device const uint *which [[buffer(4)]])
{
    uint i = uint(p.position.y) * 8 + uint(p.position.x);
    return float4(through_pair(in[i], which[i], a, b), 0.0f, 0.0f, 1.0f);
}
#endif

// An argument buffer read from a fragment function: a texture and a
// pointer to constants.
struct FragmentArguments {
    texture2d<float> image;
    constant float4 *tint;
};

struct ArgumentPixel {
    float4 position [[position]];
};

vertex ArgumentPixel vert_argument_pixel(uint v [[vertex_id]])
{ return {float4(v & 1 ? 1.0f : -1.0f, v & 2 ? 1.0f : -1.0f, 0.0f, 1.0f)}; }

fragment float4 frag_arguments(ArgumentPixel p [[stage_in]], constant FragmentArguments &args [[buffer(0)]])
{
    uint2 at = uint2(p.position.xy);
    return args.image.read(at) * args.tint[at.x % 2];
}

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
