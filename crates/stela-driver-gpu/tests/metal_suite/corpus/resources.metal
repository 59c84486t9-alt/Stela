// SPDX-License-Identifier: GPL-2.0-or-later
// Resources beyond device buffers and textures: heaps (allocation,
// placement, aliasing, residency through useHeap), texture views (pixel
// format, type, mipmap and slice ranges, swizzle) and programmable sample
// positions, seen through which samples an edge covers.
#include <metal_stdlib>
using namespace metal;

kernel void copy_words(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                       uint i [[thread_position_in_grid]])
{ out[i] = in[i]; }

kernel void scale_words(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                        uint i [[thread_position_in_grid]])
{ out[i] = in[i] * 3u + 1u; }

// Resources only an argument buffer names: residency comes from useHeap.
struct HeapArguments {
    device const uint *values [[id(0)]];
    texture2d<float> image [[id(1)]];
};

kernel void read_heap_arguments(constant HeapArguments &a [[buffer(0)]], device float4 *out [[buffer(1)]],
                                uint i [[thread_position_in_grid]])
{ out[i] = a.image.read(uint2(i % 8, i / 8)) + float(a.values[i]); }

// Each texel of a view, with the view's own extent.
kernel void read_float(texture2d<float> t [[texture(0)]], device float4 *out [[buffer(0)]],
                       device uint *size [[buffer(1)]], uint2 p [[thread_position_in_grid]])
{
    if (p.x < t.get_width() && p.y < t.get_height())
        out[p.y * t.get_width() + p.x] = t.read(p);
    if (p.x == 0 && p.y == 0) {
        size[0] = t.get_width(); size[1] = t.get_height(); size[2] = t.get_num_mip_levels(); size[3] = 1;
    }
}

kernel void read_uint(texture2d<uint> t [[texture(0)]], device uint4 *out [[buffer(0)]],
                      uint2 p [[thread_position_in_grid]])
{ out[p.y * t.get_width() + p.x] = t.read(p); }

kernel void read_array(texture2d_array<float> t [[texture(0)]], device float4 *out [[buffer(0)]],
                       device uint *size [[buffer(1)]], uint3 p [[thread_position_in_grid]])
{
    out[(p.z * t.get_height() + p.y) * t.get_width() + p.x] = t.read(p.xy, p.z);
    if (all(p == 0)) {
        size[0] = t.get_width(); size[1] = t.get_height(); size[2] = t.get_num_mip_levels(); size[3] = t.get_array_size();
    }
}

kernel void read_cube(texturecube<float> t [[texture(0)]], device float4 *out [[buffer(0)]],
                      uint3 p [[thread_position_in_grid]])
{ out[(p.z * t.get_height() + p.y) * t.get_width() + p.x] = t.read(p.xy, p.z); }

// A swizzled view sampled at texel centres: the swizzle applies to samples.
kernel void sample_float(texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]], device float4 *out [[buffer(0)]],
                         uint2 p [[thread_position_in_grid]])
{ out[p.y * t.get_width() + p.x] = t.sample(s, (float2(p) + 0.5f) / float2(t.get_width(), t.get_height())); }

struct Covered {
    float4 position [[position]];
};

// A rectangle (x0, y0, x1, y1) in clip space, as a 4-vertex strip.
vertex Covered vert_rect(constant float4 &r [[buffer(0)]], uint v [[vertex_id]])
{ return {float4(v & 1 ? r.z : r.x, v & 2 ? r.w : r.y, 0.0f, 1.0f)}; }

fragment float4 frag_one() { return float4(1.0f); }

kernel void read_samples4(texture2d_ms<float> t [[texture(0)]], device float4 *out [[buffer(0)]],
                          uint2 p [[thread_position_in_grid]])
{
    for (uint s = 0; s < 4; s++)
        out[(p.y * t.get_width() + p.x) * 4 + s] = t.read(p, s);
}

kernel void read_depth_samples4(depth2d_ms<float> t [[texture(0)]], device float *out [[buffer(0)]],
                                uint2 p [[thread_position_in_grid]])
{
    for (uint s = 0; s < 4; s++)
        out[(p.y * t.get_width() + p.x) * 4 + s] = t.read(p, s);
}

// Two textures a placement heap holds at their own offsets.
kernel void read_two(texture2d<float> a [[texture(0)]], texture2d<float> b [[texture(1)]],
                     device float4 *out [[buffer(0)]], uint2 p [[thread_position_in_grid]])
{
    uint i = p.y * a.get_width() + p.x;
    out[i * 2] = a.read(p);
    out[i * 2 + 1] = b.read(p);
}
