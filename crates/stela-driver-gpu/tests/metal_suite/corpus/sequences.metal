// SPDX-License-Identifier: MIT
// Work that depends on earlier work in the same command buffer or queue:
// dispatches in one encoder and across encoders, blits around compute,
// arguments a dispatch or draw reads from what an earlier dispatch wrote,
// render targets read by compute and later passes, textures and vertices
// compute writes for a draw, and multisampled targets read per sample.
#include <metal_stdlib>
using namespace metal;

kernel void scale(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                  uint i [[thread_position_in_grid]])
{ out[i] = in[i] * 3u + 1u; }

// Reads a neighbour's element: correct only once every thread of the
// previous dispatch has written.
kernel void neighbours(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                       constant uint &n [[buffer(2)]], uint i [[thread_position_in_grid]])
{ out[i] = in[i] + in[(i + 1) % n] * 2u; }

// Threadgroup counts for an indirect dispatch, and arguments for an
// indirect draw of a full-target rectangle the same dispatch writes.
kernel void write_arguments(device uint *dispatch [[buffer(0)]], device uint *draw [[buffer(1)]],
                            device float4 *corners [[buffer(2)]])
{
    dispatch[0] = 5; dispatch[1] = 1; dispatch[2] = 1;
    draw[0] = 4; draw[1] = 1; draw[2] = 0; draw[3] = 0;
    corners[0] = float4(-1, -1, 0, 1);
    corners[1] = float4(1, -1, 0, 1);
    corners[2] = float4(-1, 1, 0, 1);
    corners[3] = float4(1, 1, 0, 1);
}

kernel void count_threads(device atomic_uint *count [[buffer(0)]], device uint *seen [[buffer(1)]],
                          uint i [[thread_position_in_grid]], uint group [[threadgroup_position_in_grid]])
{
    atomic_fetch_add_explicit(count, 1u, memory_order_relaxed);
    seen[i] = group * 1000u + i;
}

kernel void read_target(texture2d<float> t [[texture(0)]], device float4 *out [[buffer(0)]],
                        uint2 p [[thread_position_in_grid]])
{ out[p.y * t.get_width() + p.x] = t.read(p) * 2.0f; }

kernel void write_texture(texture2d<float, access::write> t [[texture(0)]], uint2 p [[thread_position_in_grid]])
{ t.write(float4(float(p.x) * 0.125f, float(p.y) * 0.25f, 0.5f, 1.0f), p); }

// Every sample of a multisampled target, and its sample count.
kernel void read_samples(texture2d_ms<float> t [[texture(0)]], device float *out [[buffer(0)]],
                         device uint *count [[buffer(1)]], uint2 p [[thread_position_in_grid]])
{
    uint n = t.get_num_samples();
    for (uint s = 0; s < n; s++)
        out[(p.y * t.get_width() + p.x) * n + s] = t.read(p, s).x;
    if (p.x == 0 && p.y == 0)
        count[0] = n;
}

struct Rect {
    float4 position [[position]];
};

// A rectangle in clip space, from the corners buffer or a constant rect
// (x0, y0, x1, y1), as a 4-vertex triangle strip.
vertex Rect vert_corners(device const float4 *corners [[buffer(0)]], uint v [[vertex_id]])
{ return {corners[v]}; }

vertex Rect vert_rect(constant float4 &r [[buffer(0)]], uint v [[vertex_id]])
{ return {float4(v & 1 ? r.z : r.x, v & 2 ? r.w : r.y, 0.0f, 1.0f)}; }

fragment float4 frag_constant(constant float4 &color [[buffer(0)]])
{ return color; }

fragment float4 frag_coordinates(Rect in [[stage_in]])
{ return float4(in.position.x / 16.0f, in.position.y / 16.0f, 0.25f, 1.0f); }

// One minus the earlier pass's target at this pixel.
fragment float4 frag_invert(Rect in [[stage_in]], texture2d<float> earlier [[texture(0)]])
{ return 1.0f - earlier.read(uint2(in.position.xy)); }

// Half of the texture compute wrote, at this pixel.
fragment float4 frag_halve(Rect in [[stage_in]], texture2d<float> written [[texture(0)]])
{ return written.read(uint2(in.position.xy)) * 0.5f; }

// Shaded per sample: each sample's value names it.
fragment float4 frag_sample(uint s [[sample_id]])
{ return float4(float(s + 1) * 0.25f, 0.0f, 0.0f, 1.0f); }

// Indirect command buffers. Each command of icb_step updates its own
// slice; commands that share one order through barriers.
kernel void icb_step(device uint *data [[buffer(0)]], constant uint &k [[buffer(1)]],
                     uint i [[thread_position_in_grid]])
{ data[i] = data[i] * 2u + k; }

kernel void icb_scale(device uint *data [[buffer(0)]], uint i [[thread_position_in_grid]])
{ data[i] = data[i] * 3u + 1u; }

struct Commands {
    command_buffer commands [[id(0)]];
};

// Encodes one dispatch per thread into the indirect command buffer: each
// over its own 64-element slice of data.
kernel void encode_dispatches(device Commands &c [[buffer(0)]], device uint *data [[buffer(1)]],
                              uint i [[thread_position_in_grid]])
{
    compute_command command(c.commands, i);
    command.set_kernel_buffer(data + i * 64, 0);
    command.concurrent_dispatch_threadgroups(uint3(1, 1, 1), uint3(64, 1, 1));
}

// Encodes one rectangle draw per thread: rect i of rects, colour i.
kernel void encode_draws(device Commands &c [[buffer(0)]], constant float4 *rects [[buffer(1)]],
                         constant float4 *colors [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    render_command command(c.commands, i);
    command.set_vertex_buffer(rects + i, 0);
    command.set_fragment_buffer(colors + i, 0);
    command.draw_primitives(primitive_type::triangle_strip, 0, 4, 1, 0);
}
