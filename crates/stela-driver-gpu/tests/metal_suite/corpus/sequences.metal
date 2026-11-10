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

// One stage of work between events: its level is one past the highest
// level of the stages it follows (`stage.y` and `stage.z`, each a slot plus
// one, zero for none), so a stage that runs before one it follows writes a
// lower level.
kernel void stage_level(device uint *levels [[buffer(0)]], constant uint4 &stage [[buffer(1)]])
{
    uint after = 0;
    if (stage.y != 0) after = max(after, levels[stage.y - 1]);
    if (stage.z != 0) after = max(after, levels[stage.z - 1]);
    levels[stage.x] = after + 1;
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

struct Corner {
    float2 position [[attribute(0)]];
};

vertex Rect vert_corner_attribute(Corner in [[stage_in]])
{ return {float4(in.position, 0.0f, 1.0f)}; }

// A rectangle at a depth the command sets.
vertex Rect vert_rect_z(constant float4 &r [[buffer(0)]], constant float &z [[buffer(1)]], uint v [[vertex_id]])
{ return {float4(v & 1 ? r.z : r.x, v & 2 ? r.w : r.y, z, 1.0f)}; }

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

// A slice's sum through threadgroup memory the command sizes.
kernel void icb_group_sum(device const uint *data [[buffer(0)]], device uint *sum [[buffer(1)]],
                          threadgroup uint *partial [[threadgroup(0)]], uint l [[thread_index_in_threadgroup]],
                          uint n [[threads_per_threadgroup]])
{
    partial[l] = data[l];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (l == 0) {
        uint total = 0;
        for (uint k = 0; k < n; k++)
            total += partial[k];
        sum[0] = total;
    }
}

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

// A kernel that encodes everything a compute command can hold: its own
// pipeline, a dispatch of threads leaving a partial threadgroup, a
// barrier, and threadgroup memory for a second dispatch that sums each
// 64-element block of what the first wrote.
struct FullCommands {
    command_buffer commands [[id(0)]];
    compute_pipeline_state scale [[id(1)]];
    compute_pipeline_state sum [[id(2)]];
};

kernel void encode_full_dispatches(device FullCommands &c [[buffer(0)]], device uint *data [[buffer(1)]],
                                   device uint *sums [[buffer(2)]])
{
    compute_command first(c.commands, 0);
    first.set_compute_pipeline_state(c.scale);
    first.set_kernel_buffer(data, 0);
    first.concurrent_dispatch_threads(uint3(100, 1, 1), uint3(64, 1, 1));
    compute_command second(c.commands, 1);
    second.set_compute_pipeline_state(c.sum);
    second.set_kernel_buffer(data, 0);
    second.set_kernel_buffer(sums, 1);
    second.set_threadgroup_memory_length(64 * 4, 0);
    second.set_barrier();
    second.concurrent_dispatch_threadgroups(uint3(4, 1, 1), uint3(64, 1, 1));
}

kernel void icb_block_sum(device const uint *data [[buffer(0)]], device uint *sums [[buffer(1)]],
                          threadgroup uint *scratch [[threadgroup(0)]], uint t [[thread_index_in_threadgroup]],
                          uint g [[threadgroup_position_in_grid]])
{
    scratch[t] = data[g * 64 + t];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (t == 0) {
        uint total = 0;
        for (uint k = 0; k < 64; k++)
            total += scratch[k];
        sums[g] = total;
    }
}

// Indexed rectangle draws encoded by a kernel: four corners from the
// shared corner buffer, by the index buffer, with the pipeline the
// argument buffer holds.
struct IndexedCommands {
    command_buffer commands [[id(0)]];
    render_pipeline_state pipeline [[id(1)]];
};

kernel void encode_indexed_draws(device IndexedCommands &c [[buffer(0)]], constant float4 *rects [[buffer(1)]],
                                 constant float4 *colors [[buffer(2)]], constant ushort *indices [[buffer(3)]],
                                 uint i [[thread_position_in_grid]])
{
    render_command command(c.commands, i);
    command.set_render_pipeline_state(c.pipeline);
    command.set_vertex_buffer(rects + i, 0);
    command.set_fragment_buffer(colors + i, 0);
    command.draw_indexed_primitives(primitive_type::triangle, 6, indices, 1, 0, 0);
}

// Commands a kernel encodes and then edits: the first over slice 0; the
// second a copy of it moved to slice 1, its barrier set and cleared; the
// third over slice 2, reset to nothing; the fourth a copy of the first
// ordered after the rest by its barrier.
kernel void encode_dispatch_edits(device Commands &c [[buffer(0)]], device uint *data [[buffer(1)]])
{
    compute_command first(c.commands, 0);
    first.set_kernel_buffer(data, 0);
    first.concurrent_dispatch_threadgroups(uint3(1, 1, 1), uint3(64, 1, 1));
    compute_command copied(c.commands, 1);
    copied.copy_command(first);
    copied.set_kernel_buffer(data + 64, 0);
    copied.set_barrier();
    copied.clear_barrier();
    compute_command reset(c.commands, 2);
    reset.set_kernel_buffer(data + 128, 0);
    reset.concurrent_dispatch_threadgroups(uint3(1, 1, 1), uint3(64, 1, 1));
    reset.reset();
    compute_command again(c.commands, 3);
    again.copy_command(first);
    again.set_barrier();
}

// sequence.icb.cpu_draw_state's commands, encoded by a kernel: each sets
// every piece of fixed-function state itself, the depth-stencil states
// from the argument buffer.
struct StateCommands {
    command_buffer commands [[id(0)]];
    depth_stencil_state always [[id(1)]];
    depth_stencil_state always_write [[id(2)]];
    depth_stencil_state less_equal_write [[id(3)]];
    depth_stencil_state less [[id(4)]];
};

kernel void encode_draw_state(device StateCommands &c [[buffer(0)]], constant float4 *rects [[buffer(1)]],
                              constant float *depths [[buffer(2)]], constant float4 *colors [[buffer(3)]],
                              uint i [[thread_position_in_grid]])
{
    render_command command(c.commands, i);
    command.set_vertex_buffer(rects + i, 0);
    command.set_vertex_buffer(depths + i, 1);
    command.set_fragment_buffer(colors + i, 0);
    command.set_cull_mode(i < 2 ? cull_mode::back : cull_mode::none);
    command.set_front_facing_winding(i == 1 ? winding::counterclockwise : winding::clockwise);
    command.set_triangle_fill_mode(triangle_fill_mode::fill);
    command.set_depth_clip_mode(i == 2 ? depth_clip_mode::clamp : depth_clip_mode::clip);
    command.set_depth_bias(i == 4 ? -1000.0f : 0.0f, 0.0f, 0.0f);
    if (i == 2)
        command.set_depth_stencil_state(c.always_write);
    else if (i == 3)
        command.set_depth_stencil_state(c.less_equal_write);
    else if (i == 4)
        command.set_depth_stencil_state(c.less);
    else
        command.set_depth_stencil_state(c.always);
    command.draw_primitives(primitive_type::triangle_strip, 0, 4, 1, 0);
    if (i == 2) {
        command.set_barrier();
        command.clear_barrier();
    }
    if (i == 4)
        command.set_barrier();
    if (i == 5)
        command.reset();
}

// Draws fetching corners at the stride each command gives: 8 bytes for
// the left half, 16 for the right.
kernel void encode_strided_draws(device Commands &c [[buffer(0)]], constant float2 *corners [[buffer(1)]],
                                 constant float4 *colors [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    render_command command(c.commands, i);
    if (i == 0)
        command.set_vertex_buffer(corners, 8, 1);
    else
        command.set_vertex_buffer(corners + 4, 16, 1);
    command.set_fragment_buffer(colors + i, 0);
    command.draw_primitives(primitive_type::triangle_strip, 0, 4, 1, 0);
}
