// SPDX-License-Identifier: GPL-2.0-or-later
// Shader features macOS's own shaders use that the other families do not
// reach: SIMD-group indices and counts, null texture and function table
// handles, device-coherent memory, packing formats, multisampled depth
// and multisampled array reads, gradient sampling of 3D, cube and array
// textures, compute stage-in, stencil export and invariant positions.
#include <metal_stdlib>
using namespace metal;

// (simdgroup index, simdgroups, dispatched simdgroups, lane) of each
// thread, its SIMD-group width, and the threadgroup's size as it runs and
// as dispatched, for a grid that leaves the last threadgroup partial.
kernel void simd_ids(device uint4 *out [[buffer(0)]], device uint *width [[buffer(1)]],
                     uint3 grid [[thread_position_in_grid]],
                     uint group [[simdgroup_index_in_threadgroup]],
                     uint groups [[simdgroups_per_threadgroup]],
                     uint dispatched [[dispatch_simdgroups_per_threadgroup]],
                     uint lane [[thread_index_in_simdgroup]],
                     uint w [[threads_per_simdgroup]],
                     uint3 tg [[threads_per_threadgroup]],
                     uint3 dtg [[dispatch_threads_per_threadgroup]])
{
    uint i = grid.x;
    out[i] = uint4(group, groups, dispatched, lane);
    if (i == 0) {
        width[0] = w; width[1] = tg.x;
    }
    if (i == 128) {
        width[2] = tg.x; width[3] = dtg.x;
    }
}

// Whether each handle is null: bound ones are not, unbound ones are.
kernel void null_handles(texture1d<float> bound1d [[texture(0)]], texture1d<float> unbound1d [[texture(1)]],
                         texturecube_array<float> boundcube [[texture(2)]],
                         texturecube_array<float> unboundcube [[texture(3)]],
                         visible_function_table<float(float)> table [[buffer(1)]],
                         device uint *out [[buffer(0)]])
{
    out[0] = is_null_texture(bound1d);
    out[1] = is_null_texture(unbound1d);
    out[2] = is_null_texture(boundcube);
    out[3] = is_null_texture(unboundcube);
    out[4] = is_null_visible_function_table(table);
}

// Each thread writes its slot through a device-coherent pointer, fences,
// and reads the neighbour its SIMD-group partner wrote.
kernel void coherent_exchange(coherent(device) device uint *data [[buffer(0)]], device uint *out [[buffer(1)]],
                              uint i [[thread_position_in_grid]])
{
    data[i] = i * 7u + 3u;
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, thread_scope_threadgroup);
    threadgroup_barrier(mem_flags::mem_device);
    out[i] = data[i ^ 1u];
}

// Packing to and unpacking from 565 and 10:10:10:2 normalized formats,
// each from its own input.
kernel void pack_formats(device const float4 *in [[buffer(0)]], device uint4 *packed [[buffer(1)]],
                         device float4 *unpacked [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    ushort p565 = pack_float_to_unorm565(in[i * 3].xyz);
    uint pu = pack_float_to_unorm10a2(in[i * 3 + 1]);
    uint ps = pack_float_to_snorm10a2(in[i * 3 + 2]);
    packed[i] = uint4(p565, pu, ps, 0);
    unpacked[i * 3] = float4(unpack_unorm565_to_float(p565), 0.0f);
    unpacked[i * 3 + 1] = unpack_unorm10a2_to_float(pu);
    unpacked[i * 3 + 2] = unpack_snorm10a2_to_float(ps);
}

// Every sample of each slice of a multisampled depth array.
kernel void read_ms_depth_array(depth2d_ms_array<float> depth [[texture(0)]], device float *depths [[buffer(0)]],
                                uint2 p [[thread_position_in_grid]])
{
    uint w = depth.get_width(), h = depth.get_height(), n = depth.get_num_samples();
    for (uint l = 0; l < depth.get_array_size(); l++)
        for (uint s = 0; s < n; s++)
            depths[((l * h + p.y) * w + p.x) * n + s] = depth.read(p, l, s);
}

// Each normalized packing of the same values, which sit near rounding ties.
kernel void pack_ties(device const float4 *in [[buffer(0)]], device uint4 *packed [[buffer(1)]],
                      uint i [[thread_position_in_grid]])
{
    float4 v = in[i];
    packed[i] = uint4(pack_float_to_unorm4x8(v), pack_float_to_snorm4x8(v),
                      pack_float_to_unorm2x16(v.xy), pack_float_to_snorm2x16(v.zw));
}

// Every sample of a multisampled depth texture and of each slice of a
// multisampled colour array.
kernel void read_ms(depth2d_ms<float> depth [[texture(0)]], texture2d_ms_array<float> layers [[texture(1)]],
                    device float *depths [[buffer(0)]], device float4 *colors [[buffer(1)]],
                    uint2 p [[thread_position_in_grid]])
{
    uint w = depth.get_width(), n = depth.get_num_samples();
    for (uint s = 0; s < n; s++) {
        depths[(p.y * w + p.x) * n + s] = depth.read(p, s);
        for (uint l = 0; l < layers.get_array_size(); l++)
            colors[((l * layers.get_height() + p.y) * w + p.x) * n + s] = layers.read(p, l, s);
    }
}

// Samples with explicit gradients: each case's gradient selects a mipmap
// level, whose texels name it.
kernel void sample_gradients(texture3d<float> volume [[texture(0)]], texturecube<float> cube [[texture(1)]],
                             texture2d_array<float> layers [[texture(2)]], sampler s [[sampler(0)]],
                             constant float4 *grads [[buffer(0)]], device float4 *out [[buffer(1)]],
                             uint i [[thread_position_in_grid]])
{
    float g = grads[i].x;
    out[i * 3] = volume.sample(s, float3(0.3f, 0.6f, 0.4f), gradient3d(float3(g, 0, 0), float3(0, g, 0)));
    out[i * 3 + 1] = cube.sample(s, float3(1.0f, 0.2f, -0.3f), gradientcube(float3(0, g, 0), float3(0, 0, g)));
    out[i * 3 + 2] = layers.sample(s, float2(0.3f, 0.6f), 1, gradient2d(float2(g, 0), float2(0, g)));
}

// Compute stage-in: each thread's attributes come from buffers indexed by
// its grid position, as the pipeline's stage input descriptor lays out.
struct Fetched {
    float2 a [[attribute(0)]];
    uchar4 b [[attribute(1)]];
};

kernel void stage_in_compute(Fetched in [[stage_in]], device float4 *out [[buffer(2)]],
                             uint i [[thread_position_in_grid]])
{ out[i] = float4(in.a, float(in.b.x) + float(in.b.y) * 256.0f, float(in.b.z) - float(in.b.w)); }

// The same over a grid one thread wide, a row per element.
kernel void stage_in_rows(Fetched in [[stage_in]], device float4 *out [[buffer(2)]],
                          uint2 p [[thread_position_in_grid]])
{ out[p.y] = float4(in.a, float(in.b.x) + float(in.b.y) * 256.0f, float(in.b.z) - float(in.b.w)); }

struct Pixel {
    float4 position [[position]];
};

vertex Pixel vert_full(uint v [[vertex_id]])
{ return {float4(v & 1 ? 1.0f : -1.0f, v & 2 ? 1.0f : -1.0f, 0.5f, 1.0f)}; }

// The stencil value each fragment exports, from its position.
struct Exported {
    float4 color [[color(0)]];
    uint stencil [[stencil]];
};

fragment Exported frag_stencil(Pixel in [[stage_in]])
{ return {float4(1.0f), uint(in.position.x) * 16u + uint(in.position.y)}; }

// Overlapping quads in one draw, each at its own depth and exporting its
// own stencil value: x from x0 to x1, at depth z, of value v.
struct Overlap {
    float4 position [[position]];
    uint value [[flat]];
};

constant uint overlap_corners[6] = {0, 1, 2, 2, 1, 3};

vertex Overlap vert_overlap(constant float4 *quads [[buffer(0)]], uint v [[vertex_id]])
{
    float4 q = quads[v / 6];
    uint corner = overlap_corners[v % 6];
    float x = corner & 1 ? q.y : q.x;
    float y = corner & 2 ? 1.0f : -1.0f;
    return {float4(x, y, q.z, 1.0f), uint(q.w)};
}

fragment Exported frag_overlap(Overlap in [[stage_in]])
{ return {float4(float(in.value) / 255.0f), in.value}; }

// An invariant position: a later pass with depth test "equal" matches the
// depth an earlier pass wrote with another fragment function.
struct Invariant {
    float4 position [[position, invariant]];
};

vertex Invariant vert_invariant(constant float4 *corners [[buffer(0)]], constant float &scale [[buffer(1)]],
                                uint v [[vertex_id]])
{
    float4 c = corners[v];
    return {float4(c.xy * scale, sin(c.z * 3.1f) * 0.25f + 0.5f, 1.0f)};
}

fragment float4 frag_first() { return float4(0.25f, 0.5f, 0.75f, 1.0f); }
fragment float4 frag_second() { return float4(1.0f, 0.0f, 0.5f, 1.0f); }

// Scalar bfloat conversions, both ways, with round to nearest even.
kernel void bfloat_scalar(device const float *in [[buffer(0)]], device ushort *narrow [[buffer(1)]],
                          device float *wide [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    bfloat b = bfloat(in[i]);
    narrow[i] = as_type<ushort>(b);
    wide[i] = float(b) * 2.0f;
}

// A kernel limited to 64 threads per threadgroup by attribute.
[[max_total_threads_per_threadgroup(64)]]
kernel void limited(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]],
                    uint t [[threads_per_threadgroup]])
{ out[i] = i * 3u + t; }

// The stage-in fetch as a command a kernel encodes: its buffers, the
// float2s at the stride the command gives, and its region.
struct StageInCommands {
    command_buffer commands [[id(0)]];
};

kernel void encode_stage_in(device StageInCommands &c [[buffer(0)]], device const float2 *a [[buffer(1)]],
                            device const uchar4 *b [[buffer(2)]], device float4 *out [[buffer(3)]],
                            constant uint &n [[buffer(4)]])
{
    compute_command command(c.commands, 0);
    command.set_kernel_buffer(a, 16, 0);
    command.set_kernel_buffer(b, 1);
    command.set_kernel_buffer(out, 2);
    command.set_stage_in_region(uint3(0), uint3(n, 1, 1));
    command.concurrent_dispatch_threadgroups(uint3(n / 64, 1, 1), uint3(64, 1, 1));
}

// (quadgroup index, quadgroups, dispatched quadgroups, lane) of each
// thread, for simd_ids's grid.
kernel void quad_ids(device uint4 *out [[buffer(0)]], uint3 grid [[thread_position_in_grid]],
                     uint group [[quadgroup_index_in_threadgroup]],
                     uint groups [[quadgroups_per_threadgroup]],
                     uint dispatched [[dispatch_quadgroups_per_threadgroup]],
                     uint lane [[thread_index_in_quadgroup]])
{
    out[grid.x] = uint4(group, groups, dispatched, lane);
}

// A stage-in region's origin and size, with the attribute each thread of
// the region fetches.
struct Indexed {
    uint v [[attribute(0)]];
};

kernel void stage_in_origin(Indexed in [[stage_in]], device uint4 *out [[buffer(1)]], uint3 origin [[grid_origin]],
                            uint3 size [[grid_size]], uint3 p [[thread_position_in_grid]])
{
    if (p.x < size.x)
        out[p.x] = uint4(in.v, origin.x, size.x, p.x);
}

// Atomic booleans: each thread swaps its own flags, so every result is
// fixed: the first flag exchanged for true, the second set if it was
// false (retrying the weak exchange's spurious failures), the first
// stored inverted, then the second read back.
kernel void atomic_flags(device atomic_bool *first [[buffer(0)]], device atomic_bool *second [[buffer(1)]],
                         device uint *out [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    bool was = atomic_exchange_explicit(&first[i], true, memory_order_relaxed);
    bool expected, swapped;
    do {
        expected = false;
        swapped = atomic_compare_exchange_weak_explicit(&second[i], &expected, true, memory_order_relaxed,
                                                        memory_order_relaxed);
    } while (!swapped && !expected);
    atomic_store_explicit(&first[i], !atomic_load_explicit(&first[i], memory_order_relaxed), memory_order_relaxed);
    out[i] = uint(was) | uint(swapped) << 1 | uint(expected) << 2 | uint(atomic_load_explicit(&second[i], memory_order_relaxed)) << 3;
}

// Two attributes fetched through the stage input's index buffer: the
// first by the thread's x position, the second by its y.
struct IndexedPair {
    uint a [[attribute(0)]];
    uint b [[attribute(1)]];
};

kernel void stage_in_indexed(IndexedPair in [[stage_in]], device uint2 *out [[buffer(2)]],
                             uint2 p [[thread_position_in_grid]], uint2 n [[threads_per_grid]])
{
    out[p.y * n.x + p.x] = uint2(in.a, in.b);
}
