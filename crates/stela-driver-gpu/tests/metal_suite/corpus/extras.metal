// SPDX-License-Identifier: MIT
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
