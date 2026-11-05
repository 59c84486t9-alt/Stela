// SPDX-License-Identifier: MIT
// Textures from compute: read, sample, gather and compare sampling, write,
// read-write access, atomics and queries, over the texture types. The host
// binds the texture and sampler state each case names; each thread takes
// one coordinate from a buffer and writes its result to another.
#include <metal_stdlib>
using namespace metal;

#define READ2D(NAME, T) \
kernel void NAME(texture2d<T> t [[texture(0)]], device const uint4 *c [[buffer(0)]], \
                 device vec<T, 4> *out [[buffer(1)]], uint i [[thread_position_in_grid]]) \
{ out[i] = t.read(c[i].xy, c[i].z); }
READ2D(read2d_float, float)
READ2D(read2d_half, half)
READ2D(read2d_uint, uint)
READ2D(read2d_int, int)
READ2D(read2d_ushort, ushort)
READ2D(read2d_short, short)

kernel void read1d(texture1d<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                   device float4 *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].x); }

kernel void read1d_array(texture1d_array<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                         device float4 *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].x, c[i].y); }

kernel void read2d_array(texture2d_array<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                         device float4 *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].xy, c[i].w, c[i].z); }

kernel void read3d(texture3d<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                   device float4 *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].xyz, c[i].w); }

kernel void readcube(texturecube<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                     device float4 *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].xy, c[i].w, c[i].z); }

kernel void read_depth(depth2d<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                       device float *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].xy, c[i].z); }

#ifndef SKIP_read_buffer
kernel void read_buffer(texture_buffer<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                        device float4 *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].x); }
#endif

// Sampling at explicit coordinates (xy) and level of detail (z).
kernel void sample2d_level(texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                           device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xy, level(c[i].z)); }

kernel void sample2d_grad(texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                          device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                          uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xy, gradient2d(float2(c[i].z, 0), float2(0, c[i].w))); }

kernel void sample2d_offset(texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                            device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                            uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xy, level(0), int2(-2, 3)); }

#ifndef SKIP_sample2d_min_lod
kernel void sample2d_min_lod(texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                             device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                             uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xy, gradient2d(float2(c[i].z, 0), float2(0, c[i].z)), min_lod_clamp(c[i].w)); }
#endif

kernel void sample2d_array(texture2d_array<float> t [[texture(0)]], sampler s [[sampler(0)]],
                           device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xy, uint(c[i].w), level(c[i].z)); }

kernel void sample3d(texture3d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                     device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                     uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xyz, level(c[i].w)); }

kernel void samplecube(texturecube<float> t [[texture(0)]], sampler s [[sampler(0)]],
                       device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                       uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xyz, level(c[i].w)); }

kernel void sample1d(texture1d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                     device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                     uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].x); }

// Sampler states declared in the shader, which AIR carries as constants.
kernel void sample_constexpr(texture2d<float> t [[texture(0)]], device const float4 *c [[buffer(0)]],
                             device float4 *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{
    constexpr sampler nearest_repeat(filter::nearest, address::repeat);
    constexpr sampler linear_mirror(filter::linear, address::mirrored_repeat);
    constexpr sampler pixel_clamp(coord::pixel, filter::linear, address::clamp_to_edge);
    constexpr sampler border(filter::nearest, address::clamp_to_border, border_color::opaque_white);
    out[i * 4 + 0] = t.sample(nearest_repeat, c[i].xy, level(0));
    out[i * 4 + 1] = t.sample(linear_mirror, c[i].xy, level(0));
    out[i * 4 + 2] = t.sample(pixel_clamp, c[i].xy * float2(t.get_width(), t.get_height()));
    out[i * 4 + 3] = t.sample(border, c[i].xy, level(0));
}

#define GATHER(N, C) \
kernel void gather_##N(texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]], \
                       device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]], \
                       uint i [[thread_position_in_grid]]) \
{ out[i * 2] = t.gather(s, c[i].xy, int2(0), component::C); \
  out[i * 2 + 1] = t.gather(s, c[i].xy, int2(1, -1), component::C); }
GATHER(x, x)
GATHER(y, y)
GATHER(z, z)
GATHER(w, w)

kernel void sample_compare(depth2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                           device const float4 *c [[buffer(0)]], device float *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{ out[i] = t.sample_compare(s, c[i].xy, c[i].z, level(0)); }

kernel void gather_compare(depth2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                           device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{ out[i] = t.gather_compare(s, c[i].xy, c[i].z); }

kernel void sample_depth(depth2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                         device const float4 *c [[buffer(0)]], device float *out [[buffer(1)]],
                         uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xy, level(0)); }

#define WRITE2D(NAME, T) \
kernel void NAME(texture2d<T, access::write> t [[texture(0)]], device const vec<T, 4> *v [[buffer(0)]], \
                 uint2 p [[thread_position_in_grid]]) \
{ t.write(v[p.y * t.get_width() + p.x], p); }
WRITE2D(write2d_float, float)
WRITE2D(write2d_uint, uint)
WRITE2D(write2d_int, int)

kernel void write2d_level(texture2d<float, access::write> t [[texture(0)]], device const float4 *v [[buffer(0)]],
                          uint2 p [[thread_position_in_grid]])
{
    uint w = t.get_width(1), h = t.get_height(1);
    if (p.x < w && p.y < h)
        t.write(v[p.y * w + p.x], p, 1);
}

kernel void write3d(texture3d<float, access::write> t [[texture(0)]], device const float4 *v [[buffer(0)]],
                    uint3 p [[thread_position_in_grid]])
{ t.write(v[(p.z * t.get_height() + p.y) * t.get_width() + p.x], p); }

kernel void write2d_array(texture2d_array<float, access::write> t [[texture(0)]], device const float4 *v [[buffer(0)]],
                          uint3 p [[thread_position_in_grid]])
{ t.write(v[(p.z * t.get_height() + p.y) * t.get_width() + p.x], p.xy, p.z); }

#ifndef SKIP_read_write
// Read-write access: each texel becomes a function of itself.
kernel void read_write(texture2d<float, access::read_write> t [[texture(0)]], uint2 p [[thread_position_in_grid]])
{
    float4 v = t.read(p);
    t.fence();
    t.write(v.wzyx * 0.5f + 0.25f, p);
}
#endif

#ifndef SKIP_read_write
// Read-write integer textures: each texel times three plus its rotated
// lanes, plus or minus one.
kernel void read_write_uint(texture2d<uint, access::read_write> t [[texture(0)]], uint2 p [[thread_position_in_grid]])
{
    uint4 v = t.read(p);
    t.fence();
    t.write(v * 3u + v.yzwx + 1u, p);
}

kernel void read_write_int(texture2d<int, access::read_write> t [[texture(0)]], uint2 p [[thread_position_in_grid]])
{
    int4 v = t.read(p);
    t.fence();
    t.write(v * 3 + v.yzwx - 1, p);
}
#endif

#ifndef SKIP_texture_atomics_ops
// Every texture atomic: thread i applies op i % 8 to texel i % 8 of row 0;
// in row 1, every thread tries once to swap 0 for its index + 1 and
// counts its success, and exchanges its index + 1 into texel 1.
template <typename T>
static void atomic_ops(texture2d<T, access::read_write> t, device atomic_uint *wins, T v, uint i)
{
    uint2 p = uint2(i % 8, 0);
    switch (i % 8) {
    case 0: t.atomic_fetch_add(p, v); break;
    case 1: t.atomic_fetch_sub(p, v); break;
    case 2: t.atomic_fetch_and(p, v); break;
    case 3: t.atomic_fetch_or(p, v); break;
    case 4: t.atomic_fetch_xor(p, v); break;
    case 5: t.atomic_fetch_min(p, v); break;
    case 6: t.atomic_fetch_max(p, v); break;
    default: t.atomic_fetch_add(p, T(1)); break;
    }
    // A weak exchange may fail spuriously: retried while the texel is 0.
    vec<T, 4> expected = vec<T, 4>(0);
    while (!t.atomic_compare_exchange_weak(uint2(0, 1), &expected, T(i + 1))) {
        if (expected.x != 0)
            break;
    }
    if (expected.x == 0)
        atomic_fetch_add_explicit(wins, 1u, memory_order_relaxed);
    t.atomic_exchange(uint2(1, 1), T(i + 1));
}

kernel void texture_atomics_uint(texture2d<uint, access::read_write> t [[texture(0)]], device const uint *v [[buffer(0)]],
                                 device atomic_uint *wins [[buffer(1)]], uint i [[thread_position_in_grid]])
{
    atomic_ops(t, wins, v[i], i);
}

kernel void texture_atomics_int(texture2d<int, access::read_write> t [[texture(0)]], device const int *v [[buffer(0)]],
                                device atomic_uint *wins [[buffer(1)]], uint i [[thread_position_in_grid]])
{
    atomic_ops(t, wins, v[i], i);
}

// An atomic add on each texture type that has atomics, at texel i % 4.
kernel void texture_atomics_types(texture1d<uint, access::read_write> t1 [[texture(0)]],
                                  texture1d_array<uint, access::read_write> t1a [[texture(1)]],
                                  texture2d_array<uint, access::read_write> t2a [[texture(2)]],
                                  texture3d<uint, access::read_write> t3 [[texture(3)]],
                                  texture_buffer<uint, access::read_write> tb [[texture(4)]],
                                  uint i [[thread_position_in_grid]])
{
    uint k = i % 4;
    t1.atomic_fetch_add(k, 1u);
    t1a.atomic_fetch_add(k, 1, 2u);
    t2a.atomic_fetch_add(uint2(k, 1), 1, 3u);
    t3.atomic_fetch_add(uint3(k, 1, 1), 4u);
    tb.atomic_fetch_add(k, 5u);
}
#endif

#ifndef SKIP_texture_atomics
// Texture atomics: every thread adds to one of 16 texels.
kernel void texture_atomics(texture2d<uint, access::read_write> t [[texture(0)]],
                            device const uint *v [[buffer(0)]], uint i [[thread_position_in_grid]])
{
    t.atomic_fetch_add(uint2(i % 4, (i / 4) % 4), v[i]);
    t.atomic_fetch_max(uint2(i % 4, 4 + (i / 4) % 4), v[i]);
}
#endif

kernel void queries(texture2d<float> t2 [[texture(0)]], texture3d<float> t3 [[texture(1)]],
                    texture2d_array<float> ta [[texture(2)]], texturecube<float> tc [[texture(3)]],
                    device uint *out [[buffer(0)]])
{
    out[0] = t2.get_width(); out[1] = t2.get_height(); out[2] = t2.get_num_mip_levels();
    out[3] = t2.get_width(2); out[4] = t2.get_height(2);
    out[5] = t3.get_width(); out[6] = t3.get_height(); out[7] = t3.get_depth();
    out[8] = ta.get_array_size(); out[9] = ta.get_width(1);
    out[10] = tc.get_width(); out[11] = tc.get_num_mip_levels();
}

// Types and operations of the cases above on other texture types: gathers
// on arrays and depth, depth arrays and cubes, cube arrays, 1D arrays,
// writes to cubes and 1D textures, and queries of every type.
kernel void gather2d_array(texture2d_array<float> t [[texture(0)]], sampler s [[sampler(0)]],
                           device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{ out[i] = t.gather(s, c[i].xy, uint(c[i].w), int2(0), component::y); }

kernel void gather_depth(depth2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                         device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                         uint i [[thread_position_in_grid]])
{ out[i] = t.gather(s, c[i].xy); }

kernel void gather_depth_array(depth2d_array<float> t [[texture(0)]], sampler s [[sampler(0)]],
                               device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                               uint i [[thread_position_in_grid]])
{ out[i] = t.gather(s, c[i].xy, uint(c[i].w)); }

kernel void sample_depth_array(depth2d_array<float> t [[texture(0)]], sampler s [[sampler(0)]],
                               device const float4 *c [[buffer(0)]], device float *out [[buffer(1)]],
                               uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xy, uint(c[i].w), level(0)); }

kernel void sample_compare_array(depth2d_array<float> t [[texture(0)]], sampler s [[sampler(0)]],
                                 device const float4 *c [[buffer(0)]], device float *out [[buffer(1)]],
                                 uint i [[thread_position_in_grid]])
{ out[i] = t.sample_compare(s, c[i].xy, uint(c[i].w), c[i].z, level(0)); }

kernel void read_depth_array(depth2d_array<float> t [[texture(0)]], device const uint4 *c [[buffer(0)]],
                             device float *out [[buffer(1)]], uint i [[thread_position_in_grid]])
{ out[i] = t.read(c[i].xy, c[i].z); }

kernel void sample_depth_cube(depthcube<float> t [[texture(0)]], sampler s [[sampler(0)]],
                              device const float4 *c [[buffer(0)]], device float *out [[buffer(1)]],
                              uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xyz, level(0)); }

kernel void samplecube_array(texturecube_array<float> t [[texture(0)]], sampler s [[sampler(0)]],
                             device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                             uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].xyz, uint(c[i].w), level(0)); }

kernel void sample1d_array(texture1d_array<float> t [[texture(0)]], sampler s [[sampler(0)]],
                           device const float4 *c [[buffer(0)]], device float4 *out [[buffer(1)]],
                           uint i [[thread_position_in_grid]])
{ out[i] = t.sample(s, c[i].x, uint(c[i].w)); }

kernel void writecube(texturecube<float, access::write> t [[texture(0)]], device const float4 *v [[buffer(0)]],
                      uint3 p [[thread_position_in_grid]])
{ t.write(v[(p.z * t.get_height() + p.y) * t.get_width() + p.x], p.xy, p.z); }

kernel void write1d(texture1d<float, access::write> t [[texture(0)]], device const float4 *v [[buffer(0)]],
                    uint p [[thread_position_in_grid]])
{ t.write(v[p], p); }

kernel void write1d_array(texture1d_array<float, access::write> t [[texture(0)]], device const float4 *v [[buffer(0)]],
                          uint2 p [[thread_position_in_grid]])
{ t.write(v[p.y * t.get_width() + p.x], p.x, p.y); }

kernel void queries_types(depth2d<float> d [[texture(0)]], texturecube_array<float> ca [[texture(1)]],
                          texture2d_ms<float> ms [[texture(2)]], texture2d_array<float> ta [[texture(3)]],
                          depthcube<float> dc [[texture(4)]], texture1d<float> t1 [[texture(5)]],
                          texture3d<float> t3 [[texture(6)]], depth2d_array<float> da [[texture(7)]],
                          texturecube<float> tc [[texture(8)]], device uint *out [[buffer(0)]])
{
    out[0] = d.get_width(); out[1] = d.get_height(); out[2] = d.get_num_mip_levels(); out[3] = d.get_width(1);
    out[4] = ca.get_width(); out[5] = ca.get_array_size(); out[6] = ca.get_num_mip_levels();
    out[7] = ms.get_width(); out[8] = ms.get_height(); out[9] = ms.get_num_samples();
    out[10] = ta.get_num_mip_levels(); out[11] = dc.get_width(); out[12] = dc.get_num_mip_levels();
    out[13] = t1.get_width(); out[14] = t3.get_num_mip_levels(); out[15] = da.get_width();
    out[16] = da.get_height(); out[17] = da.get_array_size(); out[18] = tc.get_height();
    out[19] = da.get_num_mip_levels();
}
