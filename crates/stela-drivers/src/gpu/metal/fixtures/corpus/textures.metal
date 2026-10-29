// SPDX-License-Identifier: MIT
// Every texture type's reads, writes, samples, gathers, comparisons,
// queries and atomics.
#include <metal_stdlib>
using namespace metal;

kernel void sampled(texture1d<float> t1 [[texture(0)]], texture2d<float> t2 [[texture(1)]],
                    texture3d<float> t3 [[texture(2)]], texturecube<float> tc [[texture(3)]],
                    texture2d_array<float> ta [[texture(4)]], texturecube_array<float> tca [[texture(5)]],
                    texture1d_array<float> t1a [[texture(6)]], texture2d_ms<float> tms [[texture(7)]],
                    depth2d<float> d2 [[texture(8)]], depth2d_array<float> da [[texture(9)]],
                    depthcube<float> dc [[texture(10)]], depth2d_ms<float> dms [[texture(11)]],
                    texture2d<int> ti [[texture(12)]], texture2d<uint> tu [[texture(13)]],
                    texture2d<half> th [[texture(14)]], texture_buffer<float> tb [[texture(15)]],
                    sampler s [[sampler(0)]], sampler cmp [[sampler(1)]],
                    device float4 *out [[buffer(0)]], uint2 gid [[thread_position_in_grid]])
{
    float2 uv = float2(gid) / 64.0f;
    constexpr sampler linear(filter::linear, address::repeat, mip_filter::linear);
    float4 r = t1.sample(s, uv.x) + t2.sample(s, uv) + t2.sample(linear, uv, level(1.5f));
    r += t2.sample(s, uv, bias(0.5f)) + t2.sample(s, uv, gradient2d(uv, uv)) + t2.sample(s, uv, int2(1, -1));
    r += t2.sample(s, uv, min_lod_clamp(1.0f));
    r += t3.sample(s, float3(uv, 0.5f)) + tc.sample(s, float3(uv, 1.0f)) + ta.sample(s, uv, 2);
    r += tca.sample(s, float3(uv, 1.0f), 1) + t1a.sample(s, uv.x, 1);
    r += t2.gather(s, uv) + t2.gather(s, uv, int2(0), component::y) + ta.gather(s, uv, 1);
    r += t2.read(gid) + t2.read(gid, 1) + t3.read(uint3(gid, 0)) + ta.read(gid, 1) + tms.read(gid, 2);
    r += tc.read(gid, 3) + t1.read(gid.x) + tb.read(gid.x);
    r += float4(d2.sample_compare(cmp, uv, 0.5f) + d2.sample(s, uv) + da.sample_compare(cmp, uv, 1, 0.5f));
    r += float4(dc.sample_compare(cmp, float3(uv, 1.0f), 0.5f) + d2.read(gid) + dms.read(gid, 1));
    r += d2.gather_compare(cmp, uv, 0.5f) + d2.gather(s, uv);
    r += float4(ti.read(gid)) + float4(tu.read(gid)) + float4(th.sample(s, uv));
    r += float4(t2.get_width(), t2.get_height(1), t2.get_num_mip_levels(), t3.get_depth());
    r += float4(ta.get_array_size(), tms.get_num_samples(), tb.get_width(), tc.get_width());
    r += float4(t2.calculate_clamped_lod(s, uv), t2.calculate_unclamped_lod(s, uv), 0, 0);
    out[gid.y * 64 + gid.x] = r;
}

kernel void written(texture1d<float, access::write> w1 [[texture(0)]],
                    texture2d<float, access::read_write> rw [[texture(1)]],
                    texture3d<half, access::write> w3 [[texture(2)]],
                    texture2d_array<uint, access::write> wa [[texture(3)]],
                    texturecube<float, access::write> wc [[texture(4)]],
                    texture_buffer<float, access::read_write> wb [[texture(5)]],
                    texture2d<uint, access::read_write> atomics2 [[texture(6)]],
                    texture3d<int, access::read_write> atomics3 [[texture(7)]],
                    uint2 gid [[thread_position_in_grid]])
{
    float4 v = rw.read(gid);
    rw.write(v * 2.0f, gid);
    rw.fence();
    w1.write(v, gid.x);
    w3.write(half4(v), uint3(gid, 1));
    wa.write(uint4(gid, 0, 1), gid, 2);
    wc.write(v, gid, 3);
    wb.write(wb.read(gid.x) + v, gid.x);
    uint4 old = atomics2.atomic_fetch_add(gid, 1u);
    old += atomics2.atomic_fetch_max(gid, 7u);
    int4 i = atomics3.atomic_fetch_or(uint3(gid, 0), 3);
    atomics3.atomic_compare_exchange_weak(uint3(gid, 1), &i, int4(5));
    atomics3.atomic_exchange(uint3(gid, 2), i.x);
}
