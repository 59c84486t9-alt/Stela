// SPDX-License-Identifier: MIT
// Vertex and fragment stage inputs and outputs.
#include <metal_stdlib>
using namespace metal;

struct VertexIn {
    float3 position [[attribute(0)]];
    half4 color [[attribute(1)]];
    float2 uv [[attribute(2)]];
    ushort2 bones [[attribute(3)]];
};

struct VertexOut {
    float4 position [[position, invariant]];
    float point_size [[point_size]];
    float clip [[clip_distance]] [2];
    uint layer [[render_target_array_index]];
    uint viewport [[viewport_array_index]];
    float4 color;
    float2 uv [[center_no_perspective]];
    uint flat_id [[flat]];
    float sample_value [[sample_perspective]];
    float centroid_value [[centroid_perspective]];
};

struct FragmentIn {
    float4 position [[position]];
    uint layer [[render_target_array_index]];
    float4 color;
    float2 uv [[center_no_perspective]];
    uint flat_id [[flat]];
    float sample_value [[sample_perspective]];
    float centroid_value [[centroid_perspective]];
};

struct Uniforms {
    float4x4 mvp;
    float4 tint;
};

vertex VertexOut vertex_main(VertexIn in [[stage_in]], constant Uniforms &uniforms [[buffer(1)]],
                             const device float4 *instances [[buffer(2)]],
                             uint vid [[vertex_id]], uint iid [[instance_id]],
                             uint base_vertex [[base_vertex]], uint base_instance [[base_instance]],
                             ushort amplification [[amplification_id]])
{
    VertexOut out;
    out.position = uniforms.mvp * float4(in.position, 1.0f) + instances[iid];
    out.point_size = 4.0f;
    out.clip[0] = out.position.x;
    out.clip[1] = out.position.y;
    out.layer = iid & 1;
    out.viewport = amplification;
    out.color = float4(in.color) * uniforms.tint + float4(in.bones.x);
    out.uv = in.uv;
    out.flat_id = vid + base_vertex + base_instance;
    out.sample_value = out.position.z;
    out.centroid_value = out.position.w;
    return out;
}

vertex float4 vertex_pulled(const device packed_float3 *positions [[buffer(0)]], uint vid [[vertex_id]])
{
    return float4(float3(positions[vid]), 1.0f);
}

struct FragmentOut {
    float4 color0 [[color(0)]];
    half4 color1 [[color(1)]];
    uint4 color2 [[color(2)]];
    float depth [[depth(greater)]];
    uint mask [[sample_mask]];
};

fragment FragmentOut fragment_main(FragmentIn in [[stage_in]], texture2d<float> tex [[texture(0)]],
                                   sampler s [[sampler(0)]], bool front [[front_facing]],
                                   uint sample [[sample_id]], float2 point [[point_coord]],
                                   uint primitive [[primitive_id]], uint coverage [[sample_mask]])
{
    FragmentOut out;
    float4 c = tex.sample(s, in.uv) * in.color;
    c += float4(dfdx(in.uv), dfdy(in.uv)) + float4(fwidth(in.sample_value));
    c += float4(front, sample, primitive, in.flat_id) + float4(point, in.position.xy);
    if (c.a < 0.01f)
        discard_fragment();
    out.color0 = c;
    out.color1 = half4(c);
    out.color2 = uint4(c * 255.0f);
    out.depth = in.position.z;
    out.mask = coverage & 0x5;
    return out;
}

// Programmable blending, which only Apple GPU families have: refused.
fragment float4 fragment_blended(FragmentIn in [[stage_in]], float4 previous [[color(0)]])
{
    return previous * in.color;
}

fragment float4 fragment_interpolated(FragmentIn in [[stage_in]],
                                      float3 bary [[barycentric_coord]])
{
    return in.color * bary.x + float4(in.uv, 0, 0) * bary.y + bary.z;
}

struct Pulled {
    interpolant<float4, interpolation::perspective> color;
};

fragment float4 fragment_pulled(Pulled in [[stage_in]], uint sample [[sample_id]])
{
    return in.color.interpolate_at_center() + in.color.interpolate_at_centroid() +
           in.color.interpolate_at_sample(sample) + in.color.interpolate_at_offset(float2(0.25f));
}

fragment void fragment_counted(float4 position [[position]], device atomic_uint *count [[buffer(0)]])
{
    atomic_fetch_add_explicit(count, 1u, memory_order_relaxed);
}

[[early_fragment_tests]] fragment half4 fragment_early(float4 position [[position]])
{
    return half4(position);
}
