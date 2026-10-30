// SPDX-License-Identifier: MIT
// Post-tessellation vertex functions over triangle and quad patches, with
// the compute kernel that writes their factors.
#include <metal_stdlib>
using namespace metal;

struct ControlPoint {
    float4 position [[attribute(0)]];
    float2 uv [[attribute(1)]];
};

struct TrianglePatch {
    patch_control_point<ControlPoint> points;
    float4 color [[attribute(2)]];
};

struct Out {
    float4 position [[position]];
    float2 uv;
};

[[patch(triangle, 3)]] vertex Out triangle_domain(TrianglePatch patch [[stage_in]],
                                                  float3 position [[position_in_patch]],
                                                  uint id [[patch_id]], constant float4x4 &mvp [[buffer(1)]])
{
    Out out;
    float4 p = patch.points[0].position * position.x + patch.points[1].position * position.y +
               patch.points[2].position * position.z;
    out.position = mvp * p + patch.color + float4(id);
    out.uv = patch.points[0].uv * position.x + patch.points[2].uv * position.z;
    return out;
}

[[patch(quad, 4)]] vertex Out quad_domain(patch_control_point<ControlPoint> points [[stage_in]],
                                          float2 uv [[position_in_patch]])
{
    Out out;
    float4 top = mix(points[0].position, points[1].position, uv.x);
    float4 bottom = mix(points[3].position, points[2].position, uv.x);
    out.position = mix(top, bottom, uv.y);
    out.uv = uv;
    return out;
}

kernel void factors(device MTLTriangleTessellationFactorsHalf *triangles [[buffer(0)]],
                    device MTLQuadTessellationFactorsHalf *quads [[buffer(1)]],
                    uint id [[thread_position_in_grid]])
{
    triangles[id].edgeTessellationFactor[0] = 4.0h;
    triangles[id].edgeTessellationFactor[1] = 4.0h;
    triangles[id].edgeTessellationFactor[2] = 4.0h;
    triangles[id].insideTessellationFactor = 4.0h;
    for (int i = 0; i < 4; i++)
        quads[id].edgeTessellationFactor[i] = 8.0h;
    quads[id].insideTessellationFactor[0] = quads[id].insideTessellationFactor[1] = 8.0h;
}
