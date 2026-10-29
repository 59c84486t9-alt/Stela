// SPDX-License-Identifier: MIT
// Object and mesh functions with payloads and per-primitive data.
#include <metal_stdlib>
using namespace metal;

struct Payload {
    uint meshlets[32];
};

[[object]] void object_main(object_data Payload &payload [[payload]],
                            mesh_grid_properties grid,
                            const device uint *visible [[buffer(0)]],
                            uint tid [[thread_position_in_grid]], uint lane [[thread_index_in_threadgroup]])
{
    payload.meshlets[lane] = visible[tid];
    if (lane == 0)
        grid.set_threadgroups_per_grid(uint3(simd_sum(visible[tid] & 1), 1, 1));
}

struct MeshVertex {
    float4 position [[position]];
    float2 uv;
};

struct MeshPrimitive {
    float4 color [[flat]];
    uint layer [[render_target_array_index]];
    bool culled [[primitive_culled]];
};

using Mesh = metal::mesh<MeshVertex, MeshPrimitive, 64, 126, topology::triangle>;

[[mesh]] void mesh_main(Mesh output, const object_data Payload &payload [[payload]],
                        const device float4 *positions [[buffer(0)]],
                        uint lane [[thread_index_in_threadgroup]], uint group [[threadgroup_position_in_grid]])
{
    uint meshlet = payload.meshlets[group];
    if (lane < 64)
        output.set_vertex(lane, MeshVertex{positions[meshlet * 64 + lane], float2(lane)});
    if (lane < 126) {
        output.set_index(lane * 3, lane);
        output.set_index(lane * 3 + 1, (lane + 1) & 63);
        output.set_index(lane * 3 + 2, (lane + 2) & 63);
        output.set_primitive(lane, MeshPrimitive{float4(meshlet), lane & 1, false});
    }
    if (lane == 0)
        output.set_primitive_count(126);
}

struct MeshFragment {
    MeshVertex vertex_data;
    MeshPrimitive primitive_data;
};

fragment float4 mesh_fragment(MeshFragment in [[stage_in]])
{
    return in.primitive_data.color + float4(in.vertex_data.uv, 0, 1);
}
