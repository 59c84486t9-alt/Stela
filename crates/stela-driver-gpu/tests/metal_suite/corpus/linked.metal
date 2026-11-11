// SPDX-License-Identifier: GPL-2.0-or-later
// Calls to visible functions that another library (linked_def.metal)
// defines, resolved when a pipeline links them: from a kernel, from
// vertex and fragment functions, and from object and mesh functions.
#include <metal_stdlib>
using namespace metal;

[[visible]] float linked_shade(float x);
[[visible]] float linked_bias();
// Linked as a specialization named so (linked_named.metal).
[[visible]] uint linked_scaled(uint x);

kernel void call_linked_scaled(device const uint *in [[buffer(0)]], device uint *out [[buffer(1)]],
                               uint i [[thread_position_in_grid]])
{
    out[i] = linked_scaled(in[i]);
}

kernel void call_linked(device const float *in [[buffer(0)]], device float *out [[buffer(1)]],
                        uint i [[thread_position_in_grid]])
{
    out[i] = linked_shade(in[i]) + linked_bias();
}

// One point per pixel of an 8x8 target, carrying its shaded value.
struct LinkedPoint {
    float4 position [[position]];
    float size [[point_size]];
    float value [[flat]];
};

static LinkedPoint linked_point(uint i, float value)
{
    float2 p = (float2(i % 8, i / 8) + 0.5f) / 4.0f;
    return {float4(p.x - 1.0f, 1.0f - p.y, 0.0f, 1.0f), 1.0f, value};
}

vertex LinkedPoint vert_linked(device const float *in [[buffer(0)]], uint v [[vertex_id]])
{
    return linked_point(v, linked_shade(in[v]));
}

fragment float4 frag_linked(LinkedPoint p [[stage_in]])
{
    return float4(p.value, linked_bias(), 0.0f, 1.0f);
}

struct LinkedPayload {
    float bias;
};

[[object]] void object_linked(object_data LinkedPayload &payload [[payload]], mesh_grid_properties grid,
                              uint l [[thread_index_in_threadgroup]])
{
    if (l == 0) {
        payload.bias = linked_bias();
        grid.set_threadgroups_per_grid(uint3(1));
    }
}

[[mesh]] void mesh_linked(mesh<LinkedPoint, void, 64, 64, topology::point> m, const object_data LinkedPayload &payload [[payload]],
                          device const float *in [[buffer(0)]], uint l [[thread_index_in_threadgroup]])
{
    if (l == 0)
        m.set_primitive_count(64);
    m.set_vertex(l, linked_point(l, linked_shade(in[l]) - payload.bias));
    m.set_index(l, l);
}
