// SPDX-License-Identifier: MIT
// Programmable stages beyond vertex and fragment: tessellation of quad
// patches with control points read through stage-in.
#include <metal_stdlib>
using namespace metal;

struct ControlPoint {
    float2 position [[attribute(0)]];
    float value [[attribute(1)]];
};

struct Patch {
    patch_control_point<ControlPoint> points;
};

struct Tessellated {
    float4 position [[position]];
    float value;
};

// The patch's corners are 0 (u, v) = (0, 0), 1 (1, 0), 2 (1, 1), 3 (0, 1),
// interpolated bilinearly.
static Tessellated evaluate(Patch patch, float2 uv)
{
    float2 a = mix(patch.points[0].position, patch.points[1].position, uv.x);
    float2 b = mix(patch.points[3].position, patch.points[2].position, uv.x);
    float va = mix(patch.points[0].value, patch.points[1].value, uv.x);
    float vb = mix(patch.points[3].value, patch.points[2].value, uv.x);
    return {float4(mix(a, b, uv.y), 0.0f, 1.0f), mix(va, vb, uv.y)};
}

[[patch(quad, 4)]]
vertex Tessellated tess_quad(Patch patch [[stage_in]], float2 uv [[position_in_patch]])
{ return evaluate(patch, uv); }

// Records each domain point it evaluates at its slot of an (n + 1) x
// (n + 1) grid per patch, as (u, v, value, patch); nothing is rasterized.
[[patch(quad, 4)]]
vertex void tess_record(Patch patch [[stage_in]], float2 uv [[position_in_patch]], uint id [[patch_id]],
                        device float4 *points [[buffer(2)]], constant uint &n [[buffer(3)]])
{
    uint slot = id * (n + 1) * (n + 1) + uint(round(uv.y * float(n))) * (n + 1) + uint(round(uv.x * float(n)));
    points[slot] = float4(uv, evaluate(patch, uv).value, float(id));
}

fragment float4 frag_tessellated(Tessellated in [[stage_in]])
{ return float4(in.value, 0.0f, 0.0f, 1.0f); }

// Mesh shading: each mesh threadgroup emits one rectangle (x0, y0, x1, y1)
// as two triangles with a per-primitive colour.
struct MeshVertex {
    float4 position [[position]];
};

struct MeshPrimitive {
    float4 color [[flat]];
};

using RectMesh = metal::mesh<MeshVertex, MeshPrimitive, 4, 2, topology::triangle>;

static void emit_rect(RectMesh m, float4 r, float4 color, uint t)
{
    if (t < 4)
        m.set_vertex(t, {float4(t & 1 ? r.z : r.x, t & 2 ? r.w : r.y, 0.0f, 1.0f)});
    if (t < 2)
        m.set_primitive(t, {color});
    if (t < 6) {
        const uint indices[6] = {0, 1, 2, 2, 1, 3};
        m.set_index(t, indices[t]);
    }
    if (t == 0)
        m.set_primitive_count(2);
}

[[mesh]] void mesh_rects(RectMesh m, constant float4 *rects [[buffer(0)]], constant float4 *colors [[buffer(1)]],
                         uint g [[threadgroup_position_in_grid]], uint t [[thread_index_in_threadgroup]])
{ emit_rect(m, rects[g], colors[g], t); }

// An object threadgroup chooses how many mesh threadgroups run, and hands
// each its rectangle through the payload.
struct RectPayload {
    float4 rects[8];
    float4 colors[8];
};

[[object]] void object_rects(object_data RectPayload &payload [[payload]], mesh_grid_properties grid,
                             constant float4 *rects [[buffer(0)]], constant float4 *colors [[buffer(1)]],
                             constant uint &count [[buffer(2)]], uint t [[thread_index_in_threadgroup]])
{
    if (t < count) {
        payload.rects[t] = rects[t];
        payload.colors[t] = colors[t];
    }
    if (t == 0)
        grid.set_threadgroups_per_grid(uint3(count, 1, 1));
}

[[mesh]] void mesh_payload(RectMesh m, const object_data RectPayload &payload [[payload]],
                           uint g [[threadgroup_position_in_grid]], uint t [[thread_index_in_threadgroup]])
{ emit_rect(m, payload.rects[g], payload.colors[g], t); }

struct MeshFragment {
    MeshVertex v;
    MeshPrimitive p;
};

fragment float4 frag_mesh(MeshFragment in [[stage_in]])
{ return in.p.color; }

// Vertex amplification: one draw, each view its own colour, routed to a
// target layer or viewport by the encoder's view mappings.
struct AmplifiedVertex {
    float4 position [[position]];
    float4 color;
};

vertex AmplifiedVertex vert_amplified(uint v [[vertex_id]], ushort view [[amplification_id]],
                                      ushort views [[amplification_count]], constant float4 *colors [[buffer(0)]])
{
    float4 c = colors[view];
    c.w = float(views) * 0.25f;
    return {float4(v & 1 ? 1.0f : -1.0f, v & 2 ? 1.0f : -1.0f, 0.0f, 1.0f), c};
}

fragment float4 frag_amplified(AmplifiedVertex in [[stage_in]])
{ return in.color; }
