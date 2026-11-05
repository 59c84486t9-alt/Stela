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

// The same rectangles, their six indices set four and then two at a time.
[[mesh]] void mesh_rects_packed(RectMesh m, constant float4 *rects [[buffer(0)]], constant float4 *colors [[buffer(1)]],
                                uint g [[threadgroup_position_in_grid]], uint t [[thread_index_in_threadgroup]])
{
    float4 r = rects[g];
    if (t < 4)
        m.set_vertex(t, {float4(t & 1 ? r.z : r.x, t & 2 ? r.w : r.y, 0.0f, 1.0f)});
    if (t < 2)
        m.set_primitive(t, {colors[g]});
    if (t == 0) {
        m.set_indices(0, uchar4(0, 1, 2, 2));
        m.set_indices(4, uchar2(1, 3));
        m.set_primitive_count(2);
    }
}

// The rectangles again, every primitive of the second marked culled.
struct CulledPrimitive {
    float4 color [[flat]];
    bool culled [[primitive_culled]];
};

using CulledMesh = metal::mesh<MeshVertex, CulledPrimitive, 4, 2, topology::triangle>;

[[mesh]] void mesh_rects_culled(CulledMesh m, constant float4 *rects [[buffer(0)]], constant float4 *colors [[buffer(1)]],
                                uint g [[threadgroup_position_in_grid]], uint t [[thread_index_in_threadgroup]])
{
    float4 r = rects[g];
    if (t < 4)
        m.set_vertex(t, {float4(t & 1 ? r.z : r.x, t & 2 ? r.w : r.y, 0.0f, 1.0f)});
    if (t < 2)
        m.set_primitive(t, {colors[g], g == 1});
    if (t < 6) {
        const uint indices[6] = {0, 1, 2, 2, 1, 3};
        m.set_index(t, indices[t]);
    }
    if (t == 0)
        m.set_primitive_count(2);
}

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

// The same payload, the live count summed from each object thread's vote
// in threadgroup memory.
[[object]] void object_shared(object_data RectPayload &payload [[payload]], mesh_grid_properties grid,
                              constant float4 *rects [[buffer(0)]], constant float4 *colors [[buffer(1)]],
                              constant uint &count [[buffer(2)]], threadgroup uint *votes [[threadgroup(0)]],
                              uint t [[thread_index_in_threadgroup]], uint n [[threads_per_threadgroup]])
{
    votes[t] = t < count ? 1u : 0u;
    if (t < count) {
        payload.rects[t] = rects[t];
        payload.colors[t] = colors[t];
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (t == 0) {
        uint live = 0;
        for (uint k = 0; k < n; k++)
            live += votes[k];
        grid.set_threadgroups_per_grid(uint3(live, 1, 1));
    }
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

// More tessellation: triangle patches, instances placed side by side, and
// patches with no control points, which read their rectangles by patch.
struct TrianglePatch {
    patch_control_point<ControlPoint> points;
};

[[patch(triangle, 3)]]
vertex Tessellated tess_triangle(TrianglePatch patch [[stage_in]], float3 b [[position_in_patch]])
{
    float2 p = b.x * patch.points[0].position + b.y * patch.points[1].position + b.z * patch.points[2].position;
    float v = b.x * patch.points[0].value + b.y * patch.points[1].value + b.z * patch.points[2].value;
    return {float4(p, 0.0f, 1.0f), v};
}

[[patch(quad, 4)]]
vertex Tessellated tess_quad_instanced(Patch patch [[stage_in]], float2 uv [[position_in_patch]],
                                       uint instance [[instance_id]])
{
    Tessellated t = evaluate(patch, uv);
    t.position.x += float(instance);
    t.value += float(instance) * 0.2f;
    return t;
}

// (x0, y0, x1, y1) per patch; the value is linear in clip space.
[[patch(quad)]]
vertex Tessellated tess_quad_free(float2 uv [[position_in_patch]], uint id [[patch_id]],
                                  constant float4 *rects [[buffer(0)]])
{
    float4 r = rects[id];
    float2 p = mix(r.xy, r.zw, uv);
    return {float4(p, 0.0f, 1.0f), 0.3f + 0.2f * p.x + 0.1f * p.y};
}

// Mesh outputs beyond position: a target layer and a viewport per
// primitive, and a clip distance per vertex.
struct RoutedVertex {
    float4 position [[position]];
    float clip [[clip_distance]] [1];
};

struct RoutedPrimitive {
    float4 color [[flat]];
    uint layer [[render_target_array_index]];
    uint viewport [[viewport_array_index]];
};

using RoutedMesh = metal::mesh<RoutedVertex, RoutedPrimitive, 4, 2, topology::triangle>;

// Threadgroup g covers clip space in colour g, routed to the (layer,
// viewport) route[g] gives, and clipped where x < clip_x[g].
[[mesh]] void mesh_routed(RoutedMesh m, constant float4 *colors [[buffer(0)]], constant float *clip_x [[buffer(1)]],
                          constant uint2 *route [[buffer(2)]], uint g [[threadgroup_position_in_grid]],
                          uint t [[thread_index_in_threadgroup]])
{
    if (t < 4) {
        float x = t & 1 ? 1.0f : -1.0f;
        m.set_vertex(t, {float4(x, t & 2 ? 1.0f : -1.0f, 0.0f, 1.0f), {x - clip_x[g]}});
    }
    if (t < 2)
        m.set_primitive(t, {colors[g], route[g].x, route[g].y});
    if (t < 6) {
        const uint indices[6] = {0, 1, 2, 2, 1, 3};
        m.set_index(t, indices[t]);
    }
    if (t == 0)
        m.set_primitive_count(2);
}

// The fragment reads the primitive's colour alone.
struct RoutedFragment {
    float4 color [[flat]];
};

fragment float4 frag_routed(RoutedFragment in [[stage_in]])
{ return in.color; }

// Indirect commands a kernel encodes, for an executing encoder whose
// pipeline they inherit.
struct StageCommands {
    command_buffer commands [[id(0)]];
};

// Both patches from their control points, by the factors given; then the
// same patches with the control points fetched through an index buffer.
kernel void encode_patches(device StageCommands &c [[buffer(0)]], device const float *controls [[buffer(1)]],
                           const device MTLQuadTessellationFactorsHalf *factors [[buffer(2)]],
                           device const uint *point_index [[buffer(3)]], constant uint &indexed [[buffer(4)]])
{
    render_command command(c.commands, 0);
    command.set_vertex_buffer(controls, 0);
    if (indexed)
        command.draw_indexed_patches(4, 0, 2, (const device uint *)nullptr, point_index, 1, 0, factors);
    else
        command.draw_patches(4, 0, 2, (const device uint *)nullptr, 1, 0, factors);
}

// Rectangles drawn by object threadgroups sharing threadgroup memory, or
// by a grid of mesh threads reading the rectangles themselves.
kernel void encode_mesh_draws(device StageCommands &c [[buffer(0)]], device const float4 *rects [[buffer(1)]],
                              device const float4 *colors [[buffer(2)]], device const uint *count [[buffer(3)]],
                              constant uint &threads [[buffer(4)]])
{
    render_command command(c.commands, 0);
    if (threads) {
        command.set_mesh_buffer(rects, 0);
        command.set_mesh_buffer(colors, 1);
        command.draw_mesh_threads(uint3(12, 1, 1), uint3(1, 1, 1), uint3(6, 1, 1));
    } else {
        command.set_object_buffer(rects, 0);
        command.set_object_buffer(colors, 1);
        command.set_object_buffer(count, 2);
        command.set_object_threadgroup_memory_length(32, 0);
        command.draw_mesh_threadgroups(uint3(1, 1, 1), uint3(8, 1, 1), uint3(6, 1, 1));
    }
}
