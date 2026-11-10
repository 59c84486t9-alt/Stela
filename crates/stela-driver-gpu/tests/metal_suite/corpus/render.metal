// SPDX-License-Identifier: MIT
// The render pipeline: interpolation qualifiers, derivatives, fragment
// builtins, blending, multiple render targets, discard, depth output,
// multisampling, points and vertex fetch. Vertex positions are clip-space
// float4s in buffer 0 and per-vertex attributes float4s in buffer 1; a
// fragment's per-pixel inputs come from buffer 0 indexed by its pixel, the
// target's width in buffer 1. Function constant 0 picks what a fragment
// that can return several things returns.
#include <metal_stdlib>
using namespace metal;

constant int which [[function_constant(0)]];

struct Interp {
    float4 position [[position]];
    float4 flat_ [[flat]];
    float4 center_p [[center_perspective]];
    float4 center_np [[center_no_perspective]];
    float4 centroid_p [[centroid_perspective]];
    float4 centroid_np [[centroid_no_perspective]];
    float4 sample_p [[sample_perspective]];
    float4 sample_np [[sample_no_perspective]];
    half4 half_p;
    float2 pair;
    float single;
    int4 integer [[flat]];
    uint4 unsigned_ [[flat]];
};

vertex Interp vert_interp(uint v [[vertex_id]], device const float4 *pos [[buffer(0)]],
                          device const float4 *attr [[buffer(1)]])
{
    Interp o;
    float4 a = attr[v];
    o.position = pos[v];
    o.flat_ = o.center_p = o.center_np = o.centroid_p = o.centroid_np = o.sample_p = o.sample_np = a;
    o.half_p = half4(a);
    o.pair = a.yz;
    o.single = a.w;
    o.integer = int4(a * 1000.0f);
    o.unsigned_ = uint4(v, v * 7u, 0xFFFFFFFFu - v, 0x80000000u + v);
    return o;
}

fragment float4 frag_interp(Interp in [[stage_in]])
{
    switch (which) {
    case 0: return in.flat_;
    case 1: return in.center_p;
    case 2: return in.center_np;
    case 3: return in.centroid_p;
    case 4: return in.centroid_np;
    case 5: return in.sample_p;
    case 6: return in.sample_np;
    case 7: return float4(in.half_p);
    case 8: return float4(in.pair, in.single, 1.0f);
    case 9: return float4(in.integer);
    default: return as_type<float4>(in.unsigned_);
    }
}

// Flat integers, bit for bit, into an integer target.
fragment uint4 frag_interp_uint(Interp in [[stage_in]])
{
    return in.unsigned_;
}

// Every qualifier at once, as a linked program reads them.
struct All {
    float4 a [[color(0)]];
    float4 b [[color(1)]];
    float4 c [[color(2)]];
    float4 d [[color(3)]];
};

fragment All frag_interp_all(Interp in [[stage_in]])
{
    return {in.flat_, in.center_p, in.center_np, float4(in.half_p)};
}

struct Plain {
    float4 position [[position]];
    float4 a [[center_no_perspective]];
    float4 p;
};

vertex Plain vert_plain(uint v [[vertex_id]], device const float4 *pos [[buffer(0)]],
                        device const float4 *attr [[buffer(1)]])
{
    return {pos[v], attr[v], attr[v]};
}

// Derivatives of varyings linear in the window (u in x, v in y) and of
// functions of them.
fragment float4 frag_deriv(Plain in [[stage_in]])
{
    float u = in.a.x, v = in.a.y;
    switch (which) {
    case 0: return float4(dfdx(u), dfdy(u), fwidth(u), u);
    case 1: return float4(dfdx(v), dfdy(v), fwidth(v), v);
    case 2: return float4(dfdx(in.position.xy), dfdy(in.position.xy));
    case 3: { float w = u * v; return float4(dfdx(w), dfdy(w), fwidth(w), w); }
    case 4: { float w = u * u; return float4(dfdx(w), dfdy(w), fwidth(w), w); }
    case 5: { half h = half(u); return float4(dfdx(h), dfdy(h), fwidth(h), h); }
    case 6: { half h = half(v) * 0.5h; return float4(dfdx(h), dfdy(h), fwidth(h), h); }
    case 7: { float2 q = in.a.xy; return float4(dfdx(q), fwidth(q)); }
    case 8: { half2 q = half2(in.a.xy); return float4(float2(dfdx(q)), float2(fwidth(q))); }
    case 9: return float4(dfdx(in.p.x), dfdy(in.p.y), fwidth(in.p.z), in.p.w);
    case 10: { float d = fwidth(u + v); if (uint(in.position.x) & 1) discard_fragment(); return float4(d); }
    case 12: {
        // Derivatives in a branch only some of a quad's pixels take, of a
        // value all of them computed before it.
        float w = u * u;
        if ((uint(in.position.x) + uint(in.position.y)) % 3 == 0)
            return float4(0);
        return float4(dfdx(w), dfdy(w), fwidth(w), w);
    }
    default: { float s = sin(u * 3.0f) * v; return float4(dfdx(s), dfdy(s), fwidth(s), s); }
    }
}

// A derivative in a branch some of a quad's pixels skip, of a value the
// branch computes from an interpolant and a constant buffer, which Apple
// GPUs take from every pixel of the quad (case 0); a biased sample whose
// coordinates the buffer scales (case 1); a sample with an implicit level at
// coordinates the buffer scales, in the branch (case 2); and the derivatives
// of a texel the branch reads at the pixel (case 3). Cases 2 and 3 skip whole
// quads: an M1 Pro returns other values where only some pixels skip.
struct DerivUniforms {
    float scale;
    float lod_scale;
    float bias;
};

fragment float4 frag_deriv_branch(Plain in [[stage_in]], constant DerivUniforms *k [[buffer(0)]],
                                  texture2d<float> levels [[texture(0)]], sampler s [[sampler(0)]])
{
    if (which == 1)
        return levels.sample(s, in.position.xy * k->lod_scale, bias(k->bias));
    float u = in.a.x;
    uint2 p = uint2(in.position.xy) >> (which >= 2 ? 1 : 0);
    if ((p.x + p.y) % 3 == 0)
        return float4(0);
    if (which == 2)
        return levels.sample(s, in.position.xy * k->lod_scale);
    if (which == 3) {
        float4 t = levels.read(uint2(in.position.xy));
        return float4(dfdx(t.x), dfdy(t.x), dfdx(t.y), dfdy(t.y));
    }
    float w = u * u * k->scale;
    return float4(dfdx(w), dfdy(w), fwidth(w), w);
}

fragment float4 frag_position(Plain in [[stage_in]])
{
    return in.position;
}

fragment float4 frag_facing(Plain in [[stage_in]], bool front [[front_facing]], uint primitive [[primitive_id]])
{
    return float4(front ? 1.0f : 0.0f, float(primitive), 0.0f, 1.0f);
}

#ifndef SKIP_frag_barycentric
fragment float4 frag_barycentric(Plain in [[stage_in]], float3 b [[barycentric_coord]])
{
    return float4(b, 1.0f);
}
#endif

fragment float4 frag_one(Plain in [[stage_in]])
{
    return float4(1.0f);
}

fragment float4 frag_attribute(Plain in [[stage_in]])
{
    return in.p;
}

// A 2D float texture's texels, row by row.
kernel void read_texels(texture2d<float, access::read> t [[texture(0)]], device float4 *out [[buffer(0)]],
                        uint2 p [[thread_position_in_grid]], uint2 n [[threads_per_grid]])
{
    out[p.y * n.x + p.x] = t.read(p);
}

// Window-filling triangle; per-pixel data from buffer 0.
struct Full {
    float4 position [[position]];
};

vertex Full vert_full(uint v [[vertex_id]], constant float &depth [[buffer(2)]])
{
    float2 p = float2((v << 1) & 2, v & 2);
    return {float4(p * 2.0f - 1.0f, depth, 1.0f)};
}

static uint pixel(float4 position, uint width)
{
    return uint(position.y) * width + uint(position.x);
}

fragment float4 frag_color(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                           constant uint &width [[buffer(1)]])
{
    return c[pixel(in.position, width)];
}

// frag_color with the target also read, which only a zero width returns.
fragment float4 frag_color_read(Full in [[stage_in]], float4 target [[color(0)]],
                                device const float4 *c [[buffer(0)]], constant uint &width [[buffer(1)]])
{
    return width == 0 ? target : c[pixel(in.position, width)];
}

// Integer outputs for integer targets, from the same per-pixel buffer.
fragment uint4 frag_color_uint(Full in [[stage_in]], device const uint4 *c [[buffer(0)]],
                               constant uint &width [[buffer(1)]])
{
    return c[pixel(in.position, width)];
}

fragment int4 frag_color_int(Full in [[stage_in]], device const int4 *c [[buffer(0)]],
                             constant uint &width [[buffer(1)]])
{
    return c[pixel(in.position, width)];
}

fragment half4 frag_color_half(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                               constant uint &width [[buffer(1)]])
{
    return half4(c[pixel(in.position, width)]);
}

struct Dual {
    float4 c0 [[color(0), index(0)]];
    float4 c1 [[color(0), index(1)]];
};

fragment Dual frag_dual(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                        constant uint &width [[buffer(1)]], device const float4 *second [[buffer(3)]])
{
    uint i = pixel(in.position, width);
    return {c[i], second[i]};
}

struct Targets {
    float4 unorm [[color(0)]];
    uint4 integer [[color(1)]];
    half4 floating [[color(2)]];
    int signed_ [[color(3)]];
};

fragment Targets frag_mrt(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                          constant uint &width [[buffer(1)]])
{
    uint i = pixel(in.position, width);
    float4 v = c[i];
    return {v, uint4(v * 65535.0f), half4(v * 2.0f - 1.0f), int(i) - 128};
}

fragment float4 frag_discard(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                             constant uint &width [[buffer(1)]])
{
    float4 v = c[pixel(in.position, width)];
    if (v.w < 0.5f)
        discard_fragment();
    return v;
}

struct DepthAny {
    float4 color [[color(0)]];
    float depth [[depth(any)]];
};

fragment DepthAny frag_depth(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                             constant uint &width [[buffer(1)]])
{
    return {float4(1.0f), c[pixel(in.position, width)].x};
}

struct DepthGreater {
    float4 color [[color(0)]];
    float depth [[depth(greater)]];
};

fragment DepthGreater frag_depth_greater(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                                         constant uint &width [[buffer(1)]])
{
    return {float4(1.0f), max(c[pixel(in.position, width)].x, in.position.z)};
}

struct DepthLess {
    float4 color [[color(0)]];
    float depth [[depth(less)]];
};

fragment DepthLess frag_depth_less(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                                   constant uint &width [[buffer(1)]])
{
    return {float4(1.0f), min(c[pixel(in.position, width)].x, in.position.z)};
}

struct Masked {
    float4 color [[color(0)]];
    uint mask [[sample_mask]];
};

fragment Masked frag_sample_mask(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                                 constant uint &width [[buffer(1)]])
{
    return {float4(1.0f), as_type<uint>(c[pixel(in.position, width)].x)};
}

fragment float4 frag_sample_id(Full in [[stage_in]], uint sample [[sample_id]])
{
    return float4(float(sample + 1) * 0.25f, float(sample) * 0.125f, 0.0f, 1.0f);
}

// Each sample's position within the pixel, which the resolve averages.
fragment float4 frag_sample_position(Full in [[stage_in]], uint sample [[sample_id]])
{
    return float4(get_sample_position(sample), 0.0f, 1.0f);
}

fragment float4 frag_mask_in(Plain in [[stage_in]], uint mask [[sample_mask]])
{
    return float4(float(popcount(mask)) * 0.25f, 0.0f, 0.0f, 1.0f);
}

fragment float4 frag_alpha(Full in [[stage_in]], device const float4 *c [[buffer(0)]],
                           constant uint &width [[buffer(1)]])
{
    return c[pixel(in.position, width)];
}

struct Point {
    float4 position [[position]];
    float size [[point_size]];
};

vertex Point vert_point(uint v [[vertex_id]], device const float4 *pos [[buffer(0)]],
                        device const float4 *attr [[buffer(1)]])
{
    return {pos[v], attr[v].x};
}

fragment float4 frag_point(Point in [[stage_in]], float2 coord [[point_coord]])
{
    return float4(coord, 0.0f, 1.0f);
}

// The pixels a point covers.
fragment float4 frag_point_cover(Point in [[stage_in]])
{
    return float4(1.0f);
}

// Vertex fetch: each vertex stores its attributes, rasterization off.
struct FloatAttr {
    float4 a [[attribute(0)]];
};

vertex void vert_fetch_float(FloatAttr in [[stage_in]], uint v [[vertex_id]], device float4 *out [[buffer(2)]])
{
    out[v] = in.a;
}

struct UintAttr {
    uint4 a [[attribute(0)]];
};

vertex void vert_fetch_uint(UintAttr in [[stage_in]], uint v [[vertex_id]], device uint4 *out [[buffer(2)]])
{
    out[v] = in.a;
}

struct IntAttr {
    int4 a [[attribute(0)]];
};

vertex void vert_fetch_int(IntAttr in [[stage_in]], uint v [[vertex_id]], device int4 *out [[buffer(2)]])
{
    out[v] = in.a;
}

struct HalfAttr {
    half4 a [[attribute(0)]];
};

vertex void vert_fetch_half(HalfAttr in [[stage_in]], uint v [[vertex_id]], device float4 *out [[buffer(2)]])
{
    out[v] = float4(in.a);
}

// The same fetches by a kernel, through its stage input descriptor.
kernel void stage_fetch_float(FloatAttr in [[stage_in]], uint i [[thread_position_in_grid]], device float4 *out [[buffer(2)]])
{
    out[i] = in.a;
}

kernel void stage_fetch_uint(UintAttr in [[stage_in]], uint i [[thread_position_in_grid]], device uint4 *out [[buffer(2)]])
{
    out[i] = in.a;
}

kernel void stage_fetch_int(IntAttr in [[stage_in]], uint i [[thread_position_in_grid]], device int4 *out [[buffer(2)]])
{
    out[i] = in.a;
}

kernel void stage_fetch_half(HalfAttr in [[stage_in]], uint i [[thread_position_in_grid]], device float4 *out [[buffer(2)]])
{
    out[i] = float4(in.a);
}

struct Instanced {
    float4 a [[attribute(0)]];
    float4 b [[attribute(1)]];
    float4 c [[attribute(2)]];
};

vertex void vert_instanced(Instanced in [[stage_in]], uint v [[vertex_id]], uint i [[instance_id]],
                           uint base_vertex [[base_vertex]], uint base_instance [[base_instance]],
                           device float4 *out [[buffer(3)]], constant uint &count [[buffer(4)]])
{
    uint slot = ((i - base_instance) * count + (v - base_vertex)) * 4;
    out[slot] = in.a;
    out[slot + 1] = in.b;
    out[slot + 2] = in.c;
    out[slot + 3] = float4(v, i, base_vertex, base_instance);
}

vertex void vert_ids(uint v [[vertex_id]], uint i [[instance_id]], device uint2 *out [[buffer(2)]],
                     constant uint &count [[buffer(3)]])
{
    out[i * count + v] = uint2(v, i);
}

// Mixed widths in one interleaved layout: float4, two float2s and a half4,
// as a vertex stage reads them.
struct MixedAttr {
    float4 a [[attribute(0)]];
    float2 b [[attribute(1)]];
    float2 c [[attribute(2)]];
    half4 d [[attribute(3)]];
};

vertex void vert_fetch_mixed(MixedAttr in [[stage_in]], uint v [[vertex_id]], device float4 *out [[buffer(2)]])
{
    out[v * 3] = in.a;
    out[v * 3 + 1] = float4(in.b, in.c);
    out[v * 3 + 2] = float4(in.d);
}

// The level of detail a fragment's derivatives select, clamped by the
// sampler and texture and not: uv moves `scale` per pixel.
fragment float4 frag_lod(Full in [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]],
                         constant float &scale [[buffer(3)]])
{
    float2 uv = in.position.xy * scale;
    return float4(t.calculate_clamped_lod(s, uv), t.calculate_unclamped_lod(s, uv), 0.0f, 1.0f);
}

// The pass's sample count and whether this thread is a helper.
fragment float4 frag_samples_helpers(Full in [[stage_in]])
{
    return float4(float(get_num_samples()), float(simd_is_helper_thread()), float(quad_is_helper_thread()), 1.0f);
}

#ifndef SKIP_frag_interpolant
struct Pulled {
    float4 position [[position]];
    float2 uv;
};

// uv is the pixel coordinate over the target size, (x / W, y / H).
vertex Pulled vert_uv(uint v [[vertex_id]])
{
    float2 p = float2((v << 1) & 2, v & 2) * 2.0f - 1.0f;
    return {float4(p, 0.0f, 1.0f), float2(p.x + 1.0f, 1.0f - p.y) * 0.5f};
}

struct PullIn {
    float4 position [[position]];
    interpolant<float2, interpolation::perspective> uv;
};

// The interpolant at the pixel centre, at an offset and at sample 0.
fragment float4 frag_interpolant(PullIn in [[stage_in]], constant float2 &offset [[buffer(0)]])
{
    float2 center = in.uv.interpolate_at_center();
    float2 at = in.uv.interpolate_at_offset(offset);
    float2 sample = in.uv.interpolate_at_sample(0);
    float2 centroid = in.uv.interpolate_at_centroid();
    return float4(center.x - sample.x + center.y - sample.y + centroid.x - center.x + centroid.y - center.y, center.y, at.x,
                  at.y);
}
#endif

// Layered rendering: instance i draws into slice i through viewport i.
struct Layered {
    float4 position [[position]];
    uint layer [[render_target_array_index]];
    uint viewport [[viewport_array_index]];
};

vertex Layered vert_layered(uint v [[vertex_id]], uint i [[instance_id]])
{
    float2 p = float2((v << 1) & 2, v & 2) * 2.0f - 1.0f;
    return {float4(p, 0.0f, 1.0f), i, i};
}

fragment float4 frag_layer(Layered in [[stage_in]])
{ return float4(float(in.layer), float(in.viewport), in.position.x, in.position.y); }

// Two clip distances: x * a + b and y * c + d in clip space.
struct Clipped {
    float4 position [[position]];
    float clip [[clip_distance]] [2];
};

vertex Clipped vert_clip(uint v [[vertex_id]], constant float4 &planes [[buffer(0)]])
{
    float2 p = float2((v << 1) & 2, v & 2) * 2.0f - 1.0f;
    Clipped o;
    o.position = float4(p, 0.0f, 1.0f);
    o.clip[0] = p.x * planes.x + planes.y;
    o.clip[1] = p.y * planes.z + planes.w;
    return o;
}

fragment float4 frag_white(Full in [[stage_in]])
{ return float4(1.0f); }

// Programmable blending: the target's current value read in the shader.
fragment float4 frag_fetch(Full in [[stage_in]], float4 target [[color(0)]], device const float4 *c [[buffer(0)]],
                           constant uint &width [[buffer(1)]])
{ return target * 0.5f + c[pixel(in.position, width)]; }

// Instances of one full-target triangle, all in one draw. Each counts the
// fragments before it at its pixel in x and, in y, whether those were exactly
// the instances before it, so an access that misses an earlier fragment's
// write or sees a later one loses a count.
struct Ordered {
    float4 position [[position]];
    uint instance [[flat]];
};

vertex Ordered vert_ordered(uint v [[vertex_id]], uint i [[instance_id]])
{
    float2 p = float2((v << 1) & 2, v & 2);
    return {float4(p * 2.0f - 1.0f, 0.5f, 1.0f), i};
}

// The same count kept in the target, read in the shader.
fragment float4 frag_ordered(Ordered in [[stage_in]], float4 target [[color(0)]])
{
    return float4(target.x + 1.0f, target.y + float(target.x == float(in.instance)), 0.0f, 1.0f);
}

fragment float4 frag_raster_ordered(Ordered in [[stage_in]],
                                    device uint2 *counts [[buffer(0), raster_order_group(0)]],
                                    constant uint &width [[buffer(1)]])
{
    device uint2 &count = counts[pixel(in.position, width)];
    uint2 seen = count;
    count = uint2(seen.x + 1, seen.y + uint(seen.x == in.instance));
    return float4(0.0f);
}

// Two instances in order: an occluder over the left half at depth 0.25,
// then the whole target at 0.75. With early fragment tests the hidden
// fragments of the second never run, so each instance counts exactly the
// fragments it shows.
struct Occluded {
    float4 position [[position]];
    uint instance [[flat]];
};

vertex Occluded vert_occluder(uint v [[vertex_id]], uint i [[instance_id]])
{
    float x1 = i == 0 ? 0.0f : 1.0f;
    return {float4(v & 1 ? x1 : -1.0f, v & 2 ? 1.0f : -1.0f, i == 0 ? 0.25f : 0.75f, 1.0f), i};
}

[[early_fragment_tests]]
fragment float4 frag_early(Occluded in [[stage_in]], device atomic_uint *runs [[buffer(0)]],
                           constant float4 *colors [[buffer(1)]])
{
    atomic_fetch_add_explicit(&runs[in.instance], 1u, memory_order_relaxed);
    return colors[in.instance];
}

// Each vertex's value of the triangle, uninterpolated, in the order the
// triangle's vertices were drawn.
struct PerVertex {
    float4 position [[position]];
    vertex_value<float> single;
};

fragment float4 frag_vertex_values(PerVertex in [[stage_in]])
{
    return float4(in.single.get(vertex_index::first), in.single.get(vertex_index::second),
                  in.single.get(vertex_index::third), 1.0f);
}

// Tile functions over a pass's float4 color attachment.
struct TileColor {
    float4 c [[color(0)]];
};

// Every pixel of the tile, its threads striding over it: the read color
// plus the pixel's place in the tile, and the tile's position and width.
kernel void tile_rewrite(imageblock<TileColor, imageblock_layout_implicit> block,
                         ushort2 tid [[thread_position_in_threadgroup]],
                         ushort2 tpt [[threads_per_threadgroup]],
                         ushort2 tile [[threadgroup_position_in_grid]])
{
    for (ushort y = tid.y; y < block.get_height(); y += tpt.y) {
        for (ushort x = tid.x; x < block.get_width(); x += tpt.x) {
            TileColor v = block.read(ushort2(x, y));
            v.c = float4(v.c.x + float(x), v.c.y + float(y), float(tile.x),
                         float(tile.y) + float(block.get_width()) * 0.25f);
            block.write(v, ushort2(x, y));
        }
    }
}

// Leaves a value of its tile in the tile's threadgroup memory.
kernel void tile_remember(imageblock<TileColor, imageblock_layout_implicit> block,
                          threadgroup uint *memory [[threadgroup(0)]],
                          ushort2 tid [[thread_position_in_threadgroup]],
                          ushort2 tile [[threadgroup_position_in_grid]])
{
    if (tid.x == 0 && tid.y == 0)
        memory[1] = uint(tile.x) + 10u * uint(tile.y) + 100u;
}

// Writes what an earlier dispatch left in the tile's threadgroup memory
// into the red channel of each pixel.
kernel void tile_recall(imageblock<TileColor, imageblock_layout_implicit> block,
                        threadgroup uint *memory [[threadgroup(0)]],
                        ushort2 tid [[thread_position_in_threadgroup]],
                        ushort2 tpt [[threads_per_threadgroup]])
{
    for (ushort y = tid.y; y < block.get_height(); y += tpt.y) {
        for (ushort x = tid.x; x < block.get_width(); x += tpt.x) {
            TileColor v = block.read(ushort2(x, y));
            v.c.x = float(memory[1]);
            block.write(v, ushort2(x, y));
        }
    }
}

// The tile's dimensions and the grid of tiles, at the tile's pixels.
/* Where an Apple GPU places a tile function's threads: each one's SIMD
 * lane and index in the threadgroup, its quad index, and the positions its
 * quad neighbors hold, where they exist. */
kernel void tile_lanes(imageblock<TileColor, imageblock_layout_implicit> block,
                       device uint4 *out [[buffer(0)]],
                       ushort2 p [[thread_position_in_threadgroup]],
                       ushort2 tpt [[threads_per_threadgroup]],
                       ushort lane [[thread_index_in_simdgroup]],
                       ushort simd [[simdgroup_index_in_threadgroup]],
                       ushort index [[thread_index_in_threadgroup]],
                       ushort quad [[thread_index_in_quadgroup]],
                       ushort2 tile [[threadgroup_position_in_grid]])
{
    ushort2 across = quad_shuffle_xor(p, 1), down = quad_shuffle_xor(p, 2);
    uint first = (p.x ^ 1u) < tpt.x ? uint(across.x) | uint(across.y) << 8 | 1u << 16 : 0u;
    uint second = (p.y ^ 1u) < tpt.y ? uint(down.x) | uint(down.y) << 8 | 1u << 16 : 0u;
    if (all(tile == 0))
        out[p.y * 32 + p.x] = uint4(uint(simd) * 32u + lane, uint(index) | uint(quad) << 16, first, second);
}

kernel void tile_dimensions(imageblock<TileColor, imageblock_layout_implicit> block,
                            ushort2 tid [[thread_position_in_threadgroup]],
                            ushort2 tpt [[threads_per_threadgroup]],
                            ushort2 tiles [[threadgroups_per_grid]])
{
    for (ushort y = tid.y; y < block.get_height(); y += tpt.y) {
        for (ushort x = tid.x; x < block.get_width(); x += tpt.x) {
            TileColor v = {float4(float(block.get_width()), float(block.get_height()), float(tiles.x),
                                  float(tiles.y))};
            block.write(v, ushort2(x, y));
        }
    }
}

// A pass's explicit imageblock data: tile functions set and read it, and
// fragment functions change it in raster order.
struct IbData {
    float4 a [[raster_order_group(0)]];
    float4 n [[raster_order_group(0)]];
};

struct IbOut {
    IbData d [[imageblock_data]];
    float4 c [[color(0)]];
};

// Every color of each pixel's data from the pixel's position.
kernel void tile_ib_init(imageblock<IbData, imageblock_layout_explicit> block,
                         ushort2 tid [[thread_position_in_threadgroup]],
                         ushort2 tile [[threadgroup_position_in_grid]])
{
    ushort2 p = tile * ushort2(block.get_width(), block.get_height()) + tid;
    for (ushort i = 0; i < block.get_num_colors(tid); i++) {
        threadgroup_imageblock IbData *d = block.data(tid, i, imageblock_data_rate::color);
        d->a = float4(float(p.x), float(p.y), 0.0f, 1.0f);
        d->n = float4(float(p.x) + 100.0f * float(p.y), 0.0f, 0.0f, 0.0f);
    }
}

// Adds to its pixel's data, and colors the pixel with it.
fragment IbOut frag_ib_add(float4 pos [[position]], IbData in [[imageblock_data]],
                           constant float4 &add [[buffer(0)]])
{
    IbOut o;
    o.d.a = in.a + add;
    o.d.n = in.n + float4(1000.0f, 0.0f, 0.0f, 0.0f);
    o.c = o.d.a;
    return o;
}

// Each pixel's first color's data, and its colors.
kernel void tile_ib_resolve(imageblock<IbData, imageblock_layout_explicit> block,
                            device float4 *out [[buffer(0)]],
                            constant uint2 &size [[buffer(1)]],
                            ushort2 tid [[thread_position_in_threadgroup]],
                            ushort2 tile [[threadgroup_position_in_grid]])
{
    ushort2 p = tile * ushort2(block.get_width(), block.get_height()) + tid;
    if (p.x >= size.x || p.y >= size.y)
        return;
    threadgroup_imageblock IbData *d = block.data(tid);
    out[p.y * size.x + p.x] = float4(d->a.xyz, d->n.x);
}

// A tile function of both imageblocks: the data's n.x adds the pixel's
// color's x and y, then the color becomes the data's a.xy doubled, its z
// plus the new n.x, and alpha 3.
kernel void tile_ib_mix(imageblock<TileColor, imageblock_layout_implicit> colors,
                        imageblock<IbData, imageblock_layout_explicit> data,
                        ushort2 tid [[thread_position_in_threadgroup]])
{
    TileColor c = colors.read(tid);
    threadgroup_imageblock IbData *d = data.data(tid);
    d->n.x += c.c.x + c.c.y;
    c.c = float4(d->a.xy * 2.0f, c.c.z + d->n.x, 3.0f);
    colors.write(c, tid);
}

// Functions a tile function's tables call on a pixel's color, given its
// position in the tile.
[[visible]] float4 tile_offset(float4 c, ushort2 p)
{
    return c + float4(float(p.x), float(p.y), 1.0f, 0.0f);
}

[[visible]] float4 tile_swap(float4 c, ushort2 p)
{
    return float4(c.y, c.x, c.w, float(p.x) * 2.0f + float(p.y));
}

// Each pixel's color through entry (x + y + shift) % 2 of the first table,
// then entry 0 of the second.
kernel void tile_call(imageblock<TileColor, imageblock_layout_implicit> block,
                      visible_function_table<float4(float4, ushort2)> first [[buffer(0)]],
                      visible_function_table<float4(float4, ushort2)> second [[buffer(1)]],
                      constant uint &shift [[buffer(2)]],
                      ushort2 tid [[thread_position_in_threadgroup]],
                      ushort2 tpt [[threads_per_threadgroup]])
{
    for (ushort y = tid.y; y < block.get_height(); y += tpt.y) {
        for (ushort x = tid.x; x < block.get_width(); x += tpt.x) {
            ushort2 p = ushort2(x, y);
            TileColor v = block.read(p);
            v.c = second[0](first[(uint(x) + uint(y) + shift) & 1u](v.c, p), p);
            block.write(v, p);
        }
    }
}

// Which pixels share a SIMD-group: each pixel's lane, the index of the
// pixel in lane 0, the active lanes and the group's width.
fragment float4 frag_simd_layout(Plain in [[stage_in]], uint lane [[thread_index_in_simdgroup]],
                                 uint width [[threads_per_simdgroup]])
{
    uint pixel = uint(in.position.x) + uint(in.position.y) * 1024u;
    return float4(float(lane), float(simd_broadcast(pixel, 0)), float(simd_sum(1u)), float(width));
}

// A fragment's quad through SIMD-group shuffles: its lane in the quad, the
// pixels across (lane ^ 1) and below or above (lane ^ 2), and the quad's
// last pixel by its lane index.
fragment float4 frag_simd_quads(Plain in [[stage_in]], uint lane [[thread_index_in_simdgroup]])
{
    uint pixel = uint(in.position.x) + uint(in.position.y) * 1024u;
    return float4(float(lane & 3u), float(simd_shuffle_xor(pixel, 1u)), float(simd_shuffle_xor(pixel, 2u)),
                  float(simd_shuffle(pixel, ushort(lane | 3u))));
}
