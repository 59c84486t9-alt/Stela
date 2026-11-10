// The API surface around shaders: storage modes, host copies, inline
// constants, counters, visibility results, logging, reflection, resolves
// and render targets within a texture.
#include <metal_stdlib>
using namespace metal;

// Each element doubled plus its index.
kernel void touch(device uint *data [[buffer(0)]], uint i [[thread_position_in_grid]])
{
    data[i] = data[i] * 2u + i;
}

// Nothing: a case whose outputs come from the host's copies alone.
kernel void nothing() {}

// Constants set inline with setBytes.
struct Params {
    uint scale;
    uint offset;
    float4 weights;
};

kernel void params(device uint *data [[buffer(0)]], constant Params &p [[buffer(1)]],
                   uint i [[thread_position_in_grid]])
{
    data[i] = data[i] * p.scale + p.offset + uint(p.weights[i % 4]);
}

// One minus each texel, from one texture into another.
kernel void invert_texture(texture2d<float, access::read> in [[texture(0)]],
                           texture2d<float, access::write> out [[texture(1)]],
                           uint2 p [[thread_position_in_grid]])
{
    out.write(1.0f - in.read(p), p);
}

// Each texel of a 2D texture, row by row.
kernel void read_rows(texture2d<float> t [[texture(0)]], device float4 *out [[buffer(0)]],
                      uint2 p [[thread_position_in_grid]])
{
    out[p.y * t.get_width() + p.x] = t.read(p);
}

// What the shader logs: formatted values, on the default log and on a
// named subsystem and category at each level.
constant os_log suite_log("com.stela.suite", "api");

kernel void log_values(device const uint *data [[buffer(0)]], uint i [[thread_position_in_grid]])
{
    if (i != 0)
        return;
    os_log_default.log("value %u signed %d hex %x", data[0], int(data[1]), data[2]);
    suite_log.log_debug("debug %u", data[3]);
    suite_log.log_info("info %.3f", float(data[4]) / 8.0f);
    suite_log.log_error("error text %u", data[2] & 0xFu);
    suite_log.log_fault("fault %u", data[5]);
}

// A kernel whose every binding reflection reports.
struct Item {
    float4 position;
    uint id;
    half2 uv;
    float3x3 basis;
};

kernel void reflected(device Item *items [[buffer(0)]], constant float4 *weights [[buffer(2)]],
                      device const uint *ids [[buffer(5)]],
                      texture2d<half, access::read> src [[texture(0)]],
                      texture2d_array<uint, access::write> dst [[texture(3)]],
                      depth2d<float> shadow [[texture(4)]], sampler s [[sampler(1)]],
                      threadgroup float *scratch [[threadgroup(0)]],
                      uint i [[thread_position_in_grid]], uint l [[thread_index_in_threadgroup]])
{
    threadgroup uint fixed[64];
    fixed[l % 64] = ids[i];
    scratch[l] = weights[i].x + float(src.read(uint2(i, 0)).x) + shadow.sample(s, float2(0.5f));
    threadgroup_barrier(mem_flags::mem_threadgroup);
    items[i].id = fixed[(l + 1) % 64] + uint(scratch[l]);
    dst.write(uint4(items[i].id), uint2(i, 0), 0);
}

// Nested types reflection describes in full: a struct holding an array
// of structs, an argument buffer of textures, a sampler, a pointer and
// an array of textures, and an atomic counter.
struct Inner {
    float2 uv;
    uint ids[3];
};

struct Outer {
    float4 color;
    Inner inner[2];
    packed_float3 p;
};

struct Resources {
    texture2d<float> image [[id(0)]];
    depth2d<float> shadow [[id(1)]];
    sampler s [[id(2)]];
    device float *data [[id(3)]];
    array<texture2d<float>, 2> layers [[id(4)]];
};

kernel void reflected_types(device Outer *outer [[buffer(0)]], constant Resources &res [[buffer(1)]],
                            device atomic_uint *count [[buffer(2)]], uint i [[thread_position_in_grid]])
{
    float4 v = res.image.sample(res.s, outer[i].inner[0].uv) + res.layers[1].read(uint2(0));
    outer[i].color = v + float4(res.shadow.read(uint2(0)), res.data[i], float(outer[i].inner[1].ids[2]), outer[i].p.x);
    atomic_fetch_add_explicit(count, 1u, memory_order_relaxed);
}

// Rectangles at a depth, four vertices each: x0, y0, x1, y1 and z.
struct DepthRect {
    float4 rect;
    float4 depth;
};

struct Placed {
    float4 position [[position]];
};

vertex Placed vert_depth_rect(device const DepthRect *rects [[buffer(0)]], uint v [[vertex_id]])
{
    DepthRect r = rects[v / 4];
    uint c = v % 4;
    return {float4(c & 1 ? r.rect.z : r.rect.x, c & 2 ? r.rect.w : r.rect.y, r.depth.x, 1.0f)};
}

fragment float4 frag_flat(Placed in [[stage_in]], constant float4 &color [[buffer(0)]])
{
    return color;
}

// The colour less what the attachment holds, which the function reads.
fragment float4 frag_flat_less_target(Placed in [[stage_in]], float4 target [[color(0)]],
                                      constant float4 &color [[buffer(0)]])
{
    return color - target;
}

// The fragment's depth as its colour.
fragment float4 frag_depth_color(Placed in [[stage_in]])
{
    return float4(in.position.z);
}

// A rectangle and colour given inline with setVertexBytes and
// setFragmentBytes.
vertex Placed vert_inline_rect(constant float4 &r [[buffer(0)]], uint v [[vertex_id]])
{
    return {float4(v & 1 ? r.z : r.x, v & 2 ? r.w : r.y, 0.0f, 1.0f)};
}

// Corners from a buffer, for indexed strips.
vertex Placed vert_corner(device const float2 *corners [[buffer(0)]], uint v [[vertex_id]])
{
    return {float4(corners[v], 0.0f, 1.0f)};
}

// A colour whose alpha alpha-to-one replaces.
fragment float4 frag_translucent()
{
    return float4(0.25f, 0.5f, 0.75f, 0.3f);
}

// Per sample: depth 0.1 * (sample + 1) and stencil sample + 1, for
// resolving each by its filter.
struct SampleDepth {
    float4 color [[color(0)]];
    float depth [[depth(any)]];
    uint stencil [[stencil]];
};

fragment SampleDepth frag_sample_depth(Placed in [[stage_in]], uint s [[sample_id]])
{
    return {float4(float(s) / 8.0f), 0.1f * float(s + 1), s + 1};
}

struct SampleDepthOnly {
    float4 color [[color(0)]];
    float depth [[depth(any)]];
};

fragment SampleDepthOnly frag_sample_depth_only(Placed in [[stage_in]], uint s [[sample_id]])
{
    return {float4(float(s) / 8.0f), 0.1f * float(s + 1)};
}

fragment float4 frag_sample_value(Placed in [[stage_in]], uint s [[sample_id]])
{
    return float4(float(s) / 8.0f);
}

// Each texel 1 where it is lit, for checking which lines a wireframe
// lights: per edge, whether enough texels within a texel of it are lit.
kernel void edge_hits(texture2d<float> t [[texture(0)]], device const float4 *edges [[buffer(0)]],
                      device uint *hits [[buffer(1)]], uint e [[thread_position_in_grid]])
{
    float4 line = edges[e];
    uint lit = 0, steps = 64;
    for (uint k = 1; k < steps; k++) {
        float2 p = mix(line.xy, line.zw, float(k) / float(steps));
        bool near = false;
        for (int dy = -1; dy <= 1; dy++)
            for (int dx = -1; dx <= 1; dx++) {
                int2 q = int2(p) + int2(dx, dy);
                if (q.x >= 0 && q.y >= 0 && q.x < int(t.get_width()) && q.y < int(t.get_height()))
                    near = near || t.read(uint2(q)).x > 0.0f;
            }
        lit += near ? 1u : 0u;
    }
    hits[e] = lit >= steps - 1 - 4 ? 1u : 0u;
}

// Each texel's stencil, read through a stencil view.
kernel void read_stencil(texture2d<uint> t [[texture(0)]], device uint *out [[buffer(0)]],
                         uint2 p [[thread_position_in_grid]])
{
    out[p.y * t.get_width() + p.x] = t.read(p).x;
}

// A 1024-thread threadgroup over 32 KiB of threadgroup memory: each
// thread fills its share, then sums the mirrored share.
kernel void big_group(device uint *out [[buffer(0)]], threadgroup uint *shared [[threadgroup(0)]],
                      uint l [[thread_index_in_threadgroup]], uint n [[threads_per_threadgroup]])
{
    for (uint k = l; k < 8192; k += n)
        shared[k] = k * 3u;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint sum = 0;
    for (uint k = l; k < 8192; k += n)
        sum += shared[8191 - k];
    out[l] = sum;
}

// Bindings at the last index of the buffer, texture and sampler tables.
kernel void last_slots(device uint *out [[buffer(30)]], constant uint &k [[buffer(29)]],
                       texture2d<float> t [[texture(127)]], sampler s [[sampler(15)]])
{
    out[0] = uint(round(t.sample(s, float2(0.5f)).x * 255.0f)) + k;
}

// Eight colour attachments, each written its index plus one.
struct Eight {
    float c0 [[color(0)]];
    float c1 [[color(1)]];
    float c2 [[color(2)]];
    float c3 [[color(3)]];
    float c4 [[color(4)]];
    float c5 [[color(5)]];
    float c6 [[color(6)]];
    float c7 [[color(7)]];
};

fragment Eight frag_eight(Placed in [[stage_in]])
{
    return {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
}

// A position fetched from the last vertex attribute and buffer.
struct LastAttribute {
    float2 position [[attribute(30)]];
};

vertex Placed vert_last_attribute(LastAttribute in [[stage_in]])
{
    return {float4(in.position, 0.0f, 1.0f)};
}
