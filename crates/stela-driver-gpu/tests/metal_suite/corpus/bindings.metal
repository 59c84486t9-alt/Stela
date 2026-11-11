// SPDX-License-Identifier: GPL-2.0-or-later
// Every stage's binding slots read back, so that each way of binding them
// (one call per slot, calls over ranges, offsets moved after binding) and
// each way of making argument-buffer targets resident can be compared:
// buffers in a run and past a gap, an inline word, textures in a run and
// past a gap, samplers whose LOD clamps come from the state or from the
// binding, and words reached through an argument buffer, one in a heap.
#include <metal_stdlib>
using namespace metal;

struct Reach {
    device const uint *heaped [[id(0)]];
    device const uint *resident [[id(1)]];
};

#define SLOTS                                                                                                          \
    device uint *out [[buffer(0)]], device const uint *b1 [[buffer(1)]], device const uint *b2 [[buffer(2)]],          \
        constant uint &word [[buffer(3)]], device const uint *b4 [[buffer(4)]], constant Reach &reach [[buffer(6)]],  \
        texture2d<float> t0 [[texture(0)]], texture2d<float> t1 [[texture(1)]], texture2d<float> t3 [[texture(3)]], \
        sampler s0 [[sampler(0)]], sampler s1 [[sampler(1)]], sampler s3 [[sampler(3)]]
#define READ read_slots(out, b1, b2, word, b4, reach, t0, t1, t3, s0, s1, s3)

static uint level_value(texture2d<float> t, sampler s)
{
    return uint(rint(t.sample(s, float2(0.5f), level(0)).r * 255.0f));
}

// Three buffer words, the inline word, each texture's level 0, the levels
// the two clamped samplers select, and the argument buffer's two words.
static void read_slots(device uint *out, device const uint *b1, device const uint *b2, constant uint &word,
                       device const uint *b4, constant Reach &reach, texture2d<float> t0, texture2d<float> t1,
                       texture2d<float> t3, sampler s0, sampler s1, sampler s3)
{
    out[0] = b1[0];
    out[1] = b2[0];
    out[2] = word;
    out[3] = b4[0];
    out[4] = level_value(t0, s0);
    out[5] = level_value(t1, s0);
    out[6] = level_value(t3, s0);
    out[7] = level_value(t0, s1);
    out[8] = level_value(t1, s3);
    out[9] = reach.heaped[0];
    out[10] = reach.resident[0];
}

kernel void bound_compute(SLOTS)
{
    READ;
}

struct BoundPoint {
    float4 position [[position]];
    float size [[point_size]];
};

// The compiler warns that a vertex function that returns a position may
// run more than once per vertex; it writes the same words each time.
vertex BoundPoint bound_vertex(SLOTS)
{
    READ;
    return {float4(0.0f, 0.0f, 0.0f, 1.0f), 1.0f};
}

fragment float4 bound_fragment(SLOTS)
{
    READ;
    return float4(1.0f);
}

[[object]] void bound_object(SLOTS, mesh_grid_properties grid)
{
    READ;
    grid.set_threadgroups_per_grid(uint3(1));
}

[[mesh]] void bound_mesh(SLOTS, mesh<BoundPoint, void, 1, 1, topology::point> m)
{
    READ;
    m.set_primitive_count(1);
    m.set_vertex(0, {float4(0.0f, 0.0f, 0.0f, 1.0f), 1.0f});
    m.set_index(0, 0);
}
