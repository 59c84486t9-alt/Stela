// SPDX-License-Identifier: MIT
// Argument buffers with buffers, textures, samplers, arrays, nested
// structures and pointers to other argument buffers.
#include <metal_stdlib>
using namespace metal;

struct Material {
    texture2d<float> albedo;
    sampler sampler;
    constant float4 *parameters;
    uint flags;
};

struct Scene {
    array<texture2d<float>, 8> textures;
    device Material *materials;
    device float *values;
    Material inline_material;
    texture2d<float, access::write> target;
};

kernel void argument_buffers(constant Scene &scene [[buffer(0)]], device float4 *out [[buffer(1)]],
                             uint2 gid [[thread_position_in_grid]])
{
    uint index = gid.x & 7;
    float2 uv = float2(gid) / 32.0f;
    device Material &material = scene.materials[index];
    float4 c = scene.textures[index].sample(material.sampler, uv);
    c += material.albedo.sample(scene.inline_material.sampler, uv) * material.parameters[0];
    c += scene.inline_material.albedo.read(gid) + float4(scene.values[index]);
    c += float4(material.flags + scene.inline_material.flags);
    scene.target.write(c, gid);
    out[gid.x] = c;
}

fragment float4 fragment_arguments(constant Scene &scene [[buffer(0)]], float4 position [[position]])
{
    return scene.textures[0].sample(scene.inline_material.sampler, position.xy) +
           *scene.inline_material.parameters;
}
