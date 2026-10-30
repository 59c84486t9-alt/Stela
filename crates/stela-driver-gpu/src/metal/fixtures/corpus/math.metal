// SPDX-License-Identifier: MIT
// The math library over float, half and their vectors, in the default,
// precise and fast namespaces, with geometric and matrix functions.
#include <metal_stdlib>
using namespace metal;

kernel void float_math(device float4 *data [[buffer(0)]], uint tid [[thread_position_in_grid]])
{
    float4 x = data[tid], y = data[tid + 1];
    float4 r = sin(x) + cos(y) + tan(x) + asin(x) + acos(y) + atan(x) + atan2(x, y);
    r += sinh(x) + cosh(y) + tanh(x) + asinh(x) + acosh(y + 2) + atanh(x * 0.5f);
    r += exp(x) + exp2(y) + exp10(x) + log(y) + log2(x) + log10(y) + pow(x, y) + powr(x, y);
    r += sqrt(x) + rsqrt(y) + fma(x, y, r) + fmod(x, y);
    r += floor(x) + ceil(y) + round(x) + rint(y) + trunc(x) + fract(y) + abs(x) + fabs(y);
    r += min(x, y) + max(x, y) + fmin(x, y) + fmax(x, y) + clamp(x, 0.0f, 1.0f) + saturate(y);
    r += mix(x, y, 0.25f) + step(x, y) + smoothstep(0.0f, 1.0f, x) + sign(y) + copysign(x, y);
    r += fdim(x, y) + ldexp(x, int4(2)) + modf(x, y) + sinpi(x) + cospi(y) + tanpi(x);
    r += select(x, y, isnan(x) || isinf(y) || isfinite(x) || signbit(y) || isnormal(x));
    int4 e;
    r += frexp(x, e) + float4(e) + nextafter(x, y);
    r += precise::sin(x) + precise::exp(y) + precise::sqrt(x) + precise::divide(x, y);
    r += fast::cos(x) + fast::log(y) + fast::rsqrt(x) + fast::divide(x, y) + fast::pow(x, y);
    r += sincos(x, y) + y;
    data[tid] = r;
}

kernel void half_math(device half4 *data [[buffer(0)]], uint tid [[thread_position_in_grid]])
{
    half4 x = data[tid], y = data[tid + 1];
    half4 r = sin(x) + cos(y) + exp(x) + log(y) + sqrt(x) + rsqrt(y) + pow(x, y);
    r += fma(x, y, r) + floor(x) + fract(y) + clamp(x, 0.0h, 1.0h) + mix(x, y, 0.5h);
    r += min(x, y) + max(x, y) + abs(x) + sign(y) + smoothstep(0.0h, 1.0h, x);
    data[tid] = r + half4(float4(x) * 2.0f);
}

kernel void geometry(device float4 *data [[buffer(0)]], device float4x4 *matrices [[buffer(1)]],
                     uint tid [[thread_position_in_grid]])
{
    float4 x = data[tid];
    float3 a = x.xyz, b = data[tid + 1].xyz;
    float3 c = cross(a, b) + normalize(a) + reflect(a, b) + refract(a, b, 0.5f) + faceforward(a, b, a);
    float d = dot(a, b) + length(a) + distance(a, b) + length_squared(b) + distance_squared(a, b);
    float4x4 m = matrices[tid];
    float4 v = m * x + transpose(m) * x + float4(determinant(m));
    float3x3 n = float3x3(a, b, c);
    v.xyz += n * a + a * n;
    data[tid] = v + float4(c, d);
}

kernel void conversions(device uint4 *data [[buffer(0)]], uint tid [[thread_position_in_grid]])
{
    uint4 x = data[tid];
    float4 f = as_type<float4>(x);
    uint packed = pack_float_to_unorm4x8(saturate(f)) ^ pack_float_to_snorm4x8(f);
    packed ^= pack_float_to_unorm2x16(f.xy) ^ pack_float_to_snorm2x16(f.zw);
    float4 u = unpack_unorm4x8_to_float(x.x) + unpack_snorm4x8_to_float(x.y);
    u.xy += unpack_unorm2x16_to_float(x.z) + unpack_snorm2x16_to_float(x.w);
    half4 h = half4(f) + unpack_unorm4x8_to_half(x.x);
    int4 i = int4(f) + int4(rint(f));
    data[tid] = uint4(packed) + as_type<uint4>(u) + uint4(as_type<uint2>(h), uint2(i.xy)) +
                uint4(char4(i)) + uint4(ushort4(x));
}
