#include <metal_stdlib>
using namespace metal;
kernel void stela_fp32(device uint *data [[buffer(7)]], uint tid [[thread_position_in_grid]]) {
    uint base = tid * 12u;
    uint a_bits = data[base], b_bits = data[base + 1u];
    float a = as_type<float>(a_bits), b = as_type<float>(b_bits);
    int s = as_type<int>(data[base + 2u]);
    uint u = data[base + 3u];
    data[base + 4u] = a_bits;
    data[base + 5u] = as_type<uint>(-a);
    data[base + 6u] = (tid & 1u) ? a_bits : b_bits;
    data[base + 7u] = as_type<uint>(a + b);
    data[base + 8u] = as_type<uint>(a - b);
    data[base + 9u] = as_type<uint>(a * b);
    data[base + 10u] = as_type<uint>(float(s));
    data[base + 11u] = as_type<uint>(float(u));
}
