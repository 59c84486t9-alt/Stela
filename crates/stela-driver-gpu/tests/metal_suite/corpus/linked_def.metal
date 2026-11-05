// SPDX-License-Identifier: MIT
// The visible functions linked.metal calls, defined in a library of their
// own and linked into the pipelines that call them.
#include <metal_stdlib>
using namespace metal;

[[visible]] float linked_shade(float x)
{
    return x * 4.0f + 0.5f;
}

[[visible]] float linked_bias()
{
    return 0.25f;
}
