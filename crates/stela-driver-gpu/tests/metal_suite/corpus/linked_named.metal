// SPDX-License-Identifier: MIT
// A visible function linked.metal calls as linked_scaled: the pipeline links
// a specialization of linked_scale_impl that a function descriptor names so.
#include <metal_stdlib>
using namespace metal;

constant uint linked_scale [[function_constant(0)]];

[[visible]] uint linked_scale_impl(uint x)
{
    return x * linked_scale + 7u;
}
