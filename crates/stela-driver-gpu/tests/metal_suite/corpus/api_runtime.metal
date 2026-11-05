// Compiled by the device at run time: SCALE and OFFSET come from the
// compile options' macros, and the language version from their version.
#include <metal_stdlib>
using namespace metal;

#ifndef OFFSET
#define OFFSET 7u
#endif

kernel void runtime_scale(device uint *data [[buffer(0)]], uint i [[thread_position_in_grid]])
{
    data[i] = data[i] * SCALE + OFFSET + __METAL_VERSION__;
}
