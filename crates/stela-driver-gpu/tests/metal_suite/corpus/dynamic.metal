// SPDX-License-Identifier: GPL-2.0-or-later
// A dynamic library: functions other libraries link against and call.
#include <metal_stdlib>
using namespace metal;

float dyn_scale(float x) { return x * 3.0f + 1.0f; }

float4 dyn_tint(float4 c) { return float4(c.bgr, 1.0f - c.a); }
