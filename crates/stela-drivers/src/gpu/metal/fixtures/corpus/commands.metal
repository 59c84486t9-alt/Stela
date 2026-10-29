// SPDX-License-Identifier: MIT
// Kernels encoding indirect command buffers.
#include <metal_stdlib>
using namespace metal;

struct Commands {
    command_buffer draws;
    command_buffer dispatches;
    render_pipeline_state pipeline;
    compute_pipeline_state kernel_pipeline;
};

kernel void encode(device Commands &commands [[buffer(0)]], const device float4 *bounds [[buffer(1)]],
                   const device uint *counts [[buffer(2)]], uint id [[thread_position_in_grid]])
{
    render_command draw(commands.draws, id);
    if (bounds[id].w <= 0.0f) {
        draw.reset();
        return;
    }
    draw.set_render_pipeline_state(commands.pipeline);
    draw.set_vertex_buffer(bounds, 0);
    draw.set_fragment_buffer(counts, 1);
    draw.draw_primitives(primitive_type::triangle, 0, counts[id], 1, id);
    compute_command dispatch(commands.dispatches, id);
    dispatch.set_compute_pipeline_state(commands.kernel_pipeline);
    dispatch.set_kernel_buffer(counts, 0);
    dispatch.concurrent_dispatch_threadgroups(uint3(counts[id], 1, 1), uint3(64, 1, 1));
    dispatch.set_barrier();
}
