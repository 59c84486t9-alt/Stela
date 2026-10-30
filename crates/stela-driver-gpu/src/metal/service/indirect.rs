//! Indirect command buffers: creation, `gpuResourceID` and `resetWithRange:`.
//! Their commands are encoded by `EncodeIndirect` and run by committed
//! command streams.
use super::{
    Call, Object, Service, boolean, command_range, known,
    wire::{
        Empty, Fault, Handle, IndirectInherits, NewIndirectRequest, Value, commands::IndirectRange,
    },
};
use crate::metal::{
    abi::IndirectCommandType,
    indirect::{IndirectCommandBufferDescriptor, IndirectCommandBufferId},
    shader::Compiler,
    vulkan::backend::Backend,
};

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn new_indirect_command_buffer(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewIndirectRequest = call.request()?;
        let inherits = known(
            IndirectInherits::from_bits(request.inherits),
            "inherited state",
        )?;
        let inherit = |state| inherits.contains(state);
        let descriptor = IndirectCommandBufferDescriptor {
            command_types: known(
                IndirectCommandType::from_bits(request.command_types),
                "indirect command types",
            )?,
            inherit_pipeline_state: inherit(IndirectInherits::PIPELINE_STATE),
            inherit_buffers: inherit(IndirectInherits::BUFFERS),
            inherit_cull_mode: inherit(IndirectInherits::CULL_MODE),
            inherit_depth_stencil_state: inherit(IndirectInherits::DEPTH_STENCIL_STATE),
            inherit_depth_bias: inherit(IndirectInherits::DEPTH_BIAS),
            inherit_depth_clip_mode: inherit(IndirectInherits::DEPTH_CLIP_MODE),
            inherit_front_facing_winding: inherit(IndirectInherits::FRONT_FACING_WINDING),
            inherit_triangle_fill_mode: inherit(IndirectInherits::TRIANGLE_FILL_MODE),
            max_vertex_buffer_bind_count: request.max_vertex_buffer_bind_count,
            max_fragment_buffer_bind_count: request.max_fragment_buffer_bind_count,
            max_kernel_buffer_bind_count: request.max_kernel_buffer_bind_count,
            max_kernel_threadgroup_memory_bind_count: request
                .max_kernel_threadgroup_memory_bind_count,
            max_object_buffer_bind_count: request.max_object_buffer_bind_count,
            max_mesh_buffer_bind_count: request.max_mesh_buffer_bind_count,
            support_ray_tracing: boolean(request.support_ray_tracing)?,
            support_dynamic_attribute_stride: boolean(request.support_dynamic_attribute_stride)?,
        };
        let buffer = self
            .device
            .new_indirect_command_buffer(&descriptor, request.max_command_count)?;
        let handle = self.hold(call.connection, Object::IndirectCommandBuffer(buffer))?;
        call.reply(&handle)
    }

    pub(super) fn indirect_resource_id(&mut self, call: &mut Call) -> Result<(), Fault> {
        let Handle { handle } = call.request()?;
        let buffer = self.object::<IndirectCommandBufferId>(call.connection, handle)?;
        let value = self.device.indirect_command_buffer_resource_id(buffer)?;
        call.reply(&Value { value })
    }

    pub(super) fn reset_indirect(&mut self, call: &mut Call) -> Result<(), Fault> {
        let IndirectRange {
            buffer,
            first,
            count,
        } = call.request()?;
        let buffer = self.object::<IndirectCommandBufferId>(call.connection, buffer)?;
        let range = command_range(first, count)?;
        self.device
            .indirect_command_buffer_mut(buffer)?
            .reset(range)?;
        call.reply(&Empty {})
    }
}
