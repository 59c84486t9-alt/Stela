//! Indirect command buffers. The device holds their contents behind an
//! `Arc`, so an execution reads a snapshot while the CPU keeps encoding.
use super::Device;
use crate::gpu::metal::{
    error::Result,
    indirect::{IndirectCommandBuffer, IndirectCommandBufferDescriptor, IndirectCommandBufferId},
    shader::Compiler,
    vulkan::backend::Backend,
};
use alloc::sync::Arc;

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `newIndirectCommandBufferWithDescriptor:maxCommandCount:options:`.
    pub fn new_indirect_command_buffer(
        &mut self,
        descriptor: &IndirectCommandBufferDescriptor,
        max_command_count: u64,
    ) -> Result<IndirectCommandBufferId> {
        let buffer = IndirectCommandBuffer::new(&self.capabilities, descriptor, max_command_count)?;
        Ok(IndirectCommandBufferId(
            self.indirect.insert(Arc::new(buffer)),
        ))
    }

    pub fn indirect_command_buffer(
        &self,
        id: IndirectCommandBufferId,
    ) -> Result<&IndirectCommandBuffer> {
        self.indirect.get(id.0).map(|buffer| &**buffer)
    }

    /// The contents to encode commands into (`indirectRenderCommandAtIndex:`
    /// and `indirectComputeCommandAtIndex:`) or reset.
    pub fn indirect_command_buffer_mut(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<&mut IndirectCommandBuffer> {
        Ok(Arc::make_mut(self.indirect.get_mut(id.0)?))
    }

    pub fn destroy_indirect_command_buffer(&mut self, id: IndirectCommandBufferId) -> Result<()> {
        self.indirect.remove(id.0).map(drop)
    }

    pub(super) fn indirect_snapshot(
        &self,
        id: IndirectCommandBufferId,
    ) -> Result<Arc<IndirectCommandBuffer>> {
        self.indirect.get(id.0).cloned()
    }
}
