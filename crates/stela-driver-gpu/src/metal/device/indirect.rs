//! Indirect command buffers. The device holds their contents behind an
//! `Arc`, so an execution reads a snapshot while the CPU keeps encoding,
//! and a GPU-resident buffer's records in a shared buffer of their own.
use super::{BufferId, Device};
use crate::metal::{
    command_buffer::BufferRef,
    error::Result,
    indirect::{
        IndirectCommandBuffer, IndirectCommandBufferDescriptor, IndirectCommandBufferId,
        RecordLayout,
    },
    shader::Compiler,
    vulkan::backend::Backend,
};
use alloc::{sync::Arc, vec::Vec};

#[derive(Debug)]
pub(super) struct IndirectObject {
    contents: Arc<IndirectCommandBuffer>,
    /// The records of a GPU-resident buffer.
    records: Option<BufferId>,
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `newIndirectCommandBufferWithDescriptor:maxCommandCount:options:`.
    pub fn new_indirect_command_buffer(
        &mut self,
        descriptor: &IndirectCommandBufferDescriptor,
        max_command_count: u64,
    ) -> Result<IndirectCommandBufferId> {
        let buffer = IndirectCommandBuffer::new(&self.capabilities, descriptor, max_command_count)?;
        Ok(IndirectCommandBufferId(self.indirect.insert(
            IndirectObject {
                contents: Arc::new(buffer),
                records: None,
            },
        )))
    }

    pub fn indirect_command_buffer(
        &self,
        id: IndirectCommandBufferId,
    ) -> Result<&IndirectCommandBuffer> {
        self.indirect.get(id.0).map(|object| &*object.contents)
    }

    /// The contents to encode commands into (`indirectRenderCommandAtIndex:`
    /// and `indirectComputeCommandAtIndex:`) or reset.
    pub fn indirect_command_buffer_mut(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<&mut IndirectCommandBuffer> {
        Ok(Arc::make_mut(&mut self.indirect.get_mut(id.0)?.contents))
    }

    /// `gpuResourceID`: the address shaders encode commands through, which
    /// makes the buffer GPU-resident.
    pub fn indirect_command_buffer_resource_id(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<u64> {
        Ok(self.indirect_records(id)?.1.address)
    }

    pub fn destroy_indirect_command_buffer(&mut self, id: IndirectCommandBufferId) -> Result<()> {
        let object = self.indirect.remove(id.0)?;
        object
            .records
            .map_or(Ok(()), |records| self.destroy_buffer(records))
    }

    pub(super) fn indirect_snapshot(
        &self,
        id: IndirectCommandBufferId,
    ) -> Result<Arc<IndirectCommandBuffer>> {
        self.indirect
            .get(id.0)
            .map(|object| object.contents.clone())
    }

    /// The layout and buffer of an indirect command buffer's records, making
    /// it GPU-resident.
    pub(super) fn indirect_records(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<(RecordLayout, BufferRef)> {
        let object = self.indirect.get(id.0)?;
        if let (Some(records), Some(layout)) = (object.records, object.contents.records()) {
            return Ok((*layout, self.buffer(records)?));
        }
        let (layout, image) = object.contents.resident_image()?;
        let records = self.new_shared_buffer(&image)?;
        let object = self.indirect.get_mut(id.0)?;
        let contents = Arc::make_mut(&mut object.contents);
        contents.make_resident(layout);
        if self.command_barriers {
            contents.note_barriers();
        }
        object.records = Some(records);
        Ok((layout, self.buffer(records)?))
    }

    /// Notes that shaders may set or copy indirect commands' barriers, which
    /// executions of every GPU-resident buffer then order.
    pub(super) fn note_command_barriers(&mut self) {
        self.command_barriers = true;
        for object in self.indirect.entries.iter_mut().flatten() {
            if object.records.is_some() {
                Arc::make_mut(&mut object.contents).note_barriers();
            }
        }
    }

    /// Writes the CPU's encoding of GPU-resident buffers to their records,
    /// ahead of a commit.
    pub(super) fn flush_indirect_writes(&mut self) -> Result<()> {
        let pending: Vec<_> = self
            .indirect
            .entries
            .iter_mut()
            .flatten()
            .filter(|object| object.contents.has_writes())
            .filter_map(|object| {
                let writes = Arc::make_mut(&mut object.contents).take_writes();
                Some((object.records?, writes))
            })
            .collect();
        for (records, writes) in pending {
            let (memory, base, _) = self.buffer_memory(records)?;
            for (offset, bytes) in writes {
                self.backend.write_memory(memory, base + offset, &bytes)?;
            }
        }
        Ok(())
    }
}
