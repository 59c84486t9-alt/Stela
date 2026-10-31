//! `MTLResourceStateCommandEncoder`: sparse texture mapping updates.
//!
//! The encoder's updates attach to a segment of their own and become its
//! sparse binds when the device commits the command buffer, so they apply
//! after everything encoded before the encoder and before everything after
//! it. An indirect update's region is in GPU memory, but sparse binds are
//! host queue operations: the encoder copies the arguments to host-visible
//! memory and starts another segment, whose binds the device makes once the
//! copy completes. Fences need no commands on the device's one queue.
use super::{BufferRef, CommandBuffer, Encoder, Resolver, blit::TRANSFER};
use crate::metal::{
    abi::SparseTextureMappingMode,
    error::{Result, ensure},
    sparse::{MAP_INDIRECT_ARGUMENTS_BYTES, Mapping, MappingRequest, MappingUpdate, MoveEnd},
    vulkan::{
        command::{BufferCopy, Command},
        object::Image,
    },
};
use alloc::vec::Vec;

impl CommandBuffer {
    /// `resourceStateCommandEncoder`.
    pub fn begin_resource_state(&mut self, resolver: &mut dyn Resolver) -> Result<()> {
        self.idle()?;
        let current = self.recorder.segments.last().expect("a segment");
        // A segment holding only its opening barrier can take the binds.
        if current.commands.len() > 1 || !current.signals.is_empty() {
            self.recorder.pause_statistics();
            self.recorder.start_segment(Vec::new());
            self.recorder.resume_statistics(resolver, false)?;
        }
        self.encoder = Encoder::ResourceState;
        Ok(())
    }

    fn resource_state(&mut self, mapping: Mapping) -> Result<()> {
        self.resource_state_encoding()?;
        let segment = self.recorder.segments.len() - 1;
        self.recorder.mappings.push((segment, mapping));
        Ok(())
    }

    fn resource_state_encoding(&self) -> Result<()> {
        ensure(
            matches!(self.encoder, Encoder::ResourceState),
            "no resource state command encoder is encoding",
        )
    }

    /// `updateTextureMappings:mode:regions:mipLevels:slices:numRegions:`
    /// and `updateTextureMapping:mode:region:mipLevel:slice:`.
    pub fn update_texture_mappings(
        &mut self,
        image: Image,
        mode: SparseTextureMappingMode,
        updates: Vec<MappingUpdate>,
    ) -> Result<()> {
        self.resource_state(Mapping::Request(MappingRequest::Update {
            image,
            mode,
            updates,
        }))
    }

    /// `updateTextureMapping:mode:indirectBuffer:indirectBufferOffset:`.
    pub fn update_texture_mapping_indirect(
        &mut self,
        resolver: &mut dyn Resolver,
        image: Image,
        mode: SparseTextureMappingMode,
        buffer: BufferRef,
        offset: u64,
    ) -> Result<()> {
        self.resource_state_encoding()?;
        ensure(
            offset.is_multiple_of(4),
            "indirect buffer offsets are 4-byte aligned",
        )?;
        let size = MAP_INDIRECT_ARGUMENTS_BYTES as u64;
        let src_offset = buffer.at(offset, size)?;
        let arguments = self
            .recorder
            .upload(resolver, &[0; MAP_INDIRECT_ARGUMENTS_BYTES], 4)?;
        self.recorder.access(TRANSFER);
        self.recorder.push(Command::CopyBuffer {
            src: buffer.buffer,
            dst: arguments.buffer,
            regions: alloc::vec![BufferCopy {
                src_offset,
                dst_offset: arguments.offset,
                size,
            }],
        });
        if let Some(barrier) = self.recorder.hazards.host() {
            self.recorder.push(Command::Barrier(barrier));
        }
        self.recorder.pause_statistics();
        self.recorder.start_segment(Vec::new());
        self.recorder.resume_statistics(resolver, false)?;
        self.resource_state(Mapping::Indirect {
            image,
            mode,
            arguments,
        })
    }

    /// `moveTextureMappingsFromTexture:…toTexture:…`.
    pub fn move_texture_mappings(
        &mut self,
        source: MoveEnd,
        destination: MoveEnd,
        size: [u64; 3],
    ) -> Result<()> {
        self.resource_state(Mapping::Request(MappingRequest::Move {
            source,
            destination,
            size,
        }))
    }
}
