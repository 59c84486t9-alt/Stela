//! `MTLResourceStateCommandEncoder`: sparse texture mapping updates.
//!
//! The encoder's updates attach to a segment of their own and become its
//! sparse binds when the device commits the command buffer, so they apply
//! after everything encoded before the encoder and before everything after
//! it. Fences need no commands on the device's one queue.
use super::{CommandBuffer, Encoder, Resolver};
use crate::gpu::metal::{
    abi::SparseTextureMappingMode,
    error::{Error, Result, ensure},
    sparse::{MappingRequest, MappingUpdate, MoveEnd},
    vulkan::object::Image,
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

    fn resource_state(&mut self, request: MappingRequest) -> Result<()> {
        ensure(
            matches!(self.encoder, Encoder::ResourceState),
            "no resource state command encoder is encoding",
        )?;
        let segment = self.recorder.segments.len() - 1;
        self.recorder.mappings.push((segment, request));
        Ok(())
    }

    /// `updateTextureMappings:mode:regions:mipLevels:slices:numRegions:`
    /// and `updateTextureMapping:mode:region:mipLevel:slice:`.
    pub fn update_texture_mappings(
        &mut self,
        image: Image,
        mode: SparseTextureMappingMode,
        updates: Vec<MappingUpdate>,
    ) -> Result<()> {
        self.resource_state(MappingRequest::Update {
            image,
            mode,
            updates,
        })
    }

    /// `updateTextureMapping:mode:indirectBuffer:indirectBufferOffset:`:
    /// the region would come from GPU memory, but sparse binds are host
    /// queue operations.
    pub fn update_texture_mapping_indirect(&mut self) -> Result<()> {
        ensure(
            matches!(self.encoder, Encoder::ResourceState),
            "no resource state command encoder is encoding",
        )?;
        Err(Error::Unsupported("indirect sparse mapping updates"))
    }

    /// `moveTextureMappingsFromTexture:…toTexture:…`.
    pub fn move_texture_mappings(
        &mut self,
        source: MoveEnd,
        destination: MoveEnd,
        size: [u64; 3],
    ) -> Result<()> {
        self.resource_state(MappingRequest::Move {
            source,
            destination,
            size,
        })
    }
}
