//! Tile shading in a render encoder.
//!
//! A tile pipeline is a kernel whose implicit imageblock is the pass's
//! color attachments. `dispatchThreadsPerTile:` ends the pass instance,
//! dispatches a threadgroup per tile of the render target, which accesses
//! the attachments' raw texels as storage at its tile's pixels, and resumes
//! the pass with an instance that loads them. The pipeline variant is a
//! dynamic kernel of exactly the tile's threads, placing its threadgroup
//! buffers at `setThreadgroupMemoryLength:offset:atIndex:` offsets. Each
//! tile's threadgroup memory persists across the pass's tile dispatches in
//! memory the pass allocates at its first dispatch that uses any, which
//! the function copies in where it starts and out where it ends.
use super::{BufferRef, CommandBuffer, ComputePipelineState, Resolver, Slot, render::render};
use crate::metal::{
    binding::{DispatchArguments, PushConstants, ResourceId},
    capabilities::{MAX_BUFFER_BINDINGS, Size},
    error::{Error, Result, ensure},
    hazard::{RENDER_PASS, Use},
    pipeline::{TileTarget, tile_variant},
    vulkan::{Access, PipelineBindPoint, PipelineStages, command::Command},
};
use alloc::vec::Vec;

/// The most bytes of persistent tile memory a pass allocates.
const MAX_TILE_MEMORY: u64 = 64 << 20;

#[derive(Clone, Debug, Default)]
pub(in crate::metal::command_buffer) struct TileState {
    /// `setRenderPipelineState:` of a tile pipeline: the kernel and its
    /// pass.
    pipeline: Option<(ComputePipelineState, TileTarget)>,
    /// `setThreadgroupMemoryLength:offset:atIndex:`, as (index, length,
    /// offset).
    threadgroups: Vec<(u32, u64, u64)>,
    /// The address of the pass's persistent tile memory, once allocated.
    memory: Option<u64>,
}

impl CommandBuffer {
    /// `setRenderPipelineState:` of a pipeline made from a
    /// `MTLTileRenderPipelineDescriptor`.
    pub fn set_tile_pipeline_state(
        &mut self,
        state: &ComputePipelineState,
        target: TileTarget,
    ) -> Result<()> {
        render(&mut self.encoder)?.tile.pipeline = Some((state.clone(), target));
        self.bound(super::BoundPipeline::Compute(state.id));
        Ok(())
    }

    pub fn set_tile_buffer(
        &mut self,
        buffer: Option<BufferRef>,
        offset: u64,
        index: u32,
    ) -> Result<()> {
        render(&mut self.encoder)?;
        self.bindings.set_buffer(Slot::Tile, buffer, offset, index)
    }

    pub fn set_tile_buffer_offset(&mut self, offset: u64, index: u32) -> Result<()> {
        render(&mut self.encoder)?;
        self.bindings.set_buffer_offset(Slot::Tile, offset, index)
    }

    /// `setTileBytes:length:atIndex:`: the bytes are copied into upload
    /// memory.
    pub fn set_tile_bytes(
        &mut self,
        resolver: &mut dyn Resolver,
        bytes: &[u8],
        index: u32,
    ) -> Result<()> {
        render(&mut self.encoder)?;
        let buffer = self.upload_bytes(resolver, bytes)?;
        self.set_tile_buffer(Some(buffer), 0, index)
    }

    pub fn set_tile_texture(&mut self, texture: ResourceId, index: u32) -> Result<()> {
        render(&mut self.encoder)?;
        self.bindings.set_texture(Slot::Tile, texture, index)
    }

    pub fn set_tile_sampler(
        &mut self,
        resolver: &mut dyn Resolver,
        sampler: ResourceId,
        clamp: Option<(f32, f32)>,
        index: u32,
    ) -> Result<()> {
        render(&mut self.encoder)?;
        let sampler = match clamp {
            Some((min, max)) => resolver.clamped_sampler(sampler, min, max)?,
            None => sampler,
        };
        self.bindings.set_sampler(Slot::Tile, sampler, index)
    }

    /// `setThreadgroupMemoryLength:offset:atIndex:` of a render encoder:
    /// where the tile functions' threadgroup buffer `index` lies in each
    /// tile's threadgroup memory.
    pub fn set_tile_threadgroup_memory(
        &mut self,
        length: u64,
        offset: u64,
        index: u32,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        ensure(index < MAX_BUFFER_BINDINGS, "threadgroup memory index")?;
        ensure(
            offset.is_multiple_of(16),
            "tile threadgroup memory offsets are multiples of 16",
        )?;
        let tile = &mut render.tile;
        tile.threadgroups.retain(|&(slot, ..)| slot != index);
        tile.threadgroups.push((index, length, offset));
        Ok(())
    }

    /// `tileWidth` and `tileHeight` of the encoder's pass.
    pub fn tile_size(&mut self) -> Result<[u32; 2]> {
        Ok(render(&mut self.encoder)?.pass().tile.size)
    }

    /// `dispatchThreadsPerTile:`: a threadgroup of `threads` per tile.
    pub fn dispatch_threads_per_tile(
        &mut self,
        resolver: &mut dyn Resolver,
        threads: Size,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let (state, target) = render
            .tile
            .pipeline
            .clone()
            .ok_or(Error::Invalid("no tile pipeline state is set"))?;
        let pass = render.pass();
        let tile = pass.tile;
        ensure(
            target.samples == pass.sample_count.max(1),
            "the tile pipeline's samples are the pass's",
        )?;
        for (index, attachment) in target.attachments.iter().enumerate() {
            ensure(
                attachment.is_none() || pass.color.get(index).is_some_and(Option::is_some),
                "the tile pipeline's color attachments are the pass's",
            )?;
        }
        let specialization = tile_variant(&state.plan, &target, threads, tile.size)?;
        // Each threadgroup buffer the function uses lies in the tile's
        // threadgroup memory.
        let mut offsets = [0u32; MAX_BUFFER_BINDINGS as usize];
        for used in &state.interface.threadgroup {
            let &(_, length, offset) = render
                .tile
                .threadgroups
                .iter()
                .find(|(index, ..)| *index == used.index)
                .ok_or(Error::Invalid(
                    "threadgroup memory length not set for a used slot",
                ))?;
            ensure(
                length >= used.declared_bytes,
                "threadgroup memory length is smaller than the argument",
            )?;
            ensure(
                offset + length <= u64::from(tile.threadgroup_memory_length),
                "tile threadgroup memory lies within the pass's threadgroupMemoryLength",
            )?;
            offsets[used.index as usize] = offset as u32;
        }
        ensure(
            u64::from(tile.threadgroup_memory_length) + state.plan.static_threadgroup_memory_length
                <= state.plan.max_threadgroup_memory_length,
            "threadgroup memory exceeds the device limit",
        )?;
        let groups = [
            pass.extent[0].div_ceil(tile.size[0]),
            pass.extent[1].div_ceil(tile.size[1]),
        ];
        // The pass's tiles' threadgroup memory, row by row.
        let stride = u64::from(tile.threadgroup_memory_length);
        let persists = stride != 0 && !state.interface.threadgroup.is_empty();
        let memory = match render.tile.memory {
            Some(address) => address,
            None if persists => {
                let bytes = stride * u64::from(groups[0]) * u64::from(groups[1]);
                if bytes > MAX_TILE_MEMORY {
                    return Err(Error::Unsupported("tile memory of this many tiles"));
                }
                let (upload, _) = self.recorder.uploads.zeroed(resolver, bytes as usize, 16)?;
                render.tile.memory = Some(upload.address);
                upload.address
            }
            None => 0,
        };
        let pipeline = resolver.compute_pipeline(&state, &specialization)?;

        let mut words = [0u32; DispatchArguments::BYTES as usize / 4];
        let at = DispatchArguments::SHAPE_OFFSET as usize / 4;
        words[at..at + 3].copy_from_slice(&[threads.width as u32, threads.height as u32, 1]);
        let at = DispatchArguments::OFFSETS_OFFSET as usize / 4;
        words[at..at + offsets.len()].copy_from_slice(&offsets);
        let at = DispatchArguments::TILE_OFFSET as usize / 4;
        words[at..at + 4].copy_from_slice(&[
            tile.size[0] | tile.size[1] << 16,
            if persists { stride as u32 } else { 0 },
            memory as u32,
            (memory >> 32) as u32,
        ]);
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let arguments = self
            .recorder
            .upload(resolver, &bytes, DispatchArguments::ALIGNMENT)?
            .address;
        self.bindings
            .require_buffers_of(Slot::Tile, &state.interface)?;
        let table = self
            .bindings
            .upload_table(&mut self.recorder, resolver, Slot::Tile)?;
        let constants = PushConstants {
            tables: [table, 0, 0],
            arguments,
            grid: [0; 3],
            ..self.bindings.constants
        };
        self.outside_pass(resolver, |recorder| {
            recorder.access(Use::new(
                PipelineStages::COMPUTE_SHADER,
                Access::SHADER_READ | Access::SHADER_WRITE,
            ));
            recorder.push(Command::BindPipeline {
                bind_point: PipelineBindPoint::Compute,
                pipeline,
            });
            recorder.push(Command::PushConstants(constants));
            if !groups.contains(&0) {
                recorder.push(Command::Dispatch([groups[0], groups[1], 1]));
            }
            recorder.access(RENDER_PASS);
        })?;
        // The draws after it push their own constants again.
        self.bindings.pushed = None;
        Ok(())
    }
}
