//! `MTLComputeCommandEncoder`.
//!
//! Each dispatch binds the pipeline variant for its threadgroup size and
//! threadgroup memory lengths. A serial encoder orders dispatches through
//! the hazard tracker; a concurrent one orders only against earlier
//! encoders and explicit memory barriers, as Metal does. A stage-in
//! pipeline's dispatches carry the address of their stage-in region in the
//! push constants' `arguments`.
use super::{BufferRef, CommandBuffer, ComputePipelineState, Encoder, Resolver};
use crate::metal::{
    abi::{BarrierScope, DispatchType},
    binding::ResourceId,
    capabilities::Size,
    error::{Error, Result, ensure},
    hazard::Use,
    pipeline::compute_variant,
    shader::Stage,
    vulkan::{Access, PipelineBindPoint, PipelineStages, command::Command, object::Pipeline},
};
use alloc::{boxed::Box, vec::Vec};

/// Every access a compute dispatch can make.
pub(super) const COMPUTE: Use = Use::new(
    PipelineStages::COMPUTE_SHADER.union(PipelineStages::DRAW_INDIRECT),
    Access::SHADER_READ
        .union(Access::SHADER_WRITE)
        .union(Access::INDIRECT_COMMAND_READ),
);

/// `setStageInRegion:` or `setStageInRegionWithIndirectBuffer:…`.
#[derive(Clone, Copy, Debug)]
pub(super) enum StageInRegion {
    /// Origin and size, as `MTLStageInRegionIndirectArguments` holds them.
    Direct([u32; 6]),
    /// The address of the GPU's `MTLStageInRegionIndirectArguments`.
    Indirect(u64),
}

pub(super) struct ComputeState {
    pub(super) dispatch_type: DispatchType,
    pub(super) pipeline: Option<ComputePipelineState>,
    pub(super) threadgroup_lengths: Vec<(u32, u64)>,
    pub(super) bound: Option<Pipeline>,
    pub(super) stage_in: Option<StageInRegion>,
}

pub(super) fn compute(encoder: &mut Encoder) -> Result<&mut ComputeState> {
    match encoder {
        Encoder::Compute(state) => Ok(state),
        _ => Err(Error::Invalid("no compute command encoder is encoding")),
    }
}

impl CommandBuffer {
    /// `computeCommandEncoderWithDispatchType:`.
    pub fn begin_compute(&mut self, dispatch_type: DispatchType) -> Result<()> {
        self.idle()?;
        self.bindings.reset();
        if dispatch_type == DispatchType::Concurrent {
            self.recorder.access(COMPUTE);
        }
        self.encoder = Encoder::Compute(Box::new(ComputeState {
            dispatch_type,
            pipeline: None,
            threadgroup_lengths: Vec::new(),
            bound: None,
            stage_in: None,
        }));
        Ok(())
    }

    pub fn set_compute_pipeline_state(&mut self, state: &ComputePipelineState) -> Result<()> {
        compute(&mut self.encoder)?.pipeline = Some(state.clone());
        Ok(())
    }

    pub fn set_compute_buffer(
        &mut self,
        buffer: Option<BufferRef>,
        offset: u64,
        index: u32,
    ) -> Result<()> {
        compute(&mut self.encoder)?;
        self.bindings
            .set_buffer(Stage::Kernel, buffer, offset, index)
    }

    pub fn set_compute_buffer_offset(&mut self, offset: u64, index: u32) -> Result<()> {
        compute(&mut self.encoder)?;
        self.bindings
            .set_buffer_offset(Stage::Kernel, offset, index)
    }

    pub fn set_compute_bytes(
        &mut self,
        resolver: &mut dyn Resolver,
        bytes: &[u8],
        index: u32,
    ) -> Result<()> {
        compute(&mut self.encoder)?;
        let buffer = self.upload_bytes(resolver, bytes)?;
        self.bindings
            .set_buffer(Stage::Kernel, Some(buffer), 0, index)
    }

    pub fn set_compute_texture(&mut self, texture: ResourceId, index: u32) -> Result<()> {
        compute(&mut self.encoder)?;
        self.bindings.set_texture(Stage::Kernel, texture, index)
    }

    pub fn set_compute_sampler(
        &mut self,
        resolver: &mut dyn Resolver,
        sampler: ResourceId,
        clamp: Option<(f32, f32)>,
        index: u32,
    ) -> Result<()> {
        compute(&mut self.encoder)?;
        let sampler = match clamp {
            Some((min, max)) => resolver.clamped_sampler(sampler, min, max)?,
            None => sampler,
        };
        self.bindings.set_sampler(Stage::Kernel, sampler, index)
    }

    /// `setThreadgroupMemoryLength:atIndex:`.
    pub fn set_threadgroup_memory_length(&mut self, length: u64, index: u32) -> Result<()> {
        let state = compute(&mut self.encoder)?;
        ensure(
            index < crate::metal::capabilities::MAX_BUFFER_BINDINGS,
            "threadgroup memory index",
        )?;
        state.threadgroup_lengths.retain(|&(slot, _)| slot != index);
        state.threadgroup_lengths.push((index, length));
        Ok(())
    }

    /// `dispatchThreadgroups:threadsPerThreadgroup:`.
    pub fn dispatch_threadgroups(
        &mut self,
        resolver: &mut dyn Resolver,
        threadgroups: [u32; 3],
        threads: Size,
    ) -> Result<()> {
        self.prepare_dispatch(resolver, threads, [0; 3], false)?;
        if !threadgroups.contains(&0) {
            self.recorder.push(Command::Dispatch(threadgroups));
        }
        Ok(())
    }

    /// `dispatchThreads:threadsPerThreadgroup:`: whole threadgroups cover the
    /// grid, and the compiled kernel skips threads outside it.
    pub fn dispatch_threads(
        &mut self,
        resolver: &mut dyn Resolver,
        grid: [u32; 3],
        threads: Size,
    ) -> Result<()> {
        let group = [threads.width, threads.height, threads.depth];
        ensure(
            group
                .iter()
                .all(|&size| (1..=u64::from(u32::MAX)).contains(&size)),
            "threadgroup size",
        )?;
        let groups = [0, 1, 2].map(|axis| grid[axis].div_ceil(group[axis] as u32));
        self.prepare_dispatch(resolver, threads, grid, false)?;
        if !groups.contains(&0) {
            self.recorder.push(Command::Dispatch(groups));
        }
        Ok(())
    }

    /// `dispatchThreadgroupsWithIndirectBuffer:…`: Metal's arguments are
    /// `VkDispatchIndirectCommand`.
    pub fn dispatch_threadgroups_indirect(
        &mut self,
        resolver: &mut dyn Resolver,
        indirect: BufferRef,
        offset: u64,
        threads: Size,
    ) -> Result<()> {
        ensure(
            offset.is_multiple_of(4),
            "indirect arguments are 4-byte aligned",
        )?;
        let offset = indirect.at(offset, 12)?;
        self.prepare_dispatch(resolver, threads, [0; 3], true)?;
        self.recorder.push(Command::DispatchIndirect {
            buffer: indirect.buffer,
            offset,
        });
        Ok(())
    }

    /// `memoryBarrierWithScope:` and `memoryBarrierWithResources:`.
    pub fn compute_memory_barrier(&mut self, scope: BarrierScope) -> Result<()> {
        let state = compute(&mut self.encoder)?;
        ensure(!scope.is_empty(), "a barrier names a scope")?;
        let concurrent = state.dispatch_type == DispatchType::Concurrent;
        self.recorder.full_barrier();
        if concurrent {
            self.recorder.access(COMPUTE);
        }
        Ok(())
    }

    /// `setStageInRegion:`.
    pub fn set_stage_in_region(&mut self, origin: [u64; 3], size: [u64; 3]) -> Result<()> {
        let state = compute(&mut self.encoder)?;
        let mut region = [0; 6];
        for (value, field) in origin.iter().chain(&size).zip(&mut region) {
            *field = u32::try_from(*value).map_err(|_| Error::Invalid("stage-in region"))?;
        }
        state.stage_in = Some(StageInRegion::Direct(region));
        Ok(())
    }

    /// `setStageInRegionWithIndirectBuffer:indirectBufferOffset:`.
    pub fn set_stage_in_region_indirect(&mut self, indirect: BufferRef, offset: u64) -> Result<()> {
        let state = compute(&mut self.encoder)?;
        ensure(
            offset.is_multiple_of(4),
            "indirect arguments are 4-byte aligned",
        )?;
        indirect.at(offset, 24)?;
        state.stage_in = Some(StageInRegion::Indirect(indirect.address + offset));
        Ok(())
    }

    fn prepare_dispatch(
        &mut self,
        resolver: &mut dyn Resolver,
        threads: Size,
        grid: [u32; 3],
        indirect: bool,
    ) -> Result<()> {
        let state = compute(&mut self.encoder)?;
        let pipeline = state
            .pipeline
            .as_ref()
            .ok_or(Error::Invalid("no compute pipeline state is set"))?;
        let specialization = compute_variant(
            &pipeline.plan,
            &pipeline.interface,
            threads,
            &state.threadgroup_lengths,
        )?;
        let variant = resolver.compute_pipeline(pipeline, &specialization)?;
        let serial = state.dispatch_type == DispatchType::Serial;
        let writes = pipeline
            .interface
            .buffers
            .iter()
            .any(|buffer| buffer.access.writes() || buffer.argument_buffer)
            || pipeline
                .interface
                .textures
                .iter()
                .any(|texture| texture.access.writes());
        let rebind = state.bound != Some(variant);
        state.bound = Some(variant);
        if serial {
            let access = Access::SHADER_READ
                .with(Access::SHADER_WRITE, writes)
                .with(Access::INDIRECT_COMMAND_READ, indirect);
            let stages =
                PipelineStages::COMPUTE_SHADER.with(PipelineStages::DRAW_INDIRECT, indirect);
            self.recorder.access(Use::new(stages, access));
        }
        let stage_in = match (&pipeline.plan.stage_in, state.stage_in) {
            (None, _) => None,
            (Some(_), Some(region)) => Some(region),
            (Some(_), None) => return Err(Error::Invalid("no stage-in region is set")),
        };
        if rebind {
            self.recorder.push(Command::BindPipeline {
                bind_point: PipelineBindPoint::Compute,
                pipeline: variant,
            });
        }
        self.bindings.constants.arguments = match stage_in {
            None => self.bindings.constants.arguments,
            Some(StageInRegion::Indirect(address)) => address,
            Some(StageInRegion::Direct(region)) => {
                let bytes: Vec<u8> = region
                    .iter()
                    .flat_map(|value| value.to_le_bytes())
                    .collect();
                self.recorder.upload(resolver, &bytes, 16)?.address
            }
        };
        self.bindings.constants.grid = grid;
        self.bindings
            .flush(&mut self.recorder, resolver, &[Stage::Kernel])
    }
}
