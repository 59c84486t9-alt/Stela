//! Commands of `MTLComputeCommandEncoder`.
use super::{Payload, binding, grid, size};
use crate::metal::{
    abi::{BarrierScope, DispatchType},
    command_buffer::CommandBuffer,
    device::ComputePipelineId,
    service::{
        Service, boolean, known,
        wire::{
            Fault,
            commands::{
                BeginCompute, BufferOffset, ComputeCode, Dispatch, DispatchIndirect, MemoryBarrier,
                SetBuffer, SetBufferOffset, SetBytes, SetPipeline, SetSampler, SetTexture,
                SetThreadgroupMemory, StageInRegion,
            },
        },
    },
    shader::Compiler,
    vulkan::backend::Backend,
};
use core::num::NonZeroU64;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn compute(
        &mut self,
        connection: NonZeroU64,
        commands: &mut CommandBuffer,
        code: ComputeCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            ComputeCode::Begin => {
                let BeginCompute { dispatch_type } = payload.record()?;
                let dispatch_type = known(DispatchType::from_raw(dispatch_type), "dispatch type")?;
                commands.begin_compute(dispatch_type)?;
            }
            ComputeCode::SetPipeline => {
                let SetPipeline { pipeline } = payload.record()?;
                let pipeline = self.object::<ComputePipelineId>(connection, pipeline)?;
                commands
                    .set_compute_pipeline_state(self.device.compute_pipeline_state(pipeline)?)?;
            }
            ComputeCode::SetBuffer => {
                let SetBuffer {
                    buffer,
                    offset,
                    index,
                } = payload.record()?;
                let buffer = self.optional_buffer(connection, buffer)?;
                commands.set_compute_buffer(buffer, offset, binding(index)?)?;
            }
            ComputeCode::SetBufferOffset => {
                let SetBufferOffset { offset, index } = payload.record()?;
                commands.set_compute_buffer_offset(offset, binding(index)?)?;
            }
            ComputeCode::SetBytes => {
                let (SetBytes { index }, bytes) = payload.split()?;
                commands.set_compute_bytes(
                    &mut self.device.resolver(),
                    bytes.bytes(),
                    binding(index)?,
                )?;
            }
            ComputeCode::SetTexture => {
                let SetTexture { texture, index } = payload.record()?;
                let texture = self.texture_id(connection, texture)?;
                commands.set_compute_texture(texture, binding(index)?)?;
            }
            ComputeCode::SetSampler => {
                let request: SetSampler = payload.record()?;
                let sampler = self.sampler_id(connection, request.sampler)?;
                let clamp = boolean(request.clamped)?.then_some((request.lod_min, request.lod_max));
                let index = binding(request.index)?;
                commands.set_compute_sampler(&mut self.device.resolver(), sampler, clamp, index)?;
            }
            ComputeCode::SetThreadgroupMemory => {
                let SetThreadgroupMemory { length, index } = payload.record()?;
                commands.set_threadgroup_memory_length(length, binding(index)?)?;
            }
            ComputeCode::DispatchThreadgroups => {
                let Dispatch {
                    size: groups,
                    threads,
                } = payload.record()?;
                let resolver = &mut self.device.resolver();
                commands.dispatch_threadgroups(resolver, grid(groups)?, size(threads))?;
            }
            ComputeCode::DispatchThreads => {
                let Dispatch {
                    size: threads,
                    threads: group,
                } = payload.record()?;
                let resolver = &mut self.device.resolver();
                commands.dispatch_threads(resolver, grid(threads)?, size(group))?;
            }
            ComputeCode::DispatchIndirect => {
                let DispatchIndirect {
                    buffer,
                    offset,
                    threads,
                } = payload.record()?;
                let buffer = self.buffer_ref(connection, buffer)?;
                let resolver = &mut self.device.resolver();
                commands.dispatch_threadgroups_indirect(resolver, buffer, offset, size(threads))?;
            }
            ComputeCode::MemoryBarrier => {
                let MemoryBarrier { scope } = payload.record()?;
                let scope = known(BarrierScope::from_bits(scope), "barrier scope")?;
                commands.compute_memory_barrier(scope)?;
            }
            ComputeCode::SetStageInRegion => {
                let StageInRegion { origin, size } = payload.record()?;
                commands.set_stage_in_region(origin, size)?;
            }
            ComputeCode::SetStageInRegionIndirect => {
                let BufferOffset { buffer, offset } = payload.record()?;
                let buffer = self.buffer_ref(connection, buffer)?;
                commands.set_stage_in_region_indirect(buffer, offset)?;
            }
        }
        Ok(())
    }
}
