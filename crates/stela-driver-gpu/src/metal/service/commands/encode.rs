//! `EncodeIndirect`: CPU encoding of an indirect command buffer's commands
//! (`indirectRenderCommandAtIndex:`, `indirectComputeCommandAtIndex:`).
//! Each entry names its command with an `IndirectTarget` before the record
//! of the encoder command alike; entries before a refused one stay encoded,
//! as the calls they stand for would.
use super::{
    Payload, Stream, binding, count, depth_stencil_state, grid, index_type, primitive, size,
};
use crate::metal::{
    abi::{CullMode, DepthClipMode, TriangleFillMode, Winding},
    device::{ComputePipelineId, RenderPipelineId},
    indirect::{IndirectCommandBufferId, IndirectComputeCommand, IndirectRenderCommand},
    service::{
        Call, Service, known,
        pipelines::render_stage,
        wire::{
            Empty, EncodeIndirectRequest, Fault, Status,
            commands::{
                DepthBias, Dispatch, DrawIndexed, DrawMesh, DrawPrimitives, EncodeCode,
                IndirectComputeCode, IndirectPatches, IndirectRenderCode, IndirectTarget, Mode,
                SetBuffer, SetPipeline, SetThreadgroupMemory, StageBuffer, StageInRegion,
                VertexBufferStride,
            },
        },
    },
    shader::Compiler,
    vulkan::backend::Backend,
};
use core::num::NonZeroU64;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(in crate::metal::service) fn encode_indirect(
        &mut self,
        call: &mut Call,
    ) -> Result<(), Fault> {
        let EncodeIndirectRequest { buffer, commands } = call.request()?;
        let connection = call.connection;
        let id = self.object::<IndirectCommandBufferId>(connection, buffer)?;
        let commands = call.memory.read(commands)?;
        let mut stream = Stream::new(&commands, EncodeCode::from_raw);
        stream.try_for_each(|entry| {
            let (code, payload) = entry?;
            let (IndirectTarget { command }, payload) = payload.split()?;
            let command =
                usize::try_from(command).map_err(|_| Fault::malformed("command index"))?;
            match code {
                EncodeCode::Render(code) => {
                    self.encode_render(connection, id, command, code, payload)
                }
                EncodeCode::Compute(code) => {
                    self.encode_compute(connection, id, command, code, payload)
                }
            }
        })?;
        call.reply(&Empty {})
    }

    fn render_command(
        &mut self,
        id: IndirectCommandBufferId,
        index: usize,
    ) -> Result<IndirectRenderCommand<'_>, Fault> {
        Ok(self
            .device
            .indirect_command_buffer_mut(id)?
            .render_command(index)?)
    }

    fn compute_command(
        &mut self,
        id: IndirectCommandBufferId,
        index: usize,
    ) -> Result<IndirectComputeCommand<'_>, Fault> {
        Ok(self
            .device
            .indirect_command_buffer_mut(id)?
            .compute_command(index)?)
    }

    /// One call on a render command; what it names is resolved before the
    /// command is borrowed.
    fn encode_render(
        &mut self,
        connection: NonZeroU64,
        id: IndirectCommandBufferId,
        index: usize,
        code: IndirectRenderCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            IndirectRenderCode::SetPipeline => {
                let SetPipeline { pipeline } = payload.record()?;
                let pipeline = self.object::<RenderPipelineId>(connection, pipeline)?;
                let state = self.device.render_pipeline_state(pipeline)?.clone();
                self.render_command(id, index)?
                    .set_render_pipeline_state(&state)?;
            }
            IndirectRenderCode::SetBuffer => {
                let StageBuffer {
                    stage,
                    buffer,
                    offset,
                    index: slot,
                } = payload.record()?;
                let buffer = self.buffer_ref(connection, buffer)?;
                let (stage, slot) = (render_stage(stage)?, binding(slot)?);
                self.render_command(id, index)?
                    .set_buffer(stage, buffer, offset, slot)?;
            }
            IndirectRenderCode::SetVertexBufferStride => {
                let request: VertexBufferStride = payload.record()?;
                let buffer = self.buffer_ref(connection, request.buffer)?;
                let slot = binding(request.index)?;
                self.render_command(id, index)?
                    .set_vertex_buffer_with_stride(buffer, request.offset, request.stride, slot)?;
            }
            IndirectRenderCode::SetCullMode => {
                let Mode { mode } = payload.record()?;
                let mode = known(CullMode::from_raw(mode), "cull mode")?;
                self.render_command(id, index)?.set_cull_mode(mode)?;
            }
            IndirectRenderCode::SetFrontFacingWinding => {
                let Mode { mode } = payload.record()?;
                let winding = known(Winding::from_raw(mode), "winding")?;
                self.render_command(id, index)?
                    .set_front_facing_winding(winding)?;
            }
            IndirectRenderCode::SetDepthBias => {
                let DepthBias {
                    constant,
                    slope,
                    clamp,
                    reserved: _,
                } = payload.record()?;
                self.render_command(id, index)?
                    .set_depth_bias(constant, slope, clamp)?;
            }
            IndirectRenderCode::SetDepthStencilState => {
                let state = depth_stencil_state(&payload.record()?)?;
                self.render_command(id, index)?
                    .set_depth_stencil_state(Some(&state))?;
            }
            IndirectRenderCode::SetTriangleFillMode => {
                let Mode { mode } = payload.record()?;
                let mode = known(TriangleFillMode::from_raw(mode), "triangle fill mode")?;
                self.render_command(id, index)?
                    .set_triangle_fill_mode(mode)?;
            }
            IndirectRenderCode::SetDepthClipMode => {
                let Mode { mode } = payload.record()?;
                let mode = known(DepthClipMode::from_raw(mode), "clip mode")?;
                self.render_command(id, index)?.set_depth_clip_mode(mode)?;
            }
            IndirectRenderCode::SetBarrier => {
                payload.record::<Empty>()?;
                self.render_command(id, index)?.set_barrier()?;
            }
            IndirectRenderCode::ClearBarrier => {
                payload.record::<Empty>()?;
                self.render_command(id, index)?.clear_barrier()?;
            }
            IndirectRenderCode::DrawPrimitives => {
                let draw: DrawPrimitives = payload.record()?;
                let (primitive, start, vertices, instances, base) = (
                    primitive(draw.primitive)?,
                    count(draw.vertex_start)?,
                    count(draw.vertex_count)?,
                    count(draw.instance_count)?,
                    count(draw.base_instance)?,
                );
                self.render_command(id, index)?
                    .draw_primitives(primitive, start, vertices, instances, base)?;
            }
            IndirectRenderCode::DrawIndexed => {
                let draw: DrawIndexed = payload.record()?;
                let index_buffer = self.buffer_ref(connection, draw.index_buffer)?;
                let base_vertex = i32::try_from(draw.base_vertex)
                    .map_err(|_| Fault::new(Status::Invalid, "the base vertex exceeds 32 bits"))?;
                let (primitive, indices, index_type, instances, base_instance) = (
                    primitive(draw.primitive)?,
                    count(draw.index_count)?,
                    index_type(draw.index_type)?,
                    count(draw.instance_count)?,
                    count(draw.base_instance)?,
                );
                self.render_command(id, index)?.draw_indexed_primitives(
                    primitive,
                    indices,
                    index_type,
                    index_buffer,
                    draw.index_buffer_offset,
                    instances,
                    base_vertex,
                    base_instance,
                )?;
            }
            IndirectRenderCode::DrawPatches => {
                let IndirectPatches { draw, factors } = payload.record()?;
                let source = self.patch_source(connection, &draw.source)?;
                let factors = (
                    self.buffer_ref(connection, factors.buffer)?,
                    factors.offset,
                    factors.instance_stride,
                );
                let (start, patches, instances, base) = (
                    count(draw.patch_start)?,
                    count(draw.patch_count)?,
                    count(draw.instance_count)?,
                    count(draw.base_instance)?,
                );
                self.render_command(id, index)?
                    .draw_patches(&source, start, patches, instances, base, factors)?;
            }
            IndirectRenderCode::DrawMeshThreadgroups | IndirectRenderCode::DrawMeshThreads => {
                let draw: DrawMesh = payload.record()?;
                let (size, object, mesh) = (
                    grid(draw.size)?,
                    grid(draw.object_threads)?,
                    grid(draw.mesh_threads)?,
                );
                let mut command = self.render_command(id, index)?;
                match code {
                    IndirectRenderCode::DrawMeshThreadgroups => {
                        command.draw_mesh_threadgroups(size, object, mesh)
                    }
                    _ => command.draw_mesh_threads(size, object, mesh),
                }?;
            }
            IndirectRenderCode::Reset => {
                payload.record::<Empty>()?;
                self.render_command(id, index)?.reset()?;
            }
        }
        Ok(())
    }

    fn encode_compute(
        &mut self,
        connection: NonZeroU64,
        id: IndirectCommandBufferId,
        index: usize,
        code: IndirectComputeCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            IndirectComputeCode::SetPipeline => {
                let SetPipeline { pipeline } = payload.record()?;
                let pipeline = self.object::<ComputePipelineId>(connection, pipeline)?;
                let state = self.device.compute_pipeline_state(pipeline)?.clone();
                self.compute_command(id, index)?
                    .set_compute_pipeline_state(&state)?;
            }
            IndirectComputeCode::SetBuffer => {
                let SetBuffer {
                    buffer,
                    offset,
                    index: slot,
                } = payload.record()?;
                let buffer = self.buffer_ref(connection, buffer)?;
                let slot = binding(slot)?;
                self.compute_command(id, index)?
                    .set_kernel_buffer(buffer, offset, slot)?;
            }
            IndirectComputeCode::SetThreadgroupMemory => {
                let SetThreadgroupMemory {
                    length,
                    index: slot,
                } = payload.record()?;
                let slot = binding(slot)?;
                self.compute_command(id, index)?
                    .set_threadgroup_memory_length(length, slot)?;
            }
            IndirectComputeCode::SetStageInRegion => {
                let StageInRegion { origin, size } = payload.record()?;
                self.compute_command(id, index)?
                    .set_stage_in_region(origin, size)?;
            }
            IndirectComputeCode::SetBarrier => {
                payload.record::<Empty>()?;
                self.compute_command(id, index)?.set_barrier()?;
            }
            IndirectComputeCode::ClearBarrier => {
                payload.record::<Empty>()?;
                self.compute_command(id, index)?.clear_barrier()?;
            }
            IndirectComputeCode::DispatchThreadgroups | IndirectComputeCode::DispatchThreads => {
                let Dispatch {
                    size: extent,
                    threads,
                } = payload.record()?;
                let (extent, threads) = (grid(extent)?, size(threads));
                let mut command = self.compute_command(id, index)?;
                match code {
                    IndirectComputeCode::DispatchThreadgroups => {
                        command.concurrent_dispatch_threadgroups(extent, threads)
                    }
                    _ => command.concurrent_dispatch_threads(extent, threads),
                }?;
            }
            IndirectComputeCode::Reset => {
                payload.record::<Empty>()?;
                self.compute_command(id, index)?.reset()?;
            }
        }
        Ok(())
    }
}
