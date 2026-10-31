//! Executing and editing indirect command buffers (see
//! [`crate::metal::indirect`]).
//!
//! An execution replays each command of its range through the encoder's
//! own operations and then restores the encoder's Metal state: the render
//! pipeline state, buffers, vertex strides, tessellation factor buffer,
//! amplification mappings and rasterizer state, or the compute pipeline
//! state, buffers, threadgroup memory lengths and stage-in region. Commands
//! without a draw or dispatch, such as reset ones, do nothing.
//!
//! A range the GPU provides replays every command of the buffer, each under
//! conditional rendering on a flag the backend's select kernel computes
//! from the range ahead of them, outside the pass instance.
use super::{
    Bindings, BufferRef, CommandBuffer, ComputePipelineState, Encoder, Recorder,
    RenderPipelineState, Resolver,
    compute::{COMPUTE, StageInRegion, compute},
    render::{FactorBuffer, RasterState, VertexBinding, render},
};
use crate::metal::{
    abi::{BarrierScope, DispatchType, RenderStages},
    binding::SelectArguments,
    error::{Error, Result, ensure},
    hazard::{RENDER_PASS, Use},
    indirect::{
        IndirectAction, IndirectBuffer, IndirectCommand, IndirectCommandBufferDescriptor,
        IndirectCommandBufferId, RecordLayout,
    },
    shader::Stage,
    upload::Upload,
    vulkan::{Access, PipelineStages, command::Command},
};
use alloc::vec::Vec;
use core::ops::Range;

/// The commands an execution runs.
#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionRange {
    /// `executeCommandsInBuffer:withRange:`.
    Direct(Range<usize>),
    /// `executeCommandsInBuffer:indirectBuffer:indirectBufferOffset:`: the
    /// GPU reads an `MTLIndirectCommandBufferExecutionRange` there.
    Indirect { buffer: BufferRef, offset: u64 },
}

/// Buffer tables a render command's buffers replace.
const RENDER_STAGES: [Stage; 3] = [Stage::Vertex, Stage::Fragment, Stage::Mesh];

/// The render encoder's Metal state an execution restores.
struct SavedRender {
    pipeline: Option<RenderPipelineState>,
    object_threadgroup_lengths: Vec<(u32, u64)>,
    vertex_buffers: [Option<VertexBinding>; 31],
    amplification: Vec<u32>,
    factors: Option<FactorBuffer>,
    raster: RasterState,
    bindings: Bindings,
}

/// The compute encoder's Metal state an execution restores.
struct SavedCompute {
    pipeline: Option<ComputePipelineState>,
    threadgroup_lengths: Vec<(u32, u64)>,
    stage_in: Option<StageInRegion>,
    bindings: Bindings,
}

impl CommandBuffer {
    /// `executeCommandsInBuffer:…` of the render or compute encoder.
    pub fn execute_commands(
        &mut self,
        resolver: &mut dyn Resolver,
        id: IndirectCommandBufferId,
        range: ExecutionRange,
    ) -> Result<()> {
        let renders = match self.encoder {
            Encoder::Render(_) => true,
            Encoder::Compute(_) => false,
            _ => {
                return Err(Error::Invalid(
                    "indirect commands execute in render and compute encoders",
                ));
            }
        };
        let buffer = resolver.indirect_commands(id)?;
        let descriptor = *buffer.descriptor();
        ensure(
            descriptor.renders() == renders,
            "the encoder does not execute the indirect command buffer's command types",
        )?;
        if buffer.records().is_some() {
            return self.execute_records(resolver, id, &buffer, range);
        }
        let (commands, gate) = match range {
            ExecutionRange::Direct(range) => (buffer.commands(range)?, None),
            ExecutionRange::Indirect {
                buffer: source,
                offset,
            } => {
                ensure(
                    offset.is_multiple_of(4),
                    "indirect arguments are 4-byte aligned",
                )?;
                source.at(offset, 8)?;
                let flags =
                    self.select_commands(resolver, source.address + offset, buffer.size())?;
                (buffer.commands(0..buffer.size())?, Some(flags))
            }
        };
        if renders {
            self.replay_render(resolver, &descriptor, commands, gate)
        } else {
            self.replay_compute(resolver, &descriptor, commands, gate)
        }
    }

    /// Flags each of `count` commands by whether the range at `range`
    /// holds it, returning the flags.
    fn select_commands(
        &mut self,
        resolver: &mut dyn Resolver,
        range: u64,
        count: usize,
    ) -> Result<Upload> {
        let count = u32::try_from(count).map_err(|_| Error::Invalid("indirect command count"))?;
        let flags = self
            .recorder
            .upload(resolver, &alloc::vec![0; count as usize * 4], 4)?;
        let arguments = SelectArguments {
            range,
            flags: flags.address,
            count,
        };
        let arguments =
            self.recorder
                .upload(resolver, &arguments.encode(), SelectArguments::ALIGNMENT)?;
        let select = |recorder: &mut Recorder, encoder: Use| {
            recorder.access(Use::new(
                PipelineStages::COMPUTE_SHADER,
                Access::SHADER_READ | Access::SHADER_WRITE,
            ));
            recorder.push(Command::SelectCommands {
                arguments: arguments.address,
                count,
            });
            recorder.access(Use::new(
                PipelineStages::CONDITIONAL_RENDERING,
                Access::CONDITIONAL_RENDERING_READ,
            ));
            // What the encoder's work after the kernel may touch.
            recorder.access(encoder);
        };
        if let Encoder::Compute(state) = &mut self.encoder {
            select(&mut self.recorder, COMPUTE);
            state.bound = None;
        } else {
            // Compute work runs outside pass instances.
            self.outside_pass(resolver, |recorder| select(recorder, RENDER_PASS))?;
        }
        // The kernel replaced the push constants.
        self.bindings.pushed = None;
        Ok(flags)
    }

    fn replay_render(
        &mut self,
        resolver: &mut dyn Resolver,
        descriptor: &IndirectCommandBufferDescriptor,
        commands: &[IndirectCommand],
        gate: Option<Upload>,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let saved = SavedRender {
            pipeline: render.pipeline.clone(),
            object_threadgroup_lengths: render.object_threadgroup_lengths.clone(),
            vertex_buffers: render.vertex_buffers,
            amplification: render.amplification.clone(),
            factors: render.factors,
            raster: render.raster,
            bindings: self.bindings.clone(),
        };
        let mut replayed = Ok(());
        let mut buffers = None;
        for (index, command) in commands.iter().enumerate() {
            let flag = gate.map(|flags| (flags, index));
            replayed =
                self.replay_render_command(resolver, descriptor, command, &mut buffers, flag);
            if replayed.is_err() {
                break;
            }
        }
        let restored = self.restore_render(saved);
        replayed.and(restored)
    }

    /// Replays one render command; `buffers` holds the buffers last bound
    /// for a command, which the next command keeps when they match.
    fn replay_render_command<'a>(
        &mut self,
        resolver: &mut dyn Resolver,
        descriptor: &IndirectCommandBufferDescriptor,
        command: &'a IndirectCommand,
        buffers: &mut Option<&'a [IndirectBuffer]>,
        flag: Option<(Upload, usize)>,
    ) -> Result<()> {
        let Some(action) = command.action else {
            return Ok(());
        };
        let mesh = matches!(
            action,
            IndirectAction::DrawMeshThreadgroups { .. } | IndirectAction::DrawMeshThreads { .. }
        );
        if command.barrier {
            let stages = if mesh {
                RenderStages::OBJECT | RenderStages::MESH | RenderStages::FRAGMENT
            } else {
                RenderStages::VERTEX | RenderStages::FRAGMENT
            };
            let scope =
                BarrierScope::BUFFERS | BarrierScope::TEXTURES | BarrierScope::RENDER_TARGETS;
            self.render_memory_barrier(resolver, scope, stages, stages)?;
        }
        if !descriptor.inherit_pipeline_state {
            let id = command
                .pipeline
                .ok_or(Error::Invalid(
                    "an indirect command draws without a pipeline state",
                ))?
                .id;
            let current = render(&mut self.encoder)?
                .pipeline
                .as_ref()
                .map(|state| state.id);
            if current != Some(id) {
                let state = resolver.render_pipeline_state(id)?;
                self.set_render_pipeline_state(&state)?;
            }
        }
        if !descriptor.inherit_buffers && *buffers != Some(command.buffers.as_slice()) {
            self.bindings.clear_buffers(&RENDER_STAGES);
            render(&mut self.encoder)?.vertex_buffers = [None; 31];
            for binding in &command.buffers {
                match binding.stride {
                    Some(stride) => self.set_vertex_buffer_with_stride(
                        binding.buffer,
                        binding.offset,
                        stride,
                        binding.index,
                    )?,
                    None => self.set_render_buffer(
                        binding.stage,
                        Some(binding.buffer),
                        binding.offset,
                        binding.index,
                    )?,
                }
            }
            *buffers = Some(&command.buffers);
        }
        render(&mut self.encoder)?.object_threadgroup_lengths = command.threadgroup_lengths.clone();
        let mut raster = render(&mut self.encoder)?.raster;
        let own = &command.raster;
        if !descriptor.inherit_cull_mode {
            raster.cull_mode = own.cull_mode;
        }
        if !descriptor.inherit_front_facing_winding {
            raster.winding = own.winding;
        }
        if !descriptor.inherit_depth_bias {
            raster.depth_bias = own.depth_bias;
        }
        if !descriptor.inherit_depth_stencil_state {
            raster.depth_stencil = own.depth_stencil;
        }
        if !descriptor.inherit_triangle_fill_mode {
            raster.fill_mode = own.fill_mode;
        }
        if !descriptor.inherit_depth_clip_mode {
            raster.clip_mode = own.clip_mode;
        }
        self.set_raster_state(&raster)?;
        self.gated(flag, |this| this.draw(resolver, action))
    }

    fn draw(&mut self, resolver: &mut dyn Resolver, action: IndirectAction) -> Result<()> {
        match action {
            IndirectAction::Draw {
                primitive,
                vertex_start,
                vertex_count,
                instance_count,
                base_instance,
            } => self.draw_primitives(
                resolver,
                primitive,
                vertex_start,
                vertex_count,
                instance_count,
                base_instance,
            ),
            IndirectAction::DrawIndexed {
                primitive,
                index_count,
                index_type,
                index_buffer,
                index_buffer_offset,
                instance_count,
                base_vertex,
                base_instance,
            } => self.draw_indexed_primitives(
                resolver,
                primitive,
                index_count,
                index_type,
                index_buffer,
                index_buffer_offset,
                instance_count,
                base_vertex,
                base_instance,
            ),
            IndirectAction::DrawPatches {
                source,
                patch_start,
                patch_count,
                instance_count,
                base_instance,
                factors: (buffer, offset, stride),
            } => {
                self.set_tessellation_factor_buffer(Some(buffer), offset, stride)?;
                self.draw_patches(
                    resolver,
                    &source,
                    patch_start,
                    patch_count,
                    instance_count,
                    base_instance,
                )
            }
            IndirectAction::DrawMeshThreadgroups {
                threadgroups,
                object_threads,
                mesh_threads,
            } => self.draw_mesh_threadgroups(resolver, threadgroups, object_threads, mesh_threads),
            IndirectAction::DrawMeshThreads {
                threads,
                object_threads,
                mesh_threads,
            } => self.draw_mesh_threads(resolver, threads, object_threads, mesh_threads),
            IndirectAction::Dispatch { .. } | IndirectAction::DispatchThreads { .. } => {
                Err(Error::Invalid("render encoders execute draws"))
            }
        }
    }

    /// Records `work` under conditional rendering on command `index`'s
    /// flag, when the GPU selects the commands.
    fn gated(
        &mut self,
        flag: Option<(Upload, usize)>,
        work: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let Some((flags, index)) = flag else {
            return work(self);
        };
        self.recorder.push(Command::BeginConditionalRendering {
            buffer: flags.buffer,
            offset: flags.offset + index as u64 * 4,
        });
        let result = work(self);
        self.recorder.push(Command::EndConditionalRendering);
        result
    }

    fn restore_render(&mut self, saved: SavedRender) -> Result<()> {
        match &saved.pipeline {
            Some(state) => self.set_render_pipeline_state(state)?,
            None => render(&mut self.encoder)?.pipeline = None,
        }
        let render = render(&mut self.encoder)?;
        render.vertex_buffers = saved.vertex_buffers;
        render.object_threadgroup_lengths = saved.object_threadgroup_lengths;
        render.amplification = saved.amplification;
        render.factors = saved.factors;
        self.set_raster_state(&saved.raster)?;
        self.restore_bindings(saved.bindings);
        Ok(())
    }

    /// Restores bindings while keeping track of what was pushed last.
    fn restore_bindings(&mut self, bindings: Bindings) {
        let pushed = self.bindings.pushed;
        self.bindings = bindings;
        self.bindings.pushed = pushed;
    }

    fn replay_compute(
        &mut self,
        resolver: &mut dyn Resolver,
        descriptor: &IndirectCommandBufferDescriptor,
        commands: &[IndirectCommand],
        gate: Option<Upload>,
    ) -> Result<()> {
        let state = compute(&mut self.encoder)?;
        let saved = SavedCompute {
            pipeline: state.pipeline.clone(),
            threadgroup_lengths: state.threadgroup_lengths.clone(),
            stage_in: state.stage_in,
            bindings: self.bindings.clone(),
        };
        let mut replayed = Ok(());
        let mut buffers = None;
        for (index, command) in commands.iter().enumerate() {
            let flag = gate.map(|flags| (flags, index));
            replayed =
                self.replay_compute_command(resolver, descriptor, command, &mut buffers, flag);
            if replayed.is_err() {
                break;
            }
        }
        let state = compute(&mut self.encoder)?;
        state.pipeline = saved.pipeline;
        state.threadgroup_lengths = saved.threadgroup_lengths;
        state.stage_in = saved.stage_in;
        self.restore_bindings(saved.bindings);
        replayed
    }

    fn replay_compute_command<'a>(
        &mut self,
        resolver: &mut dyn Resolver,
        descriptor: &IndirectCommandBufferDescriptor,
        command: &'a IndirectCommand,
        buffers: &mut Option<&'a [IndirectBuffer]>,
        flag: Option<(Upload, usize)>,
    ) -> Result<()> {
        let Some(action) = command.action else {
            return Ok(());
        };
        let state = compute(&mut self.encoder)?;
        // A serial encoder orders every dispatch already.
        if command.barrier && state.dispatch_type == DispatchType::Concurrent {
            self.compute_memory_barrier(BarrierScope::BUFFERS | BarrierScope::TEXTURES)?;
        }
        if !descriptor.inherit_pipeline_state {
            let id = command
                .pipeline
                .ok_or(Error::Invalid(
                    "an indirect command dispatches without a pipeline state",
                ))?
                .id;
            let state = compute(&mut self.encoder)?;
            if state.pipeline.as_ref().map(|state| state.id) != Some(id) {
                state.pipeline = Some(resolver.compute_pipeline_state(id)?);
            }
        }
        if !descriptor.inherit_buffers && *buffers != Some(command.buffers.as_slice()) {
            self.bindings.clear_buffers(&[Stage::Kernel]);
            for binding in &command.buffers {
                self.set_compute_buffer(Some(binding.buffer), binding.offset, binding.index)?;
            }
            *buffers = Some(&command.buffers);
        }
        compute(&mut self.encoder)?.threadgroup_lengths = command.threadgroup_lengths.clone();
        if let Some((origin, size)) = command.stage_in {
            self.set_stage_in_region(origin, size)?;
        }
        self.gated(flag, |this| match action {
            IndirectAction::Dispatch {
                threadgroups,
                threads,
            } => this.dispatch_threadgroups(resolver, threadgroups, threads),
            IndirectAction::DispatchThreads { grid, threads } => {
                this.dispatch_threads(resolver, grid, threads)
            }
            _ => Err(Error::Invalid("compute encoders execute dispatches")),
        })
    }

    /// `resetCommandsInBuffer:withRange:` of the blit encoder, which
    /// zeroes a GPU-resident buffer's records in order.
    pub fn reset_commands(
        &mut self,
        resolver: &mut dyn Resolver,
        id: IndirectCommandBufferId,
        range: Range<usize>,
    ) -> Result<()> {
        self.blit()?;
        if resolver.indirect_commands(id)?.records().is_none() {
            return resolver
                .update_indirect_commands(id, &mut |buffer| buffer.reset(range.clone()));
        }
        let (layout, records) = resolver.indirect_records(id)?;
        let range = record_range(&layout, range)?;
        self.fill_buffer(resolver, records, range.start, range.end - range.start, 0)
    }

    /// `copyIndirectCommandBuffer:sourceRange:destination:destinationIndex:`.
    /// A copy from a GPU-resident buffer makes the destination GPU-resident
    /// and copies records in order; one into a GPU-resident buffer places
    /// the source's commands as records.
    pub fn copy_indirect_commands(
        &mut self,
        resolver: &mut dyn Resolver,
        source: IndirectCommandBufferId,
        range: Range<usize>,
        destination: IndirectCommandBufferId,
        index: usize,
    ) -> Result<()> {
        self.blit()?;
        let contents = resolver.indirect_commands(source)?;
        let resident = contents.records().is_some();
        if !resident && resolver.indirect_commands(destination)?.records().is_none() {
            return resolver.update_indirect_commands(destination, &mut |buffer| {
                buffer.copy_from(&contents, range.clone(), index)
            });
        }
        let (layout, records) = resolver.indirect_records(destination)?;
        let barriers = match resident {
            true => contents.has_barriers(),
            false => contents
                .commands(range.clone())?
                .iter()
                .any(|command| command.barrier),
        };
        if barriers {
            resolver.update_indirect_commands(destination, &mut |buffer| {
                buffer.note_barriers();
                Ok(())
            })?;
        }
        let end = index.checked_add(range.len()).ok_or(Error::Invalid(
            "range extends past the indirect command buffer",
        ))?;
        let target = record_range(&layout, index..end)?;
        let size = target.end - target.start;
        let (source, offset) = if resident {
            let (source_layout, source_records) = resolver.indirect_records(source)?;
            ensure(
                RecordLayout {
                    count: layout.count,
                    ..source_layout
                } == layout,
                "copies between indirect command buffers of one record layout",
            )?;
            (source_records, record_range(&source_layout, range)?.start)
        } else {
            let bytes = resolver
                .indirect_commands(destination)?
                .records_of(&contents, range)?;
            let alignment = u64::from(RecordLayout::RECORD_ALIGNMENT);
            let upload = self.recorder.upload(resolver, &bytes, alignment)?;
            let source = BufferRef {
                buffer: upload.buffer,
                offset: upload.offset,
                address: upload.address,
                length: size,
            };
            (source, 0)
        };
        self.copy_buffer(source, offset, records, target.start, size)
    }

    /// `optimizeIndirectCommandBuffer:withRange:`: executions already bind
    /// only state that changes, so the commands stay as they are.
    pub fn optimize_indirect_commands(
        &mut self,
        resolver: &mut dyn Resolver,
        id: IndirectCommandBufferId,
        range: Range<usize>,
    ) -> Result<()> {
        self.blit()?;
        let size = resolver.indirect_commands(id)?.size();
        ensure(
            range.start <= range.end && range.end <= size,
            "range extends past the indirect command buffer",
        )
    }
}

/// The buffer offsets of the records of `range`.
fn record_range(layout: &RecordLayout, range: Range<usize>) -> Result<Range<u64>> {
    ensure(
        range.start <= range.end && range.end <= layout.count as usize,
        "range extends past the indirect command buffer",
    )?;
    Ok(layout.record(range.start)..layout.record(range.end))
}
