//! Executing GPU-resident indirect command buffers (see
//! [`crate::gpu::metal::indirect`]) through device-generated commands.
//!
//! Outside the pass instance, the backend's resolve kernel turns each
//! command's record into a [`GeneratedSequence`] and a count per slot: a
//! pipeline class, an action and a primitive type. Generated commands
//! switch only shaders and set no dynamic state, so each command runs, in
//! order, as one execution per slot, each limited to the command's count
//! of that slot, so at most one draws. Before each, the slot's class binds
//! one of its pipelines, its rasterizer discard and the slot's topology;
//! the execution set token then switches to the command's shaders.
use super::{
    CommandBuffer, Resolver,
    indirect::ExecutionRange,
    render::{primitive_topology, render},
};
use crate::gpu::metal::{
    abi::{BarrierScope, IndirectCommandType, PrimitiveTopologyClass, PrimitiveType, RenderStages},
    binding::{ArgumentTable, GeneratedSequence, PushConstants, ResolveArguments, ResolveSlot},
    error::{Error, Result, ensure},
    hazard::{RENDER_PASS, Use},
    indirect::{IndirectCommandBuffer, IndirectCommandBufferId, RecordLayout},
    shader::Stage,
    vulkan::{
        Access, PipelineBindPoint, PipelineStages, ShaderStages,
        backend::Requirements,
        command::{Command, GeneratedCommands},
        object::{
            ExecutionSet, IndirectCommandsLayout, IndirectCommandsLayoutInfo, IndirectToken,
            Pipeline,
        },
    },
};
use alloc::vec::Vec;

/// A state class of render pipelines GPU-resident commands draw with: an
/// execution set's, or the encoder's pipeline for buffers that inherit it.
#[derive(Clone, Debug, PartialEq)]
pub struct IndirectRenderClass {
    /// The class number pipeline handles carry; zero for the encoder's.
    pub index: u32,
    pub set: Option<ExecutionSet>,
    /// A pipeline of the class to bind before its executions.
    pub pipeline: Pipeline,
    pub stages: ShaderStages,
    pub rasterization: bool,
    pub topology: PrimitiveTopologyClass,
    /// The vertex buffer indices the pipelines read, with their static
    /// strides.
    pub vertex_buffers: Vec<(u32, Option<u32>)>,
}

/// What an indirect commands layout over a [`GeneratedSequence`] binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedLayoutKey {
    pub stages: ShaderStages,
    pub execution_set: bool,
    pub indexed: bool,
    pub vertex_buffers: Vec<u32>,
}

impl GeneratedLayoutKey {
    pub fn info(&self) -> IndirectCommandsLayoutInfo {
        let mut tokens = Vec::new();
        if self.execution_set {
            let token = IndirectToken::ExecutionSet(self.stages);
            tokens.push((GeneratedSequence::PIPELINE_OFFSET, token));
        }
        let push = IndirectToken::PushConstants {
            offset: 0,
            size: PushConstants::BYTES,
        };
        tokens.push((GeneratedSequence::PUSH_OFFSET, push));
        if self.indexed {
            let token = IndirectToken::IndexBuffer;
            tokens.push((GeneratedSequence::INDEX_BUFFER_OFFSET, token));
        }
        for &index in &self.vertex_buffers {
            let offset = GeneratedSequence::VERTEX_BUFFERS_OFFSET
                + GeneratedSequence::VERTEX_BUFFER_BYTES * index;
            tokens.push((offset, IndirectToken::VertexBuffer(index)));
        }
        tokens.push(match self.indexed {
            true => (
                GeneratedSequence::DRAW_INDEXED_OFFSET,
                IndirectToken::DrawIndexed,
            ),
            false => (GeneratedSequence::DRAW_OFFSET, IndirectToken::Draw),
        });
        IndirectCommandsLayoutInfo {
            stages: self.stages,
            stride: GeneratedSequence::BYTES,
            tokens,
        }
    }
}

/// One execution of each command: its slot and how it runs.
struct Execution {
    class: usize,
    primitive: PrimitiveType,
    layout: IndirectCommandsLayout,
    preprocess: Requirements,
}

/// The primitive types draws of a topology class use.
fn primitives(class: PrimitiveTopologyClass) -> &'static [PrimitiveType] {
    use PrimitiveType::*;
    match class {
        PrimitiveTopologyClass::Unspecified => &[Point, Line, LineStrip, Triangle, TriangleStrip],
        PrimitiveTopologyClass::Point => &[Point],
        PrimitiveTopologyClass::Line => &[Line, LineStrip],
        PrimitiveTopologyClass::Triangle => &[Triangle, TriangleStrip],
    }
}

impl CommandBuffer {
    /// `executeCommandsInBuffer:…` of a GPU-resident buffer in a render
    /// encoder.
    pub(super) fn execute_records(
        &mut self,
        resolver: &mut dyn Resolver,
        id: IndirectCommandBufferId,
        buffer: &IndirectCommandBuffer,
        range: ExecutionRange,
    ) -> Result<()> {
        let descriptor = *buffer.descriptor();
        let (layout, records) = resolver.indirect_records(id)?;
        if !layout.renders {
            return Err(Error::Unsupported(
                "executing GPU-resident compute indirect command buffers",
            ));
        }
        let (first, count, range) = match range {
            ExecutionRange::Direct(range) => {
                ensure(
                    range.start <= range.end && range.end <= buffer.size(),
                    "range extends past the indirect command buffer",
                )?;
                let words = [range.start as u32, range.len() as u32];
                let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
                let upload = self.recorder.upload(resolver, &bytes, 8)?;
                (range.start, range.len(), upload.address)
            }
            ExecutionRange::Indirect {
                buffer: source,
                offset,
            } => {
                ensure(
                    offset.is_multiple_of(4),
                    "indirect arguments are 4-byte aligned",
                )?;
                source.at(offset, 8)?;
                (0, buffer.size(), source.address + offset)
            }
        };
        if count == 0 {
            return Ok(());
        }
        let classes = self.indirect_classes(resolver, descriptor.inherit_pipeline_state)?;
        let mut executions = Vec::new();
        let draws = [
            (IndirectCommandType::DRAW, false),
            (IndirectCommandType::DRAW_INDEXED, true),
        ];
        for (index, class) in classes.iter().enumerate() {
            for (_, indexed) in draws
                .iter()
                .filter(|(kind, _)| descriptor.command_types.contains(*kind))
            {
                let key = GeneratedLayoutKey {
                    stages: class.stages,
                    execution_set: class.set.is_some(),
                    indexed: *indexed,
                    vertex_buffers: class
                        .vertex_buffers
                        .iter()
                        .map(|&(index, _)| index)
                        .collect(),
                };
                let (layout, preprocess) = resolver.generated_layout(&key, class.set)?;
                for &primitive in primitives(class.topology) {
                    executions.push((
                        ResolveSlot {
                            class: class.index,
                            action: match indexed {
                                true => RecordLayout::DRAW_INDEXED,
                                false => RecordLayout::DRAW,
                            },
                            primitive: primitive.raw() as u32,
                        },
                        Execution {
                            class: index,
                            primitive,
                            layout,
                            preprocess,
                        },
                    ));
                }
            }
        }
        let (slots, executions): (Vec<_>, Vec<_>) = executions.into_iter().unzip();
        let count = u32::try_from(count).map_err(|_| Error::Invalid("indirect command count"))?;
        let resolved = self.resolve(
            resolver,
            ResolveArguments {
                header: records.address,
                range,
                count,
                first: first as u32,
                inherit_pipeline: descriptor.inherit_pipeline_state,
                inherit_buffers: descriptor.inherit_buffers,
                slots,
                ..ResolveArguments::default()
            },
            &classes,
        )?;
        let barriers = buffer.has_barriers();
        let (sequences, counts) = resolved;
        let slot_count = executions.len() as u64;
        let preprocess = self.preprocess(resolver, &executions, count)?;
        let mut regions = preprocess.into_iter();
        // The class and primitive type bound for the last execution.
        let mut bound = None;
        for command in 0..u64::from(count) {
            if barriers {
                let scope =
                    BarrierScope::BUFFERS | BarrierScope::TEXTURES | BarrierScope::RENDER_TARGETS;
                let stages = RenderStages::VERTEX | RenderStages::FRAGMENT;
                self.render_memory_barrier(resolver, scope, stages, stages)?;
            }
            for (slot, execution) in executions.iter().enumerate() {
                let class = &classes[execution.class];
                let last = bound.replace((execution.class, execution.primitive));
                // Executions that switch shaders leave no pipeline bound.
                if class.set.is_some() || last.is_none_or(|(known, _)| known != execution.class) {
                    self.recorder.push(Command::BindPipeline {
                        bind_point: PipelineBindPoint::Graphics,
                        pipeline: class.pipeline,
                    });
                    self.recorder
                        .push(Command::SetRasterizerDiscard(!class.rasterization));
                }
                if last.is_none_or(|(_, known)| known != execution.primitive) {
                    let topology = primitive_topology(execution.primitive);
                    self.recorder.push(Command::SetPrimitiveTopology(topology));
                    self.recorder
                        .push(Command::SetPrimitiveRestart(execution.primitive.is_strip()));
                }
                let preprocess = regions.next().expect("a region per execution");
                self.recorder
                    .push(Command::ExecuteGeneratedCommands(GeneratedCommands {
                        stages: class.stages,
                        set: class.set,
                        layout: execution.layout,
                        address: sequences + command * u64::from(GeneratedSequence::BYTES),
                        size: u64::from(GeneratedSequence::BYTES),
                        preprocess,
                        preprocess_size: execution.preprocess.size,
                        sequences: 1,
                        count: Some(counts + (command * slot_count + slot as u64) * 4),
                    }));
            }
        }
        self.after_generated_commands()
    }

    /// The classes of an execution: the encoder's pipeline when the buffer
    /// inherits it, else the device's.
    fn indirect_classes(
        &mut self,
        resolver: &mut dyn Resolver,
        inherit_pipeline: bool,
    ) -> Result<Vec<IndirectRenderClass>> {
        let render = render(&mut self.encoder)?;
        if render.amplification.len() > 1 {
            return Err(Error::Unsupported(
                "vertex amplification of GPU-resident indirect commands",
            ));
        }
        if !inherit_pipeline {
            return Ok(resolver.indirect_render_classes());
        }
        let state = render
            .pipeline
            .as_ref()
            .ok_or(Error::Invalid("no render pipeline state is set"))?;
        let plan = &state.plan;
        if plan.mesh || plan.tessellation.is_some() {
            return Err(Error::Unsupported(
                "GPU-resident indirect draws of mesh and tessellated pipelines",
            ));
        }
        Ok(alloc::vec![IndirectRenderClass {
            index: 0,
            set: None,
            pipeline: state
                .pipeline
                .ok_or(Error::Invalid("no render pipeline state is set"))?,
            stages: plan
                .info
                .stages
                .iter()
                .fold(ShaderStages::EMPTY, |stages, &(stage, _)| stages | stage),
            rasterization: plan.rasterization_enabled,
            topology: plan.topology_class,
            vertex_buffers: plan
                .info
                .vertex_input
                .bindings
                .iter()
                .map(|binding| (binding.binding, binding.stride))
                .collect(),
        }])
    }

    /// Runs the resolve kernel outside the pass instance, returning the
    /// addresses of its sequences and counts.
    fn resolve(
        &mut self,
        resolver: &mut dyn Resolver,
        mut arguments: ResolveArguments,
        classes: &[IndirectRenderClass],
    ) -> Result<(u64, u64)> {
        let threads = arguments.count as usize;
        let zeros = |bytes: usize| alloc::vec![0; bytes];
        let sequences = self.recorder.upload(
            resolver,
            &zeros(threads * GeneratedSequence::BYTES as usize),
            GeneratedSequence::ALIGNMENT,
        )?;
        let counts =
            self.recorder
                .upload(resolver, &zeros(threads * arguments.slots.len() * 4), 4)?;
        if !arguments.inherit_buffers {
            let tables = threads * 2 * ArgumentTable::BYTES as usize;
            arguments.tables = self
                .recorder
                .upload(resolver, &zeros(tables), ArgumentTable::ALIGNMENT)?
                .address;
        }
        let class_count = classes.iter().map(|class| class.index + 1).max();
        arguments.class_count = class_count.unwrap_or(0);
        let mut strides = zeros(arguments.class_count as usize * 4 * 31);
        for class in classes {
            for &(index, stride) in &class.vertex_buffers {
                let at = (class.index as usize * 31 + index as usize) * 4;
                strides[at..at + 4].copy_from_slice(&stride.unwrap_or(0).to_le_bytes());
            }
        }
        arguments.strides = self.recorder.upload(resolver, &strides, 4)?.address;
        // The commands' tables copy the encoder's, as they stand.
        self.begin_query(resolver)?;
        self.bindings.flush(
            &mut self.recorder,
            resolver,
            &[Stage::Vertex, Stage::Fragment],
        )?;
        arguments.constants = self.bindings.constants;
        arguments.vertex_buffers = render(&mut self.encoder)?.sequence_vertex_buffers()?;
        arguments.sequences = sequences.address;
        arguments.counts = counts.address;
        let upload =
            self.recorder
                .upload(resolver, &arguments.encode(), ResolveArguments::ALIGNMENT)?;
        let count = arguments.count;
        self.outside_pass(resolver, |recorder| {
            recorder.access(Use::new(
                PipelineStages::COMPUTE_SHADER,
                Access::SHADER_READ | Access::SHADER_WRITE,
            ));
            recorder.push(Command::ResolveDraws {
                arguments: upload.address,
                count,
            });
            recorder.access(Use::new(
                PipelineStages::COMMAND_PREPROCESS | PipelineStages::DRAW_INDIRECT,
                Access::COMMAND_PREPROCESS_READ | Access::INDIRECT_COMMAND_READ,
            ));
            recorder.access(RENDER_PASS);
        })?;
        Ok((sequences.address, counts.address))
    }

    /// Preprocess memory of each execution of each command, in execution
    /// order.
    fn preprocess(
        &mut self,
        resolver: &mut dyn Resolver,
        executions: &[Execution],
        count: u32,
    ) -> Result<Vec<u64>> {
        let alignment = executions
            .iter()
            .map(|execution| execution.preprocess.alignment.max(1))
            .max()
            .unwrap_or(1);
        let mut offsets = Vec::with_capacity(executions.len() * count as usize);
        let mut bytes = 0u64;
        for _ in 0..count {
            for execution in executions {
                bytes = bytes.next_multiple_of(execution.preprocess.alignment.max(1));
                offsets.push(bytes);
                bytes += execution.preprocess.size;
            }
        }
        let size = usize::try_from(bytes).map_err(|_| Error::OutOfMemory)?;
        let upload = self
            .recorder
            .upload(resolver, &alloc::vec![0; size], alignment)?;
        Ok(offsets
            .into_iter()
            .map(|offset| upload.address + offset)
            .collect())
    }
}
