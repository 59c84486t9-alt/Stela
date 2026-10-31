//! Execution sets of the pipelines that support indirect command buffers,
//! which GPU-resident indirect commands switch between, and the indirect
//! commands layouts their executions use.
//!
//! An execution set switches only shaders: Vulkan requires its pipelines
//! to share all other state and their fragment output interface. Render
//! pipelines with the same such state and Metal topology class form a
//! class with one execution set; compute pipelines share one set, of
//! [`IndirectPipeline::COMPUTE_CLASS`]. A pipeline's [`IndirectPipeline`]
//! names its class and its index in the set. Index 0 holds the set's first
//! pipeline as its initial pipeline, which the set keeps alive until its
//! last pipeline goes; an index returns to the set once the submissions
//! that could read it complete.
use super::{Device, Slab};
use crate::metal::{
    abi::PrimitiveTopologyClass,
    binding::DescriptorIndices,
    command_buffer::generated::{GeneratedLayoutKey, IndirectRenderClass},
    error::{Error, Result},
    indirect::IndirectPipeline,
    pipeline::RenderPipelinePlan,
    shader::{ColorOutput, Compiler, Interface, Stage},
    vulkan::{
        ShaderStages,
        backend::{Backend, Object, Requirements},
        object::{
            ExecutionSet, GraphicsPipelineInfo, IndirectCommandsLayout, MemoryRequest, Pipeline,
            ShaderCode,
        },
    },
};
use alloc::vec::Vec;

/// Pipelines one execution set holds.
const SET_CAPACITY: u32 = 4096;

/// What every pipeline of a render class shares: its Vulkan state without
/// shader code, its Metal topology class and the fragment outputs the
/// shaders write.
#[derive(Clone, Debug, PartialEq)]
struct ClassKey {
    info: GraphicsPipelineInfo,
    topology: PrimitiveTopologyClass,
    rasterization: bool,
    color_outputs: Vec<ColorOutput>,
    writes: [bool; 3],
}

impl ClassKey {
    fn new(plan: &RenderPipelinePlan, interfaces: &[Interface]) -> Self {
        let mut info = plan.info.clone();
        info.stages
            .iter_mut()
            .for_each(|(_, code)| *code = ShaderCode(0));
        let fragment = interfaces
            .iter()
            .find(|interface| interface.stage == Stage::Fragment);
        Self {
            info,
            topology: plan.topology_class,
            rasterization: plan.rasterization_enabled,
            color_outputs: fragment.map_or(Vec::new(), |fragment| fragment.color_outputs.clone()),
            writes: fragment.map_or([false; 3], |fragment| {
                [
                    fragment.writes_depth,
                    fragment.writes_stencil,
                    fragment.writes_sample_mask,
                ]
            }),
        }
    }
}

/// An execution set and the live pipelines it holds.
#[derive(Debug)]
struct Set {
    set: ExecutionSet,
    /// The set's initial pipeline at index 0.
    initial: Pipeline,
    indices: DescriptorIndices,
    /// The live pipelines by index.
    members: Vec<(u32, Pipeline)>,
}

impl Set {
    fn new(backend: &mut impl Backend, initial: Pipeline) -> Result<Self> {
        Ok(Self {
            set: backend.create_execution_set(initial, SET_CAPACITY)?,
            initial,
            indices: DescriptorIndices::new(SET_CAPACITY),
            members: Vec::new(),
        })
    }

    /// Writes `pipeline` to a free index of the set, refusing it as
    /// `kind` when the set is full.
    fn add(
        &mut self,
        backend: &mut impl Backend,
        pipeline: Pipeline,
        kind: &'static str,
    ) -> Result<u32> {
        let index = self
            .indices
            .allocate()
            .map_err(|_| Error::Unsupported(kind))?;
        self.members.push((index, pipeline));
        backend.write_execution_set(self.set, index, pipeline);
        Ok(index)
    }

    /// Returns `index` once no submission after `serial` can read it;
    /// whether the set is left without pipelines.
    fn remove(&mut self, index: u32, serial: u64) -> bool {
        self.members.retain(|&(known, _)| known != index);
        self.indices.release(index, serial);
        self.members.is_empty()
    }
}

#[derive(Debug)]
struct RenderClass {
    key: ClassKey,
    set: Set,
}

#[derive(Debug, Default)]
pub(super) struct ExecutionSets {
    render: Slab<RenderClass>,
    compute: Option<Set>,
    layouts: Vec<(GeneratedLayoutKey, IndirectCommandsLayout)>,
}

impl ExecutionSets {
    pub(super) fn retire(&mut self, completed: u64) {
        let render = self.render.entries.iter_mut().flatten();
        for set in render.map(|class| &mut class.set).chain(&mut self.compute) {
            set.indices.retire(completed);
        }
    }
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// Adds an indirect-bindable render pipeline to the execution set of its
    /// class, creating the class for its first pipeline.
    pub(super) fn add_indirect_render(
        &mut self,
        plan: &RenderPipelinePlan,
        interfaces: &[Interface],
        pipeline: Pipeline,
    ) -> Result<IndirectPipeline> {
        let key = ClassKey::new(plan, interfaces);
        let sets = &mut self.execution_sets.render;
        let found = sets
            .entries
            .iter()
            .position(|class| class.as_ref().is_some_and(|class| class.key == key));
        let class = match found {
            Some(class) => class as u32,
            None => {
                let set = Set::new(&mut self.backend, pipeline)?;
                self.execution_sets.render.insert(RenderClass { key, set })
            }
        };
        let set = &mut self.execution_sets.render.get_mut(class)?.set;
        let kind = "indirect-bindable render pipelines of one state";
        let index = set.add(&mut self.backend, pipeline, kind)?;
        Ok(IndirectPipeline { class, index })
    }

    /// Adds an indirect-bindable compute pipeline to the compute execution
    /// set, creating the set for the first.
    pub(super) fn add_indirect_compute(&mut self, pipeline: Pipeline) -> Result<IndirectPipeline> {
        let set = match self.execution_sets.compute.take() {
            Some(set) => set,
            None => Set::new(&mut self.backend, pipeline)?,
        };
        let set = self.execution_sets.compute.insert(set);
        let kind = "indirect-bindable compute pipelines";
        let index = set.add(&mut self.backend, pipeline, kind)?;
        Ok(IndirectPipeline {
            class: IndirectPipeline::COMPUTE_CLASS,
            index,
        })
    }

    /// Returns a destroyed pipeline's index once no submission can read it,
    /// and the Vulkan pipeline to destroy unless its set keeps it as its
    /// initial pipeline; the set goes with its last pipeline.
    pub(super) fn remove_indirect(
        &mut self,
        indirect: IndirectPipeline,
        pipeline: Pipeline,
    ) -> Result<Option<Pipeline>> {
        let serial = self.submitted;
        let sets = &mut self.execution_sets;
        let set = match indirect.class {
            IndirectPipeline::COMPUTE_CLASS => sets.compute.as_mut(),
            class => sets.render.get_mut(class).ok().map(|class| &mut class.set),
        };
        let set = set.ok_or(Error::Invalid("unknown pipeline"))?;
        if !set.remove(indirect.index, serial) {
            return Ok((pipeline != set.initial).then_some(pipeline));
        }
        let set = match indirect.class {
            IndirectPipeline::COMPUTE_CLASS => sets.compute.take(),
            class => sets.render.remove(class).ok().map(|class| class.set),
        };
        let set = set.ok_or(Error::Invalid("unknown pipeline"))?;
        self.defer(Object::ExecutionSet(set.set));
        if set.initial != pipeline {
            self.defer(Object::Pipeline(set.initial));
        }
        Ok(Some(pipeline))
    }

    /// The live classes, as executions of GPU-resident commands use them.
    pub(super) fn indirect_render_classes(&self) -> Vec<IndirectRenderClass> {
        let classes = self.execution_sets.render.entries.iter().enumerate();
        classes
            .filter_map(|(index, class)| {
                let class = class.as_ref()?;
                let info = &class.key.info;
                Some(IndirectRenderClass {
                    index: index as u32,
                    set: Some(class.set.set),
                    pipeline: class.set.members.first()?.1,
                    stages: info
                        .stages
                        .iter()
                        .fold(ShaderStages::EMPTY, |stages, &(stage, _)| stages | stage),
                    rasterization: class.key.rasterization,
                    topology: class.key.topology,
                    vertex_buffers: info
                        .vertex_input
                        .bindings
                        .iter()
                        .map(|binding| (binding.binding, binding.stride))
                        .collect(),
                })
            })
            .collect()
    }

    /// The compute execution set and a live pipeline of it, if any.
    pub(super) fn indirect_compute_set(&self) -> Option<(ExecutionSet, Pipeline)> {
        let set = self.execution_sets.compute.as_ref()?;
        Some((set.set, set.members.first()?.1))
    }

    /// The indirect commands layout of `key`, created on first use, and the
    /// preprocess memory `sequences` sequences of it need with `set` in
    /// memory of `request`.
    pub(super) fn generated_layout(
        &mut self,
        key: &GeneratedLayoutKey,
        set: Option<ExecutionSet>,
        sequences: u32,
        request: MemoryRequest,
    ) -> Result<(IndirectCommandsLayout, Requirements)> {
        let limits = self.backend.physical_device().limits.generated_commands;
        let limits = limits.ok_or(Error::Unsupported("device-generated commands"))?;
        if sequences > limits.max_sequences {
            return Err(Error::Unsupported(
                "GPU-resident executions of more commands than device-generated commands run \
                 at once",
            ));
        }
        let layouts = &self.execution_sets.layouts;
        let layout = match layouts.iter().find(|(known, _)| known == key) {
            Some(&(_, layout)) => layout,
            None => {
                let info = key.info();
                if info.tokens.len() as u32 > limits.max_tokens {
                    return Err(Error::Unsupported(
                        "GPU-resident indirect commands of pipelines with more vertex buffers \
                         than device-generated commands bind",
                    ));
                }
                let layout = self.backend.create_indirect_commands_layout(&info)?;
                self.execution_sets.layouts.push((key.clone(), layout));
                layout
            }
        };
        let requirements = self
            .backend
            .generated_commands_requirements(layout, set, sequences, request)?;
        Ok((layout, requirements))
    }
}
