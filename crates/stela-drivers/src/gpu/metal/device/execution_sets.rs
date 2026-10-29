//! Execution sets of the render pipelines that support indirect command
//! buffers, which GPU-resident indirect commands switch between, and the
//! indirect commands layouts their executions use.
//!
//! An execution set switches only shaders: Vulkan requires its pipelines
//! to share all other state and their fragment output interface. Render
//! pipelines with the same such state and Metal topology class form a
//! class with one execution set, and a pipeline's [`IndirectPipeline`]
//! names its class and its index in the set. Index 0 holds the class's
//! first pipeline as the set's initial pipeline, which the class keeps
//! alive until its last pipeline goes; an index returns to the class once
//! the submissions that could read it complete.
use super::{Device, Slab};
use crate::gpu::metal::{
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

/// Pipelines one class's execution set holds.
const CLASS_CAPACITY: u32 = 4096;

/// What every pipeline of a class shares: its Vulkan state without shader
/// code, its Metal topology class and the fragment outputs the shaders
/// write.
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

#[derive(Debug)]
struct RenderClass {
    key: ClassKey,
    set: ExecutionSet,
    /// The set's initial pipeline at index 0.
    initial: Pipeline,
    indices: DescriptorIndices,
    /// The live pipelines by index.
    members: Vec<(u32, Pipeline)>,
}

#[derive(Debug, Default)]
pub(super) struct ExecutionSets {
    render: Slab<RenderClass>,
    layouts: Vec<(GeneratedLayoutKey, IndirectCommandsLayout)>,
}

impl ExecutionSets {
    pub(super) fn retire(&mut self, completed: u64) {
        for class in self.render.entries.iter_mut().flatten() {
            class.indices.retire(completed);
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
                let set = self
                    .backend
                    .create_execution_set(pipeline, CLASS_CAPACITY)?;
                self.execution_sets.render.insert(RenderClass {
                    key,
                    set,
                    initial: pipeline,
                    indices: DescriptorIndices::new(CLASS_CAPACITY),
                    members: Vec::new(),
                })
            }
        };
        let entry = self.execution_sets.render.get_mut(class)?;
        let index = entry
            .indices
            .allocate()
            .map_err(|_| Error::Unsupported("indirect-bindable pipelines of one state"))?;
        entry.members.push((index, pipeline));
        let set = entry.set;
        self.backend.write_execution_set(set, index, pipeline);
        Ok(IndirectPipeline { class, index })
    }

    /// Returns a destroyed pipeline's index once no submission can read it,
    /// and the Vulkan pipeline to destroy unless the class keeps it as its
    /// initial pipeline; the class's execution set goes with its last
    /// pipeline.
    pub(super) fn remove_indirect_render(
        &mut self,
        indirect: IndirectPipeline,
        pipeline: Pipeline,
    ) -> Result<Option<Pipeline>> {
        let serial = self.submitted;
        let class = self.execution_sets.render.get_mut(indirect.class)?;
        class.members.retain(|&(index, _)| index != indirect.index);
        class.indices.release(indirect.index, serial);
        if !class.members.is_empty() {
            return Ok((pipeline != class.initial).then_some(pipeline));
        }
        let class = self.execution_sets.render.remove(indirect.class)?;
        self.defer(Object::ExecutionSet(class.set));
        if class.initial != pipeline {
            self.defer(Object::Pipeline(class.initial));
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
                    set: Some(class.set),
                    pipeline: class.members.first()?.1,
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

    /// The indirect commands layout of `key`, created on first use, and the
    /// preprocess memory one sequence of it needs with `set` in memory of
    /// `request`.
    pub(super) fn generated_layout(
        &mut self,
        key: &GeneratedLayoutKey,
        set: Option<ExecutionSet>,
        request: MemoryRequest,
    ) -> Result<(IndirectCommandsLayout, Requirements)> {
        let layouts = &self.execution_sets.layouts;
        let layout = match layouts.iter().find(|(known, _)| known == key) {
            Some(&(_, layout)) => layout,
            None => {
                let info = key.info();
                let limits = self.backend.physical_device().limits.generated_commands;
                let limits = limits.ok_or(Error::Unsupported("device-generated commands"))?;
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
            .generated_commands_requirements(layout, set, 1, request)?;
        Ok((layout, requirements))
    }
}
