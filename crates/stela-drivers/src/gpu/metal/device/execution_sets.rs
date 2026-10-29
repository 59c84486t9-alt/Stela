//! Execution sets of the render pipelines that support indirect command
//! buffers, which GPU-resident indirect commands switch between.
//!
//! An execution set switches only shaders: Vulkan requires its pipelines
//! to share all other state and their fragment output interface. Render
//! pipelines with the same such state form a class with one execution set,
//! and a pipeline's [`IndirectPipeline`] names its class and its index in
//! the set. Index 0 repeats the class's first pipeline as the set's initial
//! pipeline; an index returns to the class once the submissions that could
//! read it complete.
use super::{Device, Slab};
use crate::gpu::metal::{
    binding::DescriptorIndices,
    error::{Error, Result},
    indirect::IndirectPipeline,
    shader::{ColorOutput, Compiler, Interface, Stage},
    vulkan::{
        backend::{Backend, Object},
        object::{ExecutionSet, GraphicsPipelineInfo, Pipeline, ShaderCode},
    },
};
use alloc::vec::Vec;

/// Pipelines one class's execution set holds.
const CLASS_CAPACITY: u32 = 4096;

/// What every pipeline of a class shares: its Vulkan state without shader
/// code, and the fragment outputs the shaders write.
#[derive(Clone, Debug, PartialEq)]
struct ClassKey {
    info: GraphicsPipelineInfo,
    color_outputs: Vec<ColorOutput>,
    writes: [bool; 3],
}

impl ClassKey {
    fn new(info: &GraphicsPipelineInfo, interfaces: &[Interface]) -> Self {
        let mut info = info.clone();
        info.stages
            .iter_mut()
            .for_each(|(_, code)| *code = ShaderCode(0));
        let fragment = interfaces
            .iter()
            .find(|interface| interface.stage == Stage::Fragment);
        Self {
            info,
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
    indices: DescriptorIndices,
    /// The live pipelines by index.
    members: Vec<(u32, Pipeline)>,
}

#[derive(Debug, Default)]
pub(super) struct ExecutionSets {
    render: Slab<RenderClass>,
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
        info: &GraphicsPipelineInfo,
        interfaces: &[Interface],
        pipeline: Pipeline,
    ) -> Result<IndirectPipeline> {
        let key = ClassKey::new(info, interfaces);
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

    /// Returns a destroyed pipeline's index once no submission can read it;
    /// the class's execution set goes with its last pipeline.
    pub(super) fn remove_indirect_render(&mut self, pipeline: IndirectPipeline) -> Result<()> {
        let serial = self.submitted;
        let class = self.execution_sets.render.get_mut(pipeline.class)?;
        class.members.retain(|&(index, _)| index != pipeline.index);
        class.indices.release(pipeline.index, serial);
        if class.members.is_empty() {
            let class = self.execution_sets.render.remove(pipeline.class)?;
            self.defer(Object::ExecutionSet(class.set));
        }
        Ok(())
    }
}
