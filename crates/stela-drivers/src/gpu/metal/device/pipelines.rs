//! Functions and pipeline states, with their compiled variants.
//!
//! A pipeline stage compiles its linked functions into its function
//! ([`Linking`]). A visible function table is a buffer of 64-bit
//! [`FunctionHandle`]s, which the compiler's dispatch reads.
use super::{BufferId, ComputePipelineId, Device, FunctionId, RenderPipelineId, Slab};
use crate::gpu::metal::{
    abi::{FunctionType, PrimitiveTopologyClass},
    command_buffer::{ComputePipelineState, IndirectCompute, RenderPipelineState},
    error::{Error, Result, ensure, require},
    pipeline::{
        self, ComputePipelineDescriptor, MeshRenderPipelineDescriptor, RenderPipelineDescriptor,
        RenderTargets, TessellatedVertex, TessellationDescriptor,
    },
    shader::{
        CompiledShader, Compiler, Interface, LinkedFunction, Linking, Reflection, Specialization,
        Stage, Tessellation, TessellationStages, Varying,
    },
    vertex::{StageInputDescriptor, VertexDescriptor},
    vulkan::{
        ShaderStages,
        backend::{Backend, Object},
        object::{ComputePipelineInfo, Pipeline, ShaderCode},
    },
};
use alloc::{string::String, vec::Vec};

/// A specialized function (`newFunctionWithName:constantValues:`).
#[derive(Debug)]
struct FunctionObject {
    library: u64,
    entry: String,
    constants: Vec<(u32, Vec<u8>)>,
    reflection: Reflection,
}

impl FunctionObject {
    /// The interface of a function that becomes a pipeline stage.
    fn interface(&self) -> Result<&Interface> {
        match &self.reflection {
            Reflection::Stage(interface) => Ok(interface.as_ref()),
            Reflection::Visible { .. } => Err(Error::Invalid("a visible function is not a stage")),
        }
    }
}

/// `MTLFunctionHandle`: the value a visible function table holds to call a
/// function its stage links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FunctionHandle(pub u64);

/// A stage's linked functions: `functions` are those its handles name, in
/// order, and `linking` what its function compiles with.
#[derive(Debug, Default)]
struct Linked {
    functions: Vec<FunctionId>,
    linking: Linking,
}

impl Linked {
    /// Handle `i + 1` calls the `i`-th function; zero calls none.
    fn handle(&self, function: FunctionId) -> Option<FunctionHandle> {
        let index = self
            .functions
            .iter()
            .position(|&linked| linked == function)?;
        Some(FunctionHandle(index as u64 + 1))
    }
}

#[derive(Debug)]
struct RenderObject {
    state: RenderPipelineState,
    /// Each stage's linked functions.
    linked: Vec<(Stage, Linked)>,
    /// A mesh pipeline's compiled fragment function, which every variant
    /// links.
    fragment: Option<ShaderCode>,
    mesh: Option<MeshFunctions>,
    variants: Vec<(MeshShape, Pipeline)>,
}

/// The object and mesh functions of a mesh pipeline, which its variants
/// compile, and the varyings its mesh function links to its fragment
/// function.
#[derive(Debug)]
struct MeshFunctions {
    object: Option<FunctionId>,
    mesh: FunctionId,
    varyings: Vec<Varying>,
}

/// Threads per object and per mesh threadgroup, which mesh variants are
/// compiled for.
type MeshShape = ([u32; 3], [u32; 3]);

#[derive(Debug)]
struct ComputeObject {
    state: ComputePipelineState,
    function: FunctionId,
    linked: Linked,
    variants: Vec<(Specialization, Pipeline)>,
}

#[derive(Debug, Default)]
pub(super) struct Pipelines {
    functions: Slab<FunctionObject>,
    render: Slab<RenderObject>,
    compute: Slab<ComputeObject>,
}

impl Pipelines {
    fn interface(&self, id: FunctionId) -> Result<&Interface> {
        self.functions.get(id.0)?.interface()
    }
}

impl RenderObject {
    fn linked(&self, stage: Stage) -> Option<&Linked> {
        self.linked
            .iter()
            .find(|(linked, _)| *linked == stage)
            .map(|(_, linked)| linked)
    }
}

/// `MTLLinkedFunctions`, the `preloadedLibraries` and the call stack depth
/// of a pipeline stage, with the device's function ids and the compiler's
/// library ids. Every function compiles into the stage, so
/// `binaryFunctions` join `functions`.
#[derive(Clone, Debug)]
pub struct LinkedFunctions {
    /// The visible functions the stage's function tables call.
    pub functions: Vec<FunctionId>,
    /// Visible functions only external calls reach.
    pub private_functions: Vec<FunctionId>,
    /// Dynamic libraries resolving external calls.
    pub libraries: Vec<u64>,
    /// The stage's `maxCallStackDepth` (`maxVertexCallStackDepth`,
    /// `maxFragmentCallStackDepth`, ...).
    pub max_call_stack_depth: u32,
}

impl Default for LinkedFunctions {
    fn default() -> Self {
        Self {
            functions: Vec::new(),
            private_functions: Vec::new(),
            libraries: Vec::new(),
            max_call_stack_depth: Linking::default().max_call_stack_depth,
        }
    }
}

/// `MTLRenderPipelineDescriptor` with the device's function ids.
#[derive(Clone, Debug)]
pub struct RenderPipelineRequest {
    pub vertex_function: FunctionId,
    pub fragment_function: Option<FunctionId>,
    pub vertex_descriptor: Option<VertexDescriptor>,
    pub targets: RenderTargets,
    pub input_primitive_topology: PrimitiveTopologyClass,
    pub max_vertex_amplification_count: u64,
    pub tessellation: TessellationDescriptor,
    pub vertex_linked_functions: LinkedFunctions,
    pub fragment_linked_functions: LinkedFunctions,
    /// `supportIndirectCommandBuffers`: GPU-resident indirect commands can
    /// switch to the pipeline, unless it is tessellated or amplifies
    /// vertices, whose draws only the CPU encodes.
    pub support_indirect_command_buffers: bool,
}

/// `MTLComputePipelineDescriptor` with the device's function id.
#[derive(Clone, Debug)]
pub struct ComputePipelineRequest {
    pub compute_function: FunctionId,
    pub threadgroup_size_is_multiple_of_thread_execution_width: bool,
    /// Zero leaves the device's limit.
    pub max_total_threads_per_threadgroup: u64,
    pub stage_input: Option<StageInputDescriptor>,
    pub linked_functions: LinkedFunctions,
    /// `supportIndirectCommandBuffers`: GPU-resident indirect commands can
    /// switch to the pipeline, whose threadgroup buffers then align to at
    /// most 16 bytes.
    pub support_indirect_command_buffers: bool,
}

/// `MTLMeshRenderPipelineDescriptor` with the device's function ids.
#[derive(Clone, Debug)]
pub struct MeshPipelineRequest {
    pub object_function: Option<FunctionId>,
    pub mesh_function: FunctionId,
    pub fragment_function: Option<FunctionId>,
    pub targets: RenderTargets,
    pub max_vertex_amplification_count: u64,
    pub object_linked_functions: LinkedFunctions,
    pub mesh_linked_functions: LinkedFunctions,
    pub fragment_linked_functions: LinkedFunctions,
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `newFunctionWithName:constantValues:`: reflects the function without
    /// compiling it.
    pub fn new_function(
        &mut self,
        library: u64,
        entry: &str,
        constants: Vec<(u32, Vec<u8>)>,
    ) -> Result<FunctionId> {
        let specialization = Specialization {
            constants: constants.clone(),
            ..Specialization::default()
        };
        let reflection = self.compiler.reflect(library, entry, &specialization)?;
        reflection.validate()?;
        ensure(
            constants
                .iter()
                .enumerate()
                .all(|(n, (index, _))| constants[n + 1..].iter().all(|(other, _)| other != index)),
            "a function constant has two values",
        )?;
        for constant in reflection.constants() {
            match constants.iter().find(|(index, _)| *index == constant.index) {
                Some((_, value)) => ensure(
                    constant.accepts(value),
                    "a function constant value of another type",
                )?,
                None => ensure(
                    !constant.required,
                    "a required function constant has no value",
                )?,
            }
        }
        if reflection.command_barriers() {
            self.note_command_barriers();
        }
        let function = FunctionObject {
            library,
            entry: String::from(entry),
            constants,
            reflection,
        };
        Ok(FunctionId(self.pipelines.functions.insert(function)))
    }

    /// The interface of a function that becomes a pipeline stage.
    pub fn function_interface(&self, id: FunctionId) -> Result<&Interface> {
        self.pipelines.interface(id)
    }

    pub fn function_type(&self, id: FunctionId) -> Result<FunctionType> {
        Ok(self
            .pipelines
            .functions
            .get(id.0)?
            .reflection
            .function_type())
    }

    pub fn destroy_function(&mut self, id: FunctionId) -> Result<()> {
        self.pipelines.functions.remove(id.0).map(drop)
    }

    fn compile(
        &mut self,
        id: FunctionId,
        specialization: Specialization,
    ) -> Result<CompiledShader> {
        let function = self.pipelines.functions.get(id.0)?;
        let stage = function.interface()?.stage;
        let specialization = Specialization {
            constants: function.constants.clone(),
            ..specialization
        };
        let compiled = self
            .compiler
            .compile(function.library, &function.entry, &specialization)?;
        if compiled.interface.stage != stage {
            self.compiler.release(compiled.code);
            return Err(Error::Invalid("the compiler changed the function's stage"));
        }
        Ok(compiled)
    }

    fn compile_tessellation(
        &mut self,
        id: FunctionId,
        specialization: Specialization,
        tessellation: &Tessellation,
    ) -> Result<TessellationStages> {
        let function = self.pipelines.functions.get(id.0)?;
        let expected = function
            .interface()
            .map(|interface| (interface.stage, interface.patch))?;
        let specialization = Specialization {
            constants: function.constants.clone(),
            ..specialization
        };
        let stages = self.compiler.compile_tessellation(
            function.library,
            &function.entry,
            &specialization,
            tessellation,
        )?;
        let interface = &stages.evaluation.interface;
        if (interface.stage, interface.patch) != expected {
            for code in [stages.vertex, stages.control, stages.evaluation.code] {
                self.compiler.release(code);
            }
            return Err(Error::Invalid("the compiler changed the function's patch"));
        }
        Ok(stages)
    }

    /// `newRenderPipelineStateWithDescriptor:`. A post-tessellation vertex
    /// function compiles with the stages that feed it.
    pub fn new_render_pipeline(
        &mut self,
        request: &RenderPipelineRequest,
    ) -> Result<RenderPipelineId> {
        let vertex_linked = self.link(&request.vertex_linked_functions, true)?;
        let fragment_linked = self.link(&request.fragment_linked_functions, true)?;
        let pipelines = &self.pipelines;
        let function = pipelines.interface(request.vertex_function)?;
        let fragment_function = request
            .fragment_function
            .map(|id| pipelines.interface(id))
            .transpose()?;
        let varyings = pipeline::link_varyings(function, fragment_function)?;
        let tessellation = pipeline::tessellation(
            &self.capabilities,
            function,
            &request.tessellation,
            request.vertex_descriptor.as_ref(),
        )?;
        let specialization = Specialization {
            amplified: request.max_vertex_amplification_count > 1,
            varyings: varyings.clone(),
            linking: vertex_linked.linking.clone(),
            ..Specialization::default()
        };
        let (vertex, feeding) = match &tessellation {
            Some(tessellation) => {
                let stages = self.compile_tessellation(
                    request.vertex_function,
                    specialization,
                    tessellation,
                )?;
                (stages.evaluation, Some([stages.vertex, stages.control]))
            }
            None => (self.compile(request.vertex_function, specialization)?, None),
        };
        let mut codes: Vec<ShaderCode> = feeding.into_iter().flatten().collect();
        codes.push(vertex.code);
        let linked = Specialization {
            varyings,
            linking: fragment_linked.linking.clone(),
            ..Specialization::default()
        };
        let fragment = match request.fragment_function {
            Some(id) => match self.compile(id, linked) {
                Ok(fragment) => Some(fragment),
                Err(error) => {
                    codes.iter().for_each(|code| self.compiler.release(*code));
                    return Err(error);
                }
            },
            None => None,
        };
        codes.extend(fragment.as_ref().map(|shader| shader.code));
        let descriptor = RenderPipelineDescriptor {
            vertex_function: &vertex,
            fragment_function: fragment.as_ref(),
            vertex_descriptor: request.vertex_descriptor.as_ref(),
            targets: request.targets,
            input_primitive_topology: request.input_primitive_topology,
            max_vertex_amplification_count: request.max_vertex_amplification_count,
            tessellation: tessellation.as_ref().zip(feeding).map(
                |(tessellation, [vertex, control])| TessellatedVertex {
                    tessellation,
                    vertex,
                    control,
                },
            ),
        };
        let generated = self.backend.physical_device().limits.generated_commands;
        // The driver compiles the NIR into the pipeline, which outlives it.
        let created =
            pipeline::render_pipeline(&self.capabilities, &descriptor).and_then(|mut plan| {
                plan.info.indirect_bindable = request.support_indirect_command_buffers
                    && plan.tessellation.is_none()
                    && plan.amplification_count == 1
                    && generated.is_some();
                Ok((self.backend.create_graphics_pipeline(&plan.info)?, plan))
            });
        codes.iter().for_each(|code| self.compiler.release(*code));
        let (vulkan, plan) = created?;
        let interfaces: Vec<Interface> = core::iter::once(vertex.interface)
            .chain(fragment.map(|shader| shader.interface))
            .collect();
        let indirect = if plan.info.indirect_bindable {
            match self.add_indirect_render(&plan, &interfaces, vulkan) {
                Ok(indirect) => Some(indirect),
                Err(error) => {
                    self.defer(Object::Pipeline(vulkan));
                    return Err(error);
                }
            }
        } else {
            None
        };
        let index = self.pipelines.render.insert(RenderObject {
            state: RenderPipelineState {
                id: 0,
                pipeline: Some(vulkan),
                plan,
                interfaces,
                indirect,
            },
            linked: alloc::vec![
                (Stage::Vertex, vertex_linked),
                (Stage::Fragment, fragment_linked)
            ],
            fragment: None,
            mesh: None,
            variants: Vec::new(),
        });
        self.pipelines.render.get_mut(index)?.state.id = u64::from(index);
        Ok(RenderPipelineId(index))
    }

    /// `newRenderPipelineStateWithMeshDescriptor:`; object and mesh stages
    /// compile per threadgroup size when drawn.
    pub fn new_mesh_render_pipeline(
        &mut self,
        request: &MeshPipelineRequest,
    ) -> Result<RenderPipelineId> {
        let linked = [
            (Stage::Object, &request.object_linked_functions),
            (Stage::Mesh, &request.mesh_linked_functions),
            (Stage::Fragment, &request.fragment_linked_functions),
        ]
        .into_iter()
        .map(|(stage, functions)| Ok((stage, self.link(functions, true)?)))
        .collect::<Result<Vec<_>>>()?;
        let pipelines = &self.pipelines;
        let fragment_function = request
            .fragment_function
            .map(|id| pipelines.interface(id))
            .transpose()?;
        let varyings = pipeline::link_varyings(
            pipelines.interface(request.mesh_function)?,
            fragment_function,
        )?;
        let fragment = match request.fragment_function {
            Some(id) => {
                let specialization = Specialization {
                    varyings: varyings.clone(),
                    linking: linked[2].1.linking.clone(),
                    ..Specialization::default()
                };
                Some(self.compile(id, specialization)?)
            }
            None => None,
        };
        let pipelines = &self.pipelines;
        let object = request
            .object_function
            .map(|id| pipelines.interface(id))
            .transpose()?;
        let mesh = pipelines.interface(request.mesh_function)?;
        let descriptor = MeshRenderPipelineDescriptor {
            object_function: object,
            mesh_function: mesh,
            fragment_function: fragment.as_ref(),
            targets: request.targets,
            max_vertex_amplification_count: request.max_vertex_amplification_count,
        };
        let interfaces: Vec<Interface> = object
            .into_iter()
            .chain([mesh])
            .cloned()
            .chain(fragment.as_ref().map(|shader| shader.interface.clone()))
            .collect();
        let plan = match pipeline::mesh_render_pipeline(&self.capabilities, &descriptor) {
            Ok(plan) => plan,
            Err(error) => {
                if let Some(fragment) = &fragment {
                    self.compiler.release(fragment.code);
                }
                return Err(error);
            }
        };
        let index = self.pipelines.render.insert(RenderObject {
            state: RenderPipelineState {
                id: 0,
                pipeline: None,
                plan,
                interfaces,
                indirect: None,
            },
            linked,
            fragment: fragment.map(|shader| shader.code),
            mesh: Some(MeshFunctions {
                object: request.object_function,
                mesh: request.mesh_function,
                varyings,
            }),
            variants: Vec::new(),
        });
        self.pipelines.render.get_mut(index)?.state.id = u64::from(index);
        Ok(RenderPipelineId(index))
    }

    pub fn render_pipeline_state(&self, id: RenderPipelineId) -> Result<&RenderPipelineState> {
        Ok(&self.pipelines.render.get(id.0)?.state)
    }

    /// The mesh pipeline for one draw's threadgroup sizes.
    pub(super) fn mesh_variant(
        &mut self,
        id: u64,
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    ) -> Result<Pipeline> {
        let index = u32::try_from(id).map_err(|_| Error::Invalid("unknown pipeline"))?;
        let render = self.pipelines.render.get(index)?;
        let key = (object_threads, mesh_threads);
        if let Some((_, pipeline)) = render.variants.iter().find(|(known, _)| *known == key) {
            return Ok(*pipeline);
        }
        let functions = render
            .mesh
            .as_ref()
            .ok_or(Error::Invalid("not a mesh pipeline"))?;
        let (object, mesh, varyings) =
            (functions.object, functions.mesh, functions.varyings.clone());
        let linking = |stage| {
            render
                .linked(stage)
                .map(|linked| linked.linking.clone())
                .unwrap_or_default()
        };
        let linkings = [linking(Stage::Object), linking(Stage::Mesh)];
        let mut info = render.state.plan.info.clone();
        let limits = &self.capabilities.limits;
        let total =
            |threads: [u32; 3]| threads.iter().map(|&size| u64::from(size)).product::<u64>();
        ensure(
            total(mesh_threads) <= limits.max_mesh_threads_per_threadgroup,
            "mesh threadgroup size",
        )?;
        ensure(
            total(object_threads) <= limits.max_total_threads_per_threadgroup,
            "object threadgroup size",
        )?;
        let mut stages = Vec::new();
        let mut codes = Vec::new();
        // The first stage is the one mesh draws launch; the mesh function
        // links to the fragment function.
        let [object_linking, mesh_linking] = linkings;
        for (function, threads, stage, varyings, linking) in [
            (
                object,
                object_threads,
                Stage::Object,
                Vec::new(),
                object_linking,
            ),
            (
                Some(mesh),
                mesh_threads,
                Stage::Mesh,
                varyings,
                mesh_linking,
            ),
        ] {
            let Some(function) = function else { continue };
            let specialization = Specialization {
                workgroup_size: Some(threads),
                varyings,
                launched_by_grid: stage == Stage::Object || object.is_none(),
                linking,
                ..Specialization::default()
            };
            match self.compile(function, specialization) {
                Ok(compiled) => {
                    codes.push(compiled.code);
                    stages.push((stage.vulkan(), compiled.code));
                }
                Err(error) => {
                    codes.iter().for_each(|code| self.compiler.release(*code));
                    return Err(error);
                }
            }
        }
        stages.extend(info.stages);
        info.stages = stages;
        let pipeline = self.backend.create_graphics_pipeline(&info);
        codes
            .into_iter()
            .for_each(|code| self.compiler.release(code));
        let pipeline = pipeline?;
        self.pipelines
            .render
            .get_mut(index)?
            .variants
            .push((key, pipeline));
        Ok(pipeline)
    }

    /// `gpuResourceID`: the handle GPU-resident indirect commands name the
    /// pipeline by, or zero when they cannot switch to it.
    pub fn render_pipeline_resource_id(&self, id: RenderPipelineId) -> Result<u64> {
        let state = &self.pipelines.render.get(id.0)?.state;
        Ok(state.indirect.map_or(0, |indirect| indirect.handle()))
    }

    pub fn destroy_render_pipeline(&mut self, id: RenderPipelineId) -> Result<()> {
        let render = self.pipelines.render.remove(id.0)?;
        let pipeline = match (render.state.indirect, render.state.pipeline) {
            (Some(indirect), Some(pipeline)) => self.remove_indirect(indirect, pipeline)?,
            (_, pipeline) => pipeline,
        };
        let variants = render.variants.into_iter().map(|(_, pipeline)| pipeline);
        for pipeline in pipeline.into_iter().chain(variants) {
            self.defer(Object::Pipeline(pipeline));
        }
        if let Some(code) = render.fragment {
            self.compiler.release(code);
        }
        Ok(())
    }

    /// `newComputePipelineStateWithDescriptor:`; variants compile per
    /// dispatch shape.
    pub fn new_compute_pipeline(
        &mut self,
        request: &ComputePipelineRequest,
    ) -> Result<ComputePipelineId> {
        let function = request.compute_function;
        let linked = self.link(&request.linked_functions, false)?;
        let interface = self.pipelines.interface(function)?.clone();
        let descriptor = ComputePipelineDescriptor {
            compute_function: &interface,
            threadgroup_size_is_multiple_of_thread_execution_width: request
                .threadgroup_size_is_multiple_of_thread_execution_width,
            max_total_threads_per_threadgroup: request.max_total_threads_per_threadgroup,
            stage_input: request.stage_input.as_ref(),
        };
        let plan = pipeline::compute_pipeline(&self.capabilities, &descriptor)?;
        let generated = self.backend.physical_device().limits.generated_commands;
        let bindable =
            generated.is_some_and(|limits| limits.pipeline_stages.contains(ShaderStages::COMPUTE));
        let indirect = if request.support_indirect_command_buffers && bindable {
            let specialization = Specialization {
                linking: linked.linking.clone(),
                ..pipeline::indirect_compute_variant(&plan)
            };
            let subgroups = (plan.thread_execution_width as u32, plan.full_subgroups);
            let pipeline =
                self.create_compute_variant(function, subgroups, specialization, true)?;
            match self.add_indirect_compute(pipeline) {
                Ok(place) => Some(IndirectCompute { pipeline, place }),
                Err(error) => {
                    self.defer(Object::Pipeline(pipeline));
                    return Err(error);
                }
            }
        } else {
            None
        };
        let state = ComputePipelineState {
            id: 0,
            plan,
            interface,
            indirect,
        };
        let index = self.pipelines.compute.insert(ComputeObject {
            state,
            function,
            linked,
            variants: Vec::new(),
        });
        self.pipelines.compute.get_mut(index)?.state.id = u64::from(index);
        Ok(ComputePipelineId(index))
    }

    pub fn compute_pipeline_state(&self, id: ComputePipelineId) -> Result<&ComputePipelineState> {
        Ok(&self.pipelines.compute.get(id.0)?.state)
    }

    /// `gpuResourceID`: the handle GPU-resident indirect commands name the
    /// pipeline by, or zero when they cannot switch to it.
    pub fn compute_pipeline_resource_id(&self, id: ComputePipelineId) -> Result<u64> {
        let state = &self.pipelines.compute.get(id.0)?.state;
        Ok(state.indirect.map_or(0, |indirect| indirect.place.handle()))
    }

    /// The compute pipeline for one dispatch's specialization.
    pub(super) fn compute_variant(
        &mut self,
        id: u64,
        specialization: &Specialization,
    ) -> Result<Pipeline> {
        let index = u32::try_from(id).map_err(|_| Error::Invalid("unknown pipeline"))?;
        let compute = self.pipelines.compute.get(index)?;
        if let Some((_, pipeline)) = compute
            .variants
            .iter()
            .find(|(known, _)| known == specialization)
        {
            return Ok(*pipeline);
        }
        let plan = &compute.state.plan;
        let (function, subgroups) = (
            compute.function,
            (plan.thread_execution_width as u32, plan.full_subgroups),
        );
        let linked = Specialization {
            linking: compute.linked.linking.clone(),
            ..specialization.clone()
        };
        let pipeline = self.create_compute_variant(function, subgroups, linked, false)?;
        self.pipelines
            .compute
            .get_mut(index)?
            .variants
            .push((specialization.clone(), pipeline));
        Ok(pipeline)
    }

    /// Compiles `function`, linked, into a compute pipeline of its
    /// `(thread execution width, full subgroups)`.
    fn create_compute_variant(
        &mut self,
        function: FunctionId,
        (width, full_subgroups): (u32, bool),
        specialization: Specialization,
        indirect_bindable: bool,
    ) -> Result<Pipeline> {
        let compiled = self.compile(function, specialization)?;
        let info = ComputePipelineInfo {
            code: compiled.code,
            required_subgroup_size: width,
            full_subgroups,
            indirect_bindable,
        };
        let pipeline = self.backend.create_compute_pipeline(&info);
        self.compiler.release(compiled.code);
        pipeline
    }

    /// `functionHandleWithFunction:` of a compute pipeline: `None` when it
    /// does not link the function.
    pub fn compute_function_handle(
        &self,
        id: ComputePipelineId,
        function: FunctionId,
    ) -> Result<Option<FunctionHandle>> {
        Ok(self.pipelines.compute.get(id.0)?.linked.handle(function))
    }

    /// `functionHandleWithFunction:stage:` of a render pipeline: `None`
    /// when the stage does not link the function.
    pub fn render_function_handle(
        &self,
        id: RenderPipelineId,
        stage: Stage,
        function: FunctionId,
    ) -> Result<Option<FunctionHandle>> {
        let render = self.pipelines.render.get(id.0)?;
        Ok(render
            .linked(stage)
            .and_then(|linked| linked.handle(function)))
    }

    /// `newVisibleFunctionTableWithDescriptor:`: a shared buffer of `count`
    /// function handles, each calling no function. It binds as the buffer
    /// at a table argument's index, and its address is its
    /// `gpuResourceID`.
    pub fn new_visible_function_table(&mut self, count: u64) -> Result<BufferId> {
        const INVALID: Error = Error::Invalid("visible function table size");
        let bytes = count
            .checked_mul(8)
            .filter(|&bytes| bytes != 0)
            .ok_or(INVALID)?;
        let zeros = alloc::vec![0; usize::try_from(bytes).map_err(|_| INVALID)?];
        self.new_shared_buffer(&zeros)
    }

    /// `setFunction:atIndex:` and `setFunctions:withRange:`: writes
    /// `handles` from entry `index` of a table; `None` calls no function.
    pub fn set_visible_functions(
        &mut self,
        table: BufferId,
        index: u64,
        handles: &[Option<FunctionHandle>],
    ) -> Result<()> {
        let (memory, offset, length) = self.buffer_memory(table)?;
        let start = index.checked_mul(8);
        let end = start.and_then(|start| start.checked_add(handles.len() as u64 * 8));
        ensure(
            end.is_some_and(|end| end <= length),
            "functions past the table's end",
        )?;
        let bytes: Vec<u8> = handles
            .iter()
            .flat_map(|handle| handle.map_or(0, |handle| handle.0).to_le_bytes())
            .collect();
        self.backend
            .write_memory(memory, offset + index * 8, &bytes)
    }

    /// Resolves a stage's linked functions, which must be visible
    /// functions; `render` stages are those of render pipelines.
    fn link(&self, linked: &LinkedFunctions, render: bool) -> Result<Linked> {
        let capabilities = &self.capabilities;
        let (function_pointers, dynamic_libraries) = if render {
            (
                capabilities.supports_function_pointers_from_render,
                capabilities.supports_render_dynamic_libraries,
            )
        } else {
            (
                capabilities.supports_function_pointers,
                capabilities.supports_dynamic_libraries,
            )
        };
        let functions = || linked.functions.iter().chain(&linked.private_functions);
        require(
            function_pointers || functions().next().is_none(),
            "function pointers",
        )?;
        require(
            dynamic_libraries || linked.libraries.is_empty(),
            "dynamic libraries",
        )?;
        for &id in functions() {
            let function = self.pipelines.functions.get(id.0)?;
            ensure(
                matches!(function.reflection, Reflection::Visible { .. }),
                "linked functions are visible functions",
            )?;
        }
        let entries = |ids: &[FunctionId]| -> Result<Vec<LinkedFunction>> {
            ids.iter()
                .map(|id| {
                    let function = self.pipelines.functions.get(id.0)?;
                    let mut constants = function.constants.clone();
                    constants.sort_unstable_by_key(|&(index, _)| index);
                    Ok(LinkedFunction {
                        library: function.library,
                        entry: function.entry.clone(),
                        constants,
                    })
                })
                .collect()
        };
        Ok(Linked {
            functions: linked.functions.clone(),
            linking: Linking {
                functions: entries(&linked.functions)?,
                private_functions: entries(&linked.private_functions)?,
                libraries: linked.libraries.clone(),
                max_call_stack_depth: linked.max_call_stack_depth,
            },
        })
    }

    pub fn destroy_compute_pipeline(&mut self, id: ComputePipelineId) -> Result<()> {
        let compute = self.pipelines.compute.remove(id.0)?;
        let indirect = match compute.state.indirect {
            Some(indirect) => self.remove_indirect(indirect.place, indirect.pipeline)?,
            None => None,
        };
        let variants = compute.variants.into_iter().map(|(_, pipeline)| pipeline);
        for pipeline in indirect.into_iter().chain(variants) {
            self.defer(Object::Pipeline(pipeline));
        }
        Ok(())
    }
}
