//! Functions and pipeline states, with their compiled variants.
use super::{ComputePipelineId, Device, FunctionId, RenderPipelineId, Slab};
use crate::gpu::metal::{
    abi::PrimitiveTopologyClass,
    command_buffer::{ComputePipelineState, RenderPipelineState},
    error::{Error, Result, ensure},
    pipeline::{
        self, ComputePipelineDescriptor, MeshRenderPipelineDescriptor, RenderPipelineDescriptor,
        RenderTargets, TessellatedVertex, TessellationDescriptor,
    },
    shader::{
        CompiledShader, Compiler, Interface, Specialization, Stage, Tessellation,
        TessellationStages, Varying,
    },
    vertex::{StageInputDescriptor, VertexDescriptor},
    vulkan::{
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
    interface: Interface,
}

#[derive(Debug)]
struct RenderObject {
    state: RenderPipelineState,
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
    variants: Vec<(Specialization, Pipeline)>,
}

#[derive(Debug, Default)]
pub(super) struct Pipelines {
    functions: Slab<FunctionObject>,
    render: Slab<RenderObject>,
    compute: Slab<ComputeObject>,
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
}

/// `MTLComputePipelineDescriptor` with the device's function id.
#[derive(Clone, Debug)]
pub struct ComputePipelineRequest {
    pub compute_function: FunctionId,
    pub threadgroup_size_is_multiple_of_thread_execution_width: bool,
    /// Zero leaves the device's limit.
    pub max_total_threads_per_threadgroup: u64,
    pub stage_input: Option<StageInputDescriptor>,
}

/// `MTLMeshRenderPipelineDescriptor` with the device's function ids.
#[derive(Clone, Debug)]
pub struct MeshPipelineRequest {
    pub object_function: Option<FunctionId>,
    pub mesh_function: FunctionId,
    pub fragment_function: Option<FunctionId>,
    pub targets: RenderTargets,
    pub max_vertex_amplification_count: u64,
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
        let interface = self.compiler.reflect(library, entry, &specialization)?;
        interface.validate()?;
        let function = FunctionObject {
            library,
            entry: String::from(entry),
            constants,
            interface,
        };
        Ok(FunctionId(self.pipelines.functions.insert(function)))
    }

    pub fn function_interface(&self, id: FunctionId) -> Result<&Interface> {
        Ok(&self.pipelines.functions.get(id.0)?.interface)
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
        let specialization = Specialization {
            constants: function.constants.clone(),
            ..specialization
        };
        let compiled = self
            .compiler
            .compile(function.library, &function.entry, &specialization)?;
        if compiled.interface.stage != function.interface.stage {
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
        if (interface.stage, interface.patch)
            != (function.interface.stage, function.interface.patch)
        {
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
        let functions = &self.pipelines.functions;
        let function = &functions.get(request.vertex_function.0)?.interface;
        let fragment_function = request
            .fragment_function
            .map(|id| functions.get(id.0).map(|fragment| &fragment.interface))
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
        // The driver compiles the NIR into the pipeline, which outlives it.
        let created = pipeline::render_pipeline(&self.capabilities, &descriptor)
            .and_then(|plan| Ok((self.backend.create_graphics_pipeline(&plan.info)?, plan)));
        codes.iter().for_each(|code| self.compiler.release(*code));
        let (vulkan, plan) = created?;
        let interfaces = core::iter::once(vertex.interface)
            .chain(fragment.map(|shader| shader.interface))
            .collect();
        let index = self.pipelines.render.insert(RenderObject {
            state: RenderPipelineState {
                id: 0,
                pipeline: Some(vulkan),
                plan,
                interfaces,
            },
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
        let functions = &self.pipelines.functions;
        let fragment_function = request
            .fragment_function
            .map(|id| functions.get(id.0).map(|fragment| &fragment.interface))
            .transpose()?;
        let varyings = pipeline::link_varyings(
            &functions.get(request.mesh_function.0)?.interface,
            fragment_function,
        )?;
        let fragment = match request.fragment_function {
            Some(id) => {
                let specialization = Specialization {
                    varyings: varyings.clone(),
                    ..Specialization::default()
                };
                Some(self.compile(id, specialization)?)
            }
            None => None,
        };
        let functions = &self.pipelines.functions;
        let object = request
            .object_function
            .map(|id| functions.get(id.0).map(|function| &function.interface))
            .transpose()?;
        let mesh = &functions.get(request.mesh_function.0)?.interface;
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
            },
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
        for (function, threads, stage, varyings) in [
            (object, object_threads, Stage::Object, Vec::new()),
            (Some(mesh), mesh_threads, Stage::Mesh, varyings),
        ] {
            let Some(function) = function else { continue };
            let specialization = Specialization {
                workgroup_size: Some(threads),
                varyings,
                launched_by_grid: stage == Stage::Object || object.is_none(),
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

    pub fn destroy_render_pipeline(&mut self, id: RenderPipelineId) -> Result<()> {
        let render = self.pipelines.render.remove(id.0)?;
        let variants = render.variants.into_iter().map(|(_, pipeline)| pipeline);
        for pipeline in render.state.pipeline.into_iter().chain(variants) {
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
        let interface = self.pipelines.functions.get(function.0)?.interface.clone();
        let descriptor = ComputePipelineDescriptor {
            compute_function: &interface,
            threadgroup_size_is_multiple_of_thread_execution_width: request
                .threadgroup_size_is_multiple_of_thread_execution_width,
            max_total_threads_per_threadgroup: request.max_total_threads_per_threadgroup,
            stage_input: request.stage_input.as_ref(),
        };
        let plan = pipeline::compute_pipeline(&self.capabilities, &descriptor)?;
        let state = ComputePipelineState {
            id: 0,
            plan,
            interface,
        };
        let index = self.pipelines.compute.insert(ComputeObject {
            state,
            function,
            variants: Vec::new(),
        });
        self.pipelines.compute.get_mut(index)?.state.id = u64::from(index);
        Ok(ComputePipelineId(index))
    }

    pub fn compute_pipeline_state(&self, id: ComputePipelineId) -> Result<&ComputePipelineState> {
        Ok(&self.pipelines.compute.get(id.0)?.state)
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
        let (function, width, full_subgroups) = (
            compute.function,
            plan.thread_execution_width as u32,
            plan.full_subgroups,
        );
        let compiled = self.compile(function, specialization.clone())?;
        let info = ComputePipelineInfo {
            code: compiled.code,
            required_subgroup_size: width,
            full_subgroups,
        };
        let pipeline = self.backend.create_compute_pipeline(&info);
        self.compiler.release(compiled.code);
        let pipeline = pipeline?;
        self.pipelines
            .compute
            .get_mut(index)?
            .variants
            .push((specialization.clone(), pipeline));
        Ok(pipeline)
    }

    pub fn destroy_compute_pipeline(&mut self, id: ComputePipelineId) -> Result<()> {
        let compute = self.pipelines.compute.remove(id.0)?;
        for (_, pipeline) in compute.variants {
            self.defer(Object::Pipeline(pipeline));
        }
        Ok(())
    }
}
