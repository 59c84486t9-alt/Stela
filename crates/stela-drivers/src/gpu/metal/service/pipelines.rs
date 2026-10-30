//! Render, mesh and compute pipelines, their function handles and visible
//! function tables.
use super::{
    Call, GuestMemory, Object, Service, boolean, known,
    resources::pixel_format,
    wire::{
        self, AttributeRecord, ColorAttachmentRecord, ComputePipelineResponse, Empty, Fault,
        FunctionHandleRequest, FunctionHandleResponse, LayoutRecord, LinkedFunctionsRecord,
        NewComputePipelineRequest, NewFunctionTableRequest, NewMeshPipelineRequest,
        NewRenderPipelineRequest, PipelineFlags, RenderPipelineResponse, RenderTargetsRecord,
        SetFunctionsRequest, Status, TessellationRecord,
    },
};
use crate::gpu::metal::{
    abi::{
        BlendFactor, BlendOperation, ColorWriteMask, IndexType, PrimitiveTopologyClass,
        TessellationControlPointIndexType, TessellationFactorFormat,
        TessellationFactorStepFunction, TessellationPartitionMode, Winding,
    },
    device::{
        BufferId, FunctionId, LibraryId, RenderPipelineId,
        pipelines::{
            ComputePipelineRequest, FunctionHandle, LinkedFunctions, MeshPipelineRequest,
            RenderPipelineRequest,
        },
    },
    pipeline::{ColorAttachmentDescriptor, RenderTargets, TessellationDescriptor},
    pixel_format::PixelFormat,
    shader::{Compiler, Stage},
    vertex::{
        Attribute, Layout, StageInLayout, StageInStep, StageInputDescriptor, StepFunction,
        VertexDescriptor, VertexFormat,
    },
    vulkan::backend::Backend,
};
use alloc::vec::Vec;
use core::num::NonZeroU64;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn new_render_pipeline(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewRenderPipelineRequest = call.request()?;
        let flags = flags(request.flags)?;
        let connection = call.connection;
        let memory = &*call.memory;
        let pipeline = RenderPipelineRequest {
            vertex_function: self.object(connection, request.vertex_function)?,
            fragment_function: self.optional(connection, request.fragment_function)?,
            vertex_descriptor: flags
                .contains(PipelineFlags::DESCRIBED_INPUT)
                .then(|| vertex_descriptor(&request.vertex_descriptor))
                .transpose()?,
            targets: render_targets(&request.targets)?,
            input_primitive_topology: known(
                PrimitiveTopologyClass::from_raw(request.input_primitive_topology),
                "primitive topology class",
            )?,
            max_vertex_amplification_count: request.max_vertex_amplification_count,
            tessellation: tessellation(&request.tessellation)?,
            vertex_linked_functions: self.linked(
                connection,
                memory,
                &request.vertex_linked_functions,
            )?,
            fragment_linked_functions: self.linked(
                connection,
                memory,
                &request.fragment_linked_functions,
            )?,
            support_indirect_command_buffers: flags
                .contains(PipelineFlags::INDIRECT_COMMAND_BUFFERS),
        };
        let pipeline = self.device.new_render_pipeline(&pipeline)?;
        self.adopt_render_pipeline(call, pipeline)
    }

    pub(super) fn new_mesh_pipeline(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewMeshPipelineRequest = call.request()?;
        let connection = call.connection;
        let memory = &*call.memory;
        let pipeline = MeshPipelineRequest {
            object_function: self.optional(connection, request.object_function)?,
            mesh_function: self.object(connection, request.mesh_function)?,
            fragment_function: self.optional(connection, request.fragment_function)?,
            targets: render_targets(&request.targets)?,
            max_vertex_amplification_count: request.max_vertex_amplification_count,
            object_linked_functions: self.linked(
                connection,
                memory,
                &request.object_linked_functions,
            )?,
            mesh_linked_functions: self.linked(
                connection,
                memory,
                &request.mesh_linked_functions,
            )?,
            fragment_linked_functions: self.linked(
                connection,
                memory,
                &request.fragment_linked_functions,
            )?,
        };
        let pipeline = self.device.new_mesh_render_pipeline(&pipeline)?;
        self.adopt_render_pipeline(call, pipeline)
    }

    pub(super) fn new_compute_pipeline(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewComputePipelineRequest = call.request()?;
        let flags = flags(request.flags)?;
        let connection = call.connection;
        let pipeline = ComputePipelineRequest {
            compute_function: self.object(connection, request.compute_function)?,
            threadgroup_size_is_multiple_of_thread_execution_width: flags
                .contains(PipelineFlags::THREADGROUP_SIZE_IS_MULTIPLE_OF_WIDTH),
            max_total_threads_per_threadgroup: request.max_total_threads_per_threadgroup,
            stage_input: flags
                .contains(PipelineFlags::DESCRIBED_INPUT)
                .then(|| stage_input(&request))
                .transpose()?,
            linked_functions: self.linked(connection, &*call.memory, &request.linked_functions)?,
            support_indirect_command_buffers: flags
                .contains(PipelineFlags::INDIRECT_COMMAND_BUFFERS),
        };
        let pipeline = self.device.new_compute_pipeline(&pipeline)?;
        let object = Object::ComputePipeline(pipeline);
        let (handle, response) = self.adopt(connection, object, |device| {
            let plan = &device.compute_pipeline_state(pipeline)?.plan;
            Ok(ComputePipelineResponse {
                handle: 0,
                resource_id: device.compute_pipeline_resource_id(pipeline)?,
                max_total_threads_per_threadgroup: plan.max_total_threads_per_threadgroup,
                thread_execution_width: plan.thread_execution_width,
                static_threadgroup_memory_length: plan.static_threadgroup_memory_length,
            })
        })?;
        call.reply(&ComputePipelineResponse {
            handle: handle.handle,
            ..response
        })
    }

    pub(super) fn function_handle(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: FunctionHandleRequest = call.request()?;
        let function = self.object::<FunctionId>(call.connection, request.function)?;
        let handle = match (
            self.entry(call.connection, request.pipeline)?,
            request.stage,
        ) {
            (Object::ComputePipeline(pipeline), 0) => {
                self.device.compute_function_handle(pipeline, function)?
            }
            (Object::RenderPipeline(pipeline), stage) => {
                let stage = render_stage(stage)?;
                self.device
                    .render_function_handle(pipeline, stage, function)?
            }
            (Object::ComputePipeline(_), _) => {
                return Err(Fault::malformed("render stage of a compute pipeline"));
            }
            _ => return Err(Fault::STALE),
        };
        call.reply(&FunctionHandleResponse {
            value: handle.map_or(0, |handle| handle.0),
        })
    }

    pub(super) fn new_function_table(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewFunctionTableRequest = call.request()?;
        let table = self
            .device
            .new_visible_function_table(request.function_count)?;
        let response = self.adopt_buffer(call.connection, table)?;
        call.reply(&response)
    }

    pub(super) fn set_functions(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: SetFunctionsRequest = call.request()?;
        let table = self.object::<BufferId>(call.connection, request.table)?;
        let handles: Vec<Option<FunctionHandle>> =
            wire::read_array::<u64>(call.memory.read(request.handles)?)?
                .into_iter()
                .map(|value| (value != 0).then_some(FunctionHandle(value)))
                .collect();
        self.device
            .set_visible_functions(table, request.index, &handles)?;
        call.reply(&Empty {})
    }

    fn adopt_render_pipeline(
        &mut self,
        call: &mut Call,
        pipeline: RenderPipelineId,
    ) -> Result<(), Fault> {
        let object = Object::RenderPipeline(pipeline);
        let (handle, resource_id) = self.adopt(call.connection, object, |device| {
            device.render_pipeline_resource_id(pipeline)
        })?;
        call.reply(&RenderPipelineResponse {
            handle: handle.handle,
            resource_id,
        })
    }

    /// The function a nonzero handle names.
    fn optional(&self, connection: NonZeroU64, handle: u64) -> Result<Option<FunctionId>, Fault> {
        (handle != 0)
            .then(|| self.object(connection, handle))
            .transpose()
    }

    fn linked(
        &self,
        connection: NonZeroU64,
        memory: &dyn GuestMemory,
        record: &LinkedFunctionsRecord,
    ) -> Result<LinkedFunctions, Fault> {
        let objects = |span| -> Result<Vec<u64>, Fault> { wire::read_array(memory.read(span)?) };
        let functions = |span| {
            objects(span)?
                .into_iter()
                .map(|handle| self.object::<FunctionId>(connection, handle))
                .collect::<Result<Vec<_>, Fault>>()
        };
        Ok(LinkedFunctions {
            functions: functions(record.functions)?,
            private_functions: functions(record.private_functions)?,
            libraries: objects(record.libraries)?
                .into_iter()
                .map(|handle| self.object::<LibraryId>(connection, handle))
                .collect::<Result<_, _>>()?,
            max_call_stack_depth: u32::try_from(record.max_call_stack_depth)
                .map_err(|_| Fault::malformed("call stack depth"))?,
        })
    }
}

fn flags(raw: u64) -> Result<PipelineFlags, Fault> {
    known(PipelineFlags::from_bits(raw), "pipeline flags")
}

/// A pixel format, none for zero.
fn optional_format(raw: u64) -> Result<Option<PixelFormat>, Fault> {
    (raw != 0).then(|| pixel_format(raw)).transpose()
}

/// One bit of `MTLRenderStages`.
/// The stage of one `MTLRenderStages` bit.
pub(super) fn render_stage(raw: u64) -> Result<Stage, Fault> {
    match raw {
        1 => Ok(Stage::Vertex),
        2 => Ok(Stage::Fragment),
        4 => Err(Fault::new(Status::Unsupported, "tile functions")),
        8 => Ok(Stage::Object),
        16 => Ok(Stage::Mesh),
        _ => Err(Fault::malformed("render stage")),
    }
}

fn render_targets(record: &RenderTargetsRecord) -> Result<RenderTargets, Fault> {
    let mut targets = RenderTargets::default();
    for (attachment, record) in targets
        .color_attachments
        .iter_mut()
        .zip(&record.color_attachments)
    {
        *attachment = color_attachment(record)?;
    }
    Ok(RenderTargets {
        depth_attachment_pixel_format: optional_format(record.depth_attachment_pixel_format)?,
        stencil_attachment_pixel_format: optional_format(record.stencil_attachment_pixel_format)?,
        raster_sample_count: record.raster_sample_count,
        alpha_to_coverage_enabled: boolean(record.alpha_to_coverage_enabled)?,
        alpha_to_one_enabled: boolean(record.alpha_to_one_enabled)?,
        rasterization_enabled: boolean(record.rasterization_enabled)?,
        ..targets
    })
}

fn color_attachment(record: &ColorAttachmentRecord) -> Result<ColorAttachmentDescriptor, Fault> {
    let factor = |raw| known(BlendFactor::from_raw(raw), "blend factor");
    let operation = |raw| known(BlendOperation::from_raw(raw), "blend operation");
    Ok(ColorAttachmentDescriptor {
        pixel_format: optional_format(record.pixel_format)?,
        blending_enabled: boolean(record.blending_enabled)?,
        source_rgb_blend_factor: factor(record.source_rgb_blend_factor)?,
        destination_rgb_blend_factor: factor(record.destination_rgb_blend_factor)?,
        rgb_blend_operation: operation(record.rgb_blend_operation)?,
        source_alpha_blend_factor: factor(record.source_alpha_blend_factor)?,
        destination_alpha_blend_factor: factor(record.destination_alpha_blend_factor)?,
        alpha_blend_operation: operation(record.alpha_blend_operation)?,
        write_mask: known(
            ColorWriteMask::from_bits(record.write_mask),
            "color write mask",
        )?,
    })
}

fn tessellation(record: &TessellationRecord) -> Result<TessellationDescriptor, Fault> {
    Ok(TessellationDescriptor {
        partition_mode: known(
            TessellationPartitionMode::from_raw(record.partition_mode),
            "tessellation partition mode",
        )?,
        max_tessellation_factor: record.max_tessellation_factor,
        factor_scale_enabled: boolean(record.factor_scale_enabled)?,
        factor_format: known(
            TessellationFactorFormat::from_raw(record.factor_format),
            "tessellation factor format",
        )?,
        control_point_index_type: known(
            TessellationControlPointIndexType::from_raw(record.control_point_index_type),
            "control point index type",
        )?,
        factor_step_function: known(
            TessellationFactorStepFunction::from_raw(record.factor_step_function),
            "tessellation factor step function",
        )?,
        output_winding_order: known(Winding::from_raw(record.output_winding_order), "winding")?,
    })
}

/// The attributes a descriptor sets, and the indices of the buffers they
/// read, each once in order.
fn attributes(records: &[AttributeRecord; 31]) -> Result<(Vec<Attribute>, Vec<u32>), Fault> {
    let mut attributes = Vec::new();
    let mut buffers = Vec::new();
    for (index, record) in (0u32..).zip(records) {
        if record.format == 0 {
            continue;
        }
        let buffer_index = u32::try_from(record.buffer_index)
            .ok()
            .filter(|&buffer| buffer < 31)
            .ok_or(Fault::malformed("attribute buffer index"))?;
        attributes.push(Attribute {
            index,
            format: known(VertexFormat::from_raw(record.format), "vertex format")?,
            offset: record.offset,
            buffer_index,
        });
        if !buffers.contains(&buffer_index) {
            buffers.push(buffer_index);
        }
    }
    buffers.sort_unstable();
    Ok((attributes, buffers))
}

fn vertex_descriptor(record: &wire::VertexDescriptorRecord) -> Result<VertexDescriptor, Fault> {
    let (attributes, buffers) = attributes(&record.attributes)?;
    let layouts = buffers
        .into_iter()
        .map(|buffer_index| {
            let LayoutRecord {
                stride,
                step_function,
                step_rate,
            } = record.layouts[buffer_index as usize];
            Ok(Layout {
                buffer_index,
                stride,
                step_function: known(StepFunction::from_raw(step_function), "step function")?,
                step_rate,
            })
        })
        .collect::<Result<_, Fault>>()?;
    Ok(VertexDescriptor {
        attributes,
        layouts,
    })
}

fn stage_input(request: &NewComputePipelineRequest) -> Result<StageInputDescriptor, Fault> {
    let record = &request.stage_input;
    let (attributes, buffers) = attributes(&record.attributes)?;
    let layouts = buffers
        .into_iter()
        .map(|buffer_index| {
            let layout = record.layouts[buffer_index as usize];
            Ok(StageInLayout {
                buffer_index,
                stride: layout.stride,
                step_function: known(
                    StageInStep::from_raw(layout.step_function),
                    "stage-in step function",
                )?,
                step_rate: layout.step_rate,
            })
        })
        .collect::<Result<_, Fault>>()?;
    Ok(StageInputDescriptor {
        attributes,
        layouts,
        index_type: known(IndexType::from_raw(record.index_type), "index type")?,
        index_buffer_index: u32::try_from(record.index_buffer_index)
            .map_err(|_| Fault::malformed("index buffer index"))?,
    })
}
