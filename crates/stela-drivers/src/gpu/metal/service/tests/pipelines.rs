use super::{Memory, TestService, call, connect, new_function, new_library, service, status};
use crate::gpu::metal::{
    abi::{
        BlendFactor, BlendOperation, ColorWriteMask, PrimitiveTopologyClass,
        TessellationControlPointIndexType, TessellationFactorFormat,
        TessellationFactorStepFunction, TessellationPartitionMode, Winding,
    },
    pixel_format::PixelFormat,
    service::wire::{
        BufferResponse, ColorAttachmentRecord, ComputePipelineResponse, Empty,
        FunctionHandleRequest, FunctionHandleResponse, Handle, LinkedFunctionsRecord,
        NewComputePipelineRequest, NewFunctionTableRequest, NewRenderPipelineRequest, Operation,
        PipelineFlags, RenderPipelineResponse, RenderTargetsRecord, SetFunctionsRequest, Span,
        Status, TessellationRecord,
    },
};
use core::num::NonZeroU64;

/// Links `functions` with Metal's default call stack depth.
fn linked(memory: &mut Memory, functions: &[u64]) -> LinkedFunctionsRecord {
    LinkedFunctionsRecord {
        functions: memory.records(functions),
        private_functions: Span::default(),
        libraries: Span::default(),
        max_call_stack_depth: 1,
    }
}

fn compute_pipeline(
    service: &mut TestService,
    connection: NonZeroU64,
    function: u64,
    linked_functions: LinkedFunctionsRecord,
    flags: u64,
    memory: &mut Memory,
) -> Result<ComputePipelineResponse, super::Outcome> {
    let request = NewComputePipelineRequest {
        compute_function: function,
        max_total_threads_per_threadgroup: 0,
        stage_input: Default::default(),
        linked_functions,
        flags,
    };
    call(
        service,
        connection,
        Operation::NewComputePipeline,
        &request,
        memory,
    )
}

fn handle(
    service: &mut TestService,
    connection: NonZeroU64,
    pipeline: u64,
    function: u64,
    stage: u64,
) -> Result<FunctionHandleResponse, super::Outcome> {
    let request = FunctionHandleRequest {
        pipeline,
        function,
        stage,
    };
    call(
        service,
        connection,
        Operation::FunctionHandle,
        &request,
        &mut Memory::default(),
    )
}

#[test]
fn compute_pipelines_link_functions_and_answer_their_handles() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let mut function = |name| {
        new_function(&mut service, connection, library, name, &[], memory)
            .unwrap()
            .handle
    };
    let (kernel, visible) = (function("kernel"), function("visible"));
    let functions = linked(memory, &[visible]);
    let pipeline =
        compute_pipeline(&mut service, connection, kernel, functions, 0, memory).unwrap();
    assert_eq!(pipeline.thread_execution_width, 32);
    assert_eq!(pipeline.resource_id, 0, "not for indirect command buffers");
    assert_eq!(
        handle(&mut service, connection, pipeline.handle, visible, 0),
        Ok(FunctionHandleResponse { value: 1 })
    );
    assert_eq!(
        handle(&mut service, connection, pipeline.handle, kernel, 0),
        Ok(FunctionHandleResponse { value: 0 })
    );
    assert_eq!(
        status(handle(
            &mut service,
            connection,
            pipeline.handle,
            visible,
            1
        )),
        Status::Malformed
    );
    assert_eq!(
        status(compute_pipeline(
            &mut service,
            connection,
            kernel,
            LinkedFunctionsRecord::default(),
            1 << 40,
            memory,
        )),
        Status::Malformed
    );

    // A visible function table holds handle values.
    let table: BufferResponse = call(
        &mut service,
        connection,
        Operation::NewFunctionTable,
        &NewFunctionTableRequest { function_count: 4 },
        memory,
    )
    .unwrap();
    assert_ne!(table.gpu_address, 0);
    let set = SetFunctionsRequest {
        table: table.handle,
        index: 2,
        handles: memory.records(&[1u64, 0]),
    };
    call::<_, Empty>(
        &mut service,
        connection,
        Operation::SetFunctions,
        &set,
        memory,
    )
    .unwrap();
    let past = SetFunctionsRequest { index: 3, ..set };
    assert_eq!(
        status(call::<_, Empty>(
            &mut service,
            connection,
            Operation::SetFunctions,
            &past,
            memory
        )),
        Status::Invalid
    );

    // The pipeline keeps the functions its descriptor named.
    let release = |service: &mut TestService, handle| {
        status(call::<_, Empty>(
            service,
            connection,
            Operation::Release,
            &Handle { handle },
            &mut Memory::default(),
        ))
    };
    assert_eq!(release(&mut service, kernel), Status::Ok);
    assert_eq!(release(&mut service, visible), Status::Ok);
    assert_eq!(release(&mut service, library), Status::Ok);
    assert_eq!(
        handle(&mut service, connection, pipeline.handle, visible, 0).map_err(|o| o.status),
        Err(Status::StaleHandle)
    );
    assert_eq!(release(&mut service, pipeline.handle), Status::Ok);
}

#[test]
fn render_pipelines_decode_their_targets_and_stages() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let mut function = |name| {
        new_function(&mut service, connection, library, name, &[], memory)
            .unwrap()
            .handle
    };
    let (vertex, fragment, visible) = (
        function("vertex"),
        function("fragment"),
        function("visible"),
    );
    let unused = ColorAttachmentRecord {
        pixel_format: 0,
        source_rgb_blend_factor: BlendFactor::One.raw(),
        destination_rgb_blend_factor: BlendFactor::Zero.raw(),
        rgb_blend_operation: BlendOperation::Add.raw(),
        source_alpha_blend_factor: BlendFactor::One.raw(),
        destination_alpha_blend_factor: BlendFactor::Zero.raw(),
        alpha_blend_operation: BlendOperation::Add.raw(),
        write_mask: ColorWriteMask::KNOWN.bits(),
        blending_enabled: 0,
        reserved: 0,
    };
    let mut targets = RenderTargetsRecord {
        color_attachments: [unused; 8],
        raster_sample_count: 1,
        rasterization_enabled: 1,
        ..RenderTargetsRecord::default()
    };
    targets.color_attachments[0].pixel_format = PixelFormat::Rgba8Unorm.raw();
    let request = NewRenderPipelineRequest {
        vertex_function: vertex,
        fragment_function: fragment,
        input_primitive_topology: PrimitiveTopologyClass::Unspecified.raw(),
        max_vertex_amplification_count: 1,
        targets,
        vertex_descriptor: Default::default(),
        tessellation: TessellationRecord {
            partition_mode: TessellationPartitionMode::Pow2.raw(),
            max_tessellation_factor: 16,
            factor_format: TessellationFactorFormat::Half.raw(),
            control_point_index_type: TessellationControlPointIndexType::None.raw(),
            factor_step_function: TessellationFactorStepFunction::Constant.raw(),
            output_winding_order: Winding::Clockwise.raw(),
            factor_scale_enabled: 0,
            reserved: 0,
        },
        vertex_linked_functions: LinkedFunctionsRecord::default(),
        fragment_linked_functions: linked(memory, &[visible]),
        flags: PipelineFlags::EMPTY.bits(),
    };
    let pipeline: RenderPipelineResponse = call(
        &mut service,
        connection,
        Operation::NewRenderPipeline,
        &request,
        memory,
    )
    .unwrap();
    // MTLRenderStageFragment, then MTLRenderStageVertex.
    assert_eq!(
        handle(&mut service, connection, pipeline.handle, visible, 2),
        Ok(FunctionHandleResponse { value: 1 })
    );
    assert_eq!(
        handle(&mut service, connection, pipeline.handle, visible, 1),
        Ok(FunctionHandleResponse { value: 0 })
    );
    assert_eq!(
        status(handle(
            &mut service,
            connection,
            pipeline.handle,
            visible,
            4
        )),
        Status::Malformed
    );

    let mut masked = request;
    masked.targets.color_attachments[0].write_mask = 1 << 4;
    assert_eq!(
        status(call::<_, RenderPipelineResponse>(
            &mut service,
            connection,
            Operation::NewRenderPipeline,
            &masked,
            memory,
        )),
        Status::Malformed
    );
    let mut wrong = request;
    wrong.fragment_function = pipeline.handle;
    assert_eq!(
        status(call::<_, RenderPipelineResponse>(
            &mut service,
            connection,
            Operation::NewRenderPipeline,
            &wrong,
            memory,
        )),
        Status::StaleHandle
    );
}
