use super::{
    GuestMemory, Memory, TestService, call, connect, new_function, new_library,
    render_pipeline_request, service, status,
};
use crate::metal::service::wire::{
    ArchiveDataRequest, BufferResponse, ComputePipelineResponse, Empty, FunctionHandleRequest,
    FunctionHandleResponse, Handle, Length, LinkedFunctionsRecord, NewArchiveRequest,
    NewComputePipelineRequest, NewFunctionTableRequest, NewRenderPipelineRequest,
    NewStitchedLibraryRequest, Operation, PipelineArchivesRecord, RenderPipelineResponse,
    SetFunctionsRequest, Span, Status,
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
        archives: Default::default(),
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

#[test]
fn archives_read_back_and_answer_for_pipelines() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let kernel = new_function(&mut service, connection, library, "kernel", &[], memory)
        .unwrap()
        .handle;
    let data = memory.put(&[]);
    let archive = call::<_, Handle>(
        &mut service,
        connection,
        Operation::NewArchive,
        &NewArchiveRequest { data },
        memory,
    )
    .unwrap()
    .handle;

    let mut create = |memory: &mut Memory, searched: &[u64], added_to, required| {
        let request = NewComputePipelineRequest {
            compute_function: kernel,
            archives: PipelineArchivesRecord {
                searched: memory.records(searched),
                added_to,
                required,
            },
            ..Default::default()
        };
        status::<ComputePipelineResponse>(call(
            &mut service,
            connection,
            Operation::NewComputePipeline,
            &request,
            memory,
        ))
    };
    assert_eq!(create(memory, &[archive], 0, 1), Status::Invalid);
    assert_eq!(create(memory, &[], archive, 0), Status::Ok);
    assert_eq!(create(memory, &[archive], 0, 1), Status::Ok);

    let out = memory.put(&[0; 4]);
    let length: Length = call(
        &mut service,
        connection,
        Operation::ArchiveData,
        &ArchiveDataRequest { archive, out },
        memory,
    )
    .unwrap();
    assert_eq!(length.length, 1);
    assert_eq!(memory.read(out).unwrap(), [1, 0, 0, 0]);
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
fn stitched_libraries_take_visible_functions() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let mut function = |library, name| {
        new_function(&mut service, connection, library, name, &[], memory)
            .unwrap()
            .handle
    };
    let (kernel, visible) = (function(library, "kernel"), function(library, "visible"));
    // `f(a) = visible(a)`.
    let words = [1u32, 2, 2, 0x66, 0, 0, 1, 1, 0];
    let graphs: alloc::vec::Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let graphs = memory.put(&graphs);
    let mut stitched = |functions: &[u64], memory: &mut Memory| {
        let request = NewStitchedLibraryRequest {
            functions: memory.records(functions),
            graphs,
        };
        call::<_, Handle>(
            &mut service,
            connection,
            Operation::NewStitchedLibrary,
            &request,
            memory,
        )
    };
    assert_eq!(status(stitched(&[kernel], memory)), Status::Invalid);
    let stitched = stitched(&[visible], memory).unwrap().handle;

    let function = new_function(&mut service, connection, stitched, "visible", &[], memory)
        .unwrap()
        .handle;
    let linked = linked(memory, &[function]);
    compute_pipeline(&mut service, connection, kernel, linked, 0, memory).unwrap();
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
    let request = NewRenderPipelineRequest {
        fragment_linked_functions: linked(memory, &[visible]),
        ..render_pipeline_request(vertex, fragment)
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
    let stage = |service: &mut TestService, stage| {
        status(handle(service, connection, pipeline.handle, visible, stage))
    };
    assert_eq!(
        stage(&mut service, 4),
        Status::Unsupported,
        "tile functions"
    );
    assert_eq!(stage(&mut service, 3), Status::Malformed, "two stages");

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
