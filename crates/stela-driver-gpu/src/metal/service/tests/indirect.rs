use super::{
    Memory, Outcome, Stream, TestService, call, commit, connect, new_buffer, new_function,
    new_library, service, status, submitted,
};
use crate::metal::{
    abi::{DispatchType, IndirectCommandType, StorageMode},
    service::wire::{
        self, ComputePipelineResponse, Empty, EncodeIndirectRequest, Handle, IndirectInherits,
        NewComputePipelineRequest, NewIndirectRequest, Operation, PipelineFlags, Record, Status,
        Value,
        commands::{
            BeginCompute, ComputeCode, Dispatch, IndirectCode, IndirectComputeCode, IndirectRange,
            IndirectTarget, SetBuffer, SetPipeline,
        },
    },
    vulkan::command::Command,
};
use core::num::NonZeroU64;

/// An encoding entry for command `command`: its target, then `record`.
fn encode<T: Record>(stream: &mut Stream, code: u32, command: u64, record: &T) {
    stream.entry(
        code,
        &[
            wire::bytes(&IndirectTarget { command }),
            wire::bytes(record),
        ],
    );
}

fn new_indirect(
    service: &mut TestService,
    connection: NonZeroU64,
    request: &NewIndirectRequest,
) -> Result<Handle, Outcome> {
    call(
        service,
        connection,
        Operation::NewIndirectCommandBuffer,
        request,
        &mut Memory::default(),
    )
}

#[test]
fn indirect_compute_commands_encode_and_execute() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let kernel = new_function(&mut service, connection, library, "kernel", &[], memory)
        .unwrap()
        .handle;
    let request = NewComputePipelineRequest {
        compute_function: kernel,
        archives: Default::default(),
        flags: PipelineFlags::INDIRECT_COMMAND_BUFFERS.bits(),
        ..Default::default()
    };
    let pipeline: ComputePipelineResponse = call(
        &mut service,
        connection,
        Operation::NewComputePipeline,
        &request,
        memory,
    )
    .unwrap();
    let buffer = new_buffer(&mut service, connection, StorageMode::Shared);
    let descriptor = NewIndirectRequest {
        command_types: IndirectCommandType::CONCURRENT_DISPATCH.bits(),
        max_command_count: 2,
        max_kernel_buffer_bind_count: 1,
        ..Default::default()
    };
    let icb = new_indirect(&mut service, connection, &descriptor).unwrap();

    let mut entries = Stream::default();
    let set_buffer = SetBuffer {
        buffer,
        offset: 0,
        index: 0,
    };
    let dispatch = Dispatch {
        size: [2, 1, 1],
        threads: [32, 1, 1],
    };
    encode(
        &mut entries,
        IndirectComputeCode::SetPipeline.raw(),
        0,
        &SetPipeline {
            pipeline: pipeline.handle,
        },
    );
    encode(
        &mut entries,
        IndirectComputeCode::SetBuffer.raw(),
        0,
        &set_buffer,
    );
    encode(
        &mut entries,
        IndirectComputeCode::DispatchThreadgroups.raw(),
        0,
        &dispatch,
    );
    let request = EncodeIndirectRequest {
        buffer: icb.handle,
        commands: memory.put(&entries.0),
    };
    call::<_, Empty>(
        &mut service,
        connection,
        Operation::EncodeIndirect,
        &request,
        memory,
    )
    .unwrap();

    let mut stream = Stream::default();
    let begin = BeginCompute {
        dispatch_type: DispatchType::Serial.raw(),
    };
    let execute = IndirectRange {
        buffer: icb.handle,
        first: 0,
        count: 1,
    };
    stream
        .push(ComputeCode::Begin.raw(), &begin, &[])
        .push(IndirectCode::Execute.raw(), &execute, &[])
        .end();
    assert_eq!(
        commit(&mut service, connection, &stream),
        Ok(Value { value: 1 })
    );
    assert!(submitted(&mut service).contains(&Command::Dispatch([2, 1, 1])));

    // A command past the buffer's end, and a reset past it.
    let mut beyond = Stream::default();
    encode(&mut beyond, IndirectComputeCode::Reset.raw(), 2, &Empty {});
    let request = EncodeIndirectRequest {
        buffer: icb.handle,
        commands: memory.put(&beyond.0),
    };
    assert_eq!(
        status(call::<_, Empty>(
            &mut service,
            connection,
            Operation::EncodeIndirect,
            &request,
            memory,
        )),
        Status::Invalid
    );
    let reset = IndirectRange {
        first: 1,
        count: 2,
        ..execute
    };
    assert_eq!(
        status(call::<_, Empty>(
            &mut service,
            connection,
            Operation::ResetIndirect,
            &reset,
            memory,
        )),
        Status::Invalid
    );
    let resident: Value = call(
        &mut service,
        connection,
        Operation::IndirectResourceId,
        &icb,
        memory,
    )
    .unwrap();
    assert_ne!(resident.value, 0, "gpuResourceID is the records' address");
}

#[test]
fn indirect_descriptors_decode_their_inherited_state() {
    let mut service = service();
    let connection = connect(&mut service);
    let descriptor = NewIndirectRequest {
        command_types: IndirectCommandType::DRAW.bits(),
        inherits: (IndirectInherits::PIPELINE_STATE | IndirectInherits::BUFFERS).bits(),
        max_command_count: 1,
        ..Default::default()
    };
    assert!(new_indirect(&mut service, connection, &descriptor).is_ok());
    let unknown = NewIndirectRequest {
        inherits: 1 << 8,
        ..descriptor
    };
    assert_eq!(
        status(new_indirect(&mut service, connection, &unknown)),
        Status::Malformed
    );
    let empty = NewIndirectRequest {
        max_command_count: 0,
        ..descriptor
    };
    assert_eq!(
        status(new_indirect(&mut service, connection, &empty)),
        Status::Invalid
    );
}
