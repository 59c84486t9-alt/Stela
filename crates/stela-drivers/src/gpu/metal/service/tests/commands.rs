use super::{Memory, TestService, call, connect, new_function, new_library, service, status};
use crate::gpu::metal::{
    abi::{CpuCacheMode, DispatchType, HazardTrackingMode, ResourceOptions, StorageMode},
    service::{
        Outcome,
        wire::{
            self, BufferResponse, ComputePipelineResponse, Empty, NewBufferRequest,
            NewComputePipelineRequest, Operation, Record, Status, Value,
            commands::{
                BeginCompute, BlitCode, CommandBufferCode, CommandHeader, CommitRequest,
                ComputeCode, CopyBuffer, Dispatch, FillBuffer, Resource, SetBuffer, SetBytes,
                SetPipeline,
            },
        },
    },
    vulkan::command::Command,
};
use alloc::vec::Vec;
use core::num::NonZeroU64;

/// A command stream under construction.
#[derive(Default)]
struct Stream(Vec<u8>);

impl Stream {
    fn push<T: Record>(&mut self, code: u32, record: &T, data: &[u8]) -> &mut Self {
        let length = (core::mem::size_of::<T>() + data.len()) as u32;
        self.0
            .extend_from_slice(wire::bytes(&CommandHeader { code, length }));
        self.0.extend_from_slice(wire::bytes(record));
        self.0.extend_from_slice(data);
        self.0.resize(self.0.len().next_multiple_of(8), 0);
        self
    }

    fn end(&mut self) -> &mut Self {
        self.push(CommandBufferCode::EndEncoding.raw(), &Empty {}, &[])
    }
}

fn commit(
    service: &mut TestService,
    connection: NonZeroU64,
    stream: &Stream,
) -> Result<Value, Outcome> {
    let memory = &mut Memory::default();
    let request = CommitRequest {
        commands: memory.put(&stream.0),
    };
    call(service, connection, Operation::Commit, &request, memory)
}

fn new_buffer(service: &mut TestService, connection: NonZeroU64, storage_mode: StorageMode) -> u64 {
    let options = ResourceOptions {
        cpu_cache_mode: CpuCacheMode::DefaultCache,
        storage_mode,
        hazard_tracking_mode: HazardTrackingMode::Default,
    };
    let request = NewBufferRequest {
        length: 256,
        options: options.raw(),
    };
    let buffer: BufferResponse = call(
        service,
        connection,
        Operation::NewBuffer,
        &request,
        &mut Memory::default(),
    )
    .unwrap();
    buffer.handle
}

/// The commands of the last submission.
fn submitted(service: &mut TestService) -> Vec<Command> {
    let segments = service.device().backend().submissions.last().unwrap();
    segments
        .iter()
        .flat_map(|segment| segment.commands.iter().cloned())
        .collect()
}

#[test]
fn compute_commands_replay_into_a_submitted_command_buffer() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let kernel = new_function(&mut service, connection, library, "kernel", &[], memory)
        .unwrap()
        .handle;
    let request = NewComputePipelineRequest {
        compute_function: kernel,
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
    let mut stream = Stream::default();
    let begin = BeginCompute {
        dispatch_type: DispatchType::Serial.raw(),
    };
    let dispatch = Dispatch {
        size: [4, 1, 1],
        threads: [32, 1, 1],
    };
    stream
        .push(ComputeCode::Begin.raw(), &begin, &[])
        .push(
            ComputeCode::SetPipeline.raw(),
            &SetPipeline {
                pipeline: pipeline.handle,
            },
            &[],
        )
        .push(
            ComputeCode::SetBuffer.raw(),
            &SetBuffer {
                buffer,
                offset: 0,
                index: 0,
            },
            &[],
        )
        .push(
            ComputeCode::SetBytes.raw(),
            &SetBytes { index: 1 },
            &[7; 12],
        )
        .push(ComputeCode::DispatchThreadgroups.raw(), &dispatch, &[])
        .end();
    assert_eq!(
        commit(&mut service, connection, &stream),
        Ok(Value { value: 1 })
    );
    assert!(submitted(&mut service).contains(&Command::Dispatch([4, 1, 1])));
}

#[test]
fn blit_commands_copy_fill_and_synchronize() {
    let mut service = service();
    let connection = connect(&mut service);
    let managed = new_buffer(&mut service, connection, StorageMode::Managed);
    let shared = new_buffer(&mut service, connection, StorageMode::Shared);
    let blit = |stream: &mut Stream| {
        stream.push(BlitCode::Begin.raw(), &Empty {}, &[]);
    };
    let fill = FillBuffer {
        buffer: managed,
        start: 0,
        length: 256,
        value: 7,
    };
    let copy = CopyBuffer {
        source: managed,
        source_offset: 0,
        destination: shared,
        destination_offset: 0,
        size: 256,
    };
    let mut stream = Stream::default();
    blit(&mut stream);
    stream
        .push(BlitCode::FillBuffer.raw(), &fill, &[])
        .push(BlitCode::CopyBuffer.raw(), &copy, &[])
        .push(
            BlitCode::Synchronize.raw(),
            &Resource { resource: managed },
            &[],
        )
        .end();
    assert_eq!(
        commit(&mut service, connection, &stream),
        Ok(Value { value: 1 })
    );
    let commands = submitted(&mut service);
    assert!(commands.iter().any(|command| matches!(
        command,
        Command::FillBuffer {
            data: 0x0707_0707,
            ..
        }
    )));
    assert!(
        commands
            .iter()
            .any(|command| matches!(command, Command::CopyBuffer { .. }))
    );

    // Only managed resources synchronize, and fills take one byte.
    let mut stream = Stream::default();
    blit(&mut stream);
    stream.push(
        BlitCode::Synchronize.raw(),
        &Resource { resource: shared },
        &[],
    );
    assert_eq!(
        commit(&mut service, connection, &stream).map_err(|outcome| outcome.reason),
        Err("synchronizeResource: is for managed resources")
    );
    let mut stream = Stream::default();
    blit(&mut stream);
    let wide = FillBuffer { value: 256, ..fill };
    stream.push(BlitCode::FillBuffer.raw(), &wide, &[]);
    assert_eq!(
        status(commit(&mut service, connection, &stream)),
        Status::Malformed
    );
}

#[test]
fn refused_commands_discard_the_command_buffer() {
    let mut service = service();
    let connection = connect(&mut service);
    let buffer = new_buffer(&mut service, connection, StorageMode::Shared);
    let refused = |stream: Stream| status(commit(&mut service, connection, &stream));
    let mut unknown = Stream::default();
    unknown.push(0x7f01, &Empty {}, &[]);
    let mut truncated = Stream::default();
    truncated.push(BlitCode::Begin.raw(), &Empty {}, &[]);
    truncated.0.truncate(4);
    let mut short = Stream::default();
    short.push(BlitCode::Begin.raw(), &Empty {}, &[0; 8]);
    let mut unencoded = Stream::default();
    let dispatch = Dispatch {
        size: [1; 3],
        threads: [1; 3],
    };
    unencoded.push(ComputeCode::DispatchThreadgroups.raw(), &dispatch, &[]);
    let mut stale = Stream::default();
    let synchronize = Resource {
        resource: buffer + 1,
    };
    stale.push(BlitCode::Begin.raw(), &Empty {}, &[]).push(
        BlitCode::Synchronize.raw(),
        &synchronize,
        &[],
    );
    let mut open = Stream::default();
    open.push(BlitCode::Begin.raw(), &Empty {}, &[]);
    assert_eq!(
        [unknown, truncated, short, unencoded, stale, open].map(refused),
        [
            Status::UnknownOperation,
            Status::Malformed,
            Status::Malformed,
            Status::Invalid,
            Status::StaleHandle,
            Status::Invalid,
        ]
    );
    assert_eq!(
        commit(&mut service, connection, &Stream::default()),
        Ok(Value { value: 1 }),
        "nothing refused was submitted"
    );
}
