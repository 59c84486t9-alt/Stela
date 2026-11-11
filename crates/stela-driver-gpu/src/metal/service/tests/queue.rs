use super::{
    Memory, StorageMode, Stream, TestService, call, commit, commit_on, connect, new_buffer,
    service_on, status,
};
use crate::metal::{
    device::fixture::MockBackend,
    service::{
        GuestMemory,
        wire::{
            CommandBufferTimesResponse, CounterSetCode, Empty, EventValueRequest, Handle,
            NewCounterBufferRequest, Operation, PollResponse, ResolveCountersRequest,
            ResolveCountersResponse, Status, TimestampsResponse, Value, WaitEventRequest,
            WaitResponse,
        },
    },
};
use alloc::vec::Vec;
use core::num::NonZeroU64;

fn value(
    service: &mut TestService,
    connection: NonZeroU64,
    operation: Operation,
    handle: u64,
) -> u64 {
    let response: Value = call(
        service,
        connection,
        operation,
        &Handle { handle },
        &mut Memory::default(),
    )
    .unwrap();
    response.value
}

#[test]
fn events_signal_from_the_cpu_and_answer_waits() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let event: Handle = call(
        &mut service,
        connection,
        Operation::NewEvent,
        &Empty {},
        memory,
    )
    .unwrap();
    let signal = |service: &mut TestService, value| {
        call::<_, Empty>(
            service,
            connection,
            Operation::SetEventSignaledValue,
            &EventValueRequest {
                event: event.handle,
                value,
            },
            &mut Memory::default(),
        )
        .unwrap();
    };
    signal(&mut service, 5);
    // Timeline values only increase.
    signal(&mut service, 3);
    assert_eq!(
        value(
            &mut service,
            connection,
            Operation::EventSignaledValue,
            event.handle
        ),
        5
    );
    let mut wait = |value| {
        let request = WaitEventRequest {
            event: event.handle,
            value,
            timeout: 0,
        };
        let response: WaitResponse = call(
            &mut service,
            connection,
            Operation::WaitEvent,
            &request,
            memory,
        )
        .unwrap();
        response.reached
    };
    assert_eq!((wait(5), wait(6)), (1, 0));
}

#[test]
fn counters_resolve_into_guest_memory() {
    let mut backend = MockBackend::new();
    backend.queries_ready = true;
    let mut service = service_on(backend);
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let request = NewCounterBufferRequest {
        counter_set: CounterSetCode::Timestamp.raw(),
        sample_count: 4,
    };
    let buffer: Handle = call(
        &mut service,
        connection,
        Operation::NewCounterBuffer,
        &request,
        memory,
    )
    .unwrap();
    let out = memory.put(&[0; 16]);
    let resolve = ResolveCountersRequest {
        buffer: buffer.handle,
        first: 1,
        count: 2,
        out,
    };
    let resolved: ResolveCountersResponse = call(
        &mut service,
        connection,
        Operation::ResolveCounters,
        &resolve,
        memory,
    )
    .unwrap();
    assert_eq!((resolved.resolved, resolved.length), (1, 16));
    let values: alloc::vec::Vec<u8> = [0u64, 10]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(memory.read(out).unwrap(), values);
    let beyond = ResolveCountersRequest {
        first: 3,
        ..resolve
    };
    assert_eq!(
        status(call::<_, ResolveCountersResponse>(
            &mut service,
            connection,
            Operation::ResolveCounters,
            &beyond,
            memory,
        )),
        Status::Invalid
    );
    let unknown = NewCounterBufferRequest {
        counter_set: 2,
        ..request
    };
    assert_eq!(
        status(call::<_, Handle>(
            &mut service,
            connection,
            Operation::NewCounterBuffer,
            &unknown,
            memory,
        )),
        Status::Malformed
    );
}

#[test]
fn the_queue_answers_its_serials_and_clocks() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let completed: PollResponse =
        call(&mut service, connection, Operation::Poll, &Empty {}, memory).unwrap();
    assert_eq!(completed.value, 0);
    assert_eq!(
        status(call::<_, CommandBufferTimesResponse>(
            &mut service,
            connection,
            Operation::CommandBufferTimes,
            &Value { value: 1 },
            memory,
        )),
        Status::Invalid,
        "the command buffer has not completed"
    );
    let clocks: TimestampsResponse = call(
        &mut service,
        connection,
        Operation::SampleTimestamps,
        &Empty {},
        memory,
    )
    .unwrap();
    assert_eq!((clocks.cpu, clocks.gpu), (1, 2));
    let allocated: Value = call(
        &mut service,
        connection,
        Operation::AllocatedSize,
        &Empty {},
        memory,
    )
    .unwrap();
    assert_eq!(allocated.value, service.device().current_allocated_size());
}

#[test]
fn each_connection_counts_the_allocations_it_holds() {
    let mut service = service_on(MockBackend::new());
    let first = connect(&mut service);
    let second = connect(&mut service);
    let allocated = |service: &mut TestService, connection| {
        let size: Value = call(
            service,
            connection,
            Operation::AllocatedSize,
            &Empty {},
            &mut Memory::default(),
        )
        .unwrap();
        size.value
    };
    let buffer = new_buffer(&mut service, first, StorageMode::Private);
    new_buffer(&mut service, second, StorageMode::Shared);
    let shared = allocated(&mut service, second);
    assert_eq!(allocated(&mut service, first), 256);
    assert!(shared >= 256, "imported memory counts as its buffer's");
    assert_eq!(service.device().current_allocated_size(), 256 + shared);
    // A released buffer leaves its process's count at once, though work
    // in flight keeps the device's memory until it retires.
    commit(&mut service, first, &Stream::default()).unwrap();
    call::<_, Empty>(
        &mut service,
        first,
        Operation::Release,
        &Handle { handle: buffer },
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(allocated(&mut service, first), 0);
    assert_eq!(service.device().current_allocated_size(), 256 + shared);
    assert_eq!(allocated(&mut service, second), shared);
    // The report names what waits for the work and what each connection
    // still counts.
    let report = service.memory();
    assert_eq!(report.device.allocated, 256 + shared);
    assert_eq!(report.device.deferred_bytes, 256);
    assert!(report.device.deferred >= 1 && report.device.in_flight == 1);
    assert_eq!(report.device.completed + 1, report.device.submitted);
    let counts: alloc::vec::Vec<_> = report
        .connections
        .iter()
        .map(|connection| (connection.id, connection.objects, connection.allocated))
        .collect();
    assert_eq!(counts, [(first, 0, 0), (second, 1, shared)]);
}

#[test]
fn a_command_buffer_that_fails_still_signals_its_events() {
    use crate::metal::{
        abi::DispatchType,
        service::wire::commands::{
            BeginCompute, CommandBufferCode, ComputeCode, EventCommand, SetPipeline,
        },
    };
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let event: Handle = call(
        &mut service,
        connection,
        Operation::NewEvent,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    let signal = EventCommand {
        event: event.handle,
        value: 9,
    };
    let begin = BeginCompute {
        dispatch_type: DispatchType::Serial.raw(),
    };
    let mut stream = Stream::default();
    stream
        .push(CommandBufferCode::SignalEvent.raw(), &signal, &[])
        .push(ComputeCode::Begin.raw(), &begin, &[])
        .push(
            ComputeCode::SetPipeline.raw(),
            &SetPipeline { pipeline: 999 },
            &[],
        )
        .end();
    // The unknown pipeline fails the command buffer, but its event is still
    // signaled: work waiting for it would otherwise never run.
    assert!(commit(&mut service, connection, &stream).is_err());
    let submitted = service.device().backend().submissions.last().unwrap();
    assert!(
        submitted
            .iter()
            .flat_map(|segment| &segment.signals)
            .any(|&(_, value)| value == 9)
    );
    assert!(submitted.iter().all(|segment| {
        segment
            .commands
            .iter()
            .all(|command| !matches!(command, crate::metal::vulkan::command::Command::Dispatch(_)))
    }));
}

/// What `connection` sees complete.
fn reached(service: &mut TestService, connection: NonZeroU64) -> u64 {
    let response: PollResponse = call(
        service,
        connection,
        Operation::Poll,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    response.value
}

#[test]
fn an_event_that_never_comes_holds_only_its_own_connection() {
    use crate::metal::service::wire::commands::{CommandBufferCode, EventCommand};
    let mut service = service_on(MockBackend::new());
    let waiting = connect(&mut service);
    let other = connect(&mut service);
    let event: Handle = call(
        &mut service,
        waiting,
        Operation::NewEvent,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    let wait = EventCommand {
        event: event.handle,
        value: 1,
    };
    let mut stream = Stream::default();
    stream.push(CommandBufferCode::WaitForEvent.raw(), &wait, &[]);
    let held = commit(&mut service, waiting, &stream).unwrap().value;
    // Its connection's next command buffer waits behind it, as Metal's
    // queue order requires; the other connection's work does not.
    let behind = commit(&mut service, waiting, &Stream::default())
        .unwrap()
        .value;
    let mut last = 0;
    for _ in 0..3 {
        last = commit(&mut service, other, &Stream::default())
            .unwrap()
            .value;
        service.device().backend().finish();
        assert_eq!(reached(&mut service, other), last);
    }
    assert_eq!(reached(&mut service, waiting), held - 1);
    // No submission waits on a value nothing promised: the driver would
    // hold the whole queue there.
    assert!(service.device().backend().unpromised.is_empty());

    // The CPU's signal releases the held work; it completes after later
    // serials did, on the late timeline.
    call::<_, Empty>(
        &mut service,
        waiting,
        Operation::SetEventSignaledValue,
        &EventValueRequest {
            event: event.handle,
            value: 1,
        },
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(reached(&mut service, waiting), held - 1);
    service.device().backend().finish();
    assert_eq!(reached(&mut service, waiting), last);
    assert!(behind > held);
    assert!(service.device().backend().unpromised.is_empty());
    assert!(!service.device().holds());
}

#[test]
fn a_refused_command_buffer_waiting_on_an_event_holds_only_its_connection() {
    use crate::metal::{
        abi::DispatchType,
        service::wire::commands::{
            BeginCompute, CommandBufferCode, ComputeCode, EventCommand, SetPipeline,
        },
    };
    let mut service = service_on(MockBackend::new());
    let refused = connect(&mut service);
    let other = connect(&mut service);
    let new_event = |service: &mut TestService| -> Handle {
        call(
            service,
            refused,
            Operation::NewEvent,
            &Empty {},
            &mut Memory::default(),
        )
        .unwrap()
    };
    let (waited, signaled) = (new_event(&mut service), new_event(&mut service));
    let mut stream = Stream::default();
    stream
        .push(
            CommandBufferCode::WaitForEvent.raw(),
            &EventCommand {
                event: waited.handle,
                value: 3,
            },
            &[],
        )
        .push(
            ComputeCode::Begin.raw(),
            &BeginCompute {
                dispatch_type: DispatchType::Serial.raw(),
            },
            &[],
        )
        .push(
            ComputeCode::SetPipeline.raw(),
            &SetPipeline { pipeline: 999 },
            &[],
        )
        .end()
        .push(
            CommandBufferCode::SignalEvent.raw(),
            &EventCommand {
                event: signaled.handle,
                value: 4,
            },
            &[],
        );
    // Refused mid-stream with its events pending.
    assert!(commit(&mut service, refused, &stream).is_err());
    let last = commit(&mut service, other, &Stream::default())
        .unwrap()
        .value;
    service.device().backend().finish();
    assert_eq!(reached(&mut service, other), last);
    assert!(service.device().backend().unpromised.is_empty());
    // Once its wait is met, it signals what it promised.
    call::<_, Empty>(
        &mut service,
        refused,
        Operation::SetEventSignaledValue,
        &EventValueRequest {
            event: waited.handle,
            value: 3,
        },
        &mut Memory::default(),
    )
    .unwrap();
    reached(&mut service, refused);
    service.device().backend().finish();
    assert_eq!(
        value(
            &mut service,
            refused,
            Operation::EventSignaledValue,
            signaled.handle
        ),
        4
    );
    assert_eq!(
        reached(&mut service, refused),
        service.device().submitted_serial()
    );
}

#[test]
fn a_closed_connection_drops_its_held_work() {
    use crate::metal::service::wire::commands::{CommandBufferCode, EventCommand};
    let mut service = service_on(MockBackend::new());
    let waiting = connect(&mut service);
    let other = connect(&mut service);
    let event: Handle = call(
        &mut service,
        waiting,
        Operation::NewEvent,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    let mut stream = Stream::default();
    stream.push(
        CommandBufferCode::WaitForEvent.raw(),
        &EventCommand {
            event: event.handle,
            value: 1,
        },
        &[],
    );
    commit(&mut service, waiting, &stream).unwrap();
    let submissions = service.device().backend().submissions.len();
    service.disconnect(waiting).unwrap();
    let last = commit(&mut service, other, &Stream::default())
        .unwrap()
        .value;
    service.device().backend().finish();
    assert_eq!(reached(&mut service, other), last);
    // Only the other connection's command buffer reached the queue.
    assert_eq!(
        service.device().backend().submissions.len(),
        submissions + 1
    );
    assert!(!service.device().holds());
}

/// MetalFX's temporal scaler over MPSGraph, as the guest commits it: the
/// caller's command buffer A on one Metal queue, B, C and D on another of
/// the same connection, events between them and a CPU signal. Every command
/// buffer completes; B completes while A still waits, and the connection
/// learns of it.
#[test]
fn command_buffers_of_two_queues_wait_for_each_others_events() {
    use crate::metal::service::wire::commands::{CommandBufferCode, EventCommand};
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let events: Vec<u64> = (0..7)
        .map(|_| {
            let event: Handle = call(
                &mut service,
                connection,
                Operation::NewEvent,
                &Empty {},
                &mut Memory::default(),
            )
            .unwrap();
            event.handle
        })
        .collect();
    let stream = |steps: &[(bool, usize, u64)]| {
        let mut stream = Stream::default();
        for &(signal, event, value) in steps {
            let code = if signal {
                CommandBufferCode::SignalEvent
            } else {
                CommandBufferCode::WaitForEvent
            };
            let command = EventCommand {
                event: events[event],
                value,
            };
            stream.push(code.raw(), &command, &[]);
        }
        stream
    };
    let (signal, wait) = (true, false);
    let a = stream(&[(signal, 1, 1), (wait, 3, 2), (signal, 4, 1), (wait, 2, 1)]);
    let a = commit_on(&mut service, connection, 1, &a).unwrap().value;
    let b = stream(&[(wait, 1, 1), (signal, 5, 2), (signal, 6, 2), (signal, 3, 2)]);
    let b = commit_on(&mut service, connection, 2, &b).unwrap().value;
    service.device().backend().finish();
    assert_eq!(reached(&mut service, connection), a - 1);
    let after = |service: &mut TestService, serial| {
        let next: Value = call(
            service,
            connection,
            Operation::CompletedAfter,
            &Value { value: serial },
            &mut Memory::default(),
        )
        .unwrap();
        next.value
    };
    assert_eq!(after(&mut service, a - 1), b);
    assert_eq!(after(&mut service, b), 0);
    for event in [5, 6] {
        assert_eq!(
            value(
                &mut service,
                connection,
                Operation::EventSignaledValue,
                events[event]
            ),
            2
        );
    }
    call::<_, Empty>(
        &mut service,
        connection,
        Operation::SetEventSignaledValue,
        &EventValueRequest {
            event: events[6],
            value: 3,
        },
        &mut Memory::default(),
    )
    .unwrap();
    let c = stream(&[(wait, 6, 2), (signal, 6, 3)]);
    commit_on(&mut service, connection, 2, &c).unwrap();
    let d = stream(&[(wait, 6, 3), (wait, 4, 1), (signal, 2, 1)]);
    let d = commit_on(&mut service, connection, 2, &d).unwrap().value;
    assert!(service.device().backend().unpromised.is_empty());
    service.device().backend().finish();
    assert_eq!(reached(&mut service, connection), d);
    assert_eq!(after(&mut service, d), 0);
    assert!(!service.device().holds());
}

/// A submission the driver refuses while keeping the device fails only its
/// command buffer: the poll names it, `CommandFailure` answers its commit's
/// failure once, and the connection's later command buffers complete.
#[test]
fn a_refused_submission_fails_only_its_command_buffer() {
    use crate::metal::error::Error;
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    service.device().backend().refuse_next = Some(Error::OutOfMemory);
    let first = commit(&mut service, connection, &Stream::default())
        .unwrap()
        .value;
    let second = commit(&mut service, connection, &Stream::default())
        .unwrap()
        .value;
    service.device().backend().finish();
    let polled: PollResponse = call(
        &mut service,
        connection,
        Operation::Poll,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(polled.value, second, "later command buffers complete");
    assert_eq!(polled.refused, first);
    let failure = |service: &mut TestService, serial| {
        call::<_, Empty>(
            service,
            connection,
            Operation::CommandFailure,
            &Value { value: serial },
            &mut Memory::default(),
        )
    };
    assert!(failure(&mut service, second).is_ok(), "the second ran");
    assert_eq!(
        status(failure(&mut service, first)),
        Status::OutOfMemory,
        "the commit's own failure"
    );
    assert!(failure(&mut service, first).is_ok(), "answered once");
    let polled: PollResponse = call(
        &mut service,
        connection,
        Operation::Poll,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(polled.refused, 0);
    assert!(!service.device().is_lost());
}
