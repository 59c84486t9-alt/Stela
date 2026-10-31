use super::{Memory, TestService, call, connect, service_on, status};
use crate::metal::{
    device::fixture::MockBackend,
    service::{
        GuestMemory,
        wire::{
            CommandBufferTimesResponse, CounterSetCode, Empty, EventValueRequest, Handle,
            NewCounterBufferRequest, Operation, ResolveCountersRequest, ResolveCountersResponse,
            Status, TimestampsResponse, Value, WaitEventRequest, WaitResponse,
        },
    },
};
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
    let completed: Value =
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
