use super::{Memory, MockBackend, MockCompiler, Stream, commit, connect, service};
use crate::metal::{
    capabilities::block::Block,
    service::{
        GuestMemory, ServiceHost, SharedService,
        wire::{self, GateCall, NegotiateRequest, NegotiateResponse, Operation, Span, Status},
    },
};
use core::{
    mem::size_of,
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};
use stela_contracts::gate::{CallerFault, CallerMemory, GateService};

impl CallerMemory for Memory {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault> {
        let span = Span {
            address,
            length: buffer.len() as u64,
        };
        let bytes = GuestMemory::read(self, span).map_err(|_| CallerFault::Denied { address })?;
        buffer.copy_from_slice(&bytes);
        Ok(())
    }

    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), CallerFault> {
        let span = Span {
            address,
            length: data.len() as u64,
        };
        GuestMemory::write(self, span, data).map_err(|_| CallerFault::Denied { address })
    }
}

/// Maps a [`GateCall`] for `operation` with `request`, room for a
/// response of `response` bytes and a 64-byte reason.
fn gate_call(memory: &mut Memory, operation: Operation, request: &[u8], response: usize) -> u64 {
    let call = GateCall {
        operation: operation.raw(),
        status: u32::MAX,
        request: memory.put(request),
        response: memory.put(&alloc::vec![0; response]),
        reason: memory.put(&[0; 64]),
        reason_length: 0,
    };
    memory.records(&[call]).address
}

fn completed(memory: &mut Memory, record: u64) -> GateCall {
    let span = Span {
        address: record,
        length: size_of::<GateCall>() as u64,
    };
    wire::read(&GuestMemory::read(memory, span).unwrap()).unwrap()
}

#[test]
fn a_gate_call_completes_in_the_callers_memory() {
    let mut service = service();
    let connection = service.connect().unwrap();
    let mut memory = Memory::default();
    let mut request = [0; size_of::<NegotiateRequest>()];
    let negotiate = NegotiateRequest {
        major: wire::MAJOR,
        minor: wire::MINOR,
    };
    wire::write(&negotiate, &mut request).unwrap();
    let record = gate_call(
        &mut memory,
        Operation::Negotiate,
        &request,
        size_of::<NegotiateResponse>(),
    );
    service.serve(connection, record, &mut memory).unwrap();
    let call = completed(&mut memory, record);
    assert_eq!((call.status, call.reason_length), (Status::Ok.raw(), 0));
    let response: NegotiateResponse =
        wire::read(&GuestMemory::read(&mut memory, call.response).unwrap()).unwrap();
    assert_eq!(response.major, wire::MAJOR);
}

#[test]
fn a_failed_gate_call_reports_its_status_and_reason() {
    let mut service = service();
    let connection = service.connect().unwrap();
    let mut memory = Memory::default();
    let oversized = gate_call(
        &mut memory,
        Operation::Negotiate,
        &[0; size_of::<Block>() + 1],
        16,
    );
    service.serve(connection, oversized, &mut memory).unwrap();
    let call = completed(&mut memory, oversized);
    assert_eq!(call.status, Status::Malformed.raw());
    let reason = GuestMemory::read(&mut memory, call.reason).unwrap();
    assert_eq!(
        &reason[..call.reason_length as usize],
        b"record length".as_slice()
    );
    assert_eq!(
        service.serve(connection, 0x10, &mut memory),
        Err(CallerFault::Denied { address: 0x10 })
    );
}

#[test]
fn the_capability_block_crosses_the_gate() {
    let mut service = service();
    let connection = connect(&mut service);
    let mut memory = Memory::default();
    let record = gate_call(
        &mut memory,
        Operation::Capabilities,
        &[],
        size_of::<Block>(),
    );
    service.serve(connection, record, &mut memory).unwrap();
    assert_eq!(completed(&mut memory, record).status, Status::Ok.raw());
}

#[test]
fn a_span_the_caller_lost_asks_it_to_call_again() {
    let mut service = service();
    let connection = service.connect().unwrap();
    let mut memory = Memory::default();
    let reason = memory.put(&[0; 64]);
    let response = memory.put(&[0; size_of::<NegotiateResponse>()]);
    let record = memory
        .records(&[GateCall {
            operation: Operation::Negotiate.raw(),
            status: u32::MAX,
            request: Span {
                address: 0x10,
                length: size_of::<NegotiateRequest>() as u64,
            },
            response,
            reason,
            reason_length: 0,
        }])
        .address;
    service.serve(connection, record, &mut memory).unwrap();
    assert_eq!(
        completed(&mut memory, record).status,
        Status::Unmapped.raw()
    );
}

#[test]
fn the_gate_signals_completed_work_once() {
    let mut service = service();
    let connection = connect(&mut service);
    assert!(!service.signaled());
    commit(&mut service, connection, &Stream::default()).unwrap();
    assert!(!service.signaled());
    let backend = service.device().backend();
    let timeline = *backend.semaphores.keys().next().unwrap();
    backend.semaphores.insert(timeline, 1);
    assert!(service.signaled());
    assert!(!service.signaled());
}

type Shared = SharedService<MockBackend, MockCompiler>;

fn commit_shared(shared: &Shared, connection: NonZeroU64) {
    commit(
        &mut shared.try_turn().unwrap(),
        connection,
        &Stream::default(),
    )
    .unwrap();
}

const HOST: ServiceHost = ServiceHost {
    relax: || panic!("nothing waits"),
    run: |call| call(),
};

/// The GPU finishes what was committed.
fn complete(shared: &Shared) {
    let mut turn = shared.try_turn().unwrap();
    let backend = turn.device().backend();
    let timeline = *backend.semaphores.keys().next().unwrap();
    backend.semaphores.insert(timeline, 1);
}

#[test]
fn the_shared_service_finds_completed_work_only_after_an_interrupt() {
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    commit_shared(&shared, connection);
    assert!(!shared.signaled());
    complete(&shared);
    assert!(!shared.signaled(), "no interrupt said so");
    shared.interrupted();
    assert!(shared.signaled());
    assert!(!shared.signaled());
}

#[test]
fn every_call_runs_where_the_platform_says() {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let host = ServiceHost {
        run: |call| {
            RUNS.fetch_add(1, Ordering::Relaxed);
            call();
        },
        ..HOST
    };
    let shared = SharedService::new(service(), host);
    let connection = shared.connect().unwrap();
    assert_eq!(RUNS.load(Ordering::Relaxed), 1);
    shared.disconnect(connection);
    assert_eq!(RUNS.load(Ordering::Relaxed), 2);
}

#[test]
fn an_interrupt_during_a_call_is_left_to_that_call() {
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    commit_shared(&shared, connection);
    complete(&shared);
    {
        let turn = shared.try_turn().unwrap();
        shared.interrupted();
        assert!(!shared.signaled());
        drop(turn);
    }
    assert!(shared.signaled());
}
