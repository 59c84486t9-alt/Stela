use super::{Memory, MockBackend, MockCompiler, Stream, commit, connect, service};
use crate::metal::{
    capabilities::block::Block,
    service::{
        GuestMemory, Served, ServiceHost, SharedService,
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
fn a_gate_call_completes_when_the_request_and_response_overlap() {
    let mut service = service();
    let connection = service.connect().unwrap();
    let mut memory = Memory::default();
    let mut buffer = [0xa5; size_of::<NegotiateResponse>()];
    let negotiate = NegotiateRequest {
        major: wire::MAJOR,
        minor: wire::MINOR,
    };
    let request_bytes = size_of::<NegotiateRequest>();
    wire::write(&negotiate, &mut buffer[..request_bytes]).unwrap();
    let response = memory.put(&buffer);
    let reason = memory.put(&[0; 64]);
    let record = memory
        .records(&[GateCall {
            operation: Operation::Negotiate.raw(),
            status: u32::MAX,
            request: Span {
                address: response.address,
                length: request_bytes as u64,
            },
            response,
            reason,
            reason_length: 0,
        }])
        .address;
    service.serve(connection, record, &mut memory).unwrap();
    let call = completed(&mut memory, record);
    assert_eq!((call.status, call.reason_length), (Status::Ok.raw(), 0));
    let response: NegotiateResponse =
        wire::read(&GuestMemory::read(&mut memory, call.response).unwrap()).unwrap();
    assert_eq!(response.major, wire::MAJOR);
    assert_eq!(response.reserved, 0);
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
        alloc::format!("record length {}", size_of::<Block>() + 1).as_bytes()
    );
    // The platform's line names the operation too.
    assert_eq!(
        core::mem::take(&mut service.refused),
        [alloc::format!(
            "record length {} in operation {}",
            size_of::<Block>() + 1,
            Operation::Negotiate.raw()
        )]
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
    stack: 0x4000,
    run: |_, call| call(),
    report: |_| {},
    note: |_| {},
    ticks: || 0,
    served: |_| {},
    wake: || panic!("no turn kept an interrupt from looking"),
    bundle: |_| panic!("no kext reports"),
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

/// A `Poll` call's answered serial.
fn polled(memory: &mut Memory, record: u64) -> u64 {
    let call = completed(memory, record);
    assert_eq!(call.status, Status::Ok.raw());
    let bytes = GuestMemory::read(memory, call.response).unwrap();
    let wire::Value { value } = wire::read(&bytes).unwrap();
    value
}

#[test]
fn a_poll_while_another_call_holds_the_service_answers_what_completed() {
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    let mut memory = Memory::default();
    commit_shared(&shared, connection);
    complete(&shared);
    shared.interrupted();
    // The service answers the connection's first poll itself.
    let first = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, first, &mut memory).unwrap();
    assert_eq!(polled(&mut memory, first), 1);
    // `HOST.relax` panics, so a poll that waited for this holder would fail.
    let held = shared.try_turn().unwrap();
    let busy = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, busy, &mut memory).unwrap();
    assert_eq!(polled(&mut memory, busy), 1);
    drop(held);
}

#[test]
fn only_a_connection_the_service_answered_polls_while_it_is_held() {
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    let mut memory = Memory::default();
    let record = gate_call(&mut memory, Operation::Poll, &[], 8);
    let held = shared.try_turn().unwrap();
    assert!(!shared.poll_published(connection, record, &mut memory));
    assert_eq!(
        completed(&mut memory, record).status,
        u32::MAX,
        "left unanswered"
    );
    drop(held);
    GateService::serve(&shared, connection, record, &mut memory).unwrap();
    assert_eq!(polled(&mut memory, record), 0);
    let held = shared.try_turn().unwrap();
    let again = gate_call(&mut memory, Operation::Commit, &[], 8);
    assert!(
        !shared.poll_published(connection, again, &mut memory),
        "only polls are answered without a turn"
    );
    drop(held);
}

#[test]
fn a_busy_poll_with_a_nonempty_request_takes_the_normal_validation_path() {
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    let mut memory = Memory::default();
    let first = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, first, &mut memory).unwrap();
    assert_eq!(polled(&mut memory, first), 0);

    let malformed = gate_call(&mut memory, Operation::Poll, &[0], 8);
    let held = shared.try_turn().unwrap();
    assert!(!shared.poll_published(connection, malformed, &mut memory));
    assert_eq!(completed(&mut memory, malformed).status, u32::MAX);
    drop(held);

    GateService::serve(&shared, connection, malformed, &mut memory).unwrap();
    assert_eq!(
        completed(&mut memory, malformed).status,
        Status::Malformed.raw()
    );
}

#[test]
fn a_busy_poll_falls_back_after_the_device_loss_notification() {
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    let mut memory = Memory::default();
    let first = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, first, &mut memory).unwrap();
    assert_eq!(polled(&mut memory, first), 0);

    shared.try_turn().unwrap().device().mark_lost();
    assert!(shared.signaled());
    let busy = gate_call(&mut memory, Operation::Poll, &[], 8);
    let held = shared.try_turn().unwrap();
    assert!(!shared.poll_published(connection, busy, &mut memory));
    drop(held);

    GateService::serve(&shared, connection, busy, &mut memory).unwrap();
    assert_eq!(
        completed(&mut memory, busy).status,
        Status::DeviceLost.raw()
    );
}

#[test]
fn a_poll_that_cannot_write_its_status_does_not_enroll_the_connection() {
    struct DenyStatus<'a> {
        memory: &'a mut Memory,
        record: u64,
    }
    impl CallerMemory for DenyStatus<'_> {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault> {
            CallerMemory::read(self.memory, address, buffer)
        }

        fn write(&mut self, address: u64, data: &[u8]) -> Result<(), CallerFault> {
            if address == self.record {
                return Err(CallerFault::Denied { address });
            }
            CallerMemory::write(self.memory, address, data)
        }
    }

    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    let mut memory = Memory::default();
    let record = gate_call(&mut memory, Operation::Poll, &[], 8);
    let mut caller = DenyStatus {
        memory: &mut memory,
        record,
    };
    assert_eq!(
        GateService::serve(&shared, connection, record, &mut caller),
        Err(CallerFault::Denied { address: record })
    );

    let held = shared.try_turn().unwrap();
    let busy = gate_call(&mut memory, Operation::Poll, &[], 8);
    assert!(!shared.poll_published(connection, busy, &mut memory));
    drop(held);
}

#[test]
fn every_call_runs_where_the_platform_says() {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let host = ServiceHost {
        run: |stack, call| {
            assert_eq!(stack, HOST.stack);
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
fn an_interrupt_during_a_call_wakes_the_platform_to_look_once_it_leaves() {
    static WAKES: AtomicUsize = AtomicUsize::new(0);
    let host = ServiceHost {
        wake: || {
            WAKES.fetch_add(1, Ordering::Relaxed);
        },
        ..HOST
    };
    let shared = SharedService::new(service(), host);
    let connection = connect(&mut shared.try_turn().unwrap());
    commit_shared(&shared, connection);
    complete(&shared);
    let turn = shared.try_turn().unwrap();
    shared.interrupted();
    assert_eq!(WAKES.load(Ordering::Relaxed), 0, "the call still holds it");
    drop(turn);
    // The holder does not ask the device itself: that query would run on
    // the guest call's processor.
    assert_eq!(WAKES.load(Ordering::Relaxed), 1);
    assert!(!shared.signaled());
    shared.interrupted();
    assert!(shared.signaled());
    assert_eq!(WAKES.load(Ordering::Relaxed), 1, "the look cleared it");
}

#[test]
fn interrupt_completion_queries_use_the_services_stack() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let host = ServiceHost {
        run: |stack, call| {
            assert_eq!(stack, HOST.stack);
            RUNS.fetch_add(1, Ordering::Relaxed);
            call();
        },
        ..HOST
    };
    let shared = SharedService::new(service(), host);
    assert_eq!(RUNS.load(Ordering::Relaxed), 0);
    shared.interrupted();
    assert_eq!(RUNS.load(Ordering::Relaxed), 1);
}

#[test]
fn the_kexts_plugin_report_goes_to_the_platform() {
    use stela_contracts::gate::BundleReport;
    static REPORTS: AtomicUsize = AtomicUsize::new(0);
    let host = ServiceHost {
        bundle: |report| {
            assert_eq!(report, BundleReport::Missing);
            REPORTS.fetch_add(1, Ordering::Relaxed);
        },
        ..HOST
    };
    let shared = SharedService::new(service(), host);
    shared.bundle(BundleReport::Missing);
    assert_eq!(REPORTS.load(Ordering::Relaxed), 1);
}

#[test]
fn a_calls_device_loss_signals_waiters_without_an_interrupt() {
    let shared = SharedService::new(service(), HOST);
    {
        let mut turn = shared.try_turn().unwrap();
        turn.device().mark_lost();
    }
    assert!(shared.signaled());
    drop(shared.try_turn().unwrap());
    assert!(!shared.signaled());
}

#[test]
fn device_loss_is_latched_and_wakes_waiters_only_once() {
    use super::{
        call,
        wire::{Empty, Operation, Status, Value},
    };
    let mut service = service();
    let connection = connect(&mut service);
    let token = NonZeroU64::new(17).unwrap();
    service
        .import(
            connection,
            &[stela_contracts::gate::MemoryRange {
                address: 0x8_0000_0000,
                bytes: 4096,
            }],
            token,
        )
        .unwrap();
    commit(&mut service, connection, &Stream::default()).unwrap();
    service.device().backend().semaphore_error = Some(crate::metal::error::Error::DeviceLost);
    assert!(service.signaled());
    assert!(service.device().is_lost());
    assert!(!service.signaled());
    // The backend's injected error was one-shot. Later successful queries
    // must not make this device's old identities usable again.
    assert_eq!(service.connect().unwrap_err().status, Status::DeviceLost);
    let mut memory = Memory::default();
    let response: Result<Value, _> = call(
        &mut service,
        connection,
        Operation::Poll,
        &Empty {},
        &mut memory,
    );
    assert_eq!(response.unwrap_err().status, Status::DeviceLost);
    let result = commit(&mut service, connection, &Stream::default());
    assert_eq!(result.unwrap_err().status, Status::DeviceLost);
    service.disconnect(connection).unwrap();
    assert_eq!(
        service.retired(),
        None,
        "loss is not DMA retirement acknowledgement"
    );
}

#[test]
fn the_platform_times_each_call_by_its_operation_and_status() {
    use core::sync::atomic::AtomicU64;
    static TICKS: AtomicU64 = AtomicU64::new(0);
    static SERVED: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    fn served(served: Served) {
        // Each call reads the ticks as it rings, enters and leaves.
        assert_eq!((served.waited, served.held), (10, 10));
        let slot = &SERVED[COUNT.fetch_add(1, Ordering::Relaxed)];
        slot.store(
            u64::from(served.operation) << 32 | u64::from(served.status.raw()),
            Ordering::Relaxed,
        );
    }
    let host = ServiceHost {
        ticks: || TICKS.fetch_add(10, Ordering::Relaxed),
        served,
        ..HOST
    };
    let shared = SharedService::new(service(), host);
    let connection = shared.connect().unwrap();
    let mut memory = Memory::default();
    let record = gate_call(
        &mut memory,
        Operation::Capabilities,
        &[],
        size_of::<Block>(),
    );
    GateService::serve(&shared, connection, record, &mut memory).unwrap();
    let poll = gate_call(&mut memory, Operation::Poll, &[], 8);
    let lost = GateCall {
        request: Span {
            address: 0x10,
            length: 8,
        },
        ..completed(&mut memory, poll)
    };
    let lost = memory.records(&[lost]).address;
    GateService::serve(&shared, connection, lost, &mut memory).unwrap();
    assert_eq!(
        GateService::serve(&shared, connection, 0x10, &mut memory),
        Err(CallerFault::Denied { address: 0x10 })
    );
    let seen = SERVED.each_ref().map(|slot| slot.load(Ordering::Relaxed));
    let expect =
        |operation: u32, status: Status| u64::from(operation) << 32 | u64::from(status.raw());
    assert_eq!(
        seen,
        [
            // An unnegotiated connection's call.
            expect(Operation::Capabilities.raw(), Status::Invalid),
            expect(Operation::Poll.raw(), Status::Unmapped),
            // A record out of reach.
            expect(0, Status::Closed),
        ]
    );
    assert_eq!(COUNT.load(Ordering::Relaxed), 3);
}

#[test]
fn a_poll_on_a_free_service_answers_what_was_published_without_asking_the_device() {
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    let mut memory = Memory::default();
    let first = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, first, &mut memory).unwrap();
    assert_eq!(polled(&mut memory, first), 0);
    commit_shared(&shared, connection);
    complete(&shared);
    // A query would fail: a poll that asked the device would answer the loss.
    shared
        .try_turn()
        .unwrap()
        .device()
        .backend()
        .semaphore_error = Some(crate::metal::error::Error::DeviceLost);
    let free = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, free, &mut memory).unwrap();
    assert_eq!(
        polled(&mut memory, free),
        0,
        "nothing published completion yet"
    );
    shared
        .try_turn()
        .unwrap()
        .device()
        .backend()
        .semaphore_error = None;
    // The interrupt's look publishes it before the kext wakes the frontend.
    shared.interrupted();
    assert!(shared.signaled());
    let woken = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, woken, &mut memory).unwrap();
    assert_eq!(polled(&mut memory, woken), 1);
}

#[test]
fn the_kexts_import_is_timed_as_a_call_of_its_own() {
    use crate::metal::service::{IMPORT_AGAIN_OPERATION, IMPORT_OPERATION};
    use core::sync::atomic::AtomicU64;
    static TICKS: AtomicU64 = AtomicU64::new(0);
    static SERVED: AtomicU64 = AtomicU64::new(0);
    fn served(served: Served) {
        assert_eq!((served.waited, served.held), (10, 10));
        SERVED.store(
            u64::from(served.operation) << 32 | u64::from(served.status.raw()),
            Ordering::Relaxed,
        );
    }
    let shared = SharedService::new(
        service(),
        ServiceHost {
            ticks: || TICKS.fetch_add(10, Ordering::Relaxed),
            served,
            ..HOST
        },
    );
    let connection = shared.connect().unwrap();
    let range = stela_contracts::gate::MemoryRange {
        address: 0x8_0000_0000,
        bytes: 4096,
    };
    let expect = |operation: u32| u64::from(operation) << 32 | u64::from(Status::Ok.raw());
    let token = NonZeroU64::new(9).unwrap();
    assert!(GateService::import(&shared, connection, &[range], token).is_ok());
    assert_eq!(SERVED.load(Ordering::Relaxed), expect(IMPORT_OPERATION));
    // The same pages again, as a surface's for its next texture.
    let token = NonZeroU64::new(10).unwrap();
    assert!(GateService::import(&shared, connection, &[range], token).is_ok());
    assert_eq!(
        SERVED.load(Ordering::Relaxed),
        expect(IMPORT_AGAIN_OPERATION)
    );
    let other = stela_contracts::gate::MemoryRange {
        bytes: 8192,
        ..range
    };
    let token = NonZeroU64::new(11).unwrap();
    assert!(GateService::import(&shared, connection, &[other], token).is_ok());
    assert_eq!(SERVED.load(Ordering::Relaxed), expect(IMPORT_OPERATION));
}

/// `cargo test ... poll_paths_cost -- --ignored --nocapture`: the service's
/// own cost of a poll answered from what was published and of one that takes
/// the turn and asks the device. The mock's timeline query is free; on the
/// PC that query is a host kernel call the boot CPU serves (`GPU POSTED`).
#[test]
#[ignore = "a measurement, not a check"]
fn poll_paths_cost() {
    extern crate std;
    const CALLS: u32 = 200_000;
    let shared = SharedService::new(service(), HOST);
    let connection = connect(&mut shared.try_turn().unwrap());
    let mut memory = Memory::default();
    let record = gate_call(&mut memory, Operation::Poll, &[], 8);
    GateService::serve(&shared, connection, record, &mut memory).unwrap();
    // Work in flight, so a turn's poll asks the device.
    commit_shared(&shared, connection);
    let time = |memory: &mut Memory| {
        let started = std::time::Instant::now();
        for _ in 0..CALLS {
            GateService::serve(&shared, connection, record, memory).unwrap();
        }
        started.elapsed().as_nanos() / u128::from(CALLS)
    };
    let published = time(&mut memory);
    // What a poll did before: a turn, and the service's dispatch in it.
    let turn = {
        let started = std::time::Instant::now();
        for _ in 0..CALLS {
            let mut turn = shared.try_turn().unwrap();
            turn.serve(connection, record, &mut memory).unwrap();
        }
        started.elapsed().as_nanos() / u128::from(CALLS)
    };
    std::println!("poll ns per call: published={published} turn={turn}");
}
