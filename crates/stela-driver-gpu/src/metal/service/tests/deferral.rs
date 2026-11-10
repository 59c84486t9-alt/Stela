//! Compilations deferred outside the service's turn: a call that needs one
//! is answered `Pending` at once, other connections' calls are served while
//! the job runs, and the call made again after it completes as before.
extern crate std;

use super::{
    Memory, MockBackend, MockCompiler, Stream, TestService, connect, new_buffer, new_function,
    new_library, service, service_on, submitted,
};
use crate::metal::{
    abi::{DispatchType, StorageMode},
    service::{
        GuestMemory, Served, ServiceHost, SharedService,
        wire::{
            self, ComputePipelineResponse, Empty, GateCall, NewComputePipelineRequest, Operation,
            Record, Span, Status, Value,
            commands::{
                BeginCompute, CommitRequest, ComputeCode, Dispatch, SetBuffer, SetPipeline,
            },
        },
    },
    vulkan::command::Command,
};
use alloc::{sync::Arc, vec};
use core::{
    mem::size_of,
    num::NonZeroU64,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use stela_contracts::gate::GateService;

/// Nanoseconds since the first tick.
fn ticks() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// The longest any commit held the service, and the calls answered
/// `Pending`, for the one test whose host records them.
static COMPILER_HELD: AtomicU64 = AtomicU64::new(0);
static COMPILER_PENDING: AtomicU64 = AtomicU64::new(0);
static BACKEND_HELD: AtomicU64 = AtomicU64::new(0);
static BACKEND_PENDING: AtomicU64 = AtomicU64::new(0);

const fn host(served: fn(Served)) -> ServiceHost {
    ServiceHost {
        relax: core::hint::spin_loop,
        stack: 1,
        run: |_, call| call(),
        report: |_| {},
        note: |_| {},
        ticks,
        served,
        wake: || {},
        bundle: |_| {},
    }
}

fn count(held: &AtomicU64, pending: &AtomicU64, served: Served) {
    if served.operation == Operation::Commit.raw() {
        held.fetch_max(served.held, Ordering::Relaxed);
        if served.status == Status::Pending {
            pending.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A commit's record in `memory` that dispatches `pipeline` over `buffer`.
fn dispatching(memory: &mut Memory, pipeline: u64, buffer: u64) -> u64 {
    let mut stream = Stream::default();
    stream
        .push(
            ComputeCode::Begin.raw(),
            &BeginCompute {
                dispatch_type: DispatchType::Serial.raw(),
            },
            &[],
        )
        .push(
            ComputeCode::SetPipeline.raw(),
            &SetPipeline { pipeline },
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
            ComputeCode::DispatchThreadgroups.raw(),
            &Dispatch {
                size: [4, 1, 1],
                threads: [32, 1, 1],
            },
            &[],
        )
        .end();
    let request = CommitRequest {
        commands: memory.put(&stream.0),
        queue: 1,
    };
    gate_call(memory, Operation::Commit, &request, size_of::<Value>())
}

fn gate_call<Q: Record>(
    memory: &mut Memory,
    operation: Operation,
    request: &Q,
    response: usize,
) -> u64 {
    let mut bytes = vec![0; size_of::<Q>()];
    wire::write(request, &mut bytes).unwrap();
    let call = GateCall {
        operation: operation.raw(),
        status: u32::MAX,
        request: memory.put(&bytes),
        response: memory.put(&vec![0; response]),
        reason: memory.put(&[0; 64]),
        reason_length: 0,
    };
    memory.records(&[call]).address
}

fn status(memory: &mut Memory, record: u64) -> Status {
    let span = Span {
        address: record,
        length: size_of::<GateCall>() as u64,
    };
    let call: GateCall = wire::read(&GuestMemory::read(memory, span).unwrap()).unwrap();
    Status::from_raw(call.status).unwrap()
}

/// A connection's compute pipeline and buffer, made before the service is
/// shared.
fn pipeline(service: &mut TestService, connection: NonZeroU64) -> (u64, u64) {
    let memory = &mut Memory::default();
    let library = new_library(service, connection, memory);
    let kernel = new_function(service, connection, library, "kernel", &[], memory)
        .unwrap()
        .handle;
    let request = NewComputePipelineRequest {
        compute_function: kernel,
        ..Default::default()
    };
    let pipeline: ComputePipelineResponse = super::call(
        service,
        connection,
        Operation::NewComputePipeline,
        &request,
        memory,
    )
    .unwrap();
    (
        pipeline.handle,
        new_buffer(service, connection, StorageMode::Shared),
    )
}

/// Connection A commits a dispatch whose variant `defer` makes wait on
/// `gate`; B commits and polls while A's job runs. Returns the shared
/// service and A's commit, done.
fn run_deferred(
    mut service: TestService,
    defer: impl FnOnce(&mut TestService, Arc<AtomicBool>),
    served: fn(Served),
) -> (Arc<SharedService<MockBackend, MockCompiler>>, usize) {
    let (a, b) = (connect(&mut service), connect(&mut service));
    let (pipeline_a, buffer_a) = pipeline(&mut service, a);
    let (pipeline_b, buffer_b) = pipeline(&mut service, b);
    // B's dispatch shape compiles in its turn before A's defers.
    let mut memory_b = Memory::default();
    let commit_b = dispatching(&mut memory_b, pipeline_b, buffer_b);
    let gate = Arc::new(AtomicBool::new(false));
    defer(&mut service, gate.clone());
    let shared = Arc::new(SharedService::new(service, host(served)));
    shared.set_compile_stack(1);

    // A's commit needs the job: answered at once, nothing submitted.
    let mut memory_a = Memory::default();
    let commit_a = dispatching(&mut memory_a, pipeline_a, buffer_a);
    shared
        .serve(a, commit_a, &mut memory_a)
        .expect("the record is in reach");
    assert_eq!(status(&mut memory_a, commit_a), Status::Pending);
    assert!(shared.jobs_waiting());

    // A processor whose guest waits runs the job, which blocks.
    let runner = {
        let shared = shared.clone();
        std::thread::spawn(move || shared.run_job(0))
    };
    while shared.jobs_waiting() {
        std::thread::yield_now();
    }
    // Meanwhile B commits and polls, and A asks again without a turn.
    shared.serve(b, commit_b, &mut memory_b).unwrap();
    assert_eq!(status(&mut memory_b, commit_b), Status::Ok);
    let poll = gate_call(
        &mut memory_b,
        Operation::Poll,
        &Empty {},
        size_of::<Value>(),
    );
    shared.serve(b, poll, &mut memory_b).unwrap();
    assert_eq!(status(&mut memory_b, poll), Status::Ok);
    shared.serve(a, commit_a, &mut memory_a).unwrap();
    assert_eq!(status(&mut memory_a, commit_a), Status::Pending);
    assert_eq!(shared.take_job_report().repeated, 1);
    assert!(!runner.is_finished());

    // Released, the job ends, and A's commit runs whole once.
    std::thread::sleep(Duration::from_millis(20));
    gate.store(true, Ordering::Release);
    assert!(runner.join().unwrap());
    let before = submissions(&shared);
    shared.serve(a, commit_a, &mut memory_a).unwrap();
    assert_eq!(status(&mut memory_a, commit_a), Status::Ok);
    (shared, before)
}

fn submissions(shared: &SharedService<MockBackend, MockCompiler>) -> usize {
    let mut turn = shared.try_turn().unwrap();
    turn.device().backend().submissions.len()
}

/// The bound a commit's turn stays under while its compilation blocks for
/// longer: the job ran outside the turn.
const HELD_BOUND: u64 = 10_000_000;

#[test]
fn a_commit_whose_variant_compiles_waits_outside_the_turn() {
    let (shared, before) = run_deferred(
        service(),
        |service, gate| {
            let compiler = service.device().compiler_mut();
            compiler.defer_next = true;
            compiler.job_gate = Some(gate);
        },
        |served| count(&COMPILER_HELD, &COMPILER_PENDING, served),
    );
    let held = COMPILER_HELD.load(Ordering::Relaxed);
    assert!(held < HELD_BOUND, "a commit held the service {held} ns");
    assert_eq!(COMPILER_PENDING.load(Ordering::Relaxed), 2);
    let report = shared.take_job_report();
    assert!(report.longest >= 20_000_000, "the job blocked {report:?}");
    // A's last run submitted its dispatch once; its deferred runs nothing.
    assert_eq!(submissions(&shared), before + 1);
    let mut turn = shared.try_turn().unwrap();
    assert_eq!(turn.device().compiler_mut().adopted, 1);
    assert!(submitted(&mut turn).contains(&Command::Dispatch([4, 1, 1])));
}

#[test]
fn a_commit_whose_pipeline_creation_compiles_waits_outside_the_turn() {
    let (shared, before) = run_deferred(
        service_on(MockBackend::new()),
        |service, gate| service.device().backend().pipeline_gate = Some(gate),
        |served| count(&BACKEND_HELD, &BACKEND_PENDING, served),
    );
    let held = BACKEND_HELD.load(Ordering::Relaxed);
    assert!(held < HELD_BOUND, "a commit held the service {held} ns");
    assert_eq!(BACKEND_PENDING.load(Ordering::Relaxed), 2);
    assert_eq!(submissions(&shared), before + 1);
    let mut turn = shared.try_turn().unwrap();
    assert_eq!(turn.device().backend().adopted, 1);
    assert!(submitted(&mut turn).contains(&Command::Dispatch([4, 1, 1])));
}

#[test]
fn a_job_no_waiting_processor_takes_runs_on_its_callers() {
    let mut service = service();
    let a = connect(&mut service);
    let (pipeline, buffer) = pipeline(&mut service, a);
    let compiler = service.device().compiler_mut();
    compiler.defer_next = true;
    // Every processor is busy: none runs jobs.
    compiler.job_gate = Some(Arc::new(AtomicBool::new(true)));
    let shared = SharedService::new(service, host(|_| {}));
    shared.set_compile_stack(1);
    shared.set_force_after(1_000_000);
    let mut memory = Memory::default();
    let commit = dispatching(&mut memory, pipeline, buffer);
    shared.serve(a, commit, &mut memory).unwrap();
    assert_eq!(status(&mut memory, commit), Status::Pending);
    // Within the bound the call waits; past it, the caller runs the job,
    // then its commit.
    shared.serve(a, commit, &mut memory).unwrap();
    assert_eq!(status(&mut memory, commit), Status::Pending);
    std::thread::sleep(Duration::from_millis(2));
    shared.serve(a, commit, &mut memory).unwrap();
    assert_eq!(status(&mut memory, commit), Status::Ok);
    let report = shared.take_job_report();
    assert_eq!((report.ran, report.forced, report.repeated), (1, 1, 1));
    assert!(!shared.jobs_waiting());
}
