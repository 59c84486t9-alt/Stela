//! Native timing of the serialized basic-block dispatcher over an original loop.
//! Build with --release; output is JSON. Optional argument chooses the parent
//! directory for a fresh, automatically removed cache. No guest data accesses.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{path::Path, time::Instant};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{BLOCK_ABI, ExitKind},
};
use stela_core::sha256;
use stela_runtime::blocks::{BlockRuntime, RunOutcome, StopReason, ThreadState};

const ENTRY: GuestAddress = GuestAddress(0x100000);
const STOP: GuestAddress = GuestAddress(0x200000);
const ADDRESS_SPACE: u64 = 0x534f5245545441;
const TRIALS: usize = 7;
const RUNS_PER_TRIAL: usize = 1000;
const LOOP_COUNTS: [u64; 3] = [1, 16, 1024];
const RUNTIME_SOURCE: &str = concat!(
    include_str!("../src/lib.rs"),
    include_str!("../src/blocks.rs"),
    include_str!("../src/execution.rs"),
    include_str!("../src/dispatch.rs"),
    include_str!("../../stela-core/src/lib.rs"),
    include_str!("../../stela-core/Cargo.toml"),
    include_str!("../Cargo.toml"),
    include_str!("../../../Cargo.toml"),
    include_str!("../../../Cargo.lock"),
);

fn source() -> Vec<u8> {
    // subs x0,x0,#1; b.ne ENTRY; ret x30
    [0xf1000400u32, 0x54ffffe1, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

fn initial_state(count: u64, run_id: u64) -> ThreadState {
    let mut registers = GuestState {
        sp: 0x700000,
        nzcv: 0x90000000,
        reserved: 0xa5a55a5a ^ run_id as u32,
        ..GuestState::default()
    };
    for (index, value) in registers.x.iter_mut().enumerate() {
        *value = 0xa55a0123456789abu64
            .rotate_left(index as u32)
            .wrapping_add(run_id);
    }
    registers.v = std::array::from_fn(|index| {
        [
            0x0123456789abcdefu64.rotate_left(index as u32) ^ run_id,
            0xfedcba9876543210u64.rotate_right(index as u32) ^ run_id,
        ]
    });
    registers.fpcr = 0xa5c39e71 ^ run_id as u32;
    registers.fpsr = 0x5a3c618e ^ run_id as u32;
    registers.x[0] = count;
    registers.x[30] = STOP.0;
    ThreadState {
        registers,
        pc: ENTRY,
    }
}

fn validate_state(state: &ThreadState, count: u64, run_id: u64) -> Result<()> {
    let mut expected = initial_state(count, run_id);
    expected.registers.x[0] = 0;
    expected.registers.nzcv = 0x60000000; // final 1-1: Z=1, no borrow C=1
    expected.pc = STOP;
    ensure!(state.pc == expected.pc, "unexpected final guest PC");
    ensure!(
        state.registers == expected.registers,
        "final GPR/SP/NZCV/reserved state differs for count={count}, run={run_id}"
    );
    Ok(())
}

fn validate_outcome(outcome: &RunOutcome, count: u64) -> Result<()> {
    ensure!(
        outcome.reason == StopReason::StopAddress,
        "loop did not reach the caller-owned stop address"
    );
    ensure!(
        outcome.blocks_executed as u64 == count + 1,
        "loop dispatched an unexpected number of blocks"
    );
    ensure!(
        outcome.last_exit == Some((STOP.0, ExitKind::Return as u64)),
        "loop did not finish with the expected guest return"
    );
    Ok(())
}

fn run_loop(runtime: &mut BlockRuntime, state: &mut ThreadState, count: u64) -> Result<RunOutcome> {
    let budget = usize::try_from(count + 1)?;
    // SAFETY: The owned, immutable fixture contains only SUBS/B.NE/RET and has
    // no guest data accesses. Count is positive and the caller bounds dispatch
    // by count+1 blocks. State and runtime are exclusively borrowed; no pointer
    // escapes and no guest instruction aliases host state or mappings. The
    // declared direct-RAM block profile uses unguarded pages with GCS disabled.
    unsafe { runtime.run(state, Some(STOP), budget) }
}

fn runtime(cache: &Path) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new(ADDRESS_SPACE, cache.to_owned());
    runtime.register_code(ENTRY, source())?;
    Ok(runtime)
}

#[derive(Debug, Default, Serialize)]
struct CacheStats {
    dispatched_blocks: u64,
    compiled_blocks: u64,
    disk_cache_hits: u64,
    memory_cache_hits: u64,
}

impl CacheStats {
    fn add(&mut self, outcome: &RunOutcome) {
        self.dispatched_blocks += outcome.blocks_executed as u64;
        self.compiled_blocks += outcome.compiled_blocks as u64;
        self.disk_cache_hits += outcome.disk_cache_hits as u64;
        self.memory_cache_hits += outcome.memory_cache_hits as u64;
    }
}

#[derive(Debug, Serialize)]
struct Trial {
    trial: usize,
    runs: usize,
    elapsed_ns: u64,
    ns_per_run: f64,
    ns_per_dispatched_block: f64,
    cache: CacheStats,
}

fn elapsed_ns(start: Instant) -> Result<u64> {
    u64::try_from(start.elapsed().as_nanos()).context("benchmark duration overflow")
}

fn phase(runtime: &mut BlockRuntime, expected_disk_hit: bool) -> Result<serde_json::Value> {
    let mut state = initial_state(1, 0);
    let start = Instant::now();
    let outcome = run_loop(runtime, &mut state, 1)?;
    let elapsed_ns = elapsed_ns(start)?;
    validate_state(&state, 1, 0)?;
    validate_outcome(&outcome, 1)?;
    ensure!(runtime.address_space() == ADDRESS_SPACE, "ASID changed");
    ensure!(
        outcome.memory_cache_hits == 0,
        "phase runtime was already hot"
    );
    ensure!(
        outcome.disk_cache_hits == if expected_disk_hit { 2 } else { 0 }
            && outcome.compiled_blocks == if expected_disk_hit { 0 } else { 2 },
        "phase cache status differs from the intended cold/disk experiment"
    );
    Ok(serde_json::json!({
        "elapsed_ns": elapsed_ns,
        "outcome": outcome,
        "validated_complete_guest_state": true,
        "includes": if expected_disk_hit {
            "Disk validation/read, RW-to-RX load and native dispatch; runtime construction/registration excluded"
        } else {
            "Compilation, cache writes, RW-to-RX load and native dispatch; runtime construction/registration excluded"
        },
    }))
}

fn benchmark_case(runtime: &mut BlockRuntime, count: u64) -> Result<serde_json::Value> {
    let mut trials = Vec::with_capacity(TRIALS);
    for trial in 0..TRIALS {
        // Allocation and final-state assertions are outside timing. Resetting
        // each state and retaining its result are inside timing and not subtracted.
        let mut observations = Vec::with_capacity(RUNS_PER_TRIAL);
        let start = Instant::now();
        for index in 0..RUNS_PER_TRIAL {
            let run_id = (trial * RUNS_PER_TRIAL + index) as u64;
            let mut state = initial_state(count, run_id);
            let outcome = run_loop(runtime, &mut state, count)?;
            observations.push((state, outcome));
        }
        let elapsed_ns = elapsed_ns(start)?;
        let mut cache = CacheStats::default();
        for (index, (state, outcome)) in observations.iter().enumerate() {
            let run_id = (trial * RUNS_PER_TRIAL + index) as u64;
            validate_state(state, count, run_id)?;
            validate_outcome(outcome, count)?;
            ensure!(
                outcome.compiled_blocks == 0 && outcome.disk_cache_hits == 0,
                "warm timing unexpectedly compiled or read a disk translation"
            );
            ensure!(
                outcome.memory_cache_hits == outcome.blocks_executed,
                "warm timing contains a non-memory cache dispatch"
            );
            cache.add(outcome);
        }
        ensure!(runtime.address_space() == ADDRESS_SPACE, "ASID changed");
        let ns_per_run = elapsed_ns as f64 / RUNS_PER_TRIAL as f64;
        let ns_per_dispatched_block = elapsed_ns as f64 / cache.dispatched_blocks as f64;
        trials.push(Trial {
            trial,
            runs: RUNS_PER_TRIAL,
            elapsed_ns,
            ns_per_run,
            ns_per_dispatched_block,
            cache,
        });
    }
    let mut per_run: Vec<_> = trials.iter().map(|trial| trial.ns_per_run).collect();
    per_run.sort_by(f64::total_cmp);
    let mut per_block: Vec<_> = trials
        .iter()
        .map(|trial| trial.ns_per_dispatched_block)
        .collect();
    per_block.sort_by(f64::total_cmp);
    Ok(serde_json::json!({
        "loop_count": count,
        "expected_blocks_per_run": count + 1,
        "validated_runs": TRIALS * RUNS_PER_TRIAL,
        "validated_fields_per_run": "31 GPRs, SP, NZCV, reserved, PC, stop reason, block count, final exit and cache status",
        "median_ns_per_run": per_run[TRIALS / 2],
        "median_ns_per_dispatched_block": per_block[TRIALS / 2],
        "min_ns_per_run": per_run[0],
        "max_ns_per_run": per_run[TRIALS - 1],
        "trials": trials,
    }))
}

fn main() -> Result<()> {
    ensure!(
        !cfg!(debug_assertions),
        "build this timing example with --release"
    );
    let mut arguments = std::env::args_os().skip(1);
    let cache_parent = arguments.next();
    ensure!(
        arguments.next().is_none(),
        "expected at most one cache-parent argument"
    );
    let cache = if let Some(parent) = cache_parent {
        std::fs::create_dir_all(&parent)?;
        tempfile::Builder::new()
            .prefix("stela-block-benchmark-")
            .tempdir_in(parent)?
    } else {
        tempfile::Builder::new()
            .prefix("stela-block-benchmark-")
            .tempdir()?
    };
    let mut cold_runtime = runtime(cache.path())?;
    let cold = phase(&mut cold_runtime, false)?;
    drop(cold_runtime);
    let mut warm_runtime = runtime(cache.path())?;
    let disk = phase(&mut warm_runtime, true)?;
    let mut cases = Vec::with_capacity(LOOP_COUNTS.len());
    for count in LOOP_COUNTS {
        cases.push(benchmark_case(&mut warm_runtime, count)?);
    }
    let executable = std::fs::read(std::env::current_exe()?)?;
    let report = serde_json::json!({
        "schema": 1,
        "kind": "native_basic_block_dispatch_benchmark",
        "abi": BLOCK_ABI,
        "compiler_source_sha256": stela_compiler::SOURCE_SHA256.to_owned(),
        "runtime_source_sha256": sha256(RUNTIME_SOURCE.as_bytes()),
        "benchmark_source_sha256": sha256(include_str!("block_dispatch_benchmark.rs").as_bytes()),
        "executable_sha256": sha256(&executable),
        "guest_source_sha256": sha256(&source()),
        "guest_source_words": ["f1000400", "54ffffe1", "d65f03c0"],
        "address_space": ADDRESS_SPACE,
        "entry_pc": ENTRY.0,
        "stop_pc": STOP.0,
        "final_nzcv": 0x60000000u32,
        "environment": {
            "arch": std::env::consts::ARCH,
            "os": std::env::consts::OS,
            "family": std::env::consts::FAMILY,
            "pointer_width": usize::BITS,
            "available_parallelism": std::thread::available_parallelism()?.get(),
            "debug_assertions": cfg!(debug_assertions),
            "timing_clock": "std::time::Instant",
            "cpu_affinity_or_frequency_control": "none",
        },
        "method": {
            "trials_per_count": TRIALS,
            "runs_per_trial": RUNS_PER_TRIAL,
            "warm_timing_includes": "Guest-state reset, native runtime dispatch and final-state/outcome recording",
            "warm_timing_excludes": "Vector allocation, correctness assertions, compilation and disk-cache loading",
            "overhead_subtracted": false,
            "interpreter_timing": false,
            "guest_memory_accesses": false,
            "cache": "Fresh temporary directory, automatically removed after the report",
        },
        "cold_compile_and_rx": cold,
        "new_runtime_disk_and_rx": disk,
        "warm_cases": cases,
        "limits": "Original three-instruction register-only loop. Measures the serialized native dispatcher, not complete application or macOS performance. No CPU pinning, frequency control, native-C baseline or guest fault-delivery claim.",
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
