//! Native timing of the block dispatcher over a translated counting loop.
//!
//! `cargo run --release -p stela-runtime --example block_dispatch_benchmark`
//! prints the cold compile, disk-cache load and warm dispatch costs as JSON.
use anyhow::{Result, ensure};
use std::time::Instant;
use stela_compiler::{GuestAddress, GuestState};
use stela_engine::blocks::BlockRuntime;
use stela_engine::blocks::RunOutcome;
use stela_engine::blocks::StopReason;
use stela_engine::blocks::ThreadState;

const ENTRY: GuestAddress = GuestAddress(0x10_0000);
const STOP: GuestAddress = GuestAddress(0x20_0000);
const ADDRESS_SPACE: u64 = 1;
/// `subs x0, x0, #1; b.ne ENTRY; ret`: one block per iteration plus the return.
const LOOP: [u32; 3] = [0xf100_0400, 0x54ff_ffe1, 0xd65f_03c0];
const TRIALS: usize = 7;
const RUNS_PER_TRIAL: usize = 1000;
const LOOP_COUNTS: [u64; 3] = [1, 16, 1024];
/// Final flags after `subs` reaches zero: Z and C set.
const FINAL_NZCV: u32 = 0x6000_0000;

fn runtime(cache: &std::path::Path) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new(ADDRESS_SPACE, cache.to_owned());
    let source = LOOP.iter().flat_map(|word| word.to_le_bytes()).collect();
    runtime.register_code(ENTRY, source)?;
    Ok(runtime)
}

fn run(runtime: &mut BlockRuntime, count: u64) -> Result<RunOutcome> {
    let mut registers = GuestState::default();
    registers.x[0] = count;
    registers.x[30] = STOP.0;
    let mut state = ThreadState {
        registers,
        pc: ENTRY,
    };
    // SAFETY: the loop is register-only and returns to the stop address within
    // `count + 1` blocks.
    let outcome = unsafe { runtime.run(&mut state, Some(STOP), count as usize + 1)? };
    ensure!(
        outcome.reason == StopReason::StopAddress
            && state.pc == STOP
            && state.registers.x[0] == 0
            && state.registers.nzcv == FINAL_NZCV,
        "loop finished in an unexpected state"
    );
    Ok(outcome)
}

fn timed(runtime: &mut BlockRuntime, count: u64) -> Result<u64> {
    let start = Instant::now();
    run(runtime, count)?;
    Ok(start.elapsed().as_nanos() as u64)
}

fn main() -> Result<()> {
    ensure!(
        !cfg!(debug_assertions),
        "build this benchmark with --release"
    );
    let cache = tempfile::tempdir()?;
    let cold = timed(&mut runtime(cache.path())?, 1)?;
    let mut warm = runtime(cache.path())?;
    let disk = timed(&mut warm, 1)?;
    let mut cases = vec![];
    for count in LOOP_COUNTS {
        let mut per_run: Vec<f64> = (0..TRIALS)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..RUNS_PER_TRIAL {
                    run(&mut warm, count)?;
                }
                Ok(start.elapsed().as_nanos() as f64 / RUNS_PER_TRIAL as f64)
            })
            .collect::<Result<_>>()?;
        per_run.sort_by(f64::total_cmp);
        let median = per_run[TRIALS / 2];
        cases.push(serde_json::json!({
            "loop_count": count,
            "median_ns_per_run": median,
            "median_ns_per_block": median / (count + 1) as f64,
        }));
    }
    let report = serde_json::json!({
        "cold_compile_ns": cold,
        "disk_cache_load_ns": disk,
        "warm": cases,
        "compiler_source_sha256": stela_compiler::SOURCE_SHA256,
    });
    println!("{report:#}");
    Ok(())
}
