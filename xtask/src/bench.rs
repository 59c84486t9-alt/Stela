//! `cargo xtask bench`: time unchanged real-program functions in the two
//! process engines, against a baseline build.
//!
//! The functions are extracted, never rewritten: m1n1's `string.c` compiled
//! by clang for arm64 with m1n1's own flags, and leaf functions of the
//! 26A434 arm64e `dyld`. Each runs in the hosted engine (the system-mode
//! `Machine` PE at EL0 over the identity stage 1, as hosted processes run)
//! and in the ordinary block runtime (`BlockRuntime`, the `stela execute`
//! path), from a fixed state, until it returns to a breakpoint. Two
//! microbenchmark loops, named as such, isolate single load forms.
//!
//! A worker process times every workload once for given call counts and
//! prints one JSON line each. With `--baseline` (another build's xtask
//! executable), the driver calibrates equal call counts once, then runs the
//! baseline and this build's workers in alternating order for each round,
//! checks that both agree on every result and final register state, and
//! reports paired medians. Preparation and compilation stay outside the
//! clocks; state reset, dispatch and the return stay inside, with nothing
//! subtracted. Both clocks are kept: thread CPU time and monotonic wall time.
//!
//! Two builds also differ in the layout of the runtime's own code, which
//! moves the engines' timings by itself. So each build also dumps the native
//! blocks both engines compile, and this build's workers run either build's
//! blocks under one minimal dispatcher (engines `n-blocks` and `n-hosted`),
//! where only the native code differs.
//!
//! `bench hosted` ([`hosted`]) instead times whole same-source programs,
//! natively and as hosted processes.
mod engines;
mod fixtures;
mod hosted;

use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use engines::{Blocks, Hosted, Native, NativeBlock, Profile, Runner, compile_blocks};
use fixtures::{
    ARENA, CODE, STOP, Source, WORKLOADS, arm64e_slice, function, prepare, state_digest,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use stela_compiler::TargetCpu;

const M1N1: &str = ".stela/agx-work/src/m1n1";
const DYLD: &str = ".stela/26A434-guest-files/usr/lib/dyld";
const WORK: &str = ".stela/bench/functions";
/// m1n1's `BASE_CFLAGS` and `CFLAGS`, for an arm64 Mach-O object.
const M1N1_FLAGS: [&str; 13] = [
    "-target",
    "arm64-apple-macos13",
    "-O2",
    "-ffreestanding",
    "-fno-common",
    "-fpic",
    "-ffunction-sections",
    "-fdata-sections",
    "-nostdinc",
    "-fno-stack-protector",
    "-mstrict-align",
    "-march=armv8.2-a",
    "-mgeneral-regs-only",
];
const PAGE: usize = 16384;
const RET: u32 = 0xd65f_03c0;
const ADDRESS_SPACE: u64 = 1;

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Bench {
    #[command(subcommand)]
    command: Option<BenchCommand>,
    /// Another build's xtask executable to compare against.
    #[arg(long)]
    baseline: Option<PathBuf>,
    #[arg(long, default_value_t = 9)]
    rounds: usize,
    /// Calibrated length of each timed batch.
    #[arg(long, default_value_t = 20)]
    target_ms: u64,
    /// m1n1 source tree.
    #[arg(long)]
    m1n1: Option<PathBuf>,
    /// The 26A434 dyld.
    #[arg(long)]
    dyld: Option<PathBuf>,
    /// Write the raw samples and summary as JSON here.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Worker: time the workloads of this fixture file once.
    #[arg(long, hide = true)]
    worker: Option<PathBuf>,
    /// Worker: calls per workload and engine, in order; none calibrates.
    #[arg(long, hide = true, value_delimiter = ',')]
    calls: Vec<u64>,
    /// Worker: the round, which places the hosted engine's code.
    #[arg(long, hide = true, default_value_t = 0)]
    round: usize,
    /// Worker: write the native blocks both engines compile here instead.
    #[arg(long, hide = true)]
    dump_native: Option<PathBuf>,
    /// Worker: run the native blocks of this dump instead of the engines.
    #[arg(long, hide = true)]
    native_code: Option<PathBuf>,
}

#[derive(Subcommand)]
enum BenchCommand {
    /// Time same-source C programs natively and as hosted processes, with
    /// the hosted/native ratio per kernel.
    Hosted(Box<hosted::HostedBench>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Engine {
    Hosted,
    Blocks,
    /// A build's blocks-engine code under the bench's dispatcher.
    NativeBlocks,
    /// A build's hosted-engine code under the bench's dispatcher.
    NativeHosted,
}

impl Engine {
    fn name(self) -> &'static str {
        match self {
            Self::Hosted => "hosted",
            Self::Blocks => "blocks",
            Self::NativeBlocks => "n-blocks",
            Self::NativeHosted => "n-hosted",
        }
    }

    /// The compilation a native engine runs.
    fn profile(self) -> Option<Profile> {
        match self {
            Self::NativeBlocks => Some(Profile::Ordinary),
            Self::NativeHosted => Some(Profile::System),
            Self::Hosted | Self::Blocks => None,
        }
    }
}

const PROCESS_ENGINES: [Engine; 2] = [Engine::Hosted, Engine::Blocks];
const NATIVE_ENGINES: [Engine; 2] = [Engine::NativeBlocks, Engine::NativeHosted];

/// What a worker runs.
#[derive(Clone, Copy)]
enum Mode<'a> {
    Process,
    /// The native blocks of a dump.
    Native(&'a Path),
}

impl Bench {
    pub fn run(self) -> Result<()> {
        if let Some(BenchCommand::Hosted(task)) = self.command {
            return task.run();
        }
        ensure!(
            !cfg!(debug_assertions),
            "time a release build: cargo run --release --locked -p xtask -- bench"
        );
        if let Some(fixtures) = &self.worker {
            if let Some(path) = &self.dump_native {
                return dump_native(fixtures, path);
            }
            let mode = self
                .native_code
                .as_deref()
                .map_or(Mode::Process, Mode::Native);
            return worker(fixtures, mode, &self.calls, self.target_ms, self.round);
        }
        let fixtures = self.fixtures()?;
        let me = std::env::current_exe()?;
        let work = root().join(WORK);
        let mut builds = vec![("candidate", me.clone(), work.join("native-candidate.json"))];
        if let Some(baseline) = &self.baseline {
            builds.push((
                "baseline",
                baseline.clone(),
                work.join("native-baseline.json"),
            ));
        }
        for (_, executable, dump) in &builds {
            let status = Command::new(executable)
                .arg("bench")
                .arg("--worker")
                .arg(&fixtures)
                .arg("--dump-native")
                .arg(dump)
                .status()?;
            ensure!(
                status.success(),
                "{} failed to dump native blocks",
                executable.display()
            );
        }
        let process = Worker {
            executable: &me,
            fixtures: &fixtures,
            native: None,
            target_ms: self.target_ms,
        };
        let process_calls = process.calibrate()?;
        let native_calls = Worker {
            native: Some(&builds[0].2),
            ..process
        }
        .calibrate()?;
        let mut samples: BTreeMap<(String, &str), Vec<Value>> = BTreeMap::new();
        for round in 0..self.rounds {
            let mut order: Vec<_> = builds.iter().collect();
            if round % 2 == 1 {
                order.reverse();
            }
            for (build, executable, dump) in order {
                let runs = [
                    (
                        Worker {
                            executable,
                            ..process
                        },
                        &process_calls,
                    ),
                    (
                        Worker {
                            native: Some(dump),
                            ..process
                        },
                        &native_calls,
                    ),
                ];
                for (worker, calls) in runs {
                    for line in worker.run(calls, round)? {
                        let key = line["key"].as_str().context("key")?.to_owned();
                        samples.entry((key, *build)).or_default().push(line);
                    }
                }
            }
        }
        let summary = summarize(&samples, self.baseline.is_some())?;
        if let Some(path) = &self.report {
            let raw: Vec<Value> = samples
                .iter()
                .map(|((key, build), lines)| json!({"key": key, "build": build, "samples": lines}))
                .collect();
            let report = json!({
                "rounds": self.rounds,
                "target_ms": self.target_ms,
                "calls": process_calls,
                "native_calls": native_calls,
                "target": TargetCpu::detect().id(),
                "summary": summary,
                "raw": raw,
            });
            std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
        }
        Ok(())
    }

    /// Extract each workload's function and write the fixture file the
    /// workers share.
    fn fixtures(&self) -> Result<PathBuf> {
        let work = root().join(WORK);
        std::fs::create_dir_all(&work)?;
        let m1n1 = self.m1n1.clone().unwrap_or_else(|| root().join(M1N1));
        let dyld = self.dyld.clone().unwrap_or_else(|| root().join(DYLD));
        let object = work.join("m1n1-string.o");
        let include = String::from_utf8(
            Command::new("clang")
                .arg("-print-file-name=include")
                .output()?
                .stdout,
        )?;
        let status = Command::new("clang")
            .args(M1N1_FLAGS)
            .arg("-isystem")
            .arg(include.trim())
            .arg("-isystem")
            .arg(m1n1.join("sysinc"))
            .arg("-I")
            .arg(m1n1.join("src"))
            .arg("-c")
            .arg(m1n1.join("src/string.c"))
            .arg("-o")
            .arg(&object)
            .status()?;
        ensure!(status.success(), "clang failed on m1n1 string.c");
        let object = std::fs::read(&object)?;
        let dyld_file = std::fs::read(&dyld).with_context(|| dyld.display().to_string())?;
        let dyld_slice = arm64e_slice(&dyld_file)?;
        let mut fixtures = vec![];
        for (index, workload) in WORKLOADS.iter().enumerate() {
            let (code, origin) = match workload.source {
                Source::M1n1String => (
                    function(&object, workload.symbol)?,
                    "m1n1 src/string.c, clang -O2 arm64",
                ),
                Source::Dyld => (
                    function(dyld_slice, workload.symbol)?,
                    "26A434 /usr/lib/dyld arm64e",
                ),
                Source::Words(words) => (
                    words.iter().flat_map(|word| word.to_le_bytes()).collect(),
                    "microbenchmark",
                ),
            };
            fixtures.push(json!({
                "index": index,
                "name": workload.name,
                "symbol": workload.symbol,
                "origin": origin,
                "code": hex(&code),
                "code_sha256": stela_runtime::sha256(&code),
            }));
        }
        let path = work.join("fixtures.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&fixtures)?)?;
        Ok(path)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&text[at..at + 2], 16)?))
        .collect()
}

/// One worker invocation: an executable over the fixtures, timing its own
/// engines or, with `native`, a dump's native blocks.
#[derive(Clone, Copy)]
struct Worker<'a> {
    executable: &'a Path,
    fixtures: &'a Path,
    native: Option<&'a Path>,
    target_ms: u64,
}

impl Worker<'_> {
    fn calibrate(self) -> Result<Vec<u64>> {
        self.run(&[], 0)?
            .iter()
            .map(|line| line["calls"].as_u64().context("calls"))
            .collect()
    }

    fn run(self, calls: &[u64], round: usize) -> Result<Vec<Value>> {
        let mut command = Command::new(self.executable);
        command
            .arg("bench")
            .arg("--worker")
            .arg(self.fixtures)
            .arg("--target-ms")
            .arg(self.target_ms.to_string())
            .arg("--round")
            .arg(round.to_string());
        if let Some(dump) = self.native {
            command.arg("--native-code").arg(dump);
        }
        if !calls.is_empty() {
            let list: Vec<String> = calls.iter().map(u64::to_string).collect();
            command.arg("--calls").arg(list.join(","));
        }
        let output = command.output()?;
        ensure!(
            output.status.success(),
            "{} worker failed: {}",
            self.executable.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)?
            .lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    }
}

/// Write the native blocks both engines compile for every fixture, at its
/// arena's code address.
fn dump_native(fixtures: &Path, path: &Path) -> Result<()> {
    let fixtures: Vec<Value> = serde_json::from_slice(&std::fs::read(fixtures)?)?;
    let mut dump = vec![];
    for fixture in &fixtures {
        let code = unhex(fixture["code"].as_str().context("code")?)?;
        let entry = ARENA + CODE as u64;
        let mut profiles = json!({"index": fixture["index"]});
        for engine in NATIVE_ENGINES {
            let profile = engine.profile().context("native engine")?;
            let blocks: Vec<Value> = compile_blocks(&code, entry, profile)?
                .into_iter()
                .map(|block| {
                    json!({
                        "pc": block.pc - entry,
                        "code": hex(&block.code),
                        "resident": block.resident,
                    })
                })
                .collect();
            profiles[engine.name()] = json!(blocks);
        }
        dump.push(profiles);
    }
    std::fs::write(path, serde_json::to_vec(&dump)?)?;
    Ok(())
}

/// The blocks a dump holds for one fixture and native engine.
fn dumped_blocks(
    dump: &[Value],
    index: u64,
    engine: Engine,
    entry: u64,
) -> Result<Vec<NativeBlock>> {
    let fixture = dump
        .iter()
        .find(|fixture| fixture["index"].as_u64() == Some(index))
        .context("fixture missing from the native dump")?;
    fixture[engine.name()]
        .as_array()
        .context("native engine missing from the dump")?
        .iter()
        .map(|block| {
            Ok(NativeBlock {
                pc: entry + block["pc"].as_u64().context("pc")?,
                code: unhex(block["code"].as_str().context("code")?)?,
                resident: block["resident"].as_bool().context("resident")?,
            })
        })
        .collect()
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn per_call(line: &Value, clock: &str) -> f64 {
    line[clock].as_f64().unwrap_or_default() / line["calls"].as_f64().unwrap_or(1.0)
}

fn summarize(samples: &BTreeMap<(String, &str), Vec<Value>>, paired: bool) -> Result<Vec<Value>> {
    let keys: Vec<&String> = samples
        .keys()
        .filter(|(_, build)| *build == "candidate")
        .map(|(key, _)| key)
        .collect();
    let mut summary = vec![];
    println!(
        "{:<50} {:>8} {:>11} {:>11} {:>9} {:>9} {:>5} {:>5}",
        "workload", "engine", "base ns", "cand ns", "cpu red.", "best red.", "wins", "code"
    );
    for key in keys {
        let candidate = &samples[&(key.clone(), "candidate")];
        let first = &candidate[0];
        for line in candidate {
            ensure!(
                line["result"] == first["result"] && line["state"] == first["state"],
                "{key}: candidate runs disagree"
            );
        }
        let cpu = median(
            candidate
                .iter()
                .map(|line| per_call(line, "cpu_ns"))
                .collect(),
        );
        let mut entry = json!({
            "key": key,
            "result": first["result"],
            "blocks_per_call": first["blocks_per_call"],
            "native_bytes": first["native_bytes"],
            "native_sha256": first["native_sha256"],
            "candidate_cpu_ns": cpu,
            "candidate_wall_ns": median(candidate.iter().map(|line| per_call(line, "wall_ns")).collect()),
        });
        let (mut base_ns, mut cpu_reduction, mut best_reduction, mut wins) =
            (f64::NAN, f64::NAN, f64::NAN, 0);
        // Whether the builds ran the same native code, where the engine tells.
        let mut code = "?";
        if paired {
            let baseline = &samples[&(key.clone(), "baseline")];
            for line in baseline {
                ensure!(
                    line["result"] == first["result"] && line["state"] == first["state"],
                    "{key}: baseline and candidate disagree"
                );
            }
            let reduction = |clock: &str| {
                median(
                    baseline
                        .iter()
                        .zip(candidate)
                        .map(|(b, c)| 1.0 - per_call(c, clock) / per_call(b, clock))
                        .collect(),
                )
            };
            base_ns = median(
                baseline
                    .iter()
                    .map(|line| per_call(line, "cpu_ns"))
                    .collect(),
            );
            cpu_reduction = reduction("cpu_ns");
            // Other load on the host only adds time, so each build's best
            // round is its least disturbed one.
            let best = |lines: &[Value]| {
                lines
                    .iter()
                    .map(|line| per_call(line, "cpu_ns"))
                    .fold(f64::INFINITY, f64::min)
            };
            best_reduction = 1.0 - best(candidate) / best(baseline);
            wins = baseline
                .iter()
                .zip(candidate)
                .filter(|(b, c)| per_call(c, "cpu_ns") < per_call(b, "cpu_ns"))
                .count();
            entry["baseline_cpu_ns"] = json!(base_ns);
            entry["baseline_native_bytes"] = baseline[0]["native_bytes"].clone();
            entry["baseline_native_sha256"] = baseline[0]["native_sha256"].clone();
            if !first["native_sha256"].is_null() {
                code = if baseline[0]["native_sha256"] == first["native_sha256"] {
                    "same"
                } else {
                    "diff"
                };
            }
            entry["paired_cpu_reduction"] = json!(cpu_reduction);
            entry["paired_wall_reduction"] = json!(reduction("wall_ns"));
            entry["best_cpu_reduction"] = json!(best_reduction);
            entry["cpu_wins"] = json!(wins);
        }
        let (name, engine) = key.rsplit_once(" / ").unwrap_or((key, ""));
        println!(
            "{name:<50} {engine:>8} {base_ns:>11.1} {cpu:>11.1} {:>8.2}% {:>8.2}% {:>5} {code:>5}",
            cpu_reduction * 100.0,
            best_reduction * 100.0,
            format!("{wins}/{}", candidate.len()),
        );
        summary.push(entry);
    }
    Ok(summary)
}

fn thread_cpu_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid timespec out-parameter.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

/// Time every fixture in each engine of `mode` once, or calibrate when
/// `calls` is empty, printing one JSON line each.
fn worker(fixtures: &Path, mode: Mode, calls: &[u64], target_ms: u64, round: usize) -> Result<()> {
    let fixtures: Vec<Value> = serde_json::from_slice(&std::fs::read(fixtures)?)?;
    let (engines, dump): (_, Vec<Value>) = match mode {
        Mode::Process => (PROCESS_ENGINES, vec![]),
        Mode::Native(path) => (
            NATIVE_ENGINES,
            serde_json::from_slice(&std::fs::read(path)?)?,
        ),
    };
    let mut next = calls.iter();
    for fixture in &fixtures {
        let index = fixture["index"].as_u64().context("index")?;
        let workload = &WORKLOADS[index as usize];
        let code = unhex(fixture["code"].as_str().context("code")?)?;
        for engine in engines {
            let (mut arena, state, expected) = prepare(workload.input, &code)?;
            let entry = arena.address(CODE);
            let stop = arena.address(STOP);
            let mut runner: Box<dyn Runner> = match engine {
                Engine::Hosted => Box::new(Hosted::new(entry, stop, &code, &mut arena, round)?),
                Engine::Blocks => Box::new(Blocks::new(entry, stop, &code)?),
                Engine::NativeBlocks | Engine::NativeHosted => Box::new(Native::new(
                    &dumped_blocks(&dump, index, engine, entry)?,
                    entry,
                    stop,
                    round,
                )?),
            };
            // Translation and the first dispatches stay outside the clocks.
            let (result, blocks) = runner.call(&state)?;
            ensure!(
                result.x[0] == expected,
                "{} in {}: X0 {:#x}, expected {expected:#x}",
                workload.name,
                engine.name(),
                result.x[0]
            );
            let timed = |runner: &mut Box<dyn Runner>, calls: u64| -> Result<(u64, u64)> {
                let (cpu, wall) = (thread_cpu_ns(), Instant::now());
                for _ in 0..calls {
                    runner.call(&state)?;
                }
                Ok((thread_cpu_ns() - cpu, wall.elapsed().as_nanos() as u64))
            };
            let count = match next.next() {
                Some(&count) => count,
                None if calls.is_empty() => {
                    let mut count = 16;
                    while timed(&mut runner, count)?.1 < target_ms * 1_000_000 {
                        count *= 2;
                    }
                    count
                }
                None => bail!("fewer call counts than workloads"),
            };
            timed(&mut runner, count / 8 + 1)?;
            let (cpu_ns, wall_ns) = timed(&mut runner, count)?;
            let (last, _) = runner.call(&state)?;
            ensure!(
                last == result,
                "{}: state changed across calls",
                workload.name
            );
            let line = json!({
                "key": format!("{} / {}", workload.name, engine.name()),
                "calls": count,
                "cpu_ns": cpu_ns,
                "wall_ns": wall_ns,
                "result": format!("{:#x}", result.x[0]),
                "state": state_digest(&result),
                "blocks_per_call": blocks,
                "native_bytes": runner.native().map(|(bytes, _)| bytes),
                "native_sha256": runner.native().map(|(_, digest)| digest),
                "code_sha256": fixture["code_sha256"],
            });
            println!("{line}");
        }
    }
    Ok(())
}
