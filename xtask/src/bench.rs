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
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use object::read::macho::{FatArch, MachOFatFile32};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind, macho};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use stela_compiler::{GuestAddress, GuestState, TargetCpu, block::BlockProfile};
use stela_runtime::blocks::{BlockRuntime, StopReason, ThreadState};
use stela_runtime::hosted::{host::ProcessHost, pe, tables::Tables};
use stela_runtime::machine::{Chip, Machine, NoDevices, Stop};

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
pub struct Bench {
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
}

#[derive(Clone, Copy, Debug)]
enum Source {
    M1n1String,
    Dyld,
    /// A microbenchmark's words, not a program's.
    Words(&'static [u32]),
}

/// Microbenchmark loop: per iteration, two loads from X0 into X9 and X11,
/// ADD and EOR into X10, then SUBS X1 and B.NE; returns X10.
const fn micro_loop(first: u32, second: u32) -> [u32; 8] {
    const ADD_X10_X10_X9: u32 = 0x8b09_014a;
    const EOR_X10_X10_X11: u32 = 0xca0b_014a;
    const SUBS_X1_X1_ONE: u32 = 0xf100_0421;
    const B_NE_MINUS_5: u32 = 0x54ff_ff61;
    const MOV_X0_X10: u32 = 0xaa0a_03e0;
    [
        first,
        ADD_X10_X10_X9,
        second,
        EOR_X10_X10_X11,
        SUBS_X1_X1_ONE,
        B_NE_MINUS_5,
        MOV_X0_X10,
        RET,
    ]
}
/// LDR X9, [X0, #8] and LDR X11, [X0, #16].
const MICRO_DOUBLEWORD: [u32; 8] = micro_loop(0xf940_0409, 0xf940_080b);
/// LDRH W9, [X0, #2] and LDRH W11, [X0, #4].
const MICRO_HALFWORD: [u32; 8] = micro_loop(0x7940_0409, 0x7940_080b);
const MICRO_ITERATIONS: usize = 1000;

/// The input a workload passes, which decides its expected result.
#[derive(Clone, Copy, Debug)]
enum Input {
    /// memchr over `n` bytes without the byte.
    MemchrMiss(usize),
    /// strncmp of two equal `n`-byte strings, limit `n`.
    StrncmpEqual(usize),
    Atol(&'static str),
    /// lsl::Allocator::owned over a list of `n` regions none of which owns
    /// the pointer: half start above it, half end below it.
    AllocatorMiss(usize),
    /// RuntimeState::inPermanentRange over two chunks of `n` ranges, none
    /// containing the range: half start above it, half are compared fully.
    PermanentRangeMiss(usize),
    /// murmurHash over `n` bytes.
    Murmur(usize),
    /// A microbenchmark loop for `n` iterations over loads of `bytes`.
    Micro {
        iterations: usize,
        bytes: usize,
    },
}

struct Workload {
    name: &'static str,
    source: Source,
    symbol: &'static str,
    input: Input,
}

const WORKLOADS: [Workload; 10] = [
    Workload {
        name: "m1n1 memchr, 257-byte miss",
        source: Source::M1n1String,
        symbol: "_memchr",
        input: Input::MemchrMiss(257),
    },
    Workload {
        name: "m1n1 memchr, 4096-byte miss",
        source: Source::M1n1String,
        symbol: "_memchr",
        input: Input::MemchrMiss(4096),
    },
    Workload {
        name: "m1n1 strncmp, 257 equal bytes",
        source: Source::M1n1String,
        symbol: "_strncmp",
        input: Input::StrncmpEqual(257),
    },
    Workload {
        name: "m1n1 atol, 19 digits",
        source: Source::M1n1String,
        symbol: "_atol",
        input: Input::Atol("1234567890123456789"),
    },
    Workload {
        name: "dyld lsl::Allocator::owned, 64-region list",
        source: Source::Dyld,
        symbol: "__ZNK3lsl9Allocator5ownedEPKvy",
        input: Input::AllocatorMiss(64),
    },
    Workload {
        name: "dyld RuntimeState::inPermanentRange, 2x64 ranges",
        source: Source::Dyld,
        symbol: "__ZN5dyld412RuntimeState16inPermanentRangeEmmPhPPKNS_6LoaderE",
        input: Input::PermanentRangeMiss(64),
    },
    Workload {
        name: "dyld murmurHash, 1027 bytes",
        source: Source::Dyld,
        symbol: "__Z10murmurHashPKviy",
        input: Input::Murmur(1027),
    },
    Workload {
        name: "dyld murmurHash, 64 bytes",
        source: Source::Dyld,
        symbol: "__Z10murmurHashPKviy",
        input: Input::Murmur(64),
    },
    Workload {
        name: "micro: LDR X offset loop, 1000 iterations",
        source: Source::Words(&MICRO_DOUBLEWORD),
        symbol: "",
        input: Input::Micro {
            iterations: MICRO_ITERATIONS,
            bytes: 8,
        },
    },
    Workload {
        name: "micro: LDRH offset loop, 1000 iterations",
        source: Source::Words(&MICRO_HALFWORD),
        symbol: "",
        input: Input::Micro {
            iterations: MICRO_ITERATIONS,
            bytes: 2,
        },
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Engine {
    Hosted,
    Blocks,
}

const ENGINES: [Engine; 2] = [Engine::Hosted, Engine::Blocks];

impl Engine {
    fn name(self) -> &'static str {
        match self {
            Self::Hosted => "hosted",
            Self::Blocks => "blocks",
        }
    }
}

impl Bench {
    pub fn run(self) -> Result<()> {
        ensure!(
            !cfg!(debug_assertions),
            "time a release build: cargo run --release --locked -p xtask -- bench"
        );
        if let Some(fixtures) = &self.worker {
            return worker(fixtures, &self.calls, self.target_ms, self.round);
        }
        let fixtures = self.fixtures()?;
        let me = std::env::current_exe()?;
        let calls = calibrate(&me, &fixtures, self.target_ms)?;
        let mut samples: BTreeMap<(String, &str), Vec<Value>> = BTreeMap::new();
        for round in 0..self.rounds {
            let mut builds = vec![("candidate", me.as_path())];
            if let Some(baseline) = &self.baseline {
                builds.push(("baseline", baseline.as_path()));
                if round % 2 == 1 {
                    builds.reverse();
                }
            }
            for (build, executable) in builds {
                for line in run_worker(executable, &fixtures, &calls, self.target_ms, round)? {
                    let key = line["key"].as_str().context("key")?.to_owned();
                    samples.entry((key, build)).or_default().push(line);
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
                "calls": calls,
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

fn arm64e_slice(file: &[u8]) -> Result<&[u8]> {
    let fat = MachOFatFile32::parse(file)?;
    for arch in fat.arches() {
        if arch.cputype() == macho::CPU_TYPE_ARM64
            && arch.cpusubtype() & !macho::CPU_SUBTYPE_MASK == macho::CPU_SUBTYPE_ARM64E
        {
            return Ok(arch.data(file)?);
        }
    }
    bail!("no arm64e slice")
}

/// The bytes of `symbol`, up to the next symbol of its section, refusing
/// any relocation inside them.
fn function(data: &[u8], symbol: &str) -> Result<Vec<u8>> {
    let file = object::File::parse(data)?;
    let found = file
        .symbols()
        .find(|candidate| candidate.name() == Ok(symbol))
        .with_context(|| format!("no symbol {symbol}"))?;
    let section = file.section_by_index(found.section_index().context("undefined symbol")?)?;
    let start = found.address();
    let end = file
        .symbols()
        .filter(|other| {
            other.section_index() == found.section_index()
                && other.address() > start
                && matches!(other.kind(), SymbolKind::Text | SymbolKind::Label)
        })
        .map(|other| other.address())
        .min()
        .unwrap_or(section.address() + section.size());
    let offset = |address: u64| (address - section.address()) as usize;
    ensure!(
        section
            .relocations()
            .all(|(at, _)| !(start..end).contains(&(section.address() + at))),
        "{symbol} has relocations"
    );
    let bytes = section.data()?[offset(start)..offset(end)].to_vec();
    ensure!(
        bytes.len() % 4 == 0 && bytes.ends_with(&RET.to_le_bytes()),
        "{symbol} does not end in RET"
    );
    Ok(bytes)
}

fn calibrate(me: &Path, fixtures: &Path, target_ms: u64) -> Result<Vec<u64>> {
    run_worker(me, fixtures, &[], target_ms, 0)?
        .iter()
        .map(|line| line["calls"].as_u64().context("calls"))
        .collect()
}

fn run_worker(
    executable: &Path,
    fixtures: &Path,
    calls: &[u64],
    target_ms: u64,
    round: usize,
) -> Result<Vec<Value>> {
    let mut command = Command::new(executable);
    command
        .arg("bench")
        .arg("--worker")
        .arg(fixtures)
        .arg("--target-ms")
        .arg(target_ms.to_string())
        .arg("--round")
        .arg(round.to_string());
    if !calls.is_empty() {
        let list: Vec<String> = calls.iter().map(u64::to_string).collect();
        command.arg("--calls").arg(list.join(","));
    }
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{} worker failed: {}",
        executable.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
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
        "{:<50} {:>6} {:>11} {:>11} {:>9} {:>9} {:>5} {:>5}",
        "workload", "engine", "base ns", "cand ns", "cpu red.", "wall red.", "wins", "code"
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
        let (mut base_ns, mut cpu_reduction, mut wall_reduction, mut wins) =
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
            wall_reduction = reduction("wall_ns");
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
            entry["paired_wall_reduction"] = json!(wall_reduction);
            entry["cpu_wins"] = json!(wins);
        }
        let (name, engine) = key.rsplit_once(" / ").unwrap_or((key, ""));
        println!(
            "{name:<50} {engine:>6} {base_ns:>11.1} {cpu:>11.1} {:>8.2}% {:>8.2}% {:>5} {code:>5}",
            cpu_reduction * 100.0,
            wall_reduction * 100.0,
            format!("{wins}/{}", candidate.len()),
        );
        summary.push(entry);
    }
    Ok(summary)
}

/// Where every arena is mapped, so that code placement, pointers and final
/// states are the same in every worker and build.
const ARENA: u64 = 0x7_0000_0000;

/// Host memory a workload's function and data live in: guest addresses are
/// host addresses in both engines.
struct Arena {
    base: *mut u8,
    bytes: usize,
}

impl Arena {
    fn new(bytes: usize) -> Result<Self> {
        let bytes = bytes.next_multiple_of(PAGE);
        // SAFETY: a fresh private anonymous mapping owned by this value, at
        // a hint only, so nothing else is replaced.
        let base = unsafe {
            libc::mmap(
                ARENA as *mut libc::c_void,
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        ensure!(base != libc::MAP_FAILED, "cannot map the bench arena");
        if base as u64 != ARENA {
            // SAFETY: the mapping just made.
            unsafe { libc::munmap(base, bytes) };
            bail!("the bench arena's address {ARENA:#x} is in use");
        }
        Ok(Self {
            base: base.cast(),
            bytes,
        })
    }

    fn address(&self, offset: usize) -> u64 {
        assert!(offset < self.bytes);
        self.base as u64 + offset as u64
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.bytes);
        // SAFETY: inside the mapping.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.base.add(offset), data.len()) };
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        self.write(offset, &value.to_le_bytes());
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: the mapping this value owns.
        unsafe { libc::munmap(self.base.cast(), self.bytes) };
    }
}

const CODE: usize = 0;
const STOP: usize = PAGE - 4;
/// The hosted engine's padding function, below the stack.
const PADDING: usize = PAGE;
/// Padding instructions: round times the step, modulo the span.
const PADDING_STEP: usize = 7;
const PADDING_SPAN: usize = 32;
const STACK_TOP: usize = 2 * PAGE;
const DATA: usize = 2 * PAGE;

/// The arena, initial state and expected X0 of one workload.
fn prepare(input: Input, code: &[u8]) -> Result<(Arena, GuestState, u64)> {
    ensure!(code.len() < STOP, "function larger than its page");
    let mut arena = Arena::new(DATA + 64 * PAGE)?;
    arena.write(CODE, code);
    // Never executed: the run stops at its breakpoint first.
    arena.write(STOP, &0u32.to_le_bytes());
    let mut state = GuestState::default();
    state.x[30] = arena.address(STOP);
    state.sp = arena.address(STACK_TOP);
    let data = arena.address(DATA);
    let expected = match input {
        Input::MemchrMiss(bytes) => {
            arena.write(DATA, &vec![b'a'; bytes]);
            state.x[..3].copy_from_slice(&[data, u64::from(b'z'), bytes as u64]);
            0
        }
        Input::StrncmpEqual(bytes) => {
            let text = vec![b'a'; bytes];
            arena.write(DATA, &text);
            arena.write(DATA + PAGE, &text);
            state.x[..3].copy_from_slice(&[data, data + PAGE as u64, bytes as u64]);
            0
        }
        Input::Atol(text) => {
            arena.write(DATA, text.as_bytes());
            state.x[0] = data;
            text.parse::<i64>()? as u64
        }
        Input::AllocatorMiss(regions) => {
            // Region: next at 0x10, start at 0x20, size at 0x28.
            const NODE: usize = 0x40;
            const POINTER: u64 = 0x10_0000;
            let first = DATA + NODE;
            arena.write_u64(DATA + 8, arena.address(first));
            for index in 0..regions {
                let node = first + index * NODE;
                let next = if index + 1 == regions {
                    0
                } else {
                    arena.address(node + NODE)
                };
                let (start, size) = if index % 2 == 0 {
                    (POINTER + 0x1000, 0x100)
                } else {
                    (0x1000, 0x100)
                };
                arena.write_u64(node + 0x10, next);
                arena.write_u64(node + 0x20, start);
                arena.write_u64(node + 0x28, size);
            }
            state.x[..3].copy_from_slice(&[data, POINTER, 0x10]);
            0
        }
        Input::PermanentRangeMiss(ranges) => {
            // State: chunk list at 0x468. Chunk: next at 0, count at 8,
            // 32-byte ranges (start, end, ...) from 0x10.
            const START: u64 = 0x8000;
            let chunks = [DATA + PAGE, DATA + 2 * PAGE];
            arena.write_u64(DATA + 0x468, arena.address(chunks[0]));
            for (index, &chunk) in chunks.iter().enumerate() {
                let next = chunks.get(index + 1).map_or(0, |&next| arena.address(next));
                arena.write_u64(chunk, next);
                arena.write_u64(chunk + 8, ranges as u64);
                for range in 0..ranges {
                    let entry = chunk + 0x10 + range * 0x20;
                    let start = if range % 2 == 0 { START + 1 } else { 0x1000 };
                    arena.write_u64(entry, start);
                    arena.write_u64(entry + 8, 0x2000);
                }
            }
            state.x[..3].copy_from_slice(&[data, START, u64::MAX]);
            0
        }
        Input::Murmur(bytes) => {
            let text: Vec<u8> = (0..bytes).map(|index| (index * 131 + 7) as u8).collect();
            arena.write(DATA, &text);
            const SEED: u64 = 0x5bd1_e995_1234_5678;
            state.x[..3].copy_from_slice(&[data, bytes as u64, SEED]);
            murmur(&text, SEED)
        }
        Input::Micro { iterations, bytes } => {
            let (first, second) = (0x0123_4567_89ab_cdef_u64, 0xfedc_ba98_7654_3210_u64);
            let mask = u64::MAX >> (64 - 8 * bytes);
            arena.write_u64(DATA + bytes, first);
            arena.write_u64(DATA + 2 * bytes, second);
            let (first, second) = (first & mask, second & mask);
            state.x[..2].copy_from_slice(&[data, iterations as u64]);
            (0..iterations).fold(0u64, |sum, _| sum.wrapping_add(first) ^ second)
        }
    };
    Ok((arena, state, expected))
}

/// dyld's `murmurHash(const void*, int, uint64_t)`, as its 26A434 code
/// computes it (MurmurHash64A, multiplying once more before the
/// finalization).
fn murmur(data: &[u8], seed: u64) -> u64 {
    const M: u64 = 0xc6a4_a793_5bd1_e995;
    const R: u32 = 47;
    let mut hash = (data.len() as i64 as u64).wrapping_mul(M) ^ seed;
    let (blocks, tail) = data.split_at(data.len() / 8 * 8);
    for block in blocks.as_chunks::<8>().0 {
        let mut k = u64::from_le_bytes(*block).wrapping_mul(M);
        k ^= k >> R;
        hash ^= k.wrapping_mul(M);
        hash = hash.wrapping_mul(M);
    }
    for (index, &byte) in tail.iter().enumerate() {
        hash ^= u64::from(byte) << (8 * index);
    }
    hash = hash.wrapping_mul(M);
    hash ^= hash >> R;
    hash = hash.wrapping_mul(M);
    hash ^ (hash >> R)
}

fn state_digest(state: &GuestState) -> String {
    let mut bytes = vec![];
    for value in state.x.iter().chain([&state.sp]) {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(state.nzcv.to_le_bytes());
    stela_runtime::sha256(&bytes)
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

/// One prepared function in one engine.
trait Runner {
    /// Run one call from `state`; the final state and executed blocks.
    fn call(&mut self, state: &GuestState) -> Result<(GuestState, u64)>;
    /// The bytes and digest of the native code it runs, where the engine
    /// tells.
    fn native(&self) -> Option<(usize, String)>;
}

struct Hosted {
    machine: Box<Machine<ProcessHost, NoDevices>>,
    entry: u64,
    stop: u64,
    /// The native bytes and digest of the function's blocks.
    native: (usize, String),
}

/// The code the hosted engine compiles for `code` at `entry`: every block
/// statically reachable from the entry, compiled as the engine compiles
/// them, in the system-mode profile with the checks of the hosted PE's
/// SCTLR_EL1 at EL0 (SA0 set, A and nAA clear).
fn hosted_code(code: &[u8], entry: u64) -> Result<(usize, String)> {
    use stela_compiler::block::{CompilationPlan, analyze_with_profile};
    use stela_compiler::x86_64::MemoryChecks;
    let checks = MemoryChecks::system(true, false, true);
    let target = TargetCpu::detect();
    let mut seen = std::collections::BTreeSet::new();
    let mut pending = vec![entry];
    let (mut bytes, mut digests) = (0, String::new());
    while let Some(pc) = pending.pop() {
        if !(entry..entry + code.len() as u64).contains(&pc) || !seen.insert(pc) {
            continue;
        }
        let source = &code[(pc - entry) as usize..];
        let analysis = analyze_with_profile(source, GuestAddress(pc), BlockProfile::SystemModeV1)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let compiled =
            CompilationPlan::new(source, GuestAddress(pc), BlockProfile::SystemModeV1, target)
                .and_then(|plan| plan.with_memory_checks(checks))
                .and_then(CompilationPlan::compile)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        bytes += compiled.native.x86_64_code.len();
        digests.push_str(&stela_runtime::sha256(&compiled.native.x86_64_code));
        pending.extend(
            analysis
                .static_successors
                .iter()
                .map(|successor| successor.target.0),
        );
    }
    Ok((bytes, stela_runtime::sha256(digests.as_bytes())))
}

impl Hosted {
    /// The engine, its code arena already holding the code of a padding
    /// function the round sizes: the hosted engine places each block after
    /// the last, so this spreads the workload's code over different
    /// alignments in different rounds, the same in both builds.
    fn new(entry: u64, stop: u64, code: &[u8], arena: &mut Arena, round: usize) -> Result<Self> {
        let chip = Chip::AppleM2;
        let target = TargetCpu::detect();
        let tables = Arc::new(Tables::new()?);
        let keys = pe::Keys::random()?;
        let cpu = pe::user_thread(chip, entry, &tables, &keys);
        let mut machine = Box::new(Machine::new(
            cpu,
            ProcessHost::new(tables)?,
            NoDevices,
            pe::profile(chip, target),
            target,
        ));
        let mut breakpoints = pe::vectors().to_vec();
        breakpoints.push(stop);
        machine.set_breakpoints(&breakpoints);
        let mut hosted = Self {
            machine,
            entry: arena.address(PADDING),
            stop,
            native: hosted_code(code, entry)?,
        };
        const ADD_X0_ONE: u32 = 0x9100_0400;
        let padding: Vec<u8> = std::iter::repeat_n(ADD_X0_ONE, round * PADDING_STEP % PADDING_SPAN)
            .chain([RET])
            .flat_map(u32::to_le_bytes)
            .collect();
        arena.write(PADDING, &padding);
        let mut state = GuestState::default();
        state.x[30] = stop;
        hosted.call(&state)?;
        hosted.entry = entry;
        Ok(hosted)
    }
}

impl Runner for Hosted {
    fn call(&mut self, state: &GuestState) -> Result<(GuestState, u64)> {
        let blocks = self.machine.statistics.blocks;
        self.machine.cpu.state = state.clone();
        self.machine.cpu.pc = self.entry;
        match self.machine.run(0) {
            Stop::Breakpoint(pc) if pc == self.stop => {}
            stop => bail!(
                "hosted run stopped with {stop:?} at {:#x}",
                self.machine.cpu.pc
            ),
        }
        Ok((
            self.machine.cpu.state.clone(),
            self.machine.statistics.blocks - blocks,
        ))
    }

    fn native(&self) -> Option<(usize, String)> {
        Some(self.native.clone())
    }
}

struct Blocks {
    runtime: BlockRuntime,
    entry: u64,
    stop: u64,
    code_bytes: usize,
    _cache: tempfile::TempDir,
}

impl Blocks {
    fn new(entry: u64, stop: u64, code: &[u8]) -> Result<Self> {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE,
            cache.path().to_owned(),
            BlockProfile::Ordinary,
            TargetCpu::detect(),
        );
        runtime.register_code(GuestAddress(entry), code.to_vec())?;
        Ok(Self {
            runtime,
            entry,
            stop,
            code_bytes: code.len(),
            _cache: cache,
        })
    }
}

impl Runner for Blocks {
    fn call(&mut self, state: &GuestState) -> Result<(GuestState, u64)> {
        let mut thread = ThreadState {
            registers: state.clone(),
            pc: GuestAddress(self.entry),
        };
        // SAFETY: the unchanged function reads only the arena's prepared
        // inputs and returns to the stop address.
        let outcome = unsafe {
            self.runtime
                .run(&mut thread, Some(GuestAddress(self.stop)), usize::MAX)?
        };
        ensure!(
            outcome.reason == StopReason::StopAddress,
            "block run stopped with {:?}",
            outcome.reason
        );
        Ok((thread.registers, outcome.blocks_executed as u64))
    }

    fn native(&self) -> Option<(usize, String)> {
        let manifests: Vec<_> = (0..self.code_bytes as u64)
            .step_by(4)
            .filter_map(|offset| {
                self.runtime
                    .loaded_manifest(GuestAddress(self.entry + offset))
            })
            .collect();
        let digests: String = manifests
            .iter()
            .map(|manifest| manifest.native_sha256.as_str())
            .collect();
        Some((
            manifests.iter().map(|manifest| manifest.native_bytes).sum(),
            stela_runtime::sha256(digests.as_bytes()),
        ))
    }
}

/// Time every fixture in both engines once, or calibrate when `calls` is
/// empty, printing one JSON line each.
fn worker(fixtures: &Path, calls: &[u64], target_ms: u64, round: usize) -> Result<()> {
    let fixtures: Vec<Value> = serde_json::from_slice(&std::fs::read(fixtures)?)?;
    let mut next = calls.iter();
    for fixture in &fixtures {
        let workload = &WORKLOADS[fixture["index"].as_u64().context("index")? as usize];
        let code = unhex(fixture["code"].as_str().context("code")?)?;
        for engine in ENGINES {
            let (mut arena, state, expected) = prepare(workload.input, &code)?;
            let entry = arena.address(CODE);
            let stop = arena.address(STOP);
            let mut runner: Box<dyn Runner> = match engine {
                Engine::Hosted => Box::new(Hosted::new(entry, stop, &code, &mut arena, round)?),
                Engine::Blocks => Box::new(Blocks::new(entry, stop, &code)?),
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
