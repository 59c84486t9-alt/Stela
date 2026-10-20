//! `cargo xtask bench hosted`: same-source C workloads, built for x86_64,
//! arm64 and arm64e by `xcrun clang` at bench time, run natively and as
//! hosted Darwin processes (`stela run`), with the ratio per kernel.
//!
//! Each program times its own kernels with CLOCK_MONOTONIC and prints one
//! `stela-bench KERNEL SECONDS CHECKSUM [NOTE]` line per kernel
//! (`hosted/bench.h`), so process startup, dyld and translation of code
//! outside the kernel stay out of the kernel times; the whole process's
//! wall time is kept separately. Every build's checksum must equal the
//! native one. Rounds run every variant of a program back to back, rotating
//! their order, so each round's hosted/native ratio pairs runs under the
//! same host load; the summary reports the median of those paired ratios
//! and their range as the noise.
use crate::tools::{root, wait};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const WORK: &str = ".stela/bench/hosted";
const ROOTS: [&str; 2] = [".stela/26A434-guest-files", ".stela/26A434-shared-cache"];
/// Every build: same flags but the architecture. FP contraction is off so
/// that fused and unfused targets round alike and checksums compare.
const CFLAGS: [&str; 2] = ["-O2", "-ffp-contract=off"];
const HEADER: (&str, &str) = ("bench.h", include_str!("hosted/bench.h"));

/// A program of the suite and the kernels it reports.
struct Program {
    name: &'static str,
    source: &'static str,
    kernels: &'static [&'static str],
    libraries: &'static [&'static str],
}

const PROGRAMS: [Program; 8] = [
    Program {
        name: "sha256",
        source: include_str!("hosted/sha256.c"),
        kernels: &["sha256-scalar"],
        libraries: &[],
    },
    Program {
        name: "ccsha256",
        source: include_str!("hosted/ccsha256.c"),
        kernels: &["commoncrypto-sha256"],
        libraries: &[],
    },
    Program {
        name: "bits",
        source: include_str!("hosted/bits.c"),
        kernels: &["crc32-bitwise", "bit-twiddle"],
        libraries: &[],
    },
    Program {
        name: "qsort",
        source: include_str!("hosted/qsort.c"),
        kernels: &["qsort-10m"],
        libraries: &[],
    },
    Program {
        name: "zlib",
        source: include_str!("hosted/zlib.c"),
        kernels: &["zlib-deflate", "zlib-inflate"],
        libraries: &["-lz"],
    },
    Program {
        name: "strings",
        source: include_str!("hosted/strings.c"),
        kernels: &["memcpy-mixed", "string-ops"],
        libraries: &[],
    },
    Program {
        name: "fp",
        source: include_str!("hosted/fp.c"),
        kernels: &["nbody-scalar", "matmul-neon", "matmul-scalar"],
        libraries: &[],
    },
    Program {
        name: "interp",
        source: include_str!("hosted/interp.c"),
        kernels: &["interpreter"],
        libraries: &[],
    },
];

#[derive(Args)]
pub struct HostedBench {
    /// Rounds; each runs every variant of every program once.
    #[arg(long, default_value_t = 5)]
    rounds: usize,
    /// Work per kernel in percent of the default (about 0.05 to 1 s native).
    #[arg(long, default_value_t = 100)]
    scale: u32,
    /// Programs to run (default: all), by name: sha256, ccsha256, bits,
    /// qsort, zlib, strings, fp, interp.
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Guest architectures to run hosted.
    #[arg(long, value_delimiter = ',', default_value = "arm64,arm64e")]
    arch: Vec<String>,
    /// The `stela` executable; by default this target directory's release
    /// build, built first.
    #[arg(long)]
    stela: Option<PathBuf>,
    /// Another `stela` build to run interleaved with the candidate, for a
    /// before/after comparison.
    #[arg(long)]
    baseline: Option<PathBuf>,
    /// Guest system roots (default: the 26A434 guest files and shared cache).
    #[arg(long)]
    root: Vec<PathBuf>,
    /// Seconds before one run is stopped.
    #[arg(long, default_value_t = 900)]
    timeout: u64,
    /// Write the raw samples and summary as JSON here.
    #[arg(long)]
    report: Option<PathBuf>,
}

/// How one run executes a program build.
#[derive(Clone, Debug)]
struct Variant {
    /// `native`, or the guest architecture with the stela build's label.
    label: String,
    arch: &'static str,
    stela: Option<PathBuf>,
}

/// One run's kernel lines and process wall time.
struct Run {
    kernels: Vec<(String, f64, String, String)>,
    wall: f64,
}

impl HostedBench {
    pub fn run(self) -> Result<()> {
        ensure!(self.rounds > 0, "at least one round");
        let programs: Vec<&Program> = PROGRAMS
            .iter()
            .filter(|program| self.only.is_empty() || self.only.iter().any(|n| n == program.name))
            .collect();
        ensure!(!programs.is_empty(), "no program named {:?}", self.only);
        for arch in &self.arch {
            ensure!(
                matches!(arch.as_str(), "arm64" | "arm64e"),
                "unknown guest architecture {arch}"
            );
        }
        let stela = match &self.stela {
            Some(path) => path.clone(),
            None => build_stela()?,
        };
        let roots = if self.root.is_empty() {
            ROOTS.iter().map(|path| root().join(path)).collect()
        } else {
            self.root.clone()
        };
        // Resolve symlinks: guest paths resolve beneath the real root.
        let roots: Vec<PathBuf> = roots
            .iter()
            .map(|path| {
                path.canonicalize()
                    .with_context(|| format!("guest root {}", path.display()))
            })
            .collect::<Result<_>>()?;
        let work = root().join(WORK);
        std::fs::create_dir_all(&work)?;
        let compiler = compiler_version()?;
        let mut variants = vec![Variant {
            label: "native".into(),
            arch: "x86_64",
            stela: None,
        }];
        let mut stelas = vec![("candidate", stela)];
        if let Some(baseline) = &self.baseline {
            stelas.push(("baseline", baseline.clone()));
        }
        for (build, path) in &stelas {
            for arch in &self.arch {
                let arch = if arch == "arm64" { "arm64" } else { "arm64e" };
                variants.push(Variant {
                    label: if self.baseline.is_some() {
                        format!("{arch}-{build}")
                    } else {
                        arch.into()
                    },
                    arch,
                    stela: Some(path.clone()),
                });
            }
        }
        let mut builds = vec![];
        for program in &programs {
            builds.push(build_program(&work, program, &variants)?);
        }
        let started = Instant::now();
        // (kernel, variant) -> per-round seconds; (program, variant) -> wall.
        let mut seconds: BTreeMap<(&str, String), Vec<f64>> = BTreeMap::new();
        let mut walls: BTreeMap<(&str, String), Vec<f64>> = BTreeMap::new();
        let mut checksums: BTreeMap<&str, String> = BTreeMap::new();
        let mut notes: BTreeMap<(&str, String), String> = BTreeMap::new();
        for round in 0..self.rounds {
            for (program, binaries) in programs.iter().zip(&builds) {
                let mut order: Vec<usize> = (0..variants.len()).collect();
                order.rotate_left(round % variants.len());
                for index in order {
                    let variant = &variants[index];
                    let run = self
                        .execute(&work, variant, &binaries[index], &roots)
                        .with_context(|| format!("{} {}", program.name, variant.label))?;
                    for &kernel in program.kernels {
                        let (_, time, checksum, note) = run
                            .kernels
                            .iter()
                            .find(|line| line.0 == kernel)
                            .with_context(|| {
                                format!("{} {}: no {kernel} line", program.name, variant.label)
                            })?;
                        let expected = checksums.entry(kernel).or_insert_with(|| checksum.clone());
                        ensure!(
                            expected == checksum,
                            "{kernel} {}: checksum {checksum}, expected {expected}",
                            variant.label
                        );
                        seconds
                            .entry((kernel, variant.label.clone()))
                            .or_default()
                            .push(*time);
                        if !note.is_empty() {
                            notes.insert((kernel, variant.label.clone()), note.clone());
                        }
                    }
                    walls
                        .entry((program.name, variant.label.clone()))
                        .or_default()
                        .push(run.wall);
                }
            }
            eprintln!(
                "round {}/{} done after {:.0} s",
                round + 1,
                self.rounds,
                started.elapsed().as_secs_f64()
            );
        }
        let summary = summarize(&programs, &variants, &seconds, &walls, &notes);
        if let Some(path) = &self.report {
            let raw: Vec<Value> = seconds
                .iter()
                .map(|((kernel, variant), samples)| {
                    json!({"kernel": kernel, "variant": variant, "seconds": samples})
                })
                .collect();
            let wall: Vec<Value> = walls
                .iter()
                .map(|((program, variant), samples)| {
                    json!({"program": program, "variant": variant, "seconds": samples})
                })
                .collect();
            let report = json!({
                "rounds": self.rounds,
                "scale": self.scale,
                "compiler": compiler,
                "cflags": CFLAGS,
                "host": host_identity(),
                "stela": stelas.iter().map(|(build, path)| json!({
                    "build": build,
                    "path": path,
                    "sha256": std::fs::read(path).map(|bytes| stela_runtime::sha256(&bytes)).ok(),
                })).collect::<Vec<_>>(),
                "programs": programs.iter().map(|program| json!({
                    "name": program.name,
                    "source_sha256": stela_runtime::sha256(program.source.as_bytes()),
                })).collect::<Vec<_>>(),
                "checksums": checksums,
                "summary": summary,
                "raw": raw,
                "process_wall": wall,
            });
            std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
        }
        Ok(())
    }

    /// Run one build of a program once.
    fn execute(
        &self,
        work: &Path,
        variant: &Variant,
        binary: &Path,
        roots: &[PathBuf],
    ) -> Result<Run> {
        let mut command = match &variant.stela {
            None => Command::new(binary),
            Some(stela) => {
                let mut command = Command::new(stela);
                command.arg("run");
                for root in roots {
                    command.arg("--root").arg(root);
                }
                command.arg(binary);
                command
            }
        };
        command.arg(self.scale.to_string());
        // Files, not pipes: a chatty failure cannot fill a pipe and stall.
        let stdout = work.join("run.stdout");
        let stderr = work.join("run.stderr");
        command
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout)?)
            .stderr(std::fs::File::create(&stderr)?);
        let start = Instant::now();
        let mut child = command
            .spawn()
            .with_context(|| format!("cannot start {:?}", command.get_program()))?;
        let status = wait(&mut child, Duration::from_secs(self.timeout))?;
        let wall = start.elapsed().as_secs_f64();
        let output = std::fs::read_to_string(&stdout)?;
        let Some(status) = status else {
            bail!("stopped after {} s", self.timeout);
        };
        if !status.success() {
            let errors = std::fs::read_to_string(&stderr).unwrap_or_default();
            let tail: Vec<&str> = errors.lines().rev().take(20).collect();
            bail!(
                "exited with {status}: {}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
        let mut kernels = vec![];
        for line in output.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("stela-bench") {
                continue;
            }
            let kernel = fields.next().context("kernel name")?.to_owned();
            let time: f64 = fields.next().context("seconds")?.parse()?;
            let checksum = fields.next().context("checksum")?.to_owned();
            let note = fields.collect::<Vec<_>>().join(" ");
            kernels.push((kernel, time, checksum, note));
        }
        Ok(Run { kernels, wall })
    }
}

/// Build this target directory's release `stela` and return its path.
fn build_stela() -> Result<PathBuf> {
    // This executable lives in TARGET/{debug,release}/.
    let me = std::env::current_exe()?;
    let target = me
        .parent()
        .and_then(Path::parent)
        .context("the target directory of this executable")?
        .to_owned();
    crate::tools::exec(
        crate::tools::cargo()
            .args([
                "build",
                "--release",
                "--locked",
                "-p",
                "stela-cli",
                "--target-dir",
            ])
            .arg(&target),
    )?;
    Ok(target.join("release/stela"))
}

fn compiler_version() -> Result<String> {
    let output = Command::new("xcrun")
        .args(["clang", "--version"])
        .output()?;
    ensure!(output.status.success(), "xcrun clang --version failed");
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned())
}

fn host_identity() -> Value {
    let sysctl = |name: &str| {
        Command::new("sysctl")
            .args(["-n", name])
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    json!({
        "cpu": sysctl("machdep.cpu.brand_string"),
        "os": sysctl("kern.osproductversion"),
        "load_average": sysctl("vm.loadavg"),
        "target": stela_compiler::TargetCpu::detect().id(),
    })
}

/// Compile `program` once per architecture its variants need; the binary of
/// each variant, in their order.
fn build_program(work: &Path, program: &Program, variants: &[Variant]) -> Result<Vec<PathBuf>> {
    let directory = work.join(program.name);
    std::fs::create_dir_all(&directory)?;
    std::fs::write(directory.join(HEADER.0), HEADER.1)?;
    let source = directory.join(format!("{}.c", program.name));
    std::fs::write(&source, program.source)?;
    let mut built = BTreeMap::new();
    let mut binaries = vec![];
    for variant in variants {
        let binary = directory.join(format!("{}-{}", program.name, variant.arch));
        if built.insert(variant.arch, ()).is_none() {
            let status = Command::new("xcrun")
                .arg("clang")
                .args(CFLAGS)
                .args(["-arch", variant.arch])
                .arg(&source)
                .args(program.libraries)
                .arg("-o")
                .arg(&binary)
                .status()?;
            ensure!(
                status.success(),
                "xcrun clang failed on {} for {}",
                program.name,
                variant.arch
            );
        }
        binaries.push(binary);
    }
    Ok(binaries)
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

/// Print and return the per-kernel medians and paired ratios.
fn summarize(
    programs: &[&Program],
    variants: &[Variant],
    seconds: &BTreeMap<(&str, String), Vec<f64>>,
    walls: &BTreeMap<(&str, String), Vec<f64>>,
    notes: &BTreeMap<(&str, String), String>,
) -> Vec<Value> {
    let guests = &variants[1..];
    let mut header = format!("{:<22} {:>9}", "kernel", "native s");
    for variant in guests {
        header += &format!(
            " {:>16} {:>17}",
            format!("{} s", variant.label),
            "ratio (range)"
        );
    }
    println!("{header}");
    let mut summary = vec![];
    for program in programs {
        for &kernel in program.kernels {
            let native = &seconds[&(kernel, "native".to_owned())];
            let mut line = format!("{kernel:<22} {:>9.3}", median(native.clone()));
            let mut entry = json!({
                "kernel": kernel,
                "program": program.name,
                "native_seconds": median(native.clone()),
            });
            for variant in guests {
                let hosted = &seconds[&(kernel, variant.label.clone())];
                let ratios: Vec<f64> = hosted.iter().zip(native).map(|(h, n)| h / n).collect();
                let low = ratios.iter().copied().fold(f64::INFINITY, f64::min);
                let high = ratios.iter().copied().fold(0.0, f64::max);
                let ratio = median(ratios);
                line += &format!(
                    " {:>16.3} {:>17}",
                    median(hosted.clone()),
                    format!("{ratio:.2}x ({low:.2}-{high:.2})")
                );
                entry[&variant.label] = json!({
                    "seconds": median(hosted.clone()),
                    "ratio": ratio,
                    "ratio_low": low,
                    "ratio_high": high,
                    "note": notes.get(&(kernel, variant.label.clone())),
                });
            }
            println!("{line}");
            summary.push(entry);
        }
    }
    // A candidate/baseline pair: the paired reduction per kernel.
    let pairs: Vec<(&Variant, &Variant)> = guests
        .iter()
        .filter_map(|candidate| {
            let arch = candidate.label.strip_suffix("-candidate")?;
            let baseline = guests
                .iter()
                .find(|variant| variant.label == format!("{arch}-baseline"))?;
            Some((candidate, baseline))
        })
        .collect();
    if !pairs.is_empty() {
        println!();
        let mut header = format!("{:<22}", "kernel");
        for (candidate, _) in &pairs {
            header += &format!(" {:>28}", format!("{} vs baseline", candidate.arch));
        }
        println!("{header}");
        for (entry, kernel) in summary
            .iter_mut()
            .zip(programs.iter().flat_map(|program| program.kernels))
        {
            let mut line = format!("{kernel:<22}");
            for (candidate, baseline) in &pairs {
                let c = &seconds[&(*kernel, candidate.label.clone())];
                let b = &seconds[&(*kernel, baseline.label.clone())];
                let reduction = median(c.iter().zip(b).map(|(c, b)| 1.0 - c / b).collect());
                let wins = c.iter().zip(b).filter(|(c, b)| c < b).count();
                line += &format!(
                    " {:>28}",
                    format!("{:+.1}% ({wins}/{} wins)", reduction * 100.0, c.len())
                );
                entry[format!("{}_reduction", candidate.arch)] = json!(reduction);
                entry[format!("{}_wins", candidate.arch)] = json!(wins);
            }
            println!("{line}");
        }
    }
    println!();
    println!("process wall time (startup, dyld and translation included):");
    for program in programs {
        let mut line = format!("{:<22}", program.name);
        for variant in variants {
            let wall = median(walls[&(program.name, variant.label.clone())].clone());
            line += &format!(" {}={wall:.2}s", variant.label);
        }
        println!("{line}");
    }
    summary
}
