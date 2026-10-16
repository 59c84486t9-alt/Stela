//! Inspect and time the native AMX kernels: bytes and instructions per kernel
//! and tier, a check that the FMA tier emits no EVEX, and nanoseconds per
//! operation for each tier the host supports against the Rust model. Time with
//! a release build: `cargo run --release -p xtask -- amx-kernels`.
use crate::tools::{exec, which};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use stela_compiler::{
    TargetCpu,
    amx::{AmxRegisters, model},
    x86_64::amx::{Kernel, Library, Shape, Tier},
};

const TIERS: [Tier; 2] = [Tier::Fma, Tier::Avx512];
/// Distinct operands per kernel, cycled while timing.
const OPERANDS: usize = 64;

#[derive(Args)]
pub struct AmxKernels {
    /// Calls per kernel and tier when timing.
    #[arg(long, default_value_t = 20_000)]
    iterations: u32,
    /// Print each kernel's disassembly.
    #[arg(long)]
    listing: bool,
    /// LLVM disassembler; defaults to `llvm-objdump` on `PATH` or from Xcode.
    #[arg(long)]
    objdump: Option<PathBuf>,
}

impl AmxKernels {
    pub fn run(self) -> Result<()> {
        if cfg!(debug_assertions) {
            println!("debug build: timings are not representative");
        }
        let objdump = self.objdump.or_else(objdump);
        let host = TargetCpu::detect();
        let directory = tempfile::tempdir()?;
        println!(
            "{:<34} {:>6} {:>6} {:>6} {:>6}",
            "kernel", "fma B", "insns", "avx512", "insns"
        );
        let libraries = TIERS.map(Library::new);
        let mut listings = Vec::new();
        for kernel in Kernel::ALL {
            let mut row = format!("{:<34}", name(kernel));
            for library in &libraries {
                let offset = library.offset(kernel);
                let bytes = &library.code[offset..offset + library.kernel_bytes(kernel)];
                let instructions = match &objdump {
                    Some(objdump) => {
                        let listing = disassemble(objdump, &directory, bytes)?;
                        if library.tier == Tier::Fma {
                            ensure!(
                                !listing.contains("zmm") && !listing.contains("{k"),
                                "FMA-tier kernel {} uses EVEX:\n{listing}",
                                name(kernel)
                            );
                        }
                        ensure!(
                            !listing.contains("unknown"),
                            "undecodable bytes:\n{listing}"
                        );
                        if self.listing {
                            listings.push(format!(
                                "{} {}:\n{listing}\n",
                                library.tier.name(),
                                name(kernel)
                            ));
                        }
                        listing.lines().count().to_string()
                    }
                    None => "-".to_owned(),
                };
                row.push_str(&format!(" {:>6} {:>6}", bytes.len(), instructions));
            }
            println!("{row}");
        }
        for library in &libraries {
            println!(
                "{} library: {} bytes ({} kernels on 64-byte boundaries)",
                library.tier.name(),
                library.code.len(),
                Kernel::ALL.len()
            );
        }
        for listing in listings {
            println!("{listing}");
        }
        if objdump.is_none() {
            println!("llvm-objdump not found: instruction counts and the EVEX check were skipped");
        }
        println!();
        println!(
            "{:<34} {:>9} {:>9} {:>9}",
            "ns/op", "model", "fma", "avx512"
        );
        let executables = libraries
            .iter()
            .map(|library| {
                host.supports(library.tier.requires())
                    .then(|| Executable::new(&library.code))
                    .transpose()
            })
            .collect::<Result<Vec<_>>>()?;
        let registers_for_gather = AmxRegisters::zeroed();
        for kernel in Kernel::ALL {
            let operands = operands(kernel);
            let mut registers = AmxRegisters::zeroed();
            for (index, byte) in registers.as_bytes_mut().iter_mut().enumerate() {
                // Finite, normal values in both precisions.
                *byte = if index % 4 == 3 {
                    0x3f
                } else {
                    (index * 7) as u8
                };
            }
            let model = time(self.iterations, |index| {
                let operand = operands[index % OPERANDS];
                model::execute(&mut registers, kernel.operation(), operand, &mut NoMemory)
                    .expect("register-only operation");
            });
            let mut row = format!("{:<34} {:>9.1}", name(kernel), model);
            for (library, executable) in libraries.iter().zip(&executables) {
                let Some(executable) = executable else {
                    row.push_str(&format!(" {:>9}", "absent"));
                    continue;
                };
                let entry = executable.entry(library.offset(kernel));
                let gathered = operands.map(|operand| {
                    (
                        registers.x_operand((operand >> 10) & 0x1ff),
                        registers.y_operand(operand & 0x1ff),
                        (operand >> 20) & 63,
                    )
                });
                let native = time(self.iterations, |index| {
                    let (x, y, row) = &gathered[index % OPERANDS];
                    // SAFETY: the kernel ABI: 4 KiB Z, 64-byte X and Y.
                    unsafe {
                        entry(
                            registers.z.as_mut_ptr().cast(),
                            x.as_ptr(),
                            y.as_ptr(),
                            *row,
                        )
                    };
                });
                row.push_str(&format!(" {native:>9.1}"));
            }
            println!("{row}");
        }
        let gather_operands = operands(Kernel::ALL[0]);
        let gather = time(self.iterations, |index| {
            let operand = gather_operands[index % OPERANDS];
            std::hint::black_box((
                registers_for_gather.x_operand((operand >> 10) & 0x1ff),
                registers_for_gather.y_operand(operand & 0x1ff),
            ));
        });
        println!("X/Y operand gather before a native call: {gather:.1} ns");
        Ok(())
    }
}

fn name(kernel: Kernel) -> String {
    format!(
        "{} {}{}",
        kernel.operation().mnemonic(),
        match kernel.shape {
            Shape::Matrix => "matrix",
            Shape::Vector => "vector",
        },
        if kernel.product_only {
            " product-only"
        } else {
            ""
        }
    )
}

fn objdump() -> Option<PathBuf> {
    which("llvm-objdump").or_else(|| {
        let output = Command::new("xcrun")
            .args(["-f", "llvm-objdump"])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
    })
}

/// One line per instruction. The bytes are wrapped in an ELF object with the
/// C compiler's assembler, since not every `llvm-objdump` reads raw binaries.
fn disassemble(objdump: &PathBuf, directory: &tempfile::TempDir, bytes: &[u8]) -> Result<String> {
    let source = directory.path().join("kernel.s");
    let object = directory.path().join("kernel.o");
    let data = bytes
        .iter()
        .map(|byte| format!("{byte:#04x}"))
        .collect::<Vec<_>>()
        .join(",");
    fs::write(&source, format!(".text\n.byte {data}\n"))?;
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "clang".into());
    exec(
        Command::new(compiler)
            .args(["--target=x86_64-unknown-linux-gnu", "-c", "-o"])
            .arg(&object)
            .arg(&source),
    )?;
    let output = Command::new(objdump)
        .args([
            "-d",
            "--no-show-raw-insn",
            "--no-leading-addr",
            "-M",
            "intel",
        ])
        .arg(&object)
        .output()
        .with_context(|| format!("cannot run {}", objdump.display()))?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = String::from_utf8(output.stdout)?;
    let body = listing.split_once("<.text>:").map_or("", |(_, body)| body);
    Ok(body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Operands with random offsets and rows that select `kernel`.
fn operands(kernel: Kernel) -> [u64; OPERANDS] {
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    core::array::from_fn(|_| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let operand = (seed & 0x1ff)
            | ((seed >> 9) & 0x1ff) << 10
            | ((seed >> 18) & 63) << 20
            | u64::from(kernel.product_only) << 27
            | u64::from(kernel.shape == Shape::Vector) << 63;
        debug_assert_eq!(
            stela_compiler::x86_64::amx::select(kernel.operation(), operand),
            Some(kernel)
        );
        operand
    })
}

/// Mean nanoseconds per call over `iterations`, after a warm-up.
fn time(iterations: u32, mut call: impl FnMut(usize)) -> f64 {
    for index in 0..OPERANDS * 16 {
        call(index);
    }
    let start = Instant::now();
    for index in 0..iterations as usize {
        call(index);
    }
    let elapsed: Duration = start.elapsed();
    elapsed.as_nanos() as f64 / f64::from(iterations)
}

struct NoMemory;

impl model::AmxMemory for NoMemory {
    fn read(&mut self, address: u64, _: &mut [u8]) -> Result<(), model::MemoryFault> {
        Err(model::MemoryFault {
            address,
            write: false,
        })
    }
    fn write(&mut self, address: u64, _: &[u8]) -> Result<(), model::MemoryFault> {
        Err(model::MemoryFault {
            address,
            write: true,
        })
    }
}

type Entry = unsafe extern "sysv64" fn(*mut u8, *const u8, *const u8, u64);

/// A private RX copy of a kernel library.
struct Executable {
    pointer: *mut libc::c_void,
    length: usize,
}

impl Executable {
    fn new(code: &[u8]) -> Result<Self> {
        // SAFETY: fresh private anonymous RW memory, made RX after the copy.
        unsafe {
            let pointer = libc::mmap(
                core::ptr::null_mut(),
                code.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            ensure!(
                pointer != libc::MAP_FAILED,
                "{}",
                std::io::Error::last_os_error()
            );
            let executable = Self {
                pointer,
                length: code.len(),
            };
            core::ptr::copy_nonoverlapping(code.as_ptr(), pointer.cast(), code.len());
            ensure!(
                libc::mprotect(pointer, code.len(), libc::PROT_READ | libc::PROT_EXEC) == 0,
                "{}",
                std::io::Error::last_os_error()
            );
            Ok(executable)
        }
    }

    fn entry(&self, offset: usize) -> Entry {
        assert!(offset < self.length);
        // SAFETY: the offset starts a kernel inside the RX mapping.
        unsafe { core::mem::transmute(self.pointer.cast::<u8>().add(offset)) }
    }
}

impl Drop for Executable {
    fn drop(&mut self) {
        // SAFETY: the mapping is owned and no entry outlives `run`.
        unsafe { libc::munmap(self.pointer, self.length) };
    }
}
