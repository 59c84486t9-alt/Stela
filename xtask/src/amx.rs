//! AMX model fidelity: run the original corsix/amx C emulator, built for M2
//! (`AMX_VER_M2`) with FPCR.DN, on QEMU's AArch64 `virt` CPU, and compare every
//! step with Stela's Rust model.
//!
//! QEMU has no AMX, so this checks the port against corsix's hardware-compared
//! emulator, not against Apple hardware. Operands follow corsix `test.c`:
//! random 64-bit operands, with transfer operands reduced to the top byte and
//! low eight bits plus the buffer address, and 128-byte alignment for
//! multi-row transfers.
use crate::tools::{exec, root, wait};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use stela_compiler::amx::{
    AmxOperation, AmxRegisters,
    model::{self, AmxMemory, MemoryFault},
    state::REGISTER_BYTES,
};

const DRIVER: &str = include_str!("amx/reference.c");
const START: &str = include_str!("amx/start.S");
const LINKER_SCRIPT: &str = include_str!("amx/link.ld");
/// Freestanding stand-ins for the two libc headers the emulator includes.
const STRING_H: &str = "#pragma once\n#include <stddef.h>\nvoid* memcpy(void*, const void*, size_t);\nvoid* memset(void*, int, size_t);\n";
const EMULATOR_SOURCES: [&str; 10] = [
    "ldst.c", "extr.c", "fma.c", "fms.c", "genlut.c", "mac16.c", "matfp.c", "matint.c", "vecfp.c",
    "vecint.c",
];
/// The pinned research commit; `emulate.h` must match it.
const CORSIX_COMMIT: &str = "483714bb051da088d08a66724b22dd08a5db3c99";
const CLANG_TARGET: &str = "--target=aarch64-none-elf";
const ARCHITECTURE: &str = "-march=armv8.2-a+fp16";

// Layouts shared with reference.c and link.ld.
const IMAGE_ADDRESS: u64 = 0x4010_0000;
const BATCH_ADDRESS: u64 = 0x4100_0000;
const RESULTS_ADDRESS: u64 = 0x5000_0000;
const CHAINS_OFFSET: u64 = 0x1000;
const NAME_OFFSET: usize = 40;
const BUFFER_BYTES: usize = 384;
const RESULTS_NAME: &str = "amx-results.bin";
const BATCH_LIMIT: u64 = RESULTS_ADDRESS - BATCH_ADDRESS;
const RESULTS_LIMIT: u64 = 0x2000_0000;
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Args)]
pub struct AmxReference {
    /// A corsix/amx checkout at the pinned commit.
    #[arg(long)]
    corsix: PathBuf,
    /// Random register files per operation.
    #[arg(long, default_value_t = 64)]
    chains: usize,
    /// Operations applied to each register file in sequence.
    #[arg(long, default_value_t = 256)]
    steps: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Only this corsix mnemonic, such as `fma32`.
    #[arg(long)]
    operation: Option<String>,
    /// QEMU binary; defaults to `.tools/qemu/bin` or `PATH`.
    #[arg(long)]
    qemu: Option<PathBuf>,
}

/// xoshiro256++, as corsix `test.c` uses.
struct Random([u64; 4]);

impl Random {
    fn new(seed: u64) -> Self {
        let mut state = [
            0x180e_c6d3_3cfd_0aba,
            0xd5a6_1266_f0c9_392c,
            0xa958_2618_e03f_c9aa,
            0x39ab_dc45_29b1_661c,
        ];
        state[0] ^= seed;
        Self(state)
    }

    fn next(&mut self) -> u64 {
        let s = &mut self.0;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let value = self.next().to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
}

struct Buffer {
    address: u64,
    bytes: [u8; BUFFER_BYTES],
}

impl AmxMemory for Buffer {
    fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), MemoryFault> {
        let start = address.wrapping_sub(self.address) as usize;
        let source = self
            .bytes
            .get(start..start.wrapping_add(destination.len()))
            .ok_or(MemoryFault {
                address,
                write: false,
            })?;
        destination.copy_from_slice(source);
        Ok(())
    }
    fn write(&mut self, address: u64, source: &[u8]) -> Result<(), MemoryFault> {
        let start = address.wrapping_sub(self.address) as usize;
        self.bytes
            .get_mut(start..start.wrapping_add(source.len()))
            .ok_or(MemoryFault {
                address,
                write: true,
            })?
            .copy_from_slice(source);
        Ok(())
    }
}

struct Chain {
    registers: Box<AmxRegisters>,
    buffer: Buffer,
    operands: Vec<u64>,
}

fn digest(registers: &AmxRegisters, buffer: &[u8]) -> u64 {
    registers
        .as_bytes()
        .iter()
        .chain(buffer)
        .fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
}

impl AmxReference {
    pub fn run(self) -> Result<()> {
        let emulate = self.corsix.join("emulate.h");
        ensure!(
            emulate.is_file(),
            "{} is not a corsix/amx checkout",
            self.corsix.display()
        );
        let image = build_reference(&self.corsix)?;
        let qemu = match &self.qemu {
            Some(path) => path.clone(),
            None => {
                let local = root().join(".tools/qemu/bin/qemu-system-aarch64");
                if local.is_file() {
                    local
                } else {
                    crate::tools::which("qemu-system-aarch64")
                        .context("install QEMU 11 or newer")?
                }
            }
        };
        println!(
            "corsix/amx {CORSIX_COMMIT}: AMX_VER_M2, FPCR.DN, QEMU {}",
            qemu.display()
        );
        let mut failures = 0;
        for operation in AmxOperation::ALL {
            if matches!(operation, AmxOperation::Set | AmxOperation::Clear)
                || self
                    .operation
                    .as_deref()
                    .is_some_and(|name| name != operation.mnemonic())
            {
                continue;
            }
            let (steps, mismatch) = self.compare(&qemu, &image, operation)?;
            match mismatch {
                None => println!("{:7} {steps} steps match", operation.mnemonic()),
                Some(detail) => {
                    failures += 1;
                    println!("{:7} MISMATCH {detail}", operation.mnemonic());
                }
            }
        }
        if failures != 0 {
            bail!("{failures} AMX operations differ from the corsix emulator");
        }
        Ok(())
    }

    fn chains(&self, operation: AmxOperation) -> Vec<Chain> {
        let (code, _) = operation.encoding();
        let mut random = Random::new(self.seed ^ u64::from(code).rotate_left(32));
        let stride = chain_stride(self.steps);
        (0..self.chains)
            .map(|index| {
                let mut registers = Box::new(AmxRegisters::zeroed());
                random.fill(registers.as_bytes_mut());
                let mut bytes = [0; BUFFER_BYTES];
                random.fill(&mut bytes);
                let address =
                    BATCH_ADDRESS + CHAINS_OFFSET + index as u64 * stride + REGISTER_BYTES as u64;
                let operands = (0..self.steps)
                    .map(|_| {
                        let operand = random.next();
                        if !operation.accesses_memory() {
                            return operand;
                        }
                        let mut operand = operand & ((0xff << 56) | 0xff);
                        let interleaved = matches!(
                            operation,
                            AmxOperation::LoadZInterleaved | AmxOperation::StoreZInterleaved
                        );
                        if operand & (1 << 62) != 0 && !interleaved {
                            operand &= !0x7f;
                        }
                        operand + address
                    })
                    .collect();
                Chain {
                    registers,
                    buffer: Buffer { address, bytes },
                    operands,
                }
            })
            .collect()
    }

    /// Steps compared, and the first differing chain step.
    fn compare(
        &self,
        qemu: &Path,
        image: &[u8],
        operation: AmxOperation,
    ) -> Result<(usize, Option<String>)> {
        let chains = self.chains(operation);
        let results = run_reference(qemu, image, operation, &chains, self.steps)?;
        let record = self.steps * 8 + REGISTER_BYTES + BUFFER_BYTES;
        for (index, (mut chain, result)) in chains
            .into_iter()
            .zip(results.chunks_exact(record))
            .enumerate()
        {
            for step in 0..self.steps {
                let operand = chain.operands[step];
                model::execute(&mut chain.registers, operation, operand, &mut chain.buffer)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "chain {index} step {step} operand {operand:#018x}: {error:?}"
                        )
                    })?;
                let expected = u64::from_le_bytes(result[step * 8..][..8].try_into()?);
                if digest(&chain.registers, &chain.buffer.bytes) != expected {
                    let detail = self.explain(qemu, image, operation, index, step)?;
                    return Ok((
                        index * self.steps + step,
                        Some(format!(
                            "chain {index} step {step} operand {operand:#018x} {detail}"
                        )),
                    ));
                }
            }
        }
        Ok((self.chains * self.steps, None))
    }
}

impl AmxReference {
    /// Rerun one chain through `step` and list the first differing bytes.
    fn explain(
        &self,
        qemu: &Path,
        image: &[u8],
        operation: AmxOperation,
        index: usize,
        step: usize,
    ) -> Result<String> {
        let mut chain = self
            .chains(operation)
            .into_iter()
            .nth(index)
            .context("chain")?;
        chain.operands.truncate(step + 1);
        // Rerun alone, as the first chain: move transfer operands to its buffer.
        let first = BATCH_ADDRESS + CHAINS_OFFSET + REGISTER_BYTES as u64;
        if operation.accesses_memory() {
            for operand in &mut chain.operands {
                *operand = *operand - chain.buffer.address + first;
            }
        }
        chain.buffer.address = first;
        let record = run_reference(
            qemu,
            image,
            operation,
            core::slice::from_ref(&chain),
            step + 1,
        )?;
        for &operand in &chain.operands {
            let _ = model::execute(&mut chain.registers, operation, operand, &mut chain.buffer);
        }
        Ok(difference(&chain, &record[(step + 1) * 8..]))
    }
}

/// The first differing register-file or buffer bytes of a final record.
fn difference(chain: &Chain, record: &[u8]) -> String {
    let actual = chain.registers.as_bytes().iter().chain(&chain.buffer.bytes);
    let differing: Vec<String> = actual
        .zip(record)
        .enumerate()
        .filter(|(_, (model, reference))| model != reference)
        .take(8)
        .map(|(offset, (model, reference))| format!("{offset:#x}: {model:#04x}!={reference:#04x}"))
        .collect();
    format!(" ({})", differing.join(", "))
}

fn chain_stride(steps: usize) -> u64 {
    ((REGISTER_BYTES + BUFFER_BYTES + steps * 8) as u64).next_multiple_of(256)
}

fn run_reference(
    qemu: &Path,
    image: &[u8],
    operation: AmxOperation,
    chains: &[Chain],
    steps: usize,
) -> Result<Vec<u8>> {
    let stride = chain_stride(steps);
    let record = steps * 8 + REGISTER_BYTES + BUFFER_BYTES;
    ensure!(
        CHAINS_OFFSET + stride * chains.len() as u64 <= BATCH_LIMIT
            && (record * chains.len()) as u64 <= RESULTS_LIMIT,
        "AMX reference batch exceeds the harness memory"
    );
    let mut batch = vec![0u8; (CHAINS_OFFSET + stride * chains.len() as u64) as usize];
    let (code, _) = operation.encoding();
    for (index, value) in [
        chains.len() as u64,
        steps as u64,
        u64::from(code),
        RESULTS_NAME.len() as u64,
        stride,
    ]
    .into_iter()
    .enumerate()
    {
        batch[index * 8..][..8].copy_from_slice(&value.to_le_bytes());
    }
    batch[NAME_OFFSET..][..RESULTS_NAME.len()].copy_from_slice(RESULTS_NAME.as_bytes());
    for (chain, slot) in chains
        .iter()
        .zip(batch[CHAINS_OFFSET as usize..].chunks_exact_mut(stride as usize))
    {
        slot[..REGISTER_BYTES].copy_from_slice(chain.registers.as_bytes());
        slot[REGISTER_BYTES..][..BUFFER_BYTES].copy_from_slice(&chain.buffer.bytes);
        for (operand, bytes) in chain
            .operands
            .iter()
            .zip(slot[REGISTER_BYTES + BUFFER_BYTES..].as_chunks_mut::<8>().0)
        {
            bytes.copy_from_slice(&operand.to_le_bytes());
        }
    }
    let directory = tempfile::tempdir()?;
    let image_path = directory.path().join("reference.bin");
    let batch_path = directory.path().join("batch.bin");
    fs::write(&image_path, image)?;
    fs::write(&batch_path, batch)?;
    let mut child = Command::new(qemu)
        .current_dir(directory.path())
        .args(["-M", "virt", "-cpu", "max", "-m", "2G", "-smp", "1"])
        .args(["-nographic", "-monitor", "none", "-serial", "none"])
        .args(["-semihosting-config", "enable=on,target=native"])
        .arg("-device")
        .arg(format!(
            "loader,file={},addr={IMAGE_ADDRESS:#x},cpu-num=0",
            image_path.display()
        ))
        .arg("-device")
        .arg(format!(
            "loader,file={},addr={BATCH_ADDRESS:#x},force-raw=on",
            batch_path.display()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .with_context(|| format!("cannot run {}", qemu.display()))?;
    let status = wait(&mut child, TIMEOUT)?
        .context("QEMU AMX reference timed out (a faulting emulator step hangs at EL1)")?;
    ensure!(status.success(), "QEMU AMX reference failed with {status}");
    let results = fs::read(directory.path().join(RESULTS_NAME))?;
    ensure!(
        results.len() == record * chains.len(),
        "reference wrote {} bytes for {} chains",
        results.len(),
        chains.len()
    );
    Ok(results)
}

/// Compile the emulator and driver for bare-metal AArch64 and link a flat image
/// at [`IMAGE_ADDRESS`] with the toolchain's rust-lld.
fn build_reference(corsix: &Path) -> Result<Vec<u8>> {
    let directory = tempfile::tempdir()?;
    let work = directory.path();
    fs::create_dir(work.join("include"))?;
    fs::write(work.join("include/string.h"), STRING_H)?;
    fs::write(work.join("include/stdio.h"), "#pragma once\n")?;
    fs::write(work.join("reference.c"), DRIVER)?;
    fs::write(work.join("start.S"), START)?;
    fs::write(work.join("link.ld"), LINKER_SCRIPT)?;
    let clang = std::env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let mut objects = Vec::new();
    let sources = EMULATOR_SOURCES
        .iter()
        .map(|name| corsix.join(name))
        .chain([work.join("reference.c"), work.join("start.S")]);
    for source in sources {
        let object = work.join(format!(
            "{}.o",
            source.file_name().context("source name")?.to_string_lossy()
        ));
        exec(
            Command::new(&clang)
                .args([CLANG_TARGET, ARCHITECTURE, "-O2", "-ffreestanding"])
                // QEMU treats MMU-off data accesses as Device memory.
                .args(["-mstrict-align", "-fno-stack-protector"])
                .arg("-I")
                .arg(work.join("include"))
                .arg("-I")
                .arg(corsix)
                .arg("-c")
                .arg(&source)
                .arg("-o")
                .arg(&object),
        )?;
        objects.push(object);
    }
    let sysroot = String::from_utf8(
        Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args(["--print", "sysroot"])
            .output()?
            .stdout,
    )?;
    let sysroot = PathBuf::from(sysroot.trim());
    let tools = fs::read_dir(sysroot.join("lib/rustlib"))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("bin"))
        .find(|bin| bin.join("rust-lld").is_file())
        .context("the Rust toolchain has no rust-lld")?;
    let elf = work.join("reference.elf");
    exec(
        Command::new(tools.join("rust-lld"))
            // The toolchain keeps libLLVM beside rustc's own libraries.
            .env("DYLD_LIBRARY_PATH", sysroot.join("lib"))
            .env("LD_LIBRARY_PATH", sysroot.join("lib"))
            .args(["-flavor", "gnu", "-T"])
            .arg(work.join("link.ld"))
            .arg("-o")
            .arg(&elf)
            .args(&objects),
    )?;
    let image = work.join("reference.bin");
    exec(
        Command::new(tools.join("rust-objcopy"))
            .env("DYLD_LIBRARY_PATH", sysroot.join("lib"))
            .env("LD_LIBRARY_PATH", sysroot.join("lib"))
            .args(["-O", "binary"])
            .arg(&elf)
            .arg(&image),
    )?;
    Ok(fs::read(image)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xoshiro_matches_the_reference_sequence() {
        // corsix test.c seeds; the first output of xoshiro256++ from them.
        let mut random = Random::new(0);
        let first = random.next();
        let s1: u64 = 0xd5a6_1266_f0c9_392c;
        assert_eq!(first, s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9));
    }

    #[test]
    fn digest_covers_registers_and_buffer() {
        let registers = AmxRegisters::zeroed();
        let a = digest(&registers, &[0; BUFFER_BYTES]);
        let mut buffer = [0; BUFFER_BYTES];
        buffer[BUFFER_BYTES - 1] = 1;
        assert_ne!(a, digest(&registers, &buffer));
    }
}
