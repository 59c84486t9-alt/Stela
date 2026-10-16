//! Differential oracle: run original AArch64 code on QEMU and Stela's native
//! translation of the same code, from identical state and memory.
//!
//! The reference is QEMU's `max` CPU in a bare-metal EL0 harness. Code runs from
//! [`CODE_PAGE`] and may access only the [`DATA_WINDOW`] and the code region;
//! both engines see the same guest addresses. A case that faults on QEMU is reported but never run
//! natively, because direct-RAM native code has no fault recovery.
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use stela_compiler::GuestState;

pub mod native;

/// Guest address of the page that holds each case's code. The zero-filled
/// [`CODE_REGION_BYTES`] starting at [`CODE_REGION`] surround it, so PC-relative
/// literals within 1 MiB stay mapped.
pub const CODE_PAGE: u64 = 0x2_0020_0000;
pub const CODE_REGION: u64 = 0x2_0000_0000;
pub const CODE_REGION_BYTES: usize = 0x40_0000;
/// Guest address of the only memory EL0 code may read or write.
pub const DATA_WINDOW: u64 = 0x2_0800_0000;
pub const DATA_BYTES: usize = 0x4000;
/// Instructions per case, excluding the closing SVC the harness appends.
pub const MAX_WORDS: usize = 120;
/// Cases per QEMU run; bounded by the batch area below the data window.
pub const MAX_BATCH: usize = 4096;

const HARNESS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/harness.bin"));
const HARNESS_ADDRESS: u64 = 0x4010_0000;
const BATCH_ADDRESS: u64 = 0x4100_0000;
const RESULTS_NAME: &str = "results.bin";

// Batch and record layouts; these match `harness.S`.
const BATCH_COUNT: usize = 0;
const BATCH_NAME_BYTES: usize = 8;
const BATCH_NAME: usize = 16;
const BATCH_CASES: usize = 0x1000;
const CASE_WORDS: usize = 0;
const CASE_CODE: usize = 16;
const CASE_STATE: usize = 512;
const CASE_DATA: usize = 0x1000;
const CASE_BYTES: usize = 0x5000;
const RESULT_SP: usize = 248;
const RESULT_SPSR: usize = 256;
const RESULT_FPCR: usize = 264;
const RESULT_FPSR: usize = 272;
const RESULT_ESR: usize = 280;
const RESULT_ELR: usize = 288;
const RESULT_FAR: usize = 296;
const RESULT_V: usize = 320;
const RESULT_DATA: usize = 0x400;
const RESULT_BYTES: usize = 0x4400;

const NZCV_MASK: u32 = 0xf000_0000;
const ESR_CLASS_SHIFT: u64 = 26;
const ESR_CLASS_SVC64: u64 = 0x15;
const INSTRUCTION_BYTES: u64 = 4;

/// One instruction sequence with its initial guest state and data window.
#[derive(Clone)]
pub struct Case {
    pub code: Vec<u32>,
    pub state: GuestState,
    pub data: Box<[u8]>,
}

/// Final architectural state after a case, from either engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub state: GuestState,
    pub data: Box<[u8]>,
    pub exception: Option<Exception>,
}

/// An exception taken before the case reached its closing SVC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exception {
    pub syndrome: u64,
    pub address: u64,
    pub fault_address: u64,
}

/// A QEMU binary able to run the harness.
pub struct Oracle {
    qemu: PathBuf,
}

impl Oracle {
    /// Use an explicit `qemu-system-aarch64`.
    pub fn new(qemu: &Path) -> Result<Self> {
        Ok(Self {
            qemu: qemu
                .canonicalize()
                .with_context(|| format!("cannot find {}", qemu.display()))?,
        })
    }

    /// `qemu-system-aarch64` from `tools` when present, otherwise from `PATH`.
    pub fn locate(tools: &Path) -> Result<Self> {
        let local = tools.join("qemu-system-aarch64");
        let qemu = if local.is_file() {
            local.canonicalize()?
        } else {
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|directory| directory.join("qemu-system-aarch64"))
                .find(|path| path.is_file())
                .context("install QEMU with qemu-system-aarch64")?
        };
        Ok(Self { qemu })
    }

    /// Run every case on QEMU, in order.
    pub fn run(&self, cases: &[Case]) -> Result<Vec<Outcome>> {
        let mut outcomes = Vec::with_capacity(cases.len());
        for batch in cases.chunks(MAX_BATCH) {
            outcomes.extend(self.run_batch(batch)?);
        }
        Ok(outcomes)
    }

    fn run_batch(&self, cases: &[Case]) -> Result<Vec<Outcome>> {
        let directory = tempfile::tempdir()?;
        let harness = directory.path().join("harness.bin");
        let batch = directory.path().join("batch.bin");
        fs::write(&harness, HARNESS)?;
        fs::write(&batch, encode(cases)?)?;
        let output = Command::new(&self.qemu)
            .current_dir(directory.path())
            .args(["-M", "virt,mte=on", "-cpu", "max", "-m", "8G", "-smp", "1"])
            .args(["-nographic", "-monitor", "none", "-serial", "none"])
            .args(["-semihosting-config", "enable=on,target=native"])
            .arg("-device")
            .arg(format!(
                "loader,file={},addr={HARNESS_ADDRESS:#x},cpu-num=0",
                harness.display()
            ))
            .arg("-device")
            .arg(format!(
                "loader,file={},addr={BATCH_ADDRESS:#x},force-raw=on",
                batch.display()
            ))
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("cannot run {}", self.qemu.display()))?;
        ensure!(
            output.status.success(),
            "QEMU harness failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let results = fs::read(directory.path().join(RESULTS_NAME))?;
        ensure!(
            results.len() == cases.len() * RESULT_BYTES,
            "harness wrote {} result bytes for {} cases",
            results.len(),
            cases.len()
        );
        cases
            .iter()
            .zip(results.as_chunks::<RESULT_BYTES>().0)
            .map(|(case, record)| decode(case, record))
            .collect()
    }
}

fn encode(cases: &[Case]) -> Result<Vec<u8>> {
    let mut batch = vec![0; BATCH_CASES + cases.len() * CASE_BYTES];
    batch[BATCH_COUNT..][..8].copy_from_slice(&(cases.len() as u64).to_le_bytes());
    batch[BATCH_NAME_BYTES..][..8].copy_from_slice(&(RESULTS_NAME.len() as u64).to_le_bytes());
    batch[BATCH_NAME..][..RESULTS_NAME.len()].copy_from_slice(RESULTS_NAME.as_bytes());
    for (case, slot) in cases
        .iter()
        .zip(batch[BATCH_CASES..].as_chunks_mut::<CASE_BYTES>().0)
    {
        ensure!(
            case.code.len() <= MAX_WORDS,
            "case exceeds {MAX_WORDS} words"
        );
        ensure!(
            case.data.len() == DATA_BYTES,
            "data window must be {DATA_BYTES} bytes"
        );
        slot[CASE_WORDS..][..8].copy_from_slice(&(case.code.len() as u64).to_le_bytes());
        for (word, bytes) in case
            .code
            .iter()
            .zip(slot[CASE_CODE..].as_chunks_mut::<4>().0)
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        slot[CASE_STATE..][..size_of::<GuestState>()].copy_from_slice(state_bytes(&case.state));
        slot[CASE_DATA..][..DATA_BYTES].copy_from_slice(&case.data);
    }
    Ok(batch)
}

fn decode(case: &Case, record: &[u8]) -> Result<Outcome> {
    let quad = |offset: usize| u64::from_le_bytes(record[offset..][..8].try_into().unwrap());
    let mut state = GuestState {
        sp: quad(RESULT_SP),
        nzcv: quad(RESULT_SPSR) as u32 & NZCV_MASK,
        reserved: case.state.reserved,
        fpcr: quad(RESULT_FPCR) as u32,
        fpsr: quad(RESULT_FPSR) as u32,
        ..GuestState::default()
    };
    for (index, register) in state.x.iter_mut().enumerate() {
        *register = quad(index * 8);
    }
    for (index, vector) in state.v.iter_mut().enumerate() {
        *vector = [quad(RESULT_V + index * 16), quad(RESULT_V + index * 16 + 8)];
    }
    let syndrome = quad(RESULT_ESR);
    let address = quad(RESULT_ELR);
    let completed = syndrome >> ESR_CLASS_SHIFT == ESR_CLASS_SVC64
        && address == CODE_PAGE + (case.code.len() as u64 + 1) * INSTRUCTION_BYTES;
    let exception = (!completed).then(|| Exception {
        syndrome,
        address,
        fault_address: quad(RESULT_FAR),
    });
    Ok(Outcome {
        state,
        data: record[RESULT_DATA..][..DATA_BYTES].into(),
        exception,
    })
}

fn state_bytes(state: &GuestState) -> &[u8] {
    // SAFETY: GuestState is a repr(C) plain-data register file without padding.
    unsafe {
        std::slice::from_raw_parts(
            (state as *const GuestState).cast::<u8>(),
            size_of::<GuestState>(),
        )
    }
}

/// Fail unless `outcome` from QEMU completed.
pub fn completed(outcome: &Outcome) -> Result<()> {
    match outcome.exception {
        None => Ok(()),
        Some(exception) => bail!("original raised {exception:x?}"),
    }
}
