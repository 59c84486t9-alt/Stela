//! Differential oracle: run original AArch64 code on QEMU and Stela's native
//! translation of the same code, from identical state and memory.
//!
//! The reference is QEMU's `max` CPU, restricted to the Apple-like streaming
//! profile (SME without non-streaming SVE or FA64), in a bare-metal EL0 harness
//! that single-steps each case from [`CODE_PAGE`]. Code may access only the
//! [`DATA_WINDOW`] and read the code region; both engines see the same guest
//! addresses. A case that faults on QEMU is reported but never run natively,
//! because direct-RAM native code has no fault recovery.
//!
//! [`Oracle::with_el2`] starts the machine with `virtualization=on`: the
//! harness then runs EL1&0 under an identity stage 2 with HCR_EL2.E2H and VM
//! set, applies each case's [`Hypervisor`] state, records exceptions taken
//! to EL2 with HPFAR_EL2, and runs [`Case::el`] 2 cases at EL2t.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use stela_compiler::GuestState;

pub mod native;
pub mod system;

/// Guest address of the page that holds each case's code. The zero-filled,
/// read-only [`CODE_REGION_BYTES`] starting at [`CODE_REGION`] surround it, so
/// PC-relative literals within 1 MiB stay mapped and read the same bytes in
/// every case.
pub const CODE_PAGE: u64 = 0x2_0020_0000;
pub const CODE_REGION: u64 = 0x2_0000_0000;
pub const CODE_REGION_BYTES: usize = 0x40_0000;
/// Guest address of the only memory EL0 code may read or write.
pub const DATA_WINDOW: u64 = 0x2_0800_0000;
pub const DATA_BYTES: usize = 0x4000;
/// Words per case.
pub const MAX_WORDS: usize = 112;
pub const Z_REGISTERS: usize = 32;
pub const P_REGISTERS: usize = 16;
pub const ZT0_BYTES: usize = 64;
/// SVCR.SM: streaming mode.
pub const SVCR_SM: u64 = 1;
/// SVCR.ZA: ZA storage enabled.
pub const SVCR_ZA: u64 = 2;
const MAX_BATCH: usize = 4096;
const SVE_GRANULE: usize = 16;

const HARNESS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/harness.bin"));
const HARNESS_ADDRESS: u64 = 0x4010_0000;
const BATCH_ADDRESS: u64 = 0x4100_0000;
const RESULTS_ADDRESS: u64 = 0x5000_0000;
const RESULTS_NAME: &str = "results.bin";
const CPU: &str = "max,sve=off,sme=on,sme_fa64=off";

// Batch and record layouts; these match `harness.S`.
const BATCH_COUNT: usize = 0;
const BATCH_NAME_BYTES: usize = 8;
const BATCH_CASE_BYTES: usize = 16;
const BATCH_RESULT_BYTES: usize = 24;
const BATCH_NAME: usize = 32;
const BATCH_CASES: usize = 0x1000;
const CASE_WORDS: usize = 0;
const CASE_STEPS: usize = 8;
const CASE_SVL: usize = 16;
const CASE_SVCR: usize = 24;
const CASE_TPIDR2: usize = 32;
const CASE_FLAGS: usize = 48;
/// Run the case at EL1t, unstepped, until its first exception.
const FLAG_EL1: u64 = 2;
/// Run the case at EL2t, unstepped, until its first exception.
const FLAG_EL2: u64 = 4;
const CASE_CODE: usize = 64;
const CASE_STATE: usize = 512;
/// The case's [`Hypervisor`] state: HCR_EL2 additions, then the stage-2
/// descriptors of the code page, the data window's table page and its pages.
const CASE_EL2: usize = 0xc00;
const CASE_DATA: usize = 0x1000;
const CASE_SCALABLE: usize = 0x5000;
const RESULT_SP: usize = 248;
const RESULT_SPSR: usize = 256;
const RESULT_FPCR: usize = 264;
const RESULT_FPSR: usize = 272;
const RESULT_ESR: usize = 280;
const RESULT_ELR: usize = 288;
const RESULT_FAR: usize = 296;
const RESULT_V: usize = 320;
const RESULT_SVCR: usize = 832;
const RESULT_TPIDR2: usize = 840;
const RESULT_LEVEL: usize = 856;
const RESULT_HPFAR: usize = 864;
const RESULT_DATA: usize = 0x400;
const RESULT_SCALABLE: usize = 0x4400;

const NZCV_MASK: u32 = 0xf000_0000;
const ESR_CLASS_SHIFT: u64 = 26;
const ESR_CLASS_SOFTWARE_STEP: u64 = 0x32;

/// Code at [`CODE_PAGE`] with its initial guest state and data window. The
/// first `steps` instructions execute.
#[derive(Clone)]
pub struct Case {
    pub code: Vec<u32>,
    pub steps: usize,
    pub state: GuestState,
    pub data: Box<[u8]>,
    pub scalable: Option<Scalable>,
    /// The exception level: 0 steps the code; 1 and 2 run it at EL1t or
    /// EL2t until the first exception, as the words after `code` are UDF.
    /// Level 2 needs an [`Oracle::with_el2`] machine.
    pub el: u8,
    /// HCR_EL2 and stage 2, for an [`Oracle::with_el2`] machine only.
    pub hypervisor: Option<Hypervisor>,
}

/// Stage 1 of the harness's EL1&0 regime: the page of the data window's
/// level-3 table, which the stage-2 [`Hypervisor::table`] descriptor maps.
pub const STAGE1_DATA_TABLE: u64 = 0x4011_3000;
/// Stage-2 descriptor attributes of the harness's identity map: AF, Inner
/// Shareable, S2AP read/write and MemAttr Normal Write-Back.
pub const STAGE2_NORMAL: u64 = (1 << 10) | (3 << 8) | (3 << 6) | (0xf << 2);
/// The harness's HCR_EL2 as the engine mirrors it: E2H, RW and VM, with APK,
/// API, EnSCXT and FIEN. The harness also sets ATA, for QEMU's MTE, which
/// the profile lacks.
pub const HCR_BASE: u64 = 1 | (1 << 31) | (1 << 34) | (1 << 40) | (1 << 41) | (1 << 47) | (1 << 53);
const STAGE2_BLOCK: u64 = 1;
const STAGE2_PAGE: u64 = 3;
const DATA_PAGES: usize = DATA_BYTES / 0x1000;

/// One case's HCR_EL2 additions to [`HCR_BASE`] and its stage-2
/// descriptors: the 2 MiB block of the code page, the page holding the data
/// window's stage-1 level-3 table, and each data window page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hypervisor {
    pub hcr: u64,
    pub code: u64,
    pub table: u64,
    pub data: [u64; DATA_PAGES],
}

impl Default for Hypervisor {
    /// The identity map with no HCR_EL2 additions.
    fn default() -> Self {
        Self {
            hcr: 0,
            code: CODE_PAGE | STAGE2_NORMAL | STAGE2_BLOCK,
            table: STAGE1_DATA_TABLE | STAGE2_NORMAL | STAGE2_PAGE,
            data: std::array::from_fn(|page| {
                (DATA_WINDOW + page as u64 * 0x1000) | STAGE2_NORMAL | STAGE2_PAGE
            }),
        }
    }
}

/// SME state: streaming vector length, SVCR and the register banks.
///
/// `z` holds every Z register at full length; in streaming mode the low 16
/// bytes of each are the V register in the guest state. Banks are present only
/// while SVCR enables them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scalable {
    pub svl: usize,
    pub svcr: u64,
    pub tpidr2: u64,
    pub z: Vec<u8>,
    pub p: Vec<u8>,
    pub za: Vec<u8>,
    pub zt0: [u8; ZT0_BYTES],
}

impl Scalable {
    /// Zeroed banks for `svl` bytes with `svcr` mode bits.
    pub fn new(svl: usize, svcr: u64) -> Self {
        Self {
            svl,
            svcr,
            tpidr2: 0,
            z: vec![0; Z_REGISTERS * svl],
            p: vec![0; P_REGISTERS * svl / 8],
            za: vec![0; svl * svl],
            zt0: [0; ZT0_BYTES],
        }
    }

    fn bytes(svl: usize) -> usize {
        Z_REGISTERS * svl + P_REGISTERS * svl / 8 + svl * svl + ZT0_BYTES
    }

    fn streaming(&self) -> bool {
        self.svcr & SVCR_SM != 0
    }

    fn za_enabled(&self) -> bool {
        self.svcr & SVCR_ZA != 0
    }

    /// Serialize as the harness lays the banks out.
    fn encode(&self, output: &mut [u8]) {
        let (z, rest) = output.split_at_mut(self.z.len());
        let (p, rest) = rest.split_at_mut(self.p.len());
        let (za, zt0) = rest.split_at_mut(self.za.len());
        z.copy_from_slice(&self.z);
        p.copy_from_slice(&self.p);
        za.copy_from_slice(&self.za);
        zt0[..ZT0_BYTES].copy_from_slice(&self.zt0);
    }

    /// Read back the banks SVCR enables; others keep their initial bytes.
    fn decode(initial: &Self, svcr: u64, tpidr2: u64, input: &[u8]) -> Self {
        let mut result = Self {
            svcr,
            tpidr2,
            ..initial.clone()
        };
        let (z, rest) = input.split_at(result.z.len());
        let (p, rest) = rest.split_at(result.p.len());
        let (za, zt0) = rest.split_at(result.za.len());
        if result.streaming() {
            result.z.copy_from_slice(z);
            result.p.copy_from_slice(p);
        }
        if result.za_enabled() {
            result.za.copy_from_slice(za);
            result.zt0.copy_from_slice(&zt0[..ZT0_BYTES]);
        }
        result
    }
}

/// Final architectural state after a case, from either engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub state: GuestState,
    pub next_pc: u64,
    pub data: Box<[u8]>,
    pub scalable: Option<Scalable>,
    pub exception: Option<Exception>,
    /// SPSR of an EL1 or EL2 case's exception: PSTATE after its code.
    pub spsr: Option<u64>,
}

/// An exception other than the final step, from the registers of the EL it
/// was taken to: `address` is its ELR, and `hpfar` HPFAR_EL2 (0 at EL1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exception {
    pub syndrome: u64,
    pub address: u64,
    pub fault_address: u64,
    pub level: u8,
    pub hpfar: u64,
}

/// A QEMU binary able to run the harness.
pub struct Oracle {
    qemu: PathBuf,
    /// Start the machine at EL2 (`virtualization=on`).
    el2: bool,
}

impl Oracle {
    /// Use an explicit `qemu-system-aarch64`.
    pub fn new(qemu: &Path) -> Result<Self> {
        Ok(Self {
            qemu: qemu
                .canonicalize()
                .with_context(|| format!("cannot find {}", qemu.display()))?,
            el2: false,
        })
    }

    /// Run the harness with EL2 and stage 2.
    pub fn with_el2(self) -> Self {
        Self { el2: true, ..self }
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
                .context("install QEMU 11 or newer")?
        };
        Ok(Self { qemu, el2: false })
    }

    /// Run every case on QEMU, in order. Batches share one SVL so their
    /// records stay small.
    pub fn run(&self, cases: &[Case]) -> Result<Vec<Outcome>> {
        let mut outcomes = Vec::with_capacity(cases.len());
        let mut start = 0;
        while start < cases.len() {
            let svl = svl(&cases[start]);
            let layout = Layout::new(svl);
            let end = cases[start..]
                .iter()
                .position(|case| self::svl(case) != svl)
                .map_or(cases.len(), |offset| start + offset)
                .min(start + layout.capacity());
            outcomes.extend(self.run_batch(&cases[start..end], layout)?);
            start = end;
        }
        Ok(outcomes)
    }

    fn run_batch(&self, cases: &[Case], layout: Layout) -> Result<Vec<Outcome>> {
        ensure!(
            cases
                .iter()
                .all(|case| case.hypervisor.is_some() == self.el2 && (case.el < 2 || self.el2)),
            "hypervisor state and EL2 cases need an EL2 machine, and only they"
        );
        let directory = tempfile::tempdir()?;
        let harness = directory.path().join("harness.bin");
        let batch = directory.path().join("batch.bin");
        fs::write(&harness, HARNESS)?;
        fs::write(&batch, encode(cases, layout)?)?;
        let machine = if self.el2 {
            "virt,mte=on,virtualization=on"
        } else {
            "virt,mte=on"
        };
        let output = Command::new(&self.qemu)
            .current_dir(directory.path())
            .args(["-M", machine, "-cpu", CPU, "-m", "8G", "-smp", "1"])
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
            results.len() == cases.len() * layout.result,
            "harness wrote {} result bytes for {} cases",
            results.len(),
            cases.len()
        );
        cases
            .iter()
            .zip(results.chunks_exact(layout.result))
            .map(|(case, record)| decode(case, record))
            .collect()
    }
}

fn svl(case: &Case) -> usize {
    case.scalable.as_ref().map_or(0, |scalable| scalable.svl)
}

/// Case and result strides for one batch SVL.
#[derive(Clone, Copy)]
struct Layout {
    svl: usize,
    case: usize,
    result: usize,
}

impl Layout {
    fn new(svl: usize) -> Self {
        let scalable = if svl == 0 { 0 } else { Scalable::bytes(svl) };
        Self {
            svl,
            case: (CASE_SCALABLE + scalable).next_multiple_of(SVE_GRANULE),
            result: (RESULT_SCALABLE + scalable).next_multiple_of(SVE_GRANULE),
        }
    }

    /// Cases that fit both the batch area and the results area.
    fn capacity(self) -> usize {
        let inputs = (RESULTS_ADDRESS - BATCH_ADDRESS) as usize - BATCH_CASES;
        let results = (CODE_REGION - RESULTS_ADDRESS) as usize;
        MAX_BATCH.min(inputs / self.case).min(results / self.result)
    }
}

fn encode(cases: &[Case], layout: Layout) -> Result<Vec<u8>> {
    let mut batch = vec![0; BATCH_CASES + cases.len() * layout.case];
    let header = [
        (BATCH_COUNT, cases.len()),
        (BATCH_NAME_BYTES, RESULTS_NAME.len()),
        (BATCH_CASE_BYTES, layout.case),
        (BATCH_RESULT_BYTES, layout.result),
    ];
    for (offset, value) in header {
        batch[offset..][..8].copy_from_slice(&(value as u64).to_le_bytes());
    }
    batch[BATCH_NAME..][..RESULTS_NAME.len()].copy_from_slice(RESULTS_NAME.as_bytes());
    for (case, slot) in cases
        .iter()
        .zip(batch[BATCH_CASES..].chunks_exact_mut(layout.case))
    {
        ensure!(
            case.code.len() <= MAX_WORDS,
            "case exceeds {MAX_WORDS} words"
        );
        ensure!(case.steps > 0, "a case executes at least one instruction");
        ensure!(
            case.data.len() == DATA_BYTES,
            "data window must be {DATA_BYTES} bytes"
        );
        let quad = |slot: &mut [u8], offset: usize, value: u64| {
            slot[offset..][..8].copy_from_slice(&value.to_le_bytes())
        };
        quad(slot, CASE_WORDS, case.code.len() as u64);
        quad(slot, CASE_STEPS, case.steps as u64);
        let flags = match case.el {
            0 => 0,
            1 => FLAG_EL1,
            2 => FLAG_EL2,
            el => anyhow::bail!("no harness entry at EL{el}"),
        };
        quad(slot, CASE_FLAGS, flags);
        let hypervisor = case.hypervisor.unwrap_or_default();
        let block = [hypervisor.hcr, hypervisor.code, hypervisor.table];
        for (index, value) in block.iter().chain(&hypervisor.data).enumerate() {
            quad(slot, CASE_EL2 + index * 8, *value);
        }
        for (word, bytes) in case
            .code
            .iter()
            .zip(slot[CASE_CODE..].as_chunks_mut::<4>().0)
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        slot[CASE_STATE..][..size_of::<GuestState>()].copy_from_slice(state_bytes(&case.state));
        slot[CASE_DATA..][..DATA_BYTES].copy_from_slice(&case.data);
        if let Some(scalable) = &case.scalable {
            ensure!(scalable.svl == layout.svl, "batch mixes vector lengths");
            // Streaming mode loads V as the low part of each Z register.
            let mut scalable = scalable.clone();
            if scalable.streaming() {
                for (z, v) in scalable.z.chunks_exact_mut(scalable.svl).zip(&case.state.v) {
                    z[..8].copy_from_slice(&v[0].to_le_bytes());
                    z[8..16].copy_from_slice(&v[1].to_le_bytes());
                }
            }
            quad(slot, CASE_SVL, scalable.svl as u64);
            quad(slot, CASE_SVCR, scalable.svcr);
            quad(slot, CASE_TPIDR2, scalable.tpidr2);
            scalable.encode(&mut slot[CASE_SCALABLE..]);
        }
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
    let scalable = case.scalable.as_ref().map(|initial| {
        Scalable::decode(
            initial,
            quad(RESULT_SVCR),
            quad(RESULT_TPIDR2),
            &record[RESULT_SCALABLE..],
        )
    });
    for (index, vector) in state.v.iter_mut().enumerate() {
        *vector = match &scalable {
            // Streaming mode saves V as the low part of each Z register.
            Some(scalable) if scalable.streaming() => {
                let z = &scalable.z[index * scalable.svl..];
                [
                    u64::from_le_bytes(z[..8].try_into().unwrap()),
                    u64::from_le_bytes(z[8..16].try_into().unwrap()),
                ]
            }
            _ => [quad(RESULT_V + index * 16), quad(RESULT_V + index * 16 + 8)],
        };
    }
    let syndrome = quad(RESULT_ESR);
    let next_pc = quad(RESULT_ELR);
    let exception = (syndrome >> ESR_CLASS_SHIFT != ESR_CLASS_SOFTWARE_STEP).then(|| Exception {
        syndrome,
        address: next_pc,
        fault_address: quad(RESULT_FAR),
        level: quad(RESULT_LEVEL) as u8,
        hpfar: quad(RESULT_HPFAR),
    });
    Ok(Outcome {
        state,
        next_pc,
        data: record[RESULT_DATA..][..DATA_BYTES].into(),
        scalable,
        exception,
        spsr: (case.el != 0).then(|| quad(RESULT_SPSR)),
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
