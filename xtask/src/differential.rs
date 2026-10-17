//! Original-versus-native differential over the instruction forms.
//!
//! Each implemented leaf, block and scalable form contributes its registry
//! samples plus random words over its free encoding bits that Stela accepts.
//! Every word runs from seeded random states on the QEMU oracle and as Stela's
//! native translation; registers, scalable banks, the next PC and the data
//! window must match whenever the original completes. Service forms of the
//! system-mode profile run on the system-mode engine at EL0 instead, and their
//! exceptions (ESR, ELR and, for aborts, FAR) must match as well.
//! `--system-matrix` runs the system requirement matrix's rows the same way.
mod matrix;

use crate::oracle::{
    CODE_PAGE, CODE_REGION, CODE_REGION_BYTES, Case, DATA_BYTES, DATA_WINDOW, Oracle, Outcome,
    Scalable, native::Translation,
};
use crate::tools::root;
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use stela_cli::registry::{self, Mode, Probe, hex};
use stela_compiler::GuestState;

/// Every leaf ends in RET, so the leaf RET form needs no case of its own.
const LEAF_TERMINATOR: &str = "RET_64R_branch_reg";
/// FPCR controls that QEMU also implements: AHP, DN, FZ, RMode, FZ16 and the
/// AFP bits. QEMU has no FP trap enables.
const FPCR_MASK: u32 = 0x07c8_0007;
/// FPSR QC and cumulative flags; QEMU also keeps AArch32 NZCV, which Apple
/// silicon does not implement.
const FPSR_MASK: u32 = 0x0800_009f;
const FPCR_AH: u32 = 1 << 1;
const NZCV_SHIFT: u32 = 28;
const ESR_CLASS_SHIFT: u64 = 26;
/// Pointers land in the middle half of the window so offsets either way stay inside.
const POINTER_SPAN: u64 = DATA_BYTES as u64 / 2;
const POINTER_ALIGNMENT: u64 = 16;
/// Attempts to find each random field word Stela accepts.
const FIELD_ATTEMPTS: usize = 64;
const REGISTER_FIELD: u32 = 0x1f;
/// Words compared per oracle run; bounds memory on large runs.
const BATCH_WORDS: usize = 1024;
const ZERO_OR_SP: u32 = 31;
/// The service profile whose forms the system-mode engine completes.
const SYSTEM_MODE_PROFILE: &str = "system-mode-v1";
const WFI: u32 = 0xd503_207f;
const XPACLRI: u32 = 0xd503_20ff;
/// Exception classes whose FAR is architecturally valid: instruction and data
/// aborts, PC alignment and watchpoints.
const FAR_CLASSES: [u64; 7] = [0x20, 0x21, 0x22, 0x24, 0x25, 0x34, 0x35];

#[derive(Args)]
pub struct Differential {
    /// Random states per word.
    #[arg(long, default_value_t = 8)]
    states: usize,
    /// Random field words per form, in addition to its registry samples.
    #[arg(long, default_value_t = 4)]
    fields: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Only forms whose id contains this text.
    #[arg(long)]
    form: Option<String>,
    /// Only forms registered under this execution profile.
    #[arg(long)]
    profile: Option<String>,
    /// QEMU binary; defaults to `.tools/qemu/bin` or `PATH`.
    #[arg(long)]
    qemu: Option<PathBuf>,
    /// Mismatches to print in full.
    #[arg(long, default_value_t = 20)]
    show: usize,
    /// Run the System form and accessor rows of the system requirement
    /// matrix instead of the registries.
    #[arg(long)]
    system_matrix: bool,
    /// With --system-matrix: write per-row tallies as JSON here.
    #[arg(long, requires = "system_matrix")]
    report: Option<PathBuf>,
}

/// SplitMix64: small, fast and reproducible across hosts.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next() as u8).collect()
    }

    /// Random data, small integers, boundary values or window pointers.
    fn register(&mut self) -> u64 {
        const BOUNDARIES: [u64; 6] = [
            0,
            1,
            u64::MAX,
            i64::MIN as u64,
            i64::MAX as u64,
            0xffff_ffff,
        ];
        match self.next() % 8 {
            0 | 1 => self.next(),
            2 => self.next() % 64,
            3 => BOUNDARIES[(self.next() % BOUNDARIES.len() as u64) as usize],
            _ => self.pointer(),
        }
    }

    /// A window address, aligned for exclusive and pair accesses half the time.
    fn pointer(&mut self) -> u64 {
        let address = DATA_WINDOW + POINTER_SPAN / 2 + self.next() % POINTER_SPAN;
        if self.next().is_multiple_of(2) {
            address & !(POINTER_ALIGNMENT - 1)
        } else {
            address
        }
    }

    fn state(&mut self) -> GuestState {
        let mut state = GuestState::default();
        for register in &mut state.x {
            *register = self.register();
        }
        state.sp = self.pointer() & !(POINTER_ALIGNMENT - 1);
        state.nzcv = ((self.next() & 0xf) as u32) << NZCV_SHIFT;
        for vector in &mut state.v {
            *vector = [self.next(), self.next()];
        }
        state.fpcr = self.next() as u32 & FPCR_MASK;
        state.fpsr = self.next() as u32 & FPSR_MASK;
        state
    }

    fn scalable(&mut self, svl: usize, svcr: u64) -> Scalable {
        let mut scalable = Scalable::new(svl, svcr);
        scalable.tpidr2 = self.next();
        for bank in [&mut scalable.z, &mut scalable.p, &mut scalable.za] {
            let bytes = self.bytes(bank.len());
            bank.copy_from_slice(&bytes);
        }
        let zt0 = self.bytes(scalable.zt0.len());
        scalable.zt0.copy_from_slice(&zt0);
        scalable
    }
}

/// Load/store words whose transfer and base registers overlap are CONSTRAINED
/// UNPREDICTABLE, so the engines may legitimately differ.
fn unpredictable_overlap(form: &str, word: u32) -> bool {
    if !form.contains("_ldst") {
        return false;
    }
    let field = |shift: u32| (word >> shift) & REGISTER_FIELD;
    let mut registers = vec![field(0), field(5)];
    if form.contains("pair") {
        registers.push(field(10));
    }
    registers.iter().enumerate().any(|(index, &register)| {
        register != ZERO_OR_SP && registers[index + 1..].contains(&register)
    })
}

/// Known QEMU deviations from the architecture; matching cases are not compared.
fn oracle_limit(form: &str, state: &GuestState) -> bool {
    // QEMU changes the sign of a NaN in vector FABS and FNEG, and when negating
    // the Zm element of indexed SVE FCMLA, even when FPCR.AH is set;
    // the architecture leaves it unchanged.
    let sign_of_nan = form.starts_with("FABS_asimdmisc")
        || form.starts_with("FNEG_asimdmisc")
        || form.starts_with("fcmla_z_zzzi_");
    // QEMU implements FEAT_RPRES, which refines AH=1 estimates; the Apple
    // profile declares it absent.
    let estimate = form.starts_with("FRECPE_") || form.starts_with("FRSQRTE_");
    // QEMU leaves predicate-inactive elements of an SME tile-slice load
    // unchanged; the architecture zeroes them.
    let tile_slice_load = form.starts_with("ld1") && form.contains("_za_");
    // QEMU has no Apple AMX, so AMX words are never differential subjects:
    // `cargo xtask amx-reference` compares the model with the corsix/amx
    // emulator on QEMU instead, and no Apple hardware oracle exists.
    (sign_of_nan || estimate) && state.fpcr & FPCR_AH != 0 || tile_slice_load
}

/// Known differences between QEMU's `max` CPU and the engine's M2 profile for
/// system-mode words at EL0; matching cases are not compared.
fn system_oracle_limit(form: &str, word: u32, el1: bool, state: &GuestState) -> bool {
    // Matrix form rows carry the registry form name after a kind prefix.
    let form = form.strip_prefix("form:").unwrap_or(form);
    // QEMU completes WFI at EL0 whenever it has pending work, masked or not,
    // instead of taking the nTWI trap; the engine has no pending wake-up.
    let wfi = word == WFI;
    // QEMU implements FEAT_WFxT and FEAT_XS; the M2 identification does not.
    let absent =
        form.starts_with("WFET_") || form.starts_with("WFIT_") || form.starts_with("DSB_BOn_");
    // QEMU implements SME2 and runs MOVT GPR/ZT0 outside Debug state; the M2
    // identification has no SME.
    let sme = form.starts_with("movt_");
    // MSR SVCR* (op1=3, CRn=4, op2=3) and MSR TCO (op1=3, op2=4) need SME and
    // MTE, which QEMU implements and the M2 identification does not.
    let (op1, op2, crm) = ((word >> 16) & 7, (word >> 5) & 7, (word >> 8) & 15);
    let pstate = form == "MSR_SI_pstate" && op1 == 3 && matches!(op2, 3 | 4);
    // CFINV, XAFLAG and AXFLAG (op1=0, op2=0..2) with nonzero should-be-zero
    // CRm are CONSTRAINED UNPREDICTABLE: QEMU raises UNDEFINED, Stela ignores
    // the bits. They are FlagM forms, outside this one.
    let flags = form == "MSR_SI_pstate" && op1 == 0 && op2 <= 2 && crm != 0;
    // So is SB with nonzero should-be-zero CRm.
    let speculation = form == "SB_only_barriers" && crm != 0;
    // QEMU's virt machine without EL2 implements PSCI on the HVC conduit, so
    // HVC at EL1 completes as a firmware call instead of being UNDEFINED.
    let psci = el1 && form == "HVC_EX_exception";
    // QEMU treats XPACLRI as a NOP while SCTLR_EL1 enables no PAC key, as the
    // harness's does; the architecture strips X30 regardless.
    let strip = word == XPACLRI;
    // CNTFRQ_EL0 is writable only at the highest EL: EL2 on the engine's
    // profile, EL1 on QEMU's virt machine without EL2.
    let frequency = el1 && word & !0x1f == MSR_CNTFRQ_EL0;
    // QEMU implements FEAT_AFP, so MSR FPCR keeps FIZ, AH and NEP; the M2
    // profile has no FEAT_AFP and the engine holds them RES0.
    let rt = (word & REGISTER_FIELD) as usize;
    let afp = word & !0x1f == MSR_FPCR && rt != ZERO_OR_SP as usize && state.x[rt] & 7 != 0;
    // QEMU swaps Op1 and Op2 in the ISS of a trapped MSR DAIFSet or DAIFClr;
    // Arm `AArch64_SystemAccessTrapSyndrome` takes both from the instruction.
    let daif_trap = !el1 && word & 0xffff_f0df == MSR_DAIFSET;
    // QEMU makes DC IVAC, CVAC, CVAU and CIVAC and IC IVAU NOPs that never
    // translate, so at an address outside the windows they complete where
    // the engine's walk of the same tables may fault. It performs DC CVAP and
    // CVADP as a load of the aligned line, so their faults report CM=0,
    // WnR=0 and the line address, where the architecture reports CM=1,
    // WnR=1 and the operand.
    let selector = (word >> 5) & 0x3fff;
    let untranslated = [
        (0, 7, 6, 1),
        (3, 7, 10, 1),
        (3, 7, 11, 1),
        (3, 7, 14, 1),
        (3, 7, 5, 1),
        (3, 7, 12, 1),
        (3, 7, 13, 1),
    ]
    .iter()
    .any(|&(op1, crn, crm, op2)| selector == op1 << 11 | crn << 7 | crm << 3 | op2);
    // Rt=31 is XZR: address 0.
    let register = (word & REGISTER_FIELD) as usize;
    let address = state.x.get(register).copied().unwrap_or(0);
    let by_address = word & 0xfff8_0000 == 0xd508_0000 && untranslated && !in_windows(address);
    // QEMU's max CPU makes the MPAM registers and RAS's ERRSELR_EL1 and ERX*
    // UNDEFINED; the profile defines them (FEAT_MPAM with PARTID 0 only, and
    // FEAT_RAS with no error records, where they are RAZ/WI).
    let register_access = word & 0xffc0_0000 == 0xd500_0000 && (word >> 19) & 3 == 3;
    let (crn, crm, op1, op2) = (
        (word >> 12) & 15,
        (word >> 8) & 15,
        (word >> 16) & 7,
        (word >> 5) & 7,
    );
    let mpam = crn == 10 && (crm == 5 || crm == 6 || crm == 4 && (op1 == 4 || op2 == 4));
    let records = crn == 5 && (crm == 3 && op2 == 1 || crm == 4 || crm == 5);
    // QEMU also leaves DBGAUTHSTATUS_EL1 and DBGPRCR_EL1 UNDEFINED, which
    // every AArch64 PE implements.
    let debug = matches!(word & 0xffdf_ffe0, 0xd510_7ec0 | 0xd510_1480);
    let absent_registers = register_access && (mpam || records) || debug;
    wfi || absent
        || absent_registers
        || sme
        || pstate
        || flags
        || speculation
        || psci
        || strip
        || frequency
        || afp
        || daif_trap
        || by_address
}

/// MSR CNTFRQ_EL0, Xt (op0=3, op1=3, CRn=14, CRm=0, op2=0) without Rt.
const MSR_CNTFRQ_EL0: u32 = 0xd51b_e000;
/// MSR DAIFSet, #imm (op1=3, CRn=4, op2=6) without CRm; op2 bit 0 adds DAIFClr.
const MSR_DAIFSET: u32 = 0xd503_40df;
/// MSR FPCR, Xt (op0=3, op1=3, CRn=4, CRm=4, op2=0) without Rt.
const MSR_FPCR: u32 = 0xd51b_4400;

fn in_windows(address: u64) -> bool {
    (CODE_REGION..CODE_REGION + CODE_REGION_BYTES as u64).contains(&address)
        || (DATA_WINDOW..DATA_WINDOW + DATA_BYTES as u64).contains(&address)
}

/// Oracle limits: compare FPCR and FPSR only on bits both engines model, FAR
/// only where the exception defines it, and what MRS read only for registers
/// the case's state sets: QEMU's other System registers hold the harness's
/// values and its `max` CPU's identification, not the engine's M2 profile.
fn comparable(outcome: &Outcome, system_word: Option<u32>) -> Outcome {
    let mut outcome = outcome.clone();
    if let Some(register) = system_word.and_then(unmirrored_read) {
        outcome.state.x[register] = 0;
    }
    outcome.state.fpcr &= FPCR_MASK;
    outcome.state.fpsr &= FPSR_MASK;
    if let Some(exception) = &mut outcome.exception
        && !FAR_CLASSES.contains(&(exception.syndrome >> ESR_CLASS_SHIFT))
    {
        exception.fault_address = 0;
    }
    outcome
}

/// The destination of an MRS whose value the lane does not mirror; PSTATE
/// fields, FPCR and FPSR are the case's own state.
fn unmirrored_read(word: u32) -> Option<usize> {
    const MRS_MASK: u32 = 0xfff0_0000;
    const MRS: u32 = 0xd530_0000;
    // NZCV, DAIF, DIT, SSBS, FPCR and FPSR (op1=3); SPSel, CurrentEL, PAN
    // and UAO (op1=0); as op1:CRn:CRm:op2.
    const MIRRORED: [(u32, u32, u32, u32); 10] = [
        (3, 4, 2, 0),
        (3, 4, 2, 1),
        (3, 4, 2, 5),
        (3, 4, 2, 6),
        (3, 4, 4, 0),
        (3, 4, 4, 1),
        (0, 4, 2, 0),
        (0, 4, 2, 2),
        (0, 4, 2, 3),
        (0, 4, 2, 4),
    ];
    let field = |shift: u32, bits: u32| (word >> shift) & ((1 << bits) - 1);
    let register = field(0, 5);
    let selector = (field(16, 3), field(12, 4), field(8, 4), field(5, 3));
    (word & MRS_MASK == MRS
        && register != ZERO_OR_SP
        && !(field(19, 1) == 1 && MIRRORED.contains(&selector)))
    .then_some(register as usize)
}

fn is_system_mode(form: &Value) -> bool {
    form["profile"] == SYSTEM_MODE_PROFILE
}

/// System-mode rows below "implemented", drafts included, are compared for
/// information only.
fn is_draft(form: &Value) -> bool {
    is_system_mode(form) && form["status"] != "implemented"
}

/// One word sequence with its native translation and the state it runs under.
struct Subject {
    form: String,
    code: Vec<u32>,
    /// Streaming vector length and SVCR of scalable forms.
    scalable: Option<(usize, u64)>,
    /// Run on the system-mode engine; exceptions are compared too.
    system: bool,
    /// An unfinished system-mode row: divergences are reported as open.
    draft: bool,
    /// Run at EL1t instead of stepping at EL0 (system-mode words only).
    el1: bool,
    translation: Translation,
}

/// How one registry form is translated for comparison.
struct Lane<'a> {
    mode: Mode,
    registry: &'a Value,
    form: &'a Value,
}

impl Lane<'_> {
    /// Stela's translation of `code` at the code page under `sample`'s profile,
    /// or `None` when it needs a service the differential does not provide.
    fn translate(&self, code: &[u32], sample: &Value) -> Result<Option<Translation>> {
        match self.mode {
            Mode::Leaf => Translation::leaf(code).map(Some),
            Mode::Block => Translation::block(code).map(Some),
            Mode::Scalable => {
                let probe = Probe::new(self.mode, self.registry, self.form, sample, CODE_PAGE)?;
                if let Some(profile) = probe.context_block_profile_if_block()? {
                    return Translation::scalable_block(code, profile).map(Some);
                }
                let profile = probe
                    .context_leaf_profile()?
                    .context("scalable leaf profile")?;
                Translation::scalable_leaf(code, profile)
            }
            Mode::Service if is_system_mode(self.form) => Translation::system(code).map(Some),
            Mode::Service => unreachable!("only system-mode service forms are compared"),
        }
    }

    fn scalable(&self, sample: &Value) -> Option<(usize, u64)> {
        (self.mode == Mode::Scalable).then(|| {
            (
                sample["svl_bytes"].as_u64().unwrap_or_default() as usize,
                sample["svcr"].as_u64().unwrap_or_default(),
            )
        })
    }
}

/// Totals across every compared batch.
#[derive(Default)]
struct Report {
    words: usize,
    compared: usize,
    mismatches: usize,
    shown: usize,
    skipped: usize,
    mismatched: BTreeSet<String>,
    /// Partial system-mode forms that still diverge, with divergent cases.
    open: BTreeMap<String, usize>,
    covered: BTreeSet<String>,
    /// Original exception classes per form, kept for forms that never complete.
    uncovered: BTreeMap<String, BTreeMap<u64, usize>>,
    /// Per-row tallies of a --system-matrix run.
    rows: matrix::Rows,
}

impl Differential {
    pub fn run(self) -> Result<()> {
        let oracle = match &self.qemu {
            Some(qemu) => Oracle::new(qemu)?,
            None => Oracle::locate(&root().join(".tools/qemu/bin"))?,
        };
        let mut random = Random(self.seed);
        let mut report = Report::default();
        let mut batch = Vec::with_capacity(BATCH_WORDS);
        let mut skipped = 0;
        if self.system_matrix {
            let (rows, subjects) =
                matrix::subjects(&mut random, self.fields, self.form.as_deref())?;
            report.mismatches += rows.refused_implemented.len();
            report
                .mismatched
                .extend(rows.refused_implemented.iter().cloned());
            report.rows = rows;
            for subject in subjects {
                batch.push(subject);
                if batch.len() == BATCH_WORDS {
                    self.compare(&oracle, &mut random, &mut batch, &mut report)?;
                }
            }
        } else {
            self.subjects(&mut random, &mut skipped, |random, subject| {
                batch.push(subject);
                if batch.len() == BATCH_WORDS {
                    self.compare(&oracle, random, &mut batch, &mut report)?;
                }
                Ok(())
            })?;
        }
        self.compare(&oracle, &mut random, &mut batch, &mut report)?;
        if let Some(path) = &self.report {
            report
                .rows
                .write(path, self.seed, self.states, self.fields)?;
        }
        report
            .uncovered
            .retain(|form, _| !report.covered.contains(form));

        for form in &report.mismatched {
            println!("mismatch: {form}");
        }
        for (form, cases) in &report.open {
            println!("open: {form}, {cases} divergent cases (unfinished system-mode row)");
        }
        for (form, classes) in &report.uncovered {
            println!("uncovered: {form}, exception classes {classes:x?}");
        }
        println!(
            "{} words, {} comparisons, {} mismatches in {} forms, {} forms never \
             completed, {} samples need services the differential does not provide",
            report.words,
            report.compared,
            report.mismatches,
            report.mismatched.len(),
            report.uncovered.len(),
            report.skipped
        );
        ensure!(report.words > 0, "no forms selected");
        ensure!(
            report.mismatches == 0,
            "native translation differs from the original"
        );
        Ok(())
    }

    /// Run `batch` from random states on the oracle and natively, then empty it.
    fn compare(
        &self,
        oracle: &Oracle,
        random: &mut Random,
        batch: &mut Vec<Subject>,
        report: &mut Report,
    ) -> Result<()> {
        let cases: Vec<Case> = batch
            .iter()
            .flat_map(|subject| std::iter::repeat_n(subject, self.states))
            .map(|subject| Case {
                code: subject.code.clone(),
                steps: subject.code.len(),
                state: random.state(),
                data: random.bytes(DATA_BYTES).into(),
                scalable: subject
                    .scalable
                    .map(|(svl, svcr)| random.scalable(svl, svcr)),
                el1: subject.el1,
            })
            .collect();
        let originals = oracle.run(&cases)?;
        for (index, (case, original)) in cases.iter().zip(&originals).enumerate() {
            let subject = &mut batch[index / self.states];
            if let Some(exception) = original.exception
                && !subject.system
            {
                *report
                    .uncovered
                    .entry(subject.form.clone())
                    .or_default()
                    .entry(exception.syndrome >> ESR_CLASS_SHIFT)
                    .or_default() += 1;
                continue;
            }
            report.covered.insert(subject.form.clone());
            if oracle_limit(&subject.form, &case.state)
                || subject.system
                    && system_oracle_limit(&subject.form, case.code[0], case.el1, &case.state)
            {
                if let Some(tally) = report.rows.tally(&subject.form, case.el1) {
                    tally.limited += 1;
                }
                continue;
            }
            // SAFETY: the original completed, so every access stays in the
            // windows; system-mode words exit before any access.
            let translated = match unsafe { subject.translation.run(case) } {
                Ok(translated) => translated,
                // An engine refusal of a registered form is a mismatch.
                Err(error) if subject.system => {
                    report.compared += 1;
                    if let Some(tally) = report.rows.tally(&subject.form, case.el1) {
                        tally.compared += 1;
                        tally.refused += 1;
                    }
                    report.rows.note(&subject.form, || {
                        format!("{:08x} at {}: {error:#}", case.code[0], level(case))
                    });
                    if subject.draft {
                        *report.open.entry(subject.form.clone()).or_default() += 1;
                    } else {
                        report.mismatches += 1;
                        report.mismatched.insert(subject.form.clone());
                    }
                    if report.shown < self.show {
                        report.shown += 1;
                        println!(
                            "{} {:08x?} at {}: {error:#}",
                            subject.form,
                            case.code,
                            level(case)
                        );
                        println!("  original exception {:x?}", original.exception);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            report.compared += 1;
            let system_word = subject.system.then_some(case.code[0]);
            let matched = comparable(&translated, system_word) == comparable(original, system_word);
            if let Some(tally) = report.rows.tally(&subject.form, case.el1) {
                tally.compared += 1;
                if matched {
                    tally.matched += 1;
                } else {
                    tally.diverged += 1;
                }
            }
            if !matched {
                report.rows.note(&subject.form, || {
                    format!(
                        "{:08x} at {}: original next pc {:#x} exception {:x?}, \
                         engine next pc {:#x} exception {:x?}",
                        case.code[0],
                        level(case),
                        original.next_pc,
                        original.exception,
                        translated.next_pc,
                        translated.exception
                    )
                });
                if subject.draft {
                    *report.open.entry(subject.form.clone()).or_default() += 1;
                } else {
                    report.mismatches += 1;
                    report.mismatched.insert(subject.form.clone());
                }
                if report.shown < self.show {
                    report.shown += 1;
                    println!("{} {:08x?} at {}:", subject.form, case.code, level(case));
                    print_difference(case, original, &translated);
                }
            }
        }
        report.words += batch.len();
        batch.clear();
        Ok(())
    }

    /// Pass every compared word sequence to `each`; samples needing other
    /// services count in `skipped`.
    fn subjects(
        &self,
        random: &mut Random,
        skipped: &mut usize,
        mut each: impl FnMut(&mut Random, Subject) -> Result<()>,
    ) -> Result<()> {
        for (name, mode) in registry::REGISTRIES {
            let registry = registry::load(root(), name)?;
            for form in registry["forms"].as_array().context("forms")? {
                let id = form["id"].as_str().context("form id")?;
                if mode == Mode::Service && !is_system_mode(form)
                    || form["status"] == "unsupported" && !is_system_mode(form)
                    || mode == Mode::Leaf && id == LEAF_TERMINATOR
                    || self
                        .form
                        .as_ref()
                        .is_some_and(|filter| !id.contains(filter.as_str()))
                    || self
                        .profile
                        .as_ref()
                        .is_some_and(|profile| form["profile"] != profile.as_str())
                {
                    continue;
                }
                let lane = Lane {
                    mode,
                    registry: &registry,
                    form,
                };
                let samples = form["smoke_samples"].as_array().context("samples")?;
                let mut seen = BTreeSet::new();
                for sample in samples {
                    let mut code = vec![hex(&sample["word"])?];
                    for following in sample["following_words"].as_array().into_iter().flatten() {
                        code.push(hex(following)?);
                    }
                    let Some(translation) = lane
                        .translate(&code, sample)
                        .with_context(|| format!("{id} {code:08x?}"))?
                    else {
                        *skipped += 1;
                        continue;
                    };
                    seen.insert(code[0]);
                    for subject in subjects_for(form, id, lane.scalable(sample), code, translation)?
                    {
                        each(random, subject)?;
                    }
                }
                // Random field words reuse the first sample's profile.
                let Some(sample) = samples.first() else {
                    continue;
                };
                let mask = hex(&form["encoding_mask"])?;
                let value = hex(&form["encoding_value"])?;
                for _ in 0..self.fields {
                    let found = (0..FIELD_ATTEMPTS).find_map(|_| {
                        let word = value | (random.next() as u32 & !mask);
                        if seen.contains(&word) || unpredictable_overlap(id, word) {
                            return None;
                        }
                        let translation = lane.translate(&[word], sample).ok().flatten()?;
                        Some((word, translation))
                    });
                    if let Some((word, translation)) = found {
                        seen.insert(word);
                        let scalable = lane.scalable(sample);
                        for subject in subjects_for(form, id, scalable, vec![word], translation)? {
                            each(random, subject)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// The subject for `code`, and for an admissible system-mode word its EL1 twin.
fn subjects_for(
    form: &Value,
    id: &str,
    scalable: Option<(usize, u64)>,
    code: Vec<u32>,
    translation: Translation,
) -> Result<Vec<Subject>> {
    let system = is_system_mode(form);
    let subject = |code: Vec<u32>, translation, el1| Subject {
        form: id.into(),
        scalable,
        system,
        draft: is_draft(form),
        el1,
        code,
        translation,
    };
    let mut subjects = Vec::with_capacity(2);
    if system && el1_admissible(code[0]) {
        subjects.push(subject(code.clone(), Translation::system(&code)?, true));
    }
    subjects.push(subject(code, translation, false));
    Ok(subjects)
}

/// Whether the harness can run `word` at EL1t and still record its outcome:
/// it must not wait, return, take over the harness's translation, vectors,
/// FP access, stepping or stack selection, enable PAN or streaming mode (the
/// recording handler reads the EL0-accessible data window and FP state), zero
/// memory at a random address, or make a semihosting call.
fn el1_admissible(word: u32) -> bool {
    const WFE: u32 = 0xd503_205f;
    const WFX_TIMEOUT_MASK: u32 = 0xffff_ffc0;
    const WFX_TIMEOUT: u32 = 0xd503_1000;
    // ERET, ERETAA and ERETAB.
    const RETURNS: [u32; 3] = [0xd69f_03e0, 0xd69f_0bff, 0xd69f_0fff];
    const MSR_REGISTER_MASK: u32 = 0xfff0_0000;
    const MSR_REGISTER: u32 = 0xd510_0000;
    const PSTATE_MASK: u32 = 0xfff8_f01f;
    const PSTATE: u32 = 0xd500_401f;
    const SYS_MASK: u32 = 0xfff8_0000;
    const SYS: u32 = 0xd508_0000;
    const HLT_SEMIHOSTING: u32 = 0xd45e_0000;
    // MSR targets as op0:op1:CRn:CRm:op2 selectors (bits 19..5): the
    // harness's controls, its step count in TPIDR_EL1, the OS lock and
    // double lock that stepping needs, MTE's GCR_EL1, and the register forms
    // of SPSel, PAN and SVCR.
    const HARNESS_REGISTERS: [(u32, u32, u32, u32, u32); 16] = [
        (3, 0, 12, 0, 0), // VBAR_EL1
        (3, 0, 1, 0, 0),  // SCTLR_EL1
        (3, 0, 1, 0, 2),  // CPACR_EL1
        (3, 0, 1, 2, 6),  // SMCR_EL1
        (3, 0, 2, 0, 0),  // TTBR0_EL1
        (3, 0, 2, 0, 1),  // TTBR1_EL1
        (3, 0, 2, 0, 2),  // TCR_EL1
        (3, 0, 10, 2, 0), // MAIR_EL1
        (2, 0, 0, 2, 2),  // MDSCR_EL1
        (3, 0, 13, 0, 4), // TPIDR_EL1
        (2, 0, 1, 0, 4),  // OSLAR_EL1
        (2, 0, 1, 3, 4),  // OSDLR_EL1
        (3, 0, 1, 0, 6),  // GCR_EL1
        (3, 0, 4, 2, 0),  // SPSel
        (3, 0, 4, 2, 3),  // PAN
        (3, 3, 4, 2, 2),  // SVCR
    ];
    let field = |shift: u32, bits: u32| (word >> shift) & ((1 << bits) - 1);
    if RETURNS.contains(&word)
        || matches!(word, WFE | WFI)
        || word & WFX_TIMEOUT_MASK == WFX_TIMEOUT
        || word & 0xffff_ffe0 == HLT_SEMIHOSTING
    {
        return false;
    }
    if word & MSR_REGISTER_MASK == MSR_REGISTER {
        let target = (
            2 + field(19, 1),
            field(16, 3),
            field(12, 4),
            field(8, 4),
            field(5, 3),
        );
        return !HARNESS_REGISTERS.contains(&target);
    }
    if word & PSTATE_MASK == PSTATE {
        // SPSel (op1=0, op2=5), PAN (op1=0, op2=4) and SVCR (op1=3, op2=3).
        return !matches!((field(16, 3), field(5, 3)), (0, 5) | (0, 4) | (3, 3));
    }
    if word & SYS_MASK == SYS {
        // DC ZVA, GVA and GZVA (op1=3, CRn=7, CRm=4).
        return !(field(16, 3) == 3 && field(12, 4) == 7 && field(8, 4) == 4);
    }
    true
}

fn level(case: &Case) -> &'static str {
    if case.el1 { "EL1" } else { "EL0" }
}

fn print_difference(case: &Case, original: &Outcome, translated: &Outcome) {
    let (before, a, b) = (&case.state, &original.state, &translated.state);
    for index in 0..a.x.len() {
        if a.x[index] != b.x[index] {
            println!(
                "  x{index}: original {:#x}, native {:#x}, initial {:#x}",
                a.x[index], b.x[index], before.x[index]
            );
        }
    }
    for index in 0..a.v.len() {
        if a.v[index] != b.v[index] {
            println!(
                "  v{index}: original {:x?}, native {:x?}, initial {:x?}",
                a.v[index], b.v[index], before.v[index]
            );
        }
    }
    for (name, x, y) in [
        ("next pc", original.next_pc, translated.next_pc),
        ("sp", a.sp, b.sp),
        ("nzcv", a.nzcv.into(), b.nzcv.into()),
        (
            "fpcr",
            (a.fpcr & FPCR_MASK).into(),
            (b.fpcr & FPCR_MASK).into(),
        ),
        (
            "fpsr",
            (a.fpsr & FPSR_MASK).into(),
            (b.fpsr & FPSR_MASK).into(),
        ),
    ] {
        if x != y {
            println!("  {name}: original {x:#x}, native {y:#x}");
        }
    }
    if let (Some(a), Some(b)) = (&original.scalable, &translated.scalable) {
        let initial = case.scalable.as_ref().expect("scalable case");
        for (name, x, y, before) in [
            ("z", &a.z, &b.z, &initial.z),
            ("p", &a.p, &b.p, &initial.p),
            ("za", &a.za, &b.za, &initial.za),
        ] {
            let differing: Vec<usize> = (0..x.len()).filter(|&i| x[i] != y[i]).collect();
            if let (Some(&first), Some(&last)) = (differing.first(), differing.last()) {
                println!(
                    "  {name}: {} bytes differ in {first:#x}..={last:#x}; at {first:#x} original \
                     {:#04x}, native {:#04x}, initial {:#04x} (svl {})",
                    differing.len(),
                    x[first],
                    y[first],
                    before[first],
                    initial.svl
                );
            }
        }
        if a.zt0 != b.zt0 {
            println!("  zt0 differs");
        }
        if (a.svcr, a.tpidr2) != (b.svcr, b.tpidr2) {
            println!(
                "  svcr, tpidr2: original {:#x}, {:#x}; native {:#x}, {:#x}",
                a.svcr, a.tpidr2, b.svcr, b.tpidr2
            );
        }
    }
    if original.spsr != translated.spsr {
        println!(
            "  spsr: original {:x?}, native {:x?}",
            original.spsr, translated.spsr
        );
    }
    if original.exception != translated.exception {
        println!(
            "  exception: original {:x?}, native {:x?}",
            original.exception, translated.exception
        );
    }
    if let Some(offset) = (0..DATA_BYTES).find(|&i| original.data[i] != translated.data[i]) {
        println!("  data differs from window offset {offset:#x}");
    }
    println!("  initial fpcr {:#x}, nzcv {:#x}", before.fpcr, before.nzcv);
}
