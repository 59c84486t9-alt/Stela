//! Original-versus-native differential over the instruction forms.
//!
//! Each implemented leaf, block and scalable form contributes its registry
//! samples plus random words over its free encoding bits that Stela accepts.
//! Every word runs from seeded random states on the QEMU oracle and as Stela's
//! native translation; registers, scalable banks, the next PC and the data
//! window must match whenever the original completes. Service forms of the
//! system-mode profile run on the system-mode engine at EL0 instead, and their
//! exceptions (ESR, ELR and, for aborts, FAR) must match as well.
use crate::oracle::{
    CODE_PAGE, Case, DATA_BYTES, DATA_WINDOW, Oracle, Outcome, Scalable, native::Translation,
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
fn system_oracle_limit(form: &str, word: u32) -> bool {
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
    wfi || absent || sme || pstate || flags
}

/// Oracle limits: compare FPCR and FPSR only on bits both engines model, and
/// FAR only where the exception defines it.
fn comparable(outcome: &Outcome) -> Outcome {
    let mut outcome = outcome.clone();
    outcome.state.fpcr &= FPCR_MASK;
    outcome.state.fpsr &= FPSR_MASK;
    if let Some(exception) = &mut outcome.exception
        && !FAR_CLASSES.contains(&(exception.syndrome >> ESR_CLASS_SHIFT))
    {
        exception.fault_address = 0;
    }
    outcome
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
        self.subjects(&mut random, &mut skipped, |random, subject| {
            batch.push(subject);
            if batch.len() == BATCH_WORDS {
                self.compare(&oracle, random, &mut batch, &mut report)?;
            }
            Ok(())
        })?;
        self.compare(&oracle, &mut random, &mut batch, &mut report)?;
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
                || subject.system && system_oracle_limit(&subject.form, case.code[0])
            {
                continue;
            }
            // SAFETY: the original completed, so every access stays in the
            // windows; system-mode words exit before any access.
            let translated = match unsafe { subject.translation.run(case) } {
                Ok(translated) => translated,
                // An engine refusal of a registered form is a mismatch.
                Err(error) if subject.system => {
                    report.compared += 1;
                    if subject.draft {
                        *report.open.entry(subject.form.clone()).or_default() += 1;
                    } else {
                        report.mismatches += 1;
                        report.mismatched.insert(subject.form.clone());
                    }
                    if report.shown < self.show {
                        report.shown += 1;
                        println!("{} {:08x?}: {error:#}", subject.form, case.code);
                        println!("  original exception {:x?}", original.exception);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            report.compared += 1;
            if comparable(&translated) != comparable(original) {
                if subject.draft {
                    *report.open.entry(subject.form.clone()).or_default() += 1;
                } else {
                    report.mismatches += 1;
                    report.mismatched.insert(subject.form.clone());
                }
                if report.shown < self.show {
                    report.shown += 1;
                    println!("{} {:08x?}:", subject.form, case.code);
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
                    each(
                        random,
                        Subject {
                            form: id.into(),
                            scalable: lane.scalable(sample),
                            system: is_system_mode(form),
                            draft: is_draft(form),
                            code,
                            translation,
                        },
                    )?;
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
                        each(
                            random,
                            Subject {
                                form: id.into(),
                                scalable: lane.scalable(sample),
                                system: is_system_mode(form),
                                draft: is_draft(form),
                                code: vec![word],
                                translation,
                            },
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
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
