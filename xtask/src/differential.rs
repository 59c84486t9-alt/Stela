//! Original-versus-native differential over the reviewed leaf instruction forms.
//!
//! Each implemented form contributes its registry samples plus random words over
//! its free encoding bits that Stela accepts. Every word runs from seeded random
//! states on the QEMU oracle and as Stela's native leaf translation; registers
//! and the data window must match whenever the original completes.
use crate::tools::root;
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};
use stela_compiler::GuestState;
use stela_oracle::{CODE_PAGE, Case, DATA_BYTES, DATA_WINDOW, Oracle, Outcome, native};

const REGISTRY: &str = "isa/apple-silicon-reviewed-forms.json";
const RET: u32 = 0xd65f_03c0;
/// FPCR controls of the reviewed profile that QEMU also implements: AHP, DN,
/// FZ, RMode, FZ16 and the AFP bits. QEMU has no FP trap enables.
const FPCR_MASK: u32 = 0x07c8_0007;
/// FPSR QC and cumulative flags; QEMU also keeps AArch32 NZCV, which Apple
/// silicon does not implement.
const FPSR_MASK: u32 = 0x0800_009f;
const NZCV_SHIFT: u32 = 28;
const ESR_CLASS_SHIFT: u64 = 26;
/// Pointers land in the middle half of the window so offsets either way stay inside.
const POINTER_SPAN: u64 = DATA_BYTES as u64 / 2;
const POINTER_ALIGNMENT: u64 = 16;
/// Attempts to find each random field word Stela accepts.
const FIELD_ATTEMPTS: usize = 64;
const REGISTER_FIELD: u32 = 0x1f;
const ZERO_OR_SP: u32 = 31;
const FPCR_AH: u32 = 1 << 1;

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
    // QEMU clears the sign of a NaN for vector FABS and FNEG even when FPCR.AH
    // is set; the architecture leaves it unchanged.
    (form.starts_with("FABS_asimdmisc") || form.starts_with("FNEG_asimdmisc"))
        && state.fpcr & FPCR_AH != 0
}

/// Oracle limits: compare FPCR and FPSR only on bits both engines model.
fn comparable(outcome: &Outcome) -> Outcome {
    let mut outcome = outcome.clone();
    outcome.state.fpcr &= FPCR_MASK;
    outcome.state.fpsr &= FPSR_MASK;
    outcome
}

fn hex(value: &Value) -> Result<u32> {
    let text = value.as_str().context("expected a hex word")?;
    Ok(u32::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

/// Native leaf translation of `word` at the code page, if Stela accepts it.
fn translate(word: u32) -> Result<Vec<u8>> {
    let source: Vec<u8> = [word, RET]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    let base = CODE_PAGE.to_string();
    let arguments = [
        "stela",
        "compile-leaf",
        "s",
        "--output-dir",
        "o",
        "--guest-base",
        &base,
    ];
    Ok(stela_cli::compile::compile(&arguments, &source)?.native)
}

struct Subject {
    form: String,
    word: u32,
    native: Vec<u8>,
}

impl Differential {
    pub fn run(self) -> Result<()> {
        let mut random = Random(self.seed);
        let subjects = self.subjects(&mut random)?;
        let cases: Vec<Case> = subjects
            .iter()
            .flat_map(|subject| std::iter::repeat_n(subject.word, self.states))
            .map(|word| Case {
                code: vec![word],
                state: random.state(),
                data: (0..DATA_BYTES).map(|_| random.next() as u8).collect(),
            })
            .collect();
        let oracle = match &self.qemu {
            Some(qemu) => Oracle::new(qemu)?,
            None => Oracle::locate(&root().join(".tools/qemu/bin"))?,
        };
        let originals = oracle.run(&cases)?;

        let mut compared = 0;
        let mut mismatches = vec![];
        let mut covered = BTreeSet::new();
        // Original exception classes per form, kept for forms that never complete.
        let mut uncovered: BTreeMap<&str, BTreeMap<u64, usize>> = BTreeMap::new();
        let per_case = subjects
            .iter()
            .flat_map(|subject| std::iter::repeat_n(subject, self.states));
        for ((case, original), subject) in cases.iter().zip(&originals).zip(per_case) {
            if let Some(exception) = original.exception {
                *uncovered
                    .entry(&subject.form)
                    .or_default()
                    .entry(exception.syndrome >> ESR_CLASS_SHIFT)
                    .or_default() += 1;
                continue;
            }
            covered.insert(subject.form.as_str());
            if oracle_limit(&subject.form, &case.state) {
                continue;
            }
            // SAFETY: the original completed, so every access stays in the windows.
            let translated = unsafe { native::run(&subject.native, case)? };
            compared += 1;
            if comparable(&translated) != comparable(original) {
                mismatches.push((subject, case, original, translated));
            }
        }
        uncovered.retain(|form, _| !covered.contains(form));

        for (subject, case, original, translated) in mismatches.iter().take(self.show) {
            println!("{} {:#010x}:", subject.form, subject.word);
            print_difference(case, original, translated);
        }
        let forms: BTreeSet<_> = mismatches
            .iter()
            .map(|(subject, ..)| &subject.form)
            .collect();
        for form in &forms {
            println!("mismatch: {form}");
        }
        for (form, classes) in &uncovered {
            println!("uncovered: {form}, exception classes {classes:x?}");
        }
        println!(
            "{} words, {compared} comparisons, {} mismatches in {} forms, {} forms never completed",
            subjects.len(),
            mismatches.len(),
            forms.len(),
            uncovered.len()
        );
        ensure!(
            mismatches.is_empty(),
            "native translation differs from the original"
        );
        Ok(())
    }

    fn subjects(&self, random: &mut Random) -> Result<Vec<Subject>> {
        let registry: Value = serde_json::from_str(&fs::read_to_string(root().join(REGISTRY))?)?;
        let mut subjects = vec![];
        for form in registry["forms"].as_array().context("forms")? {
            let id = form["id"].as_str().context("form id")?;
            if form["status"] == "unsupported"
                || self
                    .form
                    .as_ref()
                    .is_some_and(|filter| !id.contains(filter.as_str()))
            {
                continue;
            }
            let mut words = BTreeSet::new();
            for sample in form["smoke_samples"].as_array().into_iter().flatten() {
                let word = hex(&sample["word"])?;
                let native = translate(word).with_context(|| format!("{id} {word:#010x}"))?;
                words.insert(word);
                subjects.push(Subject {
                    form: id.into(),
                    word,
                    native,
                });
            }
            let mask = hex(&form["encoding_mask"])?;
            let value = hex(&form["encoding_value"])?;
            for _ in 0..self.fields {
                let found = (0..FIELD_ATTEMPTS).find_map(|_| {
                    let word = value | (random.next() as u32 & !mask);
                    if words.contains(&word) || unpredictable_overlap(id, word) {
                        return None;
                    }
                    translate(word).ok().map(|native| (word, native))
                });
                if let Some((word, native)) = found {
                    words.insert(word);
                    subjects.push(Subject {
                        form: id.into(),
                        word,
                        native,
                    });
                }
            }
        }
        ensure!(!subjects.is_empty(), "no forms selected");
        Ok(subjects)
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
    if let Some(offset) = (0..DATA_BYTES).find(|&i| original.data[i] != translated.data[i]) {
        println!("  data differs from window offset {offset:#x}");
    }
    println!("  initial fpcr {:#x}, nzcv {:#x}", before.fpcr, before.nzcv);
}
