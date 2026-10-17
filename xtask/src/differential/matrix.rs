//! System requirement matrix lane: words for the matrix's System form rows
//! and concretely encoded accessor rows, run through the system-mode engine
//! lane against QEMU, with one tally per row and exception level.
//!
//! A row whose registry status is "implemented" must match; any other row's
//! divergences are reported as open. `--report` writes the tallies as JSON for
//! the matrix owner to cite.
use super::{Random, Subject, el1_admissible};
use crate::oracle::native::Translation;
use crate::system_matrix::MATRIX;
use crate::tools::root;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, process::Command};

/// Exception generation: SVC, HVC, SMC, BRK, HLT, DCPS1..3.
const EXCEPTION_MASK: u32 = 0xff00_0000;
const EXCEPTION: u32 = 0xd400_0000;
/// The System instruction class: hints, barriers, PSTATE, SYS/SYSL, MRS/MSR.
const SYSTEM_MASK: u32 = 0xffc0_0000;
const SYSTEM: u32 = 0xd500_0000;
/// ERET, ERETAA, ERETAB and DRPS.
const RETURNS: [u32; 4] = [0xd69f_03e0, 0xd69f_0bff, 0xd69f_0fff, 0xd6bf_03e0];
const UDF_MASK: u32 = 0xffff_0000;
/// MSR (immediate) with Rt=31 and CRn=4.
const PSTATE: u32 = 0xd500_401f;
const REGISTER_FIELD: u32 = 0x1f;
const IMMEDIATE_FIELD: u32 = 0xf;

/// Whether `word` belongs to the system lane: it exits to the engine or runs
/// inline without touching memory.
pub(super) fn is_system_word(word: u32) -> bool {
    word & EXCEPTION_MASK == EXCEPTION
        || word & SYSTEM_MASK == SYSTEM
        || RETURNS.contains(&word)
        || word & UDF_MASK == 0
}

/// Outcomes of one row at one exception level.
#[derive(Default, Clone, Copy)]
pub(super) struct Tally {
    pub compared: usize,
    pub matched: usize,
    pub diverged: usize,
    /// The engine or the compiler stopped instead of completing the word.
    pub refused: usize,
    /// Skipped as a recorded oracle limit.
    pub limited: usize,
}

impl Tally {
    fn json(self) -> Value {
        json!({
            "compared": self.compared,
            "matched": self.matched,
            "diverged": self.diverged,
            "refused": self.refused,
            "limited": self.limited,
        })
    }
}

/// One sampled matrix row.
pub(super) struct Row {
    status: String,
    words: Vec<u32>,
    pub el0: Tally,
    pub el1: Option<Tally>,
    /// The first divergence or refusal, for the report.
    pub first: Option<String>,
}

#[derive(Default)]
pub(super) struct Rows {
    pub rows: BTreeMap<String, Row>,
    /// Rows the lane cannot sample, with the reason.
    unsampled: Vec<(String, String)>,
    /// Implemented rows with a word the compiler refuses.
    pub refused_implemented: Vec<String>,
}

impl Rows {
    pub fn tally(&mut self, id: &str, el1: bool) -> Option<&mut Tally> {
        let row = self.rows.get_mut(id)?;
        Some(if el1 {
            row.el1.get_or_insert_default()
        } else {
            &mut row.el0
        })
    }

    pub fn note(&mut self, id: &str, text: impl FnOnce() -> String) {
        if let Some(row) = self.rows.get_mut(id)
            && row.first.is_none()
        {
            row.first = Some(text());
        }
    }

    /// Write the per-row tallies with the inputs that produced them.
    pub fn write(&self, path: &Path, seed: u64, states: usize, fields: usize) -> Result<()> {
        let matrix = std::fs::read(root().join(MATRIX)).context(MATRIX)?;
        let commit = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root())
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|commit| commit.trim().to_owned());
        let rows: Vec<Value> = self
            .rows
            .iter()
            .map(|(id, row)| {
                let mut entry = json!({
                    "id": id,
                    "status": row.status,
                    "words": row.words.iter().map(|word| format!("0x{word:08x}")).collect::<Vec<_>>(),
                    "el0": row.el0.json(),
                });
                if let Some(el1) = row.el1 {
                    entry["el1"] = el1.json();
                }
                if let Some(first) = &row.first {
                    entry["first_difference"] = first.as_str().into();
                }
                entry
            })
            .collect();
        let unsampled: Vec<Value> = self
            .unsampled
            .iter()
            .map(|(id, reason)| json!({"id": id, "reason": reason}))
            .collect();
        let report = json!({
            "schema_version": 1,
            "kind": "system_matrix_differential",
            "matrix": MATRIX,
            "matrix_sha256": stela_runtime::sha256(&matrix),
            "commit": commit,
            "seed": seed,
            "states": states,
            "fields": fields,
            "rows": rows,
            "unsampled": unsampled,
        });
        let mut bytes = serde_json::to_vec_pretty(&report)?;
        bytes.push(b'\n');
        std::fs::write(path, bytes).with_context(|| path.display().to_string())
    }
}

/// Bits of each System instruction encoding field.
fn width(field: &str) -> Option<u32> {
    match field {
        "op0" => Some(2),
        "op1" | "op2" => Some(3),
        "CRn" | "CRm" => Some(4),
        _ => None,
    }
}

/// One field's value for register index `m`: a decimal number, or a
/// concatenation of binary literals and slices of `m` (`010:m[3]`,
/// `1:m[1:0]`), where a bare `m` fills the bits the other parts leave.
fn field(name: &str, value: &str, m: u32) -> Option<u32> {
    let width = width(name)?;
    if value.bytes().all(|byte| byte.is_ascii_digit()) && !value.contains(':') && value != "m" {
        return value.parse().ok().filter(|&value| value >> width == 0);
    }
    // Split on the colons outside `m[high:low]`.
    let mut parts = Vec::new();
    let (mut start, mut depth) = (0, 0);
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b':' if depth == 0 => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    let slice = |part: &str| -> Option<(u32, u32)> {
        let range = part.strip_prefix("m[")?.strip_suffix(']')?;
        let (high, low) = range.split_once(':').unwrap_or((range, range));
        Some((high.parse().ok()?, low.parse().ok()?))
    };
    let fixed: u32 = parts
        .iter()
        .filter(|part| **part != "m")
        .map(|part| match slice(part) {
            Some((high, low)) => Some(high - low + 1),
            None => part
                .bytes()
                .all(|byte| matches!(byte, b'0' | b'1'))
                .then_some(part.len() as u32),
        })
        .sum::<Option<u32>>()?;
    let mut result = 0;
    for part in parts {
        let (bits, value) = if part == "m" {
            let bits = width.checked_sub(fixed)?;
            (bits, m & ((1 << bits) - 1))
        } else if let Some((high, low)) = slice(part) {
            let bits = high - low + 1;
            (bits, (m >> low) & ((1 << bits) - 1))
        } else {
            (part.len() as u32, u32::from_str_radix(part, 2).ok()?)
        };
        result = result << bits | value;
    }
    (result >> width == 0).then_some(result)
}

/// `op0=.. op1=.. CRn=.. [CRm=..] op2=..` for register index `m`.
fn fields(encoding: &str, m: u32) -> Option<BTreeMap<&str, u32>> {
    encoding
        .split_whitespace()
        .map(|part| {
            let (name, value) = part.split_once('=')?;
            Some((name, field(name, value, m)?))
        })
        .collect()
}

/// The accessor's base word for register index `m`, without Rt for register
/// forms or the immediate for MSR (immediate).
fn accessor(name: &str, encoding: &str, m: u32) -> Option<u32> {
    let fields = fields(encoding, m)?;
    let field = |name: &str| fields.get(name).copied();
    let (op0, op1, crn, op2) = (field("op0")?, field("op1")?, field("CRn")?, field("op2")?);
    if name.starts_with("MSR(imm)") {
        return Some(PSTATE | op1 << 16 | op2 << 5);
    }
    let read = name.starts_with("MRS ") || name.starts_with("SYSL ");
    Some(
        SYSTEM
            | u32::from(read) << 21
            | op0 << 19
            | op1 << 16
            | crn << 12
            | field("CRm")? << 8
            | op2 << 5,
    )
}

/// Sample every lane-eligible matrix row, `1 + fields` distinct words each,
/// and return the rows with one subject per word and admissible level.
pub(super) fn subjects(
    random: &mut Random,
    fields: usize,
    filter: Option<&str>,
) -> Result<(Rows, Vec<Subject>)> {
    let mut rows = Rows::default();
    let mut subjects = Vec::new();
    let matrix: Value =
        serde_json::from_slice(&std::fs::read(root().join(MATRIX)).context(MATRIX)?)?;
    for row in matrix["rows"].as_array().context("matrix rows")? {
        let id = row["id"].as_str().context("row id")?;
        let kind = row["kind"].as_str().unwrap_or_default();
        if !matches!(kind, "form" | "access") || filter.is_some_and(|filter| !id.contains(filter)) {
            continue;
        }
        let encoding = row["encoding"].as_str().unwrap_or_default();
        let words: Vec<u32> = if kind == "form" {
            let Some((value, mask)) = encoding.split_once('/').and_then(|(value, mask)| {
                let parse =
                    |text: &str| u32::from_str_radix(text.trim_start_matches("0x"), 16).ok();
                Some((parse(value)?, parse(mask)?))
            }) else {
                rows.unsampled
                    .push((id.into(), format!("form encoding {encoding:?}")));
                continue;
            };
            if !is_system_word(value) {
                rows.unsampled.push((
                    id.into(),
                    "memory access form; the block differential compares it at EL0".into(),
                ));
                continue;
            }
            let mut words = vec![value];
            for _ in 0..fields * 8 {
                if words.len() > fields {
                    break;
                }
                let word = value | (random.next() as u32 & !mask);
                if is_system_word(word) && !words.contains(&word) {
                    words.push(word);
                }
            }
            words
        } else {
            let name = row["name"].as_str().unwrap_or_default();
            if accessor(name, encoding, 0).is_none() {
                rows.unsampled.push((
                    id.into(),
                    format!("encoding {encoding:?} has a field other than a register index"),
                ));
                continue;
            }
            let free = if name.starts_with("MSR(imm)") {
                (IMMEDIATE_FIELD, 8)
            } else {
                (REGISTER_FIELD, 0)
            };
            let mut words = Vec::new();
            for _ in 0..fields * 8 {
                if words.len() > fields {
                    break;
                }
                // Indexed registers take a random index up to 15 as well.
                let index = random.next() as u32 & 0xf;
                let base = accessor(name, encoding, index).expect("checked at index 0");
                let word = base | (random.next() as u32 & free.0) << free.1;
                if !words.contains(&word) {
                    words.push(word);
                }
            }
            words
        };
        let status = row["status"].as_str().unwrap_or("open").to_owned();
        let draft = status != "implemented";
        rows.rows.insert(
            id.into(),
            Row {
                status,
                words: words.clone(),
                el0: Tally::default(),
                el1: None,
                first: None,
            },
        );
        for word in words {
            if let Err(error) = Translation::system(&[word]) {
                // The compiler refuses the word at both levels.
                for el1 in [false, true] {
                    if !el1 || el1_admissible(word) {
                        let tally = rows.tally(id, el1).expect("row inserted above");
                        tally.compared += 1;
                        tally.refused += 1;
                    }
                }
                rows.note(id, || format!("{word:08x}: compiler: {error:#}"));
                if !draft {
                    rows.refused_implemented.push(id.into());
                }
                continue;
            }
            for el1 in [true, false] {
                if el1 && !el1_admissible(word) {
                    continue;
                }
                subjects.push(Subject {
                    form: id.into(),
                    code: vec![word],
                    scalable: None,
                    system: true,
                    draft,
                    el1,
                    translation: Translation::system(&[word])?,
                });
            }
        }
    }
    Ok((rows, subjects))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessor_rows_encode_as_their_instructions() {
        // MRS MIDR_EL1, MSR SCTLR_EL1, TLBI VMALLE1, DC CIVAC and MSR DAIFSet.
        assert_eq!(
            accessor("MRS MIDR_EL1", "op0=3 op1=0 CRn=0 CRm=0 op2=0", 0),
            Some(0xd538_0000)
        );
        assert_eq!(
            accessor("MSR SCTLR_EL1", "op0=3 op1=0 CRn=1 CRm=0 op2=0", 0),
            Some(0xd518_1000)
        );
        assert_eq!(
            accessor("TLBI VMALLE1", "op0=1 op1=0 CRn=8 CRm=7 op2=0", 0),
            Some(0xd508_8700)
        );
        assert_eq!(
            accessor("DC CIVAC", "op0=1 op1=3 CRn=7 CRm=14 op2=1", 0),
            Some(0xd50b_7e20)
        );
        assert_eq!(
            accessor("MSR(imm) DAIFSet", "op0=0 op1=3 CRn=4 op2=6", 0),
            Some(0xd503_40df)
        );
        assert_eq!(
            accessor("MRS ICC_SRE_EL1", "op0=3 op1=0 CRn=12 CRm=16 op2=5", 0),
            None
        );
    }

    #[test]
    fn indexed_registers_expand_their_index_into_the_encoding() {
        // DBGBCR5_EL1, AMEVCNTR113_EL0 (S3_3_C13_C13_5) and ICC_AP1R2_EL1.
        let breakpoint = "op0=2 op1=0 CRn=0 CRm=m op2=5";
        assert_eq!(
            accessor("MRS DBGBCR<m>_EL1", breakpoint, 5),
            Some(0xd530_05a0)
        );
        let counter = "op0=3 op1=3 CRn=13 CRm=110:m[3] op2=m";
        assert_eq!(
            accessor("MRS AMEVCNTR1<m>_EL0", counter, 13),
            Some(0xd53b_dda0)
        );
        let priority = "op0=3 op1=0 CRn=12 CRm=9 op2=0:m[1:0]";
        assert_eq!(
            accessor("MSR ICC_AP1R<m>_EL1", priority, 2),
            Some(0xd518_c940)
        );
        // The IMPLEMENTATION DEFINED space is not an index.
        let private = "op0=3 op1=op1 CRn=1x11 CRm=Cm op2=op2";
        assert_eq!(accessor("MRS S3_<op1>_C<Cn>_C<Cm>_<op2>", private, 0), None);
    }

    #[test]
    fn the_lane_takes_system_words_only() {
        for word in [
            0xd400_0001,
            0xd503_201f,
            0xd538_0000,
            0xd69f_03e0,
            0x0000_1234,
        ] {
            assert!(is_system_word(word), "{word:08x}");
        }
        // LDXR, LDTR and RET.
        for word in [0xc85f_7c20, 0xb840_0820, 0xd65f_03c0] {
            assert!(!is_system_word(word), "{word:08x}");
        }
    }
}
