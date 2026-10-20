//! `machine/chip/forms.rs`: per Apple CPU, the A64 forms of the Arm checklist
//! that its Apple clang profile does not have (`isa/apple-codegen-profiles.json`
//! lists each candidate form's CPUs; a form it does not list is on no Apple
//! CPU). Such a word is UNDEFINED on the chip, or a NOP for the forms Arm
//! decodes as NOP without their feature. A form the chip has that overlaps an
//! UNDEFINED one keeps its words.
//!
//! Each form also records the chip-varying features it requires (the
//! checklist's feature expression over the profile's `varying` features of
//! `isa/a64-system-requirements.json`, in disjunctive normal form), so that a
//! PE whose identification withholds a feature its chip has lacks the
//! feature's forms too.
use crate::system_matrix::CHIPS;
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

pub const GENERATED: &str = "crates/stela-runtime/src/machine/chip/forms.rs";

/// The forms whose decode in Arm's `ISA_A64_xml_A_profile-2026-06` is
/// `if !IsFeatureImplemented(FEAT_x) then EndOfDecode(Decode_NOP)`: the hints
/// of features an Apple CPU may lack, and RPRFM in PRFM's reserved space.
/// Every other form's absent-feature decode is `Decode_UNDEF`.
const NOP_WHEN_ABSENT: [&str; 10] = [
    "CHKFEAT_HF_hints",
    "CLRBHB_HI_hints",
    "DGH_HI_hints",
    "GCSB_HD_hints",
    "PACM_HI_hints",
    "PSB_HC_hints",
    "RPRFM_R_ldst_regoff",
    "SHUH_HI_hints",
    "STCPH_HI_hints",
    "STSHH_HI_hints",
];

/// A condition in disjunctive normal form over the varying features: met
/// when every feature of one term is. `[0]` is always met, `[]` never.
type Requires = Vec<u64>;

const ALWAYS: [u64; 1] = [0];

/// The chip-varying features, in the order of the runtime's `Feature`, and
/// each chip's features, in [`CHIPS`] order.
pub struct Features {
    varying: Vec<String>,
    chips: Vec<BTreeSet<String>>,
}

impl Features {
    /// From the `profile` header of the system requirement matrix.
    pub fn from_matrix(matrix: &Value) -> Result<Self> {
        let profile = &matrix["profile"];
        let names = |value: &Value| -> Result<Vec<String>> {
            value
                .as_array()
                .context("feature list is not an array")?
                .iter()
                .map(|name| Ok(name.as_str().context("feature is not a string")?.to_owned()))
                .collect()
        };
        let varying = names(&profile["varying"]).context("profile without varying")?;
        ensure!(varying.len() <= 64, "more than 64 varying features");
        let listed = profile["chips"]
            .as_array()
            .context("profile without chips")?;
        let mut chips = Vec::new();
        for chip in CHIPS {
            let entry = listed
                .iter()
                .find(|entry| entry["chip"] == chip.name)
                .with_context(|| format!("profile without {}", chip.name))?;
            chips.push(names(&entry["features"])?.into_iter().collect());
        }
        Ok(Self { varying, chips })
    }

    /// The varying features chip `index` has.
    fn mask(&self, index: usize) -> u64 {
        self.varying
            .iter()
            .enumerate()
            .filter(|(_, name)| self.chips[index].contains(*name))
            .fold(0, |mask, (bit, _)| mask | 1 << bit)
    }

    /// What a checklist feature expression requires of the varying
    /// features, and whether it names one. A feature every chip has is met
    /// and one no chip has is not. A condition on an encoding field
    /// (`sz == '0'`) counts as met: the checklist does not place the field,
    /// so a form's words that need a feature only for some field values
    /// stay admitted while it is withheld.
    fn requires(&self, expression: &str) -> Result<(Requires, bool)> {
        let tokens = tokenize(expression)?;
        let mut parser = Parser {
            features: self,
            tokens: &tokens,
            at: 0,
            varying: false,
        };
        let requires = parser.disjunction()?;
        ensure!(
            parser.at == tokens.len(),
            "{expression}: unexpected {}",
            tokens[parser.at]
        );
        Ok((requires, parser.varying))
    }
}

fn tokenize(expression: &str) -> Result<Vec<&str>> {
    let mut tokens = Vec::new();
    let mut rest = expression.trim_start();
    while !rest.is_empty() {
        let length = if rest.starts_with("&&") || rest.starts_with("||") || rest.starts_with("==") {
            2
        } else if rest.starts_with(['(', ')']) {
            1
        } else if let Some(literal) = rest.strip_prefix('\'') {
            literal
                .find('\'')
                .with_context(|| format!("{expression}: unterminated literal"))?
                + 2
        } else {
            let length = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            ensure!(length > 0, "{expression}: unexpected {rest}");
            length
        };
        tokens.push(&rest[..length]);
        rest = rest[length..].trim_start();
    }
    Ok(tokens)
}

struct Parser<'a> {
    features: &'a Features,
    tokens: &'a [&'a str],
    at: usize,
    /// Whether the expression names a varying feature.
    varying: bool,
}

impl<'a> Parser<'a> {
    fn next(&mut self) -> Option<&'a str> {
        let token = self.tokens.get(self.at).copied();
        self.at += usize::from(token.is_some());
        token
    }

    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.at).copied()
    }

    fn disjunction(&mut self) -> Result<Requires> {
        let mut terms = self.conjunction()?;
        while self.peek() == Some("||") {
            self.next();
            terms.extend(self.conjunction()?);
        }
        Ok(minimal(terms))
    }

    fn conjunction(&mut self) -> Result<Requires> {
        let mut terms = self.atom()?;
        while self.peek() == Some("&&") {
            self.next();
            let other = self.atom()?;
            terms = and(&terms, &other);
        }
        Ok(terms)
    }

    fn atom(&mut self) -> Result<Requires> {
        let token = self.next().context("expression ends early")?;
        if token == "(" {
            let inner = self.disjunction()?;
            ensure!(self.next() == Some(")"), "unbalanced parenthesis");
            return Ok(inner);
        }
        ensure!(
            token.starts_with(|c: char| c.is_ascii_alphabetic()),
            "unexpected {token}"
        );
        if self.peek() == Some("==") {
            self.next();
            let literal = self.next().context("comparison without a value")?;
            ensure!(literal.starts_with('\''), "comparison with {literal}");
            return Ok(ALWAYS.to_vec());
        }
        if let Some(bit) = self.features.varying.iter().position(|name| name == token) {
            self.varying = true;
            return Ok(vec![1 << bit]);
        }
        let on = self
            .features
            .chips
            .iter()
            .filter(|chip| chip.contains(token))
            .count();
        match on {
            0 => Ok(Vec::new()),
            count if count == self.features.chips.len() => Ok(ALWAYS.to_vec()),
            _ => bail!("{token} is on some chips but not varying"),
        }
    }
}

/// Every term of `a` joined with every term of `b`.
fn and(a: &[u64], b: &[u64]) -> Requires {
    minimal(
        a.iter()
            .flat_map(|x| b.iter().map(move |y| x | y))
            .collect(),
    )
}

/// `terms` without duplicates and without terms that another term's
/// features imply, sorted.
fn minimal(mut terms: Requires) -> Requires {
    terms.sort_unstable_by_key(|term| (term.count_ones(), *term));
    terms.dedup();
    let mut kept: Requires = Vec::new();
    for term in terms {
        if !kept.iter().any(|smaller| smaller & !term == 0) {
            kept.push(term);
        }
    }
    kept.sort_unstable();
    kept
}

fn met(requires: &[u64], features: u64) -> bool {
    requires.iter().any(|term| term & !features == 0)
}

struct Form {
    mask: u32,
    value: u32,
    /// Bit `n` set when the form is on chip `n` of [`CHIPS`].
    present: u8,
    requires: Requires,
    /// The chips that lack the form when their identification withholds
    /// what it requires: those whose features it names.
    withholdable: u8,
}

fn hex(form: &Value, key: &str) -> Result<u32> {
    let text = form[key]
        .as_str()
        .with_context(|| format!("form without {key}"))?;
    Ok(u32::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

fn requires_text(requires: &[u64]) -> String {
    let terms: Vec<String> = requires.iter().map(|term| format!("{term:#x}")).collect();
    format!("&[{}]", terms.join(", "))
}

/// Render the table from the checklist forms, the Apple candidates and the
/// chips' features.
pub fn render(
    checklist: &BTreeMap<String, Value>,
    apple: &Value,
    features: &Features,
) -> Result<String> {
    let all: u8 = (1 << CHIPS.len()) - 1;
    let mut cpus: BTreeMap<&str, u8> = BTreeMap::new();
    for form in apple["forms"].as_array().context("no Apple forms")? {
        let id = form["id"].as_str().context("Apple form without id")?;
        let mut present = 0;
        for cpu in form["cpus"].as_array().into_iter().flatten() {
            let cpu = cpu.as_str().context("cpu is not a string")?;
            let index = CHIPS
                .iter()
                .position(|chip| chip.name == cpu)
                .with_context(|| format!("{id}: unknown CPU {cpu}"))?;
            present |= 1 << index;
        }
        cpus.insert(id, present);
    }
    let nop: BTreeSet<&str> = NOP_WHEN_ABSENT.into();
    for id in &nop {
        ensure!(checklist.contains_key(*id), "{id} is not a checklist form");
    }
    let masks: Vec<u64> = (0..CHIPS.len()).map(|index| features.mask(index)).collect();
    let mut forms = BTreeMap::new();
    for (id, form) in checklist {
        let present = cpus.get(id.as_str()).copied().unwrap_or(0);
        let expressions = form["features"].as_array().map_or(&[][..], Vec::as_slice);
        ensure!(expressions.len() <= 1, "{id} has more than one feature");
        let (requires, varying) = match expressions.first() {
            Some(feature) => {
                let expression = feature["feature"]
                    .as_str()
                    .with_context(|| format!("{id}: feature without an expression"))?;
                features
                    .requires(expression)
                    .with_context(|| format!("{id}: {expression}"))?
            }
            None => (ALWAYS.to_vec(), false),
        };
        // A form naming no varying feature is where its Apple profile
        // puts it, whatever constant its expression folds to.
        let requires = if varying { requires } else { ALWAYS.to_vec() };
        let mut withholdable = 0;
        for (index, chip) in CHIPS.iter().enumerate() {
            if present & 1 << index == 0 {
                continue;
            }
            ensure!(
                met(&requires, masks[index]),
                "{id} is on {} without the features it requires",
                chip.name
            );
            if requires != ALWAYS {
                withholdable |= 1 << index;
            }
        }
        forms.insert(
            id.as_str(),
            Form {
                mask: hex(form, "encoding_mask")?,
                value: hex(form, "encoding_value")?,
                present,
                requires,
                withholdable,
            },
        );
    }
    // Per mask, per value: (absent chips, NOP, requires, overriding forms).
    type Unless = (u32, u32, u8, Requires);
    type Entry = (u8, bool, Option<Requires>, Vec<Unless>);
    let mut groups: BTreeMap<u32, BTreeMap<u32, Entry>> = BTreeMap::new();
    for (id, form) in &forms {
        let absent = all & !form.present;
        let lacking = absent | form.withholdable;
        if lacking == 0 {
            continue;
        }
        let is_nop = nop.contains(id);
        let unless: Vec<Unless> = if is_nop {
            Vec::new()
        } else {
            forms
                .iter()
                .filter(|(other, other_form)| {
                    other != &id
                        && other_form.present & lacking != 0
                        && (form.value ^ other_form.value) & form.mask & other_form.mask == 0
                })
                .map(|(_, other)| {
                    (
                        other.mask,
                        other.value,
                        other.present & lacking,
                        other.requires.clone(),
                    )
                })
                .collect()
        };
        let entry = groups
            .entry(form.mask)
            .or_default()
            .entry(form.value)
            .or_insert((0, is_nop, None, Vec::new()));
        ensure!(
            entry.2.is_none() || entry.1 == is_nop,
            "{id} shares its encoding with a form of another absent decode"
        );
        entry.0 |= absent;
        // A word is admitted where every form it is meets its requirement.
        entry.2 = Some(match &entry.2 {
            Some(requires) => and(requires, &form.requires),
            None => form.requires.clone(),
        });
        entry.3.extend(unless);
        entry.3.sort_unstable();
        entry.3.dedup();
    }
    let mut out = String::new();
    writeln!(
        out,
        "//! Per Apple CPU, the A64 forms its Apple clang profile does not have,\n\
         //! and the chip-varying features each form requires, generated by\n\
         //! `cargo xtask progress` from `isa/a64-documented-checklist.json`,\n\
         //! `isa/apple-codegen-profiles.json` and `isa/a64-system-requirements.json`.\n\
         //! Do not edit.\n\
         use super::{{AbsentForm, AbsentGroup}};\n"
    )?;
    let quoted: Vec<String> = features
        .varying
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect();
    writeln!(
        out,
        "/// The varying features, by bit of `requires`: the order of `Feature`.\n\
         #[cfg(test)]\n\
         pub(super) const FEATURES: [&str; {}] = [{}];\n",
        quoted.len(),
        quoted.join(", ")
    )?;
    let names: Vec<&str> = CHIPS.iter().map(|chip| chip.name).collect();
    writeln!(
        out,
        "/// Grouped by encoding mask, each group sorted by value. `chips` bit `n` is\n\
         /// set when the form is absent on chip `n` ({}). `requires` is met when\n\
         /// the PE presents every feature of one of its terms.",
        names.join(", ")
    )?;
    writeln!(out, "pub(super) static ABSENT: &[AbsentGroup] = &[")?;
    for (mask, values) in &groups {
        writeln!(out, "    AbsentGroup {{ mask: {mask:#010x}, forms: &[")?;
        for (value, (chips, is_nop, requires, unless)) in values {
            let requires = requires.as_deref().unwrap_or(&ALWAYS);
            let unless: Vec<String> = unless
                .iter()
                .map(|(mask, value, chips, requires)| {
                    format!(
                        "({mask:#010x}, {value:#010x}, {chips:#04x}, {})",
                        requires_text(requires)
                    )
                })
                .collect();
            writeln!(
                out,
                "        AbsentForm {{ value: {value:#010x}, chips: {chips:#04x}, nop: {is_nop}, \
                 requires: {}, unless: &[{}] }},",
                requires_text(requires),
                unless.join(", ")
            )?;
        }
        writeln!(out, "    ] }},")?;
    }
    writeln!(out, "];")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn form(mask: &str, value: &str) -> Value {
        json!({"encoding_mask": mask, "encoding_value": value})
    }

    fn featured(mask: &str, value: &str, feature: &str) -> Value {
        json!({"encoding_mask": mask, "encoding_value": value,
               "features": [{"feature": feature, "name": feature}]})
    }

    /// PAuth_LR on the M6 and SME on the M4 to M6; PAuth everywhere.
    fn features() -> Features {
        let matrix = json!({"profile": {
            "varying": ["FEAT_PAuth_LR", "FEAT_SME", "FEAT_SME_I16I64"],
            "chips": [
                {"chip": "apple-m1", "features": ["FEAT_PAuth"]},
                {"chip": "apple-m2", "features": ["FEAT_PAuth"]},
                {"chip": "apple-m3", "features": ["FEAT_PAuth"]},
                {"chip": "apple-m4", "features": ["FEAT_PAuth", "FEAT_SME", "FEAT_SME_I16I64"]},
                {"chip": "apple-m5", "features": ["FEAT_PAuth", "FEAT_SME", "FEAT_SME_I16I64"]},
                {"chip": "apple-m6",
                 "features": ["FEAT_PAuth", "FEAT_PAuth_LR", "FEAT_SME", "FEAT_SME_I16I64"]},
            ],
        }});
        Features::from_matrix(&matrix).unwrap()
    }

    #[test]
    fn feature_expressions_become_terms_over_the_varying_features() {
        let features = features();
        let requires = |text| features.requires(text).unwrap();
        assert_eq!(requires("FEAT_SME"), (vec![0b010], true));
        // A feature on every chip is met, one on none is not.
        assert_eq!(requires("FEAT_PAuth"), (vec![0], false));
        assert_eq!(requires("FEAT_SVE"), (vec![], false));
        assert_eq!(requires("FEAT_SVE || FEAT_SME"), (vec![0b010], true));
        assert_eq!(
            requires("(FEAT_SME || FEAT_PAuth_LR) && FEAT_SME_I16I64"),
            (vec![0b101, 0b110], true)
        );
        // A term another implies is dropped; a field condition is met.
        assert_eq!(
            requires("FEAT_SME || (FEAT_SME && FEAT_PAuth_LR)"),
            (vec![0b010], true)
        );
        assert_eq!(
            requires("FEAT_SME && (sz == '0' || FEAT_SME_I16I64)"),
            (vec![0b010], true)
        );
        assert!(features.requires("!FEAT_SME").is_err());
        assert!(features.requires("FEAT_SME &&").is_err());
        assert!(features.requires("(FEAT_SME").is_err());
    }

    #[test]
    fn absent_forms_are_grouped_and_present_overlaps_override_them() {
        let checklist: BTreeMap<String, Value> = [
            ("ADD", form("0xff000000", "0x8b000000")),
            (
                "RETAA_64E_branch_reg",
                featured("0xffffffff", "0xd65f0bff", "FEAT_PAuth"),
            ),
            (
                "RETAASPPCR_64M_branch_reg",
                featured("0xffffffe0", "0xd65f0be0", "FEAT_PAuth_LR"),
            ),
            (
                "PACM_HI_hints",
                featured("0xffffffff", "0xd50324ff", "FEAT_PAuth_LR"),
            ),
            ("HINT_HM_hints", form("0xfffff01f", "0xd503201f")),
            ("SMSTART", featured("0xfffff1ff", "0xd503417f", "FEAT_SME")),
            // Every checklist form named by NOP_WHEN_ABSENT must exist.
            ("CHKFEAT_HF_hints", form("0xffffffff", "0xd503251f")),
            ("CLRBHB_HI_hints", form("0xffffffff", "0xd50322df")),
            ("DGH_HI_hints", form("0xffffffff", "0xd50320df")),
            ("GCSB_HD_hints", form("0xffffffff", "0xd503227f")),
            ("PSB_HC_hints", form("0xffffffff", "0xd503223f")),
            ("RPRFM_R_ldst_regoff", form("0xffe04c18", "0xf8a04818")),
            ("SHUH_HI_hints", form("0xffffffdf", "0xd503265f")),
            ("STCPH_HI_hints", form("0xffffffff", "0xd503269f")),
            ("STSHH_HI_hints", form("0xffffffdf", "0xd503261f")),
        ]
        .into_iter()
        .map(|(id, form)| (id.to_owned(), form))
        .collect();
        let every = json!([
            "apple-m1", "apple-m2", "apple-m3", "apple-m4", "apple-m5", "apple-m6"
        ]);
        let apple = json!({"forms": [
            {"id": "ADD", "cpus": every},
            {"id": "RETAA_64E_branch_reg", "cpus": every},
            {"id": "HINT_HM_hints", "cpus": every},
            {"id": "RETAASPPCR_64M_branch_reg", "cpus": ["apple-m6"]},
            {"id": "PACM_HI_hints", "cpus": ["apple-m6"]},
            {"id": "SMSTART", "cpus": ["apple-m4", "apple-m5", "apple-m6"]},
        ]});
        let text = render(&checklist, &apple, &features()).unwrap();
        assert!(text.contains(
            "pub(super) const FEATURES: [&str; 3] = \
             [\"FEAT_PAuth_LR\", \"FEAT_SME\", \"FEAT_SME_I16I64\"];"
        ));
        // ADD is everywhere and has no entry; RETAASPPCR is absent on M1-M5,
        // and on an M6 that withholds PAuth_LR, except where RETAA's word
        // overrides it; PACM is a NOP without its feature, whatever overlaps
        // it.
        assert!(!text.contains("0x8b000000"));
        assert!(text.contains(
            "AbsentForm { value: 0xd65f0be0, chips: 0x1f, nop: false, requires: &[0x1], \
             unless: &[(0xffffffff, 0xd65f0bff, 0x3f, &[0x0])] }"
        ));
        assert!(text.contains(
            "AbsentForm { value: 0xd50324ff, chips: 0x1f, nop: true, requires: &[0x1], \
             unless: &[] }"
        ));
        // SMSTART is absent on M1-M3 and wherever SME is withheld.
        assert!(
            text.contains(
                "AbsentForm { value: 0xd503417f, chips: 0x07, nop: false, requires: &[0x2]"
            )
        );
        // A form on no Apple CPU is absent on all six.
        assert!(text.contains("AbsentForm { value: 0xf8a04818, chips: 0x3f, nop: true"));
    }

    /// A chip whose profile has a form must have the features it requires.
    #[test]
    fn a_form_on_a_chip_without_its_features_is_refused() {
        let checklist: BTreeMap<String, Value> = NOP_WHEN_ABSENT
            .iter()
            .map(|id| (id.to_string(), form("0xffffffff", "0xd503201f")))
            .chain([(
                "SMSTART".to_owned(),
                featured("0xfffff1ff", "0xd503417f", "FEAT_SME"),
            )])
            .collect();
        let apple = json!({"forms": [{"id": "SMSTART", "cpus": ["apple-m3"]}]});
        let error = render(&checklist, &apple, &features()).unwrap_err();
        assert!(format!("{error:#}").contains("SMSTART is on apple-m3 without"));
    }
}
