//! Architectural field reset values from Arm's System register XML release
//! (`SysReg_xml_A_profile`): AARCHMRS leaves every reset empty and the ASL's
//! `AArch64_ResetControlRegisters` is IMPLEMENTATION DEFINED, so this is the
//! only machine-readable source. Only derived facts (each field's value under
//! the profile) leave this module; the archive and Arm's prose stay in `.stela`.
//!
//! A field's `field_reset` of type Warm or Cold applies at the engine's reset,
//! which is a Cold reset and so also a Warm one; a Warm reset alone, which
//! RMR_EL2.RR requests, sets only the fields with a Warm reset ([`warm`]).
//! The activity monitors' own reset (type AMU) is neither. Conditional resets name the
//! highest implemented EL, EL3 or a feature, all decided by the profile; a
//! reset whose conditions all fail does not apply. Architecturally UNKNOWN
//! values read 0 (Stela's choice), and IMPLEMENTATION DEFINED ones take the
//! choices in [`IMPLEMENTATION_DEFINED`].
use super::expression::Profile;
use super::page::{Element, Node, parse};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub const URI: &str = "https://developer.arm.com/-/cdn-downloads/permalink/\
    Exploration-Tools-Arm-Architecture-System-Registers/SysReg/\
    SysReg_xml_A_profile-2026-06.tar.gz";
pub const SHA256: &str = "4795c769085ff9056d9f18abbd9e23d7b0f0a955214cfb2a2121a9698b50d509";
pub const BYTES: usize = 43_124_482;
/// The download's published name.
pub const ARCHIVE: &str = "SysReg_xml_A_profile-2026-06.tar.gz";
/// The release directory inside the archive.
pub const DIRECTORY: &str = "SysReg_xml_A_profile-2026-06";

/// (register, field, value, reason) for every reset in the profile that the
/// XML leaves to the implementation or to state outside the profile. A reset
/// of that kind missing here stops generation.
pub const IMPLEMENTATION_DEFINED: &[(&str, &str, u64, &str)] = &[
    (
        "SSBS",
        "SSBS",
        0,
        "machine::exception::Pstate::reset clears SSBS (Arm AArch64_TakeReset: ImpDefBit)",
    ),
    (
        "DBGPRCR_EL1",
        "CORENPDRQ",
        0,
        "EDPRCR.COREPURQ: no external debugger requests core power-up",
    ),
    (
        "SCTLR_EL1",
        "DSSBS",
        0,
        "PSTATE.SSBS also resets to 0 (machine::exception::Pstate::reset)",
    ),
    (
        "SCTLR_EL2",
        "DSSBS",
        0,
        "PSTATE.SSBS also resets to 0 (machine::exception::Pstate::reset)",
    ),
    (
        "SCTLR_EL1",
        "EE",
        0,
        "little-endian; RES0 without FEAT_MixedEnd",
    ),
    (
        "SCTLR_EL2",
        "EE",
        0,
        "little-endian; RES0 without FEAT_MixedEnd",
    ),
];

/// What one field resets to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reset {
    Value(u64),
    Unknown,
    ImplementationDefined,
    /// A value named by an expression, such as `NUM_PMU_COUNTERS`.
    Expression(String),
    /// The value of another register's field, such as an external debug
    /// register's.
    Field(String),
}

/// One field's reset at bits `lsb..lsb + width`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub lsb: u32,
    pub width: u32,
    pub reset: Reset,
    /// A Warm reset, which a Cold reset also is; otherwise a Cold reset
    /// only.
    pub warm: bool,
}

/// A field whose XML gives one unconditional access type that fixes its
/// bits (RES0, RES1, RAZ/WI or RAO/WI), where AARCHMRS gives a plain field
/// with no values and no access. `fieldset`, `msb`, `lsb` and `variant` come
/// from the XML field id, `fieldset_<n>-<msb>_<lsb>[-<variant>]`; the variant
/// counts a conditional field's alternatives from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixed {
    pub fieldset: usize,
    pub msb: u32,
    pub lsb: u32,
    pub variant: Option<usize>,
    pub ones: bool,
}

/// The facts the XML adds to AARCHMRS, keyed by the register name with array
/// placeholders such as `<n>` removed.
#[derive(Debug, Default)]
pub struct Facts {
    pub resets: BTreeMap<String, Vec<Field>>,
    pub fixed: BTreeMap<String, Vec<Fixed>>,
    /// The features the register's reset conditions name, whatever the
    /// profile: the features its `resets` depend on.
    pub conditions: BTreeMap<String, BTreeSet<String>>,
}

/// Every AArch64 register's field resets under `profile` and its fields with
/// a fixed access type.
pub fn read(directory: &Path, profile: &Profile) -> Result<Facts> {
    let mut registers: BTreeMap<String, Vec<Field>> = BTreeMap::new();
    let mut fixed: BTreeMap<String, Vec<Fixed>> = BTreeMap::new();
    let mut conditions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut entries: Vec<_> = fs::read_dir(directory)
        .with_context(|| format!("cannot read {}", directory.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file = entry.file_name().to_string_lossy().into_owned();
        if !(file.starts_with("AArch64-") && file.ends_with(".xml")) {
            continue;
        }
        let text = fs::read_to_string(entry.path())?;
        let page = parse(&text).with_context(|| format!("cannot parse {file}"))?;
        for register in page.descendants("register") {
            if register.attribute("execution_state") != Some("AArch64") {
                continue;
            }
            let Some(name) = register.child("reg_short_name").map(Element::text) else {
                continue;
            };
            conditions.entry(plain_name(&name)).or_default().extend(
                register
                    .descendants("field_reset_condition")
                    .into_iter()
                    .filter_map(|condition| condition.attribute("condition"))
                    .filter_map(condition_feature)
                    .map(str::to_owned),
            );
            let fixes = fixed.entry(plain_name(&name)).or_default();
            fixes.extend(
                register
                    .descendants("field")
                    .into_iter()
                    .filter_map(fixed_access),
            );
            let fields = registers.entry(plain_name(&name)).or_default();
            for field in register.descendants("field") {
                fields.extend(field_resets(field, profile).with_context(|| {
                    format!(
                        "{name}.{}",
                        field
                            .child("field_name")
                            .map_or(String::new(), Element::text)
                    )
                })?);
            }
        }
    }
    Ok(Facts {
        resets: registers,
        fixed,
        conditions,
    })
}

/// The feature a reset condition (`FEAT_x is implemented`) names.
fn condition_feature(condition: &str) -> Option<&str> {
    let subject = condition
        .strip_suffix(" is implemented")
        .or_else(|| condition.strip_suffix(" is not implemented"))?;
    subject.starts_with("FEAT_").then_some(subject)
}

/// The fixed access type of `field`, when its only access state is one with
/// no condition.
fn fixed_access(field: &Element) -> Option<Fixed> {
    let ones = match field.child("field_access") {
        Some(access) => reserved_access(access)?,
        None => reserved_description(field)?,
    };
    let id = field.attribute("id")?.strip_prefix("fieldset_")?;
    let mut parts = id.split('-');
    let fieldset = parts.next()?.parse().ok()?;
    let (msb, lsb) = parts.next()?.split_once('_')?;
    let variant = match parts.next() {
        Some(variant) => Some(variant.parse().ok()?),
        None => None,
    };
    Some(Fixed {
        fieldset,
        msb: msb.parse().ok()?,
        lsb: lsb.parse().ok()?,
        variant,
        ones,
    })
}

/// A lone unconditional access type that reserves the field.
fn reserved_access(access: &Element) -> Option<bool> {
    let mut states = access.children_named("field_access_state");
    let state = states.next()?;
    if states.next().is_some() || state.children_named("field_access_type").count() != 1 {
        return None;
    }
    if state
        .children
        .iter()
        .any(|node| matches!(node, Node::Element(element) if element.name != "field_access_type"))
    {
        return None;
    }
    match state.child("field_access_type")?.text().trim() {
        "RES0" | "RAZ/WI" => Some(false),
        "RES1" | "RAO/WI" => Some(true),
        _ => None,
    }
}

/// A field with no access description that the XML's reserved-field
/// wording opens, as TCR_EL2.DS's variant without FEAT_LPA2 does.
fn reserved_description(field: &Element) -> Option<bool> {
    let before = field
        .children_named("field_description")
        .find(|description| description.attribute("order") == Some("before"))?;
    let text = before.child("para")?.text();
    if text.starts_with("Reserved, RES0") {
        Some(false)
    } else if text.starts_with("Reserved, RES1") {
        Some(true)
    } else {
        None
    }
}

/// `DBGBCR<n>_EL1` → `DBGBCR_EL1`, the register file's name.
pub fn plain_name(name: &str) -> String {
    super::codegen::rust_name(name)
}

fn field_resets(field: &Element, profile: &Profile) -> Result<Vec<Field>> {
    let (Some(name), Some(msb), Some(lsb)) = (
        field.child("field_name").map(Element::text),
        field.child("field_msb").map(Element::text),
        field.child("field_lsb").map(Element::text),
    ) else {
        return Ok(Vec::new());
    };
    let (msb, lsb): (u32, u32) = (msb.trim().parse()?, lsb.trim().parse()?);
    ensure!(msb >= lsb, "bad range {msb}:{lsb}");
    // 128-bit layouts (FEAT_D128) are outside the profile.
    if msb >= 64 {
        return Ok(Vec::new());
    }
    let width = msb - lsb + 1;
    let mut out = Vec::new();
    for reset in field
        .child("field_resets")
        .into_iter()
        .flat_map(|resets| resets.children_named("field_reset"))
    {
        let warm = match reset.attribute("reset_type") {
            Some("Warm") => true,
            Some("Cold") => false,
            _ => continue,
        };
        if let Some(value) = resolve(reset, width, profile)? {
            out.push(Field {
                name: name.clone(),
                lsb,
                width,
                reset: value,
                warm,
            });
        }
    }
    Ok(out)
}

/// A `field_reset` under the profile, or `None` when no condition holds.
fn resolve(reset: &Element, width: u32, profile: &Profile) -> Result<Option<Reset>> {
    if let Some(number) = reset.child("field_reset_number") {
        let bits = number.text();
        let bits = bits.trim().trim_matches('\'');
        // An array field such as CLAIM<m> gives one element's reset.
        let element = bits.len() as u32;
        ensure!(
            element != 0
                && width.is_multiple_of(element)
                && bits.chars().all(|bit| matches!(bit, '0' | '1')),
            "reset {bits:?} does not fill {width} bits"
        );
        let one = u64::from_str_radix(bits, 2)?;
        let value =
            (0..width / element).fold(0u64, |value, index| value | one << (index * element));
        return Ok(Some(Reset::Value(value)));
    }
    if let Some(expression) = reset.child("field_reset_expression") {
        let text = expression.text();
        let text = text.trim();
        return Ok(Some(match text.strip_prefix("0x") {
            Some(hex) => Reset::Value(u64::from_str_radix(hex, 16)?),
            None => Reset::Expression(text.to_owned()),
        }));
    }
    if let Some(other) = reset.child("field_reset_other_field") {
        let name = |tag| other.child(tag).map(Element::text).unwrap_or_default();
        return Ok(Some(Reset::Field(format!(
            "{}.{}",
            name("field_reset_other_field_regname").trim(),
            name("field_reset_other_field_fieldname").trim()
        ))));
    }
    if let Some(text) = reset.child("field_reset_standard_text") {
        return match text.text().trim() {
            "AU" | "U" => Ok(Some(Reset::Unknown)),
            "ID" => Ok(Some(Reset::ImplementationDefined)),
            other => bail!("unknown reset text {other:?}"),
        };
    }
    let Some(conditions) = reset.child("field_reset_conditions") else {
        bail!("field reset without a value");
    };
    for condition in conditions.children_named("field_reset_condition") {
        let holds = match condition.attribute("condition") {
            None => true,
            Some(text) => holds(text, profile)?,
        };
        if holds {
            let inner = condition
                .child("field_reset")
                .context("condition without a reset")?;
            return resolve(inner, width, profile);
        }
    }
    Ok(None)
}

/// A reset condition's truth under the profile.
fn holds(condition: &str, profile: &Profile) -> Result<bool> {
    if let Some(level) = condition.strip_prefix("the highest implemented Exception level is EL") {
        return Ok(level.parse::<u8>()? == profile.highest_el);
    }
    let (subject, implemented) = if let Some(subject) = condition.strip_suffix(" is implemented") {
        (subject, true)
    } else if let Some(subject) = condition.strip_suffix(" is not implemented") {
        (subject, false)
    } else {
        bail!("unknown reset condition {condition:?}");
    };
    let present = match subject {
        "EL3" => profile.highest_el >= 3,
        feature if feature.starts_with("FEAT_") => profile.features.contains(feature),
        other => bail!("unknown reset condition subject {other:?}"),
    };
    Ok(present == implemented)
}

/// The bits a Warm reset sets in a register whose profile layout has
/// `positions` and reserved masks `res0`/`res1`: those of every field with a
/// Warm reset under the profile. A Warm reset leaves the other bits, such as
/// the debug and performance monitor state only a Cold reset sets, as they
/// were.
pub fn warm(
    fields: &[Field],
    positions: &BTreeMap<String, (u32, u32)>,
    res0: u64,
    res1: u64,
) -> u64 {
    fields
        .iter()
        .filter(|field| field.warm && positions.get(&field.name) == Some(&(field.lsb, field.width)))
        .fold(0, |bits, field| bits | mask(field.width) << field.lsb)
        & !(res0 | res1)
}

fn mask(width: u32) -> u64 {
    if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

/// Apply `fields` to a register whose profile layout has `positions` (name →
/// (lsb, width)) and reserved masks `res0`/`res1`. Fields absent from the
/// layout, or at another position, are not part of the profile's register.
pub fn value(
    register: &str,
    fields: &[Field],
    positions: &BTreeMap<String, (u32, u32)>,
    res0: u64,
    res1: u64,
) -> Result<u64> {
    let mut value = 0u64;
    for field in fields {
        if positions.get(&field.name) != Some(&(field.lsb, field.width)) {
            continue;
        }
        let bits = match &field.reset {
            Reset::Value(bits) => *bits,
            Reset::Unknown => 0,
            choice => IMPLEMENTATION_DEFINED
                .iter()
                .find(|(name, field_name, ..)| *name == register && *field_name == field.name)
                .map(|(_, _, value, _)| *value)
                .with_context(|| {
                    format!(
                        "{register}.{} resets to {choice:?}, which has no recorded choice",
                        field.name
                    )
                })?,
        };
        let mask = mask(field.width);
        value = (value & !(mask << field.lsb)) | (bits & mask) << field.lsb;
    }
    Ok((value & !res0) | res1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const PAGE: &str = r#"<?xml version='1.0'?>
<!DOCTYPE register_page SYSTEM "registers.dtd">
<!-- comment -->
<register_page><registers>
  <register execution_state="AArch64">
    <reg_short_name>DBGBCR&lt;n&gt;_EL1</reg_short_name>
    <reg_fieldsets><fields id="fieldset_0" length="64">
      <field id="f1"><field_name>E</field_name><field_msb>0</field_msb><field_lsb>0</field_lsb>
        <field_resets>
          <field_reset reset_type="Warm">
            <field_reset_conditions>
              <field_reset_condition condition="the highest implemented Exception level is EL1">
                <field_reset><field_reset_number>'1'</field_reset_number></field_reset>
              </field_reset_condition>
              <field_reset_condition>
                <field_reset><field_reset_number>'0'</field_reset_number></field_reset>
              </field_reset_condition>
            </field_reset_conditions>
          </field_reset>
          <field_reset reset_type="Cold">
            <field_reset_conditions>
              <field_reset_condition condition="FEAT_X is implemented">
                <field_reset><field_reset_standard_text>AU</field_reset_standard_text></field_reset>
              </field_reset_condition>
            </field_reset_conditions>
          </field_reset>
        </field_resets>
      </field>
      <field id="f2"><field_name>PMC</field_name><field_msb>2</field_msb><field_lsb>1</field_lsb>
        <field_resets><field_reset reset_type="Warm"><field_reset_number>'10'</field_reset_number></field_reset></field_resets>
      </field>
      <field id="f3"><field_name>EE</field_name><field_msb>25</field_msb><field_lsb>25</field_lsb>
        <field_resets><field_reset reset_type="Warm"><field_reset_standard_text>ID</field_reset_standard_text></field_reset></field_resets>
      </field>
    </fields></reg_fieldsets>
  </register>
</registers></register_page>"#;

    fn profile() -> Profile {
        Profile {
            parameters: BTreeSet::new(),
            features: BTreeSet::new(),
            highest_el: 2,
            varying: Default::default(),
        }
    }

    #[test]
    fn page_resets_follow_conditions_under_the_profile() {
        let page = parse(PAGE).unwrap();
        let register = page.descendants("register")[0];
        assert_eq!(
            plain_name(&register.child("reg_short_name").unwrap().text()),
            "DBGBCR_EL1"
        );
        let fields: Vec<Field> = register
            .descendants("field")
            .into_iter()
            .flat_map(|field| field_resets(field, &profile()).unwrap())
            .collect();
        // E: the EL1 condition fails and the unconditional one gives '0'; the
        // Cold reset needs an absent feature and does not apply.
        assert_eq!(
            fields
                .iter()
                .map(|f| (f.name.as_str(), f.reset.clone()))
                .collect::<Vec<_>>(),
            [
                ("E", Reset::Value(0)),
                ("PMC", Reset::Value(0b10)),
                ("EE", Reset::ImplementationDefined)
            ]
        );
        let positions: BTreeMap<String, (u32, u32)> =
            [("E".into(), (0, 1)), ("PMC".into(), (1, 2))]
                .into_iter()
                .collect();
        // EE is not in this layout; bit 63 is RES1 and bit 1 RES0.
        assert_eq!(
            value("DBGBCR_EL1", &fields, &positions, 1 << 1, 1 << 63).unwrap(),
            1 << 63 | 0b100
        );
        // A Warm reset sets E and PMC, less the reserved bit, and leaves a
        // field whose only reset is a Cold one.
        assert_eq!(warm(&fields, &positions, 1 << 1, 1 << 63), 0b101);
        let cold = Field {
            name: "OSLK".into(),
            lsb: 1,
            width: 1,
            reset: Reset::Value(1),
            warm: false,
        };
        let positions: BTreeMap<String, (u32, u32)> =
            [("OSLK".into(), (1, 1))].into_iter().collect();
        assert_eq!(warm(&[cold], &positions, 0, 0), 0);
        let positions: BTreeMap<String, (u32, u32)> =
            [("EE".into(), (25, 1))].into_iter().collect();
        assert!(
            value("DBGBCR_EL1", &fields, &positions, 0, 0).is_err(),
            "unrecorded choice"
        );
        assert_eq!(value("SCTLR_EL1", &fields, &positions, 0, 0).unwrap(), 0);
    }

    #[test]
    fn a_lone_unconditional_reserved_access_fixes_a_field() {
        let field = |id: &str, state: &str| {
            let page = parse(&format!(
                "<field id=\"{id}\"><field_access><field_access_state>{state}\
                 </field_access_state></field_access></field>"
            ))
            .unwrap();
            fixed_access(page.descendants("field")[0])
        };
        let res1 =
            "<field_access_type><arm-defined-word>RES1</arm-defined-word></field_access_type>";
        assert_eq!(
            field("fieldset_0-8_8-2", res1),
            Some(Fixed {
                fieldset: 0,
                msb: 8,
                lsb: 8,
                variant: Some(2),
                ones: true
            })
        );
        assert_eq!(
            field(
                "fieldset_1-63_63",
                "<field_access_type>RAZ/WI</field_access_type>"
            ),
            Some(Fixed {
                fieldset: 1,
                msb: 63,
                lsb: 63,
                variant: None,
                ones: false
            })
        );
        // A conditional access level or a read/write type fixes nothing.
        let level = "<field_access_level>When trapping</field_access_level>\
                     <field_access_type>RAZ/WI</field_access_type>";
        assert_eq!(field("fieldset_0-15_15", level), None);
        assert_eq!(
            field(
                "fieldset_0-15_15",
                "<field_access_type>RW</field_access_type>"
            ),
            None
        );
        // Without an access description, the reserved-field wording decides.
        let described = |text: &str| {
            let page = parse(&format!(
                "<field id=\"fieldset_1-59_59-2\"><field_description order=\"before\">\
                 <para>{text}</para></field_description></field>"
            ))
            .unwrap();
            fixed_access(page.descendants("field")[0]).map(|fixed| fixed.ones)
        };
        assert_eq!(
            described(
                "Reserved, <arm-defined-word>RES0</arm-defined-word>, and the Effective value of this bit is 0."
            ),
            Some(false)
        );
        assert_eq!(
            described("Reserved, <arm-defined-word>RES1</arm-defined-word>."),
            Some(true)
        );
        assert_eq!(described("Controls the translation granule."), None);
    }

    #[test]
    fn conditions() {
        let profile = profile();
        assert!(holds("the highest implemented Exception level is EL2", &profile).unwrap());
        assert!(!holds("EL3 is implemented", &profile).unwrap());
        assert!(holds("FEAT_BRBEv1p1 is not implemented", &profile).unwrap());
        assert!(holds("the moon is full", &profile).is_err());
    }
}
