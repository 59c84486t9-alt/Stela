//! `machine/system/generated.rs`: the profile's System registers with their
//! reserved bits, and every accessor with its folded permission tree.
use super::Profiles;
use super::codegen::{Accessor, Fields, Generator, accessors, rust_name};
use super::expression::Profile;
use super::fold::{as_bool, fold};
use super::resets::Fixed;
use anyhow::{Result, bail};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

pub const GENERATED: &str = "crates/stela-runtime/src/machine/system/generated.rs";

/// A register of the profile: instances and, per chip, the bits that are
/// RES0 or RES1 in every layout the chip allows.
struct Layout {
    name: String,
    instances: u64,
    res0: Vec<u64>,
    res1: Vec<u64>,
    /// The Cold reset value under each chip's profile (`super::resets`).
    reset: Vec<u64>,
}

/// One value per chip, as Rust: a constant when every chip agrees.
fn per_chip(values: &[u64]) -> String {
    if values.iter().all(|value| *value == values[0]) {
        format!("{:#x}", values[0])
    } else {
        let list: Vec<String> = values.iter().map(|value| format!("{value:#x}")).collect();
        format!("[{}][chip as usize]", list.join(", "))
    }
}

fn is_implementation_defined_space(name: &str) -> bool {
    name.contains("<op1>")
}

/// Whether an accessor of `register` raises Arm `UnimplementedIDRegister`.
fn unimplemented_id(register: &Value) -> bool {
    register["accessors"]
        .to_string()
        .contains("\"UnimplementedIDRegister\"")
}

fn range_mask(range: &Value, offset: u64) -> u64 {
    let start = range["start"].as_u64().unwrap_or(0) + offset;
    let width = range["width"].as_u64().unwrap_or(0);
    // Bits above 63 belong to 128-bit layouts the profile does not have.
    if start >= 64 || width == 0 {
        return 0;
    }
    let mask = if width >= 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    };
    ((mask << start) & u128::from(u64::MAX)) as u64
}

fn ranges_mask(node: &Value, offset: u64) -> u64 {
    node["rangeset"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|range| range_mask(range, offset))
        .fold(0, |a, b| a | b)
}

/// RES1, RAO and RAO/WI bits read as one; RES0, RAZ, RAZ/WI and UNKNOWN
/// reserved bits are kept at zero.
fn reads_one(kind: &str) -> bool {
    kind.starts_with("RES1") || kind.starts_with("RAO")
}

/// Field positions and reserved masks of the layouts whose condition may
/// hold, up to the first the profile decides holds: layouts are ordered
/// alternatives.
fn layout(
    register: &Value,
    profile: &Profile,
    fixed: &[Fixed],
    fields: &mut BTreeMap<String, (u32, u32)>,
) -> (u64, u64) {
    let mut res0 = u64::MAX;
    let mut res1 = u64::MAX;
    let mut any = false;
    for (index, fieldset) in register["fieldsets"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let condition = fold(&fieldset["condition"], profile);
        if as_bool(&condition) == Some(false) {
            continue;
        }
        let fixed: Vec<Fixed> = fixed
            .iter()
            .filter(|field| field.fieldset == index)
            .copied()
            .collect();
        let (mut zeros, mut ones) = (0, 0);
        let mut bits = Bits {
            profile,
            fixed: &fixed,
            fields,
            res0: &mut zeros,
            res1: &mut ones,
        };
        bits.collect(&fieldset["values"], 0, None);
        res0 &= zeros;
        res1 &= ones;
        any = true;
        if as_bool(&condition) == Some(true) {
            break;
        }
    }
    if any { (res0, res1) } else { (0, 0) }
}

/// The reserved masks and field positions of one layout as it is walked.
struct Bits<'a> {
    profile: &'a Profile,
    /// The layout's fields that the XML fixes (`resets::Fixed`).
    fixed: &'a [Fixed],
    fields: &'a mut BTreeMap<String, (u32, u32)>,
    res0: &'a mut u64,
    res1: &'a mut u64,
}

impl Bits<'_> {
    /// Fields of `values` at bit `offset`: a conditional field's variants
    /// are relative to its own range, and when no variant applies its bits
    /// take the conditional field's reserved type. `variant` is the
    /// alternative, counted from 1, that `values` belongs to.
    fn collect(&mut self, values: &Value, offset: u64, variant: Option<usize>) {
        for value in values.as_array().into_iter().flatten() {
            match value["_type"].as_str().unwrap_or("") {
                "Fields.ConditionalField" => {
                    let start = value["rangeset"][0]["start"].as_u64().unwrap_or(0) + offset;
                    let mut live = false;
                    for (index, alternative) in
                        value["fields"].as_array().into_iter().flatten().enumerate()
                    {
                        let condition = fold(&alternative["condition"], self.profile);
                        if as_bool(&condition) == Some(false) {
                            continue;
                        }
                        live = true;
                        self.collect(
                            &Value::Array(vec![alternative["field"].clone()]),
                            start,
                            Some(index + 1),
                        );
                        if as_bool(&condition) == Some(true) {
                            break;
                        }
                    }
                    if !live {
                        let bits = ranges_mask(value, offset);
                        self.reserve(
                            bits,
                            reads_one(value["reservedtype"].as_str().unwrap_or("RES0")),
                        );
                    }
                }
                "Fields.Reserved" => {
                    let mask = ranges_mask(value, offset);
                    self.reserve(mask, reads_one(value["value"].as_str().unwrap_or("")));
                }
                _ => {
                    let Some(name) = value["name"].as_str() else {
                        continue;
                    };
                    let ranges: Vec<&Value> =
                        value["rangeset"].as_array().into_iter().flatten().collect();
                    if let [range] = ranges[..] {
                        let start = (range["start"].as_u64().unwrap_or(0) + offset) as u32;
                        let width = range["width"].as_u64().unwrap_or(0) as u32;
                        // A field the XML fixes as RES0, RES1, RAZ/WI or
                        // RAO/WI is reserved.
                        if let Some(fixed) = self.fixed.iter().find(|fixed| {
                            fixed.lsb == start
                                && fixed.msb + 1 == start + width
                                && fixed.variant == variant
                        }) {
                            self.reserve(ranges_mask(value, offset), fixed.ones);
                            continue;
                        }
                        self.fields.entry(name.to_owned()).or_insert((start, width));
                        // A field with one allowed value, and no value range,
                        // is a constant.
                        let allowed: Vec<Option<&str>> = value["values"]["values"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(|allowed| allowed["value"].as_str())
                            .collect();
                        if let [Some(only)] = allowed[..] {
                            let bits = only.trim_matches('\'');
                            if !bits.contains('x') && bits.len() as u32 == width {
                                for (position, bit) in bits.chars().rev().enumerate() {
                                    let mask =
                                        1u64.checked_shl(start + position as u32).unwrap_or(0);
                                    self.reserve(mask, bit == '1');
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn reserve(&mut self, mask: u64, ones: bool) {
        if ones {
            *self.res1 |= mask;
        } else {
            *self.res0 |= mask;
        }
    }
}

pub fn generate(
    registers: &Value,
    profiles: &Profiles,
    applicable: &BTreeSet<String>,
    facts: &super::resets::Facts,
    chip_facts: &[super::resets::Facts],
) -> Result<String> {
    let profile = &profiles.union;
    let mut fields: Fields = BTreeMap::new();
    let mut layouts = Vec::new();
    let mut accessor_list: Vec<Accessor> = Vec::new();
    let mut names = BTreeSet::new();
    for register in registers.as_array().into_iter().flatten() {
        if register["state"] != "AArch64" {
            continue;
        }
        let name = register["name"].as_str().unwrap_or("");
        let rust = rust_name(name);
        // Field positions of every AArch64 register, for trap controls.
        let mut positions = BTreeMap::new();
        let fixed = facts.fixed.get(&rust).map_or(&[][..], Vec::as_slice);
        layout(register, profile, fixed, &mut positions);
        let applies = applicable.contains(name) && !is_implementation_defined_space(name);
        fields.entry(rust.clone()).or_default().extend(positions);
        if !applies {
            // An ID register of a feature outside the profile keeps its
            // encoding: Arm `UnimplementedIDRegister` traps it under FEAT_IDST.
            if !is_implementation_defined_space(name) && unimplemented_id(register) {
                accessor_list.extend(accessors(register, profile)?);
            }
            continue;
        }
        if !name.contains(' ') {
            names.insert(rust.clone());
            let instances = register["indexes"]
                .as_array()
                .map(|ranges| {
                    ranges
                        .iter()
                        .map(|r| r["width"].as_u64().unwrap_or(0))
                        .sum()
                })
                .filter(|count: &u64| *count > 0)
                .unwrap_or(1);
            let (mut res0, mut res1, mut reset) = (Vec::new(), Vec::new(), Vec::new());
            for ((_, chip), chip_facts) in profiles.chips.iter().zip(chip_facts) {
                let mut positions = BTreeMap::new();
                let fixed = chip_facts.fixed.get(&rust).map_or(&[][..], Vec::as_slice);
                let (zeros, ones) = layout(register, chip, fixed, &mut positions);
                reset.push(super::resets::value(
                    &rust,
                    chip_facts.resets.get(&rust).map_or(&[][..], Vec::as_slice),
                    &positions,
                    zeros,
                    ones,
                )?);
                res0.push(zeros);
                res1.push(ones);
            }
            layouts.push(Layout {
                name: rust.clone(),
                instances,
                res0,
                res1,
                reset,
            });
        }
        accessor_list.extend(accessors(register, profile)?);
    }
    let mut generator = Generator {
        fields: &fields,
        registers: &names,
        unknown: BTreeSet::new(),
        profile,
    };
    let mut functions = String::new();
    let mut table = String::new();
    for (index, accessor) in accessor_list.iter().enumerate() {
        writeln!(functions, "/// {} ({})", accessor.name, accessor.register)?;
        writeln!(
            functions,
            "fn a{index}(c: &mut dyn Context, m: u64) -> Result<Effect, Effect> {{"
        )?;
        writeln!(functions, "    let _ = m;")?;
        let mut body = String::new();
        let returned = generator.tree(&accessor.tree, &mut body, "    ")?;
        functions.push_str(&body);
        if !returned {
            writeln!(
                functions,
                "    Ok(Effect::Refused(\"no AARCHMRS case applies\"))"
            )?;
        }
        writeln!(functions, "}}\n")?;
        let index_bits: Vec<String> = accessor
            .encoding
            .index
            .iter()
            .map(|(key, bit)| format!("({key}, {bit})"))
            .collect();
        writeln!(
            table,
            "    Accessor {{ name: {:?}, kind: {:?}, mask: {:#06x}, value: {:#06x}, index: &[{}], run: a{index} }},",
            accessor.name,
            accessor.kind,
            accessor.encoding.mask,
            accessor.encoding.value,
            index_bits.join(", "),
        )?;
    }
    if !generator.unknown.is_empty() {
        bail!(
            "the generated accessors use operations without a runtime mapping:\n{}",
            generator
                .unknown
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    let mut out = String::new();
    writeln!(
        out,
        "//! The profile's System registers and the accessors of every System\n\
         //! register and System instruction, generated by `cargo xtask system-matrix`\n\
         //! from Arm AARCHMRS {} (BSD-3-Clause; Copyright (c) 2010-2026 Arm Limited or\n\
         //! its affiliates). Each accessor is its AARCHMRS permission tree folded\n\
         //! against the Apple CPU profiles, a feature only some chips have left to\n\
         //! `Context::implemented`. Reset values come from Arm's\n\
         //! {} System register XML (SHA-256 {}). Do not edit.\n\
         #![allow(\n    clippy::all,\n    clippy::pedantic,\n    unused_parens,\n    unused_variables,\n    unreachable_code,\n    non_camel_case_types\n)]\n\
         use super::{{\n    Accessor, Broadcast, CacheOp, CacheScope, CacheType, Chip, Context, Effect, ErrorRecord, Limit,
    Operation,\n    \
         Pstate, Regime, Restrict, Stage, AtAccess, Tlbi, TlbiAttr, TlbiKind, TlbiLevel, helpers::*,\n}};\n",
        super::RELEASE,
        super::resets::DIRECTORY,
        super::resets::SHA256
    )?;
    writeln!(
        out,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]"
    )?;
    writeln!(out, "pub enum Register {{")?;
    for layout in &layouts {
        writeln!(out, "    {},", layout.name)?;
    }
    writeln!(out, "}}\n")?;
    writeln!(out, "impl Register {{")?;
    writeln!(out, "    pub const ALL: [Register; {}] = [", layouts.len())?;
    for layout in &layouts {
        writeln!(out, "        Register::{},", layout.name)?;
    }
    writeln!(out, "    ];\n")?;
    let mut offset = 0;
    writeln!(out, "    /// The register's first slot in `File`.")?;
    writeln!(out, "    pub const fn offset(self) -> usize {{")?;
    writeln!(out, "        match self {{")?;
    for layout in &layouts {
        writeln!(out, "            Register::{} => {offset},", layout.name)?;
        offset += layout.instances;
    }
    writeln!(out, "        }}\n    }}\n")?;
    writeln!(out, "    /// Slots of every register.")?;
    writeln!(out, "    pub const SLOTS: usize = {offset};\n")?;
    for (function, kind, value) in [
        ("name", "&'static str", 0),
        ("instances", "u64", 1),
        ("res0", "u64", 2),
        ("res1", "u64", 3),
        ("reset", "u64", 4),
    ] {
        let parameter = if value >= 2 { ", chip: Chip" } else { "" };
        if value >= 2 {
            writeln!(out, "    /// Under `chip`'s profile.")?;
        }
        writeln!(
            out,
            "    pub const fn {function}(self{parameter}) -> {kind} {{"
        )?;
        writeln!(out, "        match self {{")?;
        for layout in &layouts {
            let text = match value {
                0 => format!("{:?}", layout.name),
                1 => layout.instances.to_string(),
                2 => per_chip(&layout.res0),
                3 => per_chip(&layout.res1),
                _ => per_chip(&layout.reset),
            };
            writeln!(out, "            Register::{} => {text},", layout.name)?;
        }
        writeln!(out, "        }}\n    }}\n")?;
    }
    writeln!(out, "}}\n")?;
    write_features(&mut out, profiles)?;
    writeln!(
        out,
        "pub static ACCESSORS: [Accessor; {}] = [",
        accessor_list.len()
    )?;
    out.push_str(&table);
    writeln!(out, "];\n")?;
    out.push_str(&functions);
    Ok(out)
}

/// The chips in generation order, and the features only some of them have,
/// each with the chips whose profile has it.
fn write_features(out: &mut String, profiles: &Profiles) -> Result<()> {
    let chips: Vec<String> = profiles
        .chips
        .iter()
        .map(|(name, _)| format!("{name:?}"))
        .collect();
    writeln!(
        out,
        "/// The Apple CPUs, in the order of the per-chip tables."
    )?;
    writeln!(
        out,
        "pub const CHIPS: [&str; {}] = [{}];\n",
        chips.len(),
        chips.join(", ")
    )?;
    writeln!(
        out,
        "/// Each chip's Apple clang architectural features, as exported."
    )?;
    writeln!(
        out,
        "pub const CAPS: [&[&str]; {}] = [",
        profiles.caps.len()
    )?;
    for cap in &profiles.caps {
        let names: Vec<String> = cap.iter().map(|name| format!("{name:?}")).collect();
        writeln!(out, "    &[{}],", names.join(", "))?;
    }
    writeln!(out, "];\n")?;
    writeln!(out, "/// The features only some chips have.")?;
    writeln!(
        out,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]"
    )?;
    writeln!(out, "pub enum Feature {{")?;
    for feature in &profiles.union.varying {
        writeln!(out, "    {feature},")?;
    }
    writeln!(out, "}}\n")?;
    writeln!(out, "impl Feature {{")?;
    writeln!(
        out,
        "    pub const ALL: [Feature; {}] = [",
        profiles.union.varying.len()
    )?;
    for feature in &profiles.union.varying {
        writeln!(out, "        Feature::{feature},")?;
    }
    writeln!(out, "    ];\n")?;
    writeln!(out, "    pub const fn name(self) -> &'static str {{")?;
    writeln!(out, "        match self {{")?;
    for feature in &profiles.union.varying {
        writeln!(out, "            Feature::{feature} => {feature:?},")?;
    }
    writeln!(out, "        }}\n    }}\n")?;
    writeln!(
        out,
        "    /// Why an access stops on a chip with the feature when the engine"
    )?;
    writeln!(out, "    /// does not implement it.")?;
    writeln!(
        out,
        "    pub const fn unimplemented(self) -> &'static str {{"
    )?;
    writeln!(out, "        match self {{")?;
    for feature in &profiles.union.varying {
        writeln!(
            out,
            "            Feature::{feature} => \"{feature} of the chip is not implemented\","
        )?;
    }
    writeln!(out, "        }}\n    }}\n")?;
    writeln!(out, "    /// Whether `chip`'s profile has the feature.")?;
    writeln!(out, "    pub const fn on(self, chip: Chip) -> bool {{")?;
    writeln!(out, "        match self {{")?;
    for feature in &profiles.union.varying {
        let on: Vec<&str> = profiles
            .chips
            .iter()
            .map(|(_, profile)| {
                if profile.features.contains(feature) {
                    "true"
                } else {
                    "false"
                }
            })
            .collect();
        writeln!(
            out,
            "            Feature::{feature} => [{}][chip as usize],",
            on.join(", ")
        )?;
    }
    writeln!(out, "        }}\n    }}\n")?;
    writeln!(out, "}}\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_layout_the_profile_holds_decides_the_reserved_bits() {
        let profile = Profile {
            parameters: ["FEAT_AA32EL1"].map(String::from).into(),
            features: Default::default(),
            highest_el: 2,
            varying: Default::default(),
        };
        let mut fields = BTreeMap::new();
        let register = crate::system_matrix::tests::banked_spsr();
        assert_eq!(layout(&register, &profile, &[], &mut fields), (u64::MAX, 0));
        assert!(fields.is_empty());
    }

    #[test]
    fn fields_the_xml_fixes_are_reserved_bits() {
        let profile = Profile {
            parameters: Default::default(),
            features: Default::default(),
            highest_el: 2,
            varying: Default::default(),
        };
        // SCTLR_EL2.SED's shape: a conditional field whose second variant
        // is a plain field the XML gives as RES1.
        let field = |name: &str| {
            serde_json::json!({"_type": "Fields.Field", "name": name,
                               "rangeset": [{"start": 0, "width": 1}]})
        };
        let register = serde_json::json!({"fieldsets": [{
            "condition": {"_type": "AST.Bool", "value": true},
            "values": [{"_type": "Fields.ConditionalField", "rangeset": [{"start": 8, "width": 1}],
                        "fields": [
                {"condition": {"_type": "AST.Bool", "value": false}, "field": field("SED")},
                {"condition": {"_type": "AST.Bool", "value": true}, "field": field("SED")}]}]}]});
        let fixed = |variant| Fixed {
            fieldset: 0,
            msb: 8,
            lsb: 8,
            variant: Some(variant),
            ones: true,
        };
        let mut fields = BTreeMap::new();
        assert_eq!(
            layout(&register, &profile, &[fixed(2)], &mut fields),
            (0, 1 << 8)
        );
        assert!(fields.is_empty());
        // Fixing the variant that does not apply leaves a stored field.
        assert_eq!(
            layout(&register, &profile, &[fixed(1)], &mut fields),
            (0, 0)
        );
        assert_eq!(fields["SED"], (8, 1));
    }

    #[test]
    fn per_chip_values_collapse_when_every_chip_agrees() {
        assert_eq!(per_chip(&[0x10, 0x10, 0x10]), "0x10");
        assert_eq!(
            per_chip(&[0x10, 0x30, 0x30]),
            "[0x10, 0x30, 0x30][chip as usize]"
        );
    }
}
