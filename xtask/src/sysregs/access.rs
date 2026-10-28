//! `machine/system/generated.rs`: the profile's System registers with their
//! reserved bits, and every accessor with its folded permission tree. A PE
//! whose identification withholds some of its chip's features has each
//! register's layout under the chip's profile without them: the layouts
//! that differ from the chip's are listed in `WITHHELD_LAYOUTS`.
use super::Profiles;
use super::codegen::{Accessor, Fields, Generator, accessors, rust_name};
use super::expression::Profile;
use super::fold::{as_bool, fold};
use super::resets::{Facts, Fixed};
use anyhow::{Result, bail, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    path::Path,
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
    /// The bits a Warm reset sets under each chip's profile
    /// (`super::resets::warm`).
    warm: Vec<u64>,
}

/// A register's layout on a PE of a chip whose identification withholds some
/// of the chip's features, where it differs from the chip's.
struct Withheld {
    register: String,
    chip: usize,
    /// The chip's varying features (bits of `Feature`) the layout depends
    /// on: those its conditions and reset conditions name.
    relevant: u64,
    /// The relevant features the PE withholds.
    withheld: u64,
    res0: u64,
    res1: u64,
    reset: u64,
    warm: u64,
}

/// At most this many relevant features per register and chip, whose every
/// combination is laid out.
const RELEVANT_LIMIT: u32 = 12;

/// `profile` without the features in `removed`.
fn without(profile: &Profile, removed: &BTreeSet<String>) -> Profile {
    Profile {
        parameters: profile.parameters.clone(),
        features: profile.features.difference(removed).cloned().collect(),
        varying: profile.varying.clone(),
        highest_el: profile.highest_el,
    }
}

/// The text of every condition in `value`, for the features they name.
fn condition_text(value: &Value, text: &mut String) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if key == "condition" {
                    text.push_str(&inner.to_string());
                } else {
                    condition_text(inner, text);
                }
            }
        }
        Value::Array(list) => list.iter().for_each(|inner| condition_text(inner, text)),
        _ => {}
    }
}

/// Each chip's reset facts under its profile without some of its features,
/// read from the System register XML once per feature set.
struct ChipFacts<'a> {
    directory: &'a Path,
    profiles: &'a Profiles,
    base: &'a [Facts],
    read: BTreeMap<(usize, BTreeSet<String>), Facts>,
}

impl ChipFacts<'_> {
    fn get(&mut self, chip: usize, removed: BTreeSet<String>) -> Result<&Facts> {
        if removed.is_empty() {
            return Ok(&self.base[chip]);
        }
        let key = (chip, removed);
        if !self.read.contains_key(&key) {
            let profile = without(&self.profiles.chips[chip].1, &key.1);
            let facts = super::resets::read(self.directory, &profile)?;
            self.read.insert(key.clone(), facts);
        }
        Ok(&self.read[&key])
    }
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
                    if value["_type"] == "Fields.Array" {
                        self.elements(value, name, &ranges, offset);
                    }
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

    /// Each element of a field array by its own name, the index variable
    /// replaced by the index (`AMCNTEN<x>` -> `AMCNTEN0`, `AMCNTEN1`), for
    /// accessors that name one element. One range holds the elements in
    /// index order from its low bit; several ranges are one element each,
    /// listed from the highest index down (HAFGRTR_EL2.AMCNTEN<x> is bit 0
    /// for x 0 and bit 17 for x 1).
    fn elements(&mut self, value: &Value, name: &str, ranges: &[&Value], offset: u64) {
        let (Some(open), Some(close)) = (name.find('<'), name.find('>')) else {
            return;
        };
        let element = |index: u64| format!("{}{index}{}", &name[..open], &name[close + 1..]);
        let start = |range: &Value| (range["start"].as_u64().unwrap_or(0) + offset) as u32;
        let width = |range: &Value| range["width"].as_u64().unwrap_or(0) as u32;
        if let [range] = ranges {
            let count: u64 = value["indexes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|indexes| indexes["width"].as_u64().unwrap_or(0))
                .sum();
            if count == 0 || u64::from(width(range)) % count != 0 {
                return;
            }
            let each = width(range) / count as u32;
            for index in 0..count {
                self.fields
                    .entry(element(index))
                    .or_insert((start(range) + index as u32 * each, each));
            }
        } else {
            for (position, range) in ranges.iter().enumerate() {
                let index = (ranges.len() - 1 - position) as u64;
                self.fields
                    .entry(element(index))
                    .or_insert((start(range), width(range)));
            }
        }
    }
}

pub fn generate(
    registers: &Value,
    profiles: &Profiles,
    applicable: &BTreeSet<String>,
    facts: &Facts,
    chip_facts: &[Facts],
    resets_directory: &Path,
) -> Result<String> {
    let profile = &profiles.union;
    let varying: Vec<&String> = profile.varying.iter().collect();
    ensure!(varying.len() <= 64, "more than 64 varying features");
    let mut withheld_facts = ChipFacts {
        directory: resets_directory,
        profiles,
        base: chip_facts,
        read: BTreeMap::new(),
    };
    let mut withheld_layouts = Vec::new();
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
            let (mut res0, mut res1, mut reset, mut warm) =
                (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            let mut conditions = String::new();
            condition_text(&register["fieldsets"], &mut conditions);
            for (index, ((_, chip), chip_facts)) in
                profiles.chips.iter().zip(chip_facts).enumerate()
            {
                let fixed = chip_facts.fixed.get(&rust).map_or(&[][..], Vec::as_slice);
                let laid_out = |profile: &Profile, facts: &Facts| -> Result<[u64; 4]> {
                    let mut positions = BTreeMap::new();
                    let (zeros, ones) = layout(register, profile, fixed, &mut positions);
                    let fields = facts.resets.get(&rust).map_or(&[][..], Vec::as_slice);
                    Ok([
                        zeros | super::codegen::raz_by_choice(&rust),
                        ones,
                        super::resets::value(&rust, fields, &positions, zeros, ones)?,
                        super::resets::warm(fields, &positions, zeros, ones),
                    ])
                };
                let full = laid_out(chip, chip_facts)?;
                res0.push(full[0]);
                res1.push(full[1]);
                reset.push(full[2]);
                warm.push(full[3]);
                // The chip's varying features the layout or the resets name,
                // and the layout without each combination of them.
                let reset_named = chip_facts.conditions.get(&rust);
                let relevant: Vec<(usize, &String, bool)> = varying
                    .iter()
                    .enumerate()
                    .filter(|(_, name)| chip.features.contains(**name))
                    .filter_map(|(bit, name)| {
                        let in_reset = reset_named.is_some_and(|named| named.contains(*name));
                        (conditions.contains(&format!("\"{name}\"")) || in_reset)
                            .then_some((bit, *name, in_reset))
                    })
                    .collect();
                ensure!(
                    relevant.len() as u32 <= RELEVANT_LIMIT,
                    "{rust} depends on {} of {}'s features",
                    relevant.len(),
                    profiles.chips[index].0
                );
                let relevant_bits = relevant
                    .iter()
                    .fold(0u64, |bits, (bit, ..)| bits | 1 << bit);
                for combination in 1u32..1 << relevant.len() {
                    let chosen = relevant
                        .iter()
                        .enumerate()
                        .filter(|(position, _)| combination >> position & 1 != 0)
                        .map(|(_, entry)| entry);
                    let mut removed = BTreeSet::new();
                    let mut reset_removed = BTreeSet::new();
                    let mut bits = 0u64;
                    for (bit, name, in_reset) in chosen {
                        removed.insert((*name).clone());
                        if *in_reset {
                            reset_removed.insert((*name).clone());
                        }
                        bits |= 1 << bit;
                    }
                    let facts = withheld_facts.get(index, reset_removed)?;
                    let values = laid_out(&without(chip, &removed), facts)?;
                    if values != full {
                        withheld_layouts.push(Withheld {
                            register: rust.clone(),
                            chip: index,
                            relevant: relevant_bits,
                            withheld: bits,
                            res0: values[0],
                            res1: values[1],
                            reset: values[2],
                            warm: values[3],
                        });
                    }
                }
            }
            layouts.push(Layout {
                name: rust.clone(),
                instances,
                res0,
                res1,
                reset,
                warm,
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
    let mut bodies = Vec::new();
    for accessor in &accessor_list {
        let mut body = String::new();
        if !generator.tree(&accessor.tree, &mut body, "    ")? {
            writeln!(
                body,
                "    Ok(Effect::Refused(\"no AARCHMRS case applies\"))"
            )?;
        }
        bodies.push(body);
    }
    let runs = shared(&bodies);
    let mut functions = String::new();
    let mut table = String::new();
    for (index, (accessor, &run)) in accessor_list.iter().zip(&runs).enumerate() {
        if run == index {
            writeln!(functions, "/// {} ({})", accessor.name, accessor.register)?;
            writeln!(
                functions,
                "fn a{index}(c: &mut dyn Context, m: u64) -> Result<Effect, Effect> {{"
            )?;
            writeln!(functions, "    let _ = m;")?;
            functions.push_str(&bodies[index]);
            writeln!(functions, "}}\n")?;
        }
        let index_bits: Vec<String> = accessor
            .encoding
            .index
            .iter()
            .map(|(key, bit)| format!("({key}, {bit})"))
            .collect();
        writeln!(
            table,
            "    Accessor {{ name: {:?}, kind: {:?}, mask: {:#06x}, value: {:#06x}, index: &[{}], run: a{run} }},",
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
         //! register and System instruction, from Arm AARCHMRS {} (BSD-3-Clause;\n\
         //! Copyright (c) 2010-2026 Arm Limited or its affiliates), which Arm\n\
         //! publishes on developer.arm.com as\n\
         //! `{}`. Each accessor is its\n\
         //! AARCHMRS permission tree folded against the Apple CPU profiles, a feature\n\
         //! only some chips have left to `Context::implemented`; accessors with the\n\
         //! same folded tree share one function. Reset values come from Arm's\n\
         //! `{}` System register XML (SHA-256\n\
         //! {}).\n\
         //! Regenerate with `cargo xtask sysregs --aarchmrs DIR`, `DIR` holding both\n\
         //! downloads. Do not edit.\n\
         #![allow(\n    clippy::all,\n    clippy::pedantic,\n    unused_parens,\n    unused_variables,\n    unreachable_code,\n    non_camel_case_types\n)]\n\
         use super::{{\n    Accessor, Broadcast, CacheOp, CacheScope, CacheType, Chip, Context, Effect, ErrorRecord, Limit,
    Operation,\n    \
         Pstate, Regime, Restrict, Stage, AtAccess, Tlbi, TlbiAttr, TlbiKind, TlbiLevel, WithheldLayout, helpers::*,\n}};\n",
        super::RELEASE,
        super::ARCHIVE,
        super::resets::ARCHIVE,
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
        ("warm", "u64", 5),
    ] {
        let parameter = if value >= 2 { ", chip: Chip" } else { "" };
        if value == 5 {
            writeln!(
                out,
                "    /// The bits a Warm reset sets, under `chip`'s profile."
            )?;
        } else if value >= 2 {
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
                4 => per_chip(&layout.reset),
                _ => per_chip(&layout.warm),
            };
            writeln!(out, "            Register::{} => {text},", layout.name)?;
        }
        writeln!(out, "        }}\n    }}\n")?;
    }
    writeln!(out, "}}\n")?;
    writeln!(
        out,
        "/// The register layouts that differ from the chip's on a PE whose\n\
         /// identification withholds some of the chip's features: a PE of `chip`\n\
         /// that withholds exactly `withheld` of the `relevant` features has them.\n\
         pub static WITHHELD_LAYOUTS: [WithheldLayout; {}] = [",
        withheld_layouts.len()
    )?;
    for entry in &withheld_layouts {
        writeln!(
            out,
            "    WithheldLayout {{ register: Register::{}, chip: Chip::{}, relevant: {:#x}, \
             withheld: {:#x}, res0: {:#x}, res1: {:#x}, reset: {:#x}, warm: {:#x} }},",
            entry.register,
            chip_variant(profiles.chips[entry.chip].0),
            entry.relevant,
            entry.withheld,
            entry.res0,
            entry.res1,
            entry.reset,
            entry.warm
        )?;
    }
    writeln!(out, "];\n")?;
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

/// For each accessor body, the index of the first accessor whose body is the
/// same text apart from whitespace: accessors with the same folded tree share
/// its function.
fn shared(bodies: &[String]) -> Vec<usize> {
    let mut first: BTreeMap<String, usize> = BTreeMap::new();
    bodies
        .iter()
        .enumerate()
        .map(|(index, body)| {
            *first
                .entry(body.split_whitespace().collect())
                .or_insert(index)
        })
        .collect()
}

/// The runtime's `Chip` variant for an Apple clang CPU name (`apple-m5` ->
/// `AppleM5`).
fn chip_variant(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or(String::new(), |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
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
    writeln!(out, "pub const CAPS: [&[&str]; {}] = [", super::CHIPS.len())?;
    for chip in &super::CHIPS {
        let names: Vec<String> = chip.cap.iter().map(|name| format!("{name:?}")).collect();
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
    fn accessors_with_the_same_body_share_the_first_function() {
        let bodies = [
            "    Ok(a)\n",
            "    Err(b)\n",
            "    Ok(\n        a)\n",
            "    Err(b)\n",
        ]
        .map(String::from);
        assert_eq!(shared(&bodies), [0, 1, 0, 1]);
    }

    #[test]
    fn the_first_layout_the_profile_holds_decides_the_reserved_bits() {
        let profile = Profile {
            parameters: ["FEAT_AA32EL1"].map(String::from).into(),
            features: Default::default(),
            highest_el: 2,
            varying: Default::default(),
        };
        let mut fields = BTreeMap::new();
        let register = crate::sysregs::tests::banked_spsr();
        assert_eq!(layout(&register, &profile, &[], &mut fields), (u64::MAX, 0));
        assert!(fields.is_empty());
    }

    /// A PE that withholds a feature has the layout of its chip's profile
    /// without it: the feature's conditional field takes its reserved type.
    #[test]
    fn a_layout_without_a_feature_reserves_its_fields() {
        let chip = Profile {
            parameters: ["FEAT_MTE2"].map(String::from).into(),
            features: ["FEAT_MTE2"].map(String::from).into(),
            highest_el: 2,
            varying: Default::default(),
        };
        let register = serde_json::json!({"fieldsets": [{
            "condition": {"_type": "AST.Bool", "value": true},
            "values": [{"_type": "Fields.ConditionalField", "rangeset": [{"start": 43, "width": 1}],
                        "reservedtype": "RES0",
                        "fields": [{"condition": {"_type": "AST.Function",
                                                  "name": "IsFeatureImplemented",
                "arguments": [{"_type": "AST.Identifier", "value": "FEAT_MTE2"}]},
                                    "field": {"_type": "Fields.Field", "name": "ATA",
                                              "rangeset": [{"start": 0, "width": 1}]}}]}]}]});
        let mut text = String::new();
        condition_text(&register["fieldsets"], &mut text);
        assert!(text.contains("\"FEAT_MTE2\""));
        let mut fields = BTreeMap::new();
        assert_eq!(layout(&register, &chip, &[], &mut fields), (0, 0));
        assert_eq!(fields["ATA"], (43, 1));
        let withheld = without(&chip, &["FEAT_MTE2"].map(String::from).into());
        assert!(withheld.features.is_empty());
        assert_eq!(
            layout(&register, &withheld, &[], &mut BTreeMap::new()),
            (1 << 43, 0)
        );
        assert_eq!(chip_variant("apple-m5"), "AppleM5");
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
    fn array_elements_are_fields_of_their_own() {
        use serde_json::json;
        let profile = Profile {
            parameters: Default::default(),
            features: Default::default(),
            highest_el: 2,
            varying: Default::default(),
        };
        // HAFGRTR_EL2's AMCNTEN<x> (bit 0 for x 0, bit 17 for x 1) and
        // AMEVCNTR0<x>_EL0 (bits 4:1).
        let index = |width| json!([{"_type": "Range", "start": 0, "width": width}]);
        let register = json!({"fieldsets": [{
            "condition": {"_type": "AST.Bool", "value": true},
            "values": [
                {"_type": "Fields.Array", "name": "AMCNTEN<x>", "index_variable": "x",
                 "indexes": index(2),
                 "rangeset": [{"start": 17, "width": 1}, {"start": 0, "width": 1}]},
                {"_type": "Fields.Array", "name": "AMEVCNTR0<x>_EL0", "index_variable": "x",
                 "indexes": index(4), "rangeset": [{"start": 1, "width": 4}]}]}]});
        let mut fields = BTreeMap::new();
        layout(&register, &profile, &[], &mut fields);
        assert_eq!(fields["AMCNTEN0"], (0, 1));
        assert_eq!(fields["AMCNTEN1"], (17, 1));
        assert_eq!(fields["AMEVCNTR00_EL0"], (1, 1));
        assert_eq!(fields["AMEVCNTR03_EL0"], (4, 1));
        assert_eq!(fields["AMEVCNTR0<x>_EL0"], (1, 4));
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
