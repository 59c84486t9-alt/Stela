//! `machine/system/generated.rs`: the profile's System registers with their
//! reserved bits, and every accessor with its folded permission tree.
use super::codegen::{Accessor, Fields, Generator, accessors, rust_name};
use super::expression::Profile;
use super::fold::{as_bool, fold};
use anyhow::{Result, bail};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

pub const GENERATED: &str = "crates/stela-runtime/src/machine/system/generated.rs";

/// A register of the profile: instances and the bits that are RES0 or RES1
/// in every layout the profile allows.
struct Layout {
    name: String,
    instances: u64,
    res0: u64,
    res1: u64,
    /// The Cold reset value under the profile (`super::resets`).
    reset: u64,
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

/// Field positions and reserved masks of the layouts whose condition holds.
fn layout(
    register: &Value,
    profile: &Profile,
    fields: &mut BTreeMap<String, (u32, u32)>,
) -> (u64, u64) {
    let mut res0 = u64::MAX;
    let mut res1 = u64::MAX;
    let mut any = false;
    for fieldset in register["fieldsets"].as_array().into_iter().flatten() {
        let condition = fold(&fieldset["condition"], profile);
        if as_bool(&condition) == Some(false) {
            continue;
        }
        let (mut zeros, mut ones) = (0, 0);
        collect(
            &fieldset["values"],
            0,
            profile,
            fields,
            &mut zeros,
            &mut ones,
        );
        res0 &= zeros;
        res1 &= ones;
        any = true;
    }
    if any { (res0, res1) } else { (0, 0) }
}

/// Fields of `values` at bit `offset`: a conditional field's variants are
/// relative to its own range, and when no variant applies its bits take the
/// conditional field's reserved type.
fn collect(
    values: &Value,
    offset: u64,
    profile: &Profile,
    fields: &mut BTreeMap<String, (u32, u32)>,
    res0: &mut u64,
    res1: &mut u64,
) {
    for value in values.as_array().into_iter().flatten() {
        match value["_type"].as_str().unwrap_or("") {
            "Fields.ConditionalField" => {
                let start = value["rangeset"][0]["start"].as_u64().unwrap_or(0) + offset;
                let mut live = false;
                for variant in value["fields"].as_array().into_iter().flatten() {
                    let condition = fold(&variant["condition"], profile);
                    if as_bool(&condition) == Some(false) {
                        continue;
                    }
                    live = true;
                    collect(
                        &Value::Array(vec![variant["field"].clone()]),
                        start,
                        profile,
                        fields,
                        res0,
                        res1,
                    );
                    if as_bool(&condition) == Some(true) {
                        break;
                    }
                }
                if !live {
                    let bits = ranges_mask(value, offset);
                    if reads_one(value["reservedtype"].as_str().unwrap_or("RES0")) {
                        *res1 |= bits;
                    } else {
                        *res0 |= bits;
                    }
                }
            }
            "Fields.Reserved" => {
                let mask = ranges_mask(value, offset);
                if reads_one(value["value"].as_str().unwrap_or("")) {
                    *res1 |= mask;
                } else {
                    *res0 |= mask;
                }
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
                    fields.entry(name.to_owned()).or_insert((start, width));
                    // A field with one allowed value is a constant.
                    let allowed: Vec<&str> = value["values"]["values"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|allowed| allowed["value"].as_str())
                        .collect();
                    if let [only] = allowed[..] {
                        let bits = only.trim_matches('\'');
                        if !bits.contains('x') && bits.len() as u32 == width {
                            for (position, bit) in bits.chars().rev().enumerate() {
                                let mask = 1u64.checked_shl(start + position as u32).unwrap_or(0);
                                if bit == '1' {
                                    *res1 |= mask;
                                } else {
                                    *res0 |= mask;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn generate(
    registers: &Value,
    profile: &Profile,
    applicable: &BTreeSet<String>,
    resets: &BTreeMap<String, Vec<super::resets::Field>>,
) -> Result<String> {
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
        let (res0, res1) = layout(register, profile, &mut positions);
        let applies = applicable.contains(name) && !is_implementation_defined_space(name);
        let reset = if applies {
            super::resets::value(
                &rust,
                resets.get(&rust).map_or(&[][..], Vec::as_slice),
                &positions,
                res0,
                res1,
            )?
        } else {
            res1
        };
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
         //! against the declared Mac14,3 profile. Reset values come from Arm's\n\
         //! {} System register XML (SHA-256 {}). Do not edit.\n\
         #![allow(\n    clippy::all,\n    clippy::pedantic,\n    unused_parens,\n    unused_variables,\n    unreachable_code,\n    non_camel_case_types\n)]\n\
         use super::{{\n    Accessor, Broadcast, CacheOp, CacheScope, CacheType, Context, Effect, ErrorRecord, Limit,
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
        writeln!(out, "    pub const fn {function}(self) -> {kind} {{")?;
        writeln!(out, "        match self {{")?;
        for layout in &layouts {
            let text = match value {
                0 => format!("{:?}", layout.name),
                1 => layout.instances.to_string(),
                2 => format!("{:#x}", layout.res0),
                3 => format!("{:#x}", layout.res1),
                _ => format!("{:#x}", layout.reset),
            };
            writeln!(out, "            Register::{} => {text},", layout.name)?;
        }
        writeln!(out, "        }}\n    }}\n")?;
    }
    writeln!(out, "}}\n")?;
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
