//! Generate the AGX2 shader ISA tables (`platform::apple::agx::isa::generated`)
//! from Mesa's machine-readable description, `src/asahi/isa/AGX2.xml`.
//!
//! The tables are the description's own model, as Mesa's `isa.py` reads it:
//! each instruction's exact bits and lengths, its destinations, sources,
//! immediates and modifiers as bit ranges, and the operand encodings as
//! ordered cases. Groups expand into one instruction per `ins`, with the
//! group's `exact` text substituted from the instruction's attributes;
//! operand definitions with negative bit positions count from the end of the
//! long form. The runtime's decoder and disassembler interpret the tables, so
//! a new Mesa revision regenerates rather than re-transcribes them.
use crate::darwin_catalogs::rustfmt;
use crate::tools::root;
use crate::xml::{self, Element};
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf};

const XML: &str = "src/asahi/isa/AGX2.xml";
const OUTPUT: &str = "crates/stela-runtime/src/platform/apple/agx/isa/generated.rs";

#[derive(clap::Args)]
pub struct AgxIsa {
    /// Root of a Mesa source tree (or of its `src/asahi` subset with the
    /// same relative paths).
    #[arg(long)]
    mesa: PathBuf,
    /// Fail instead of writing when the generated tables differ.
    #[arg(long)]
    check: bool,
}

impl AgxIsa {
    pub fn run(&self) -> Result<()> {
        let path = self.mesa.join(XML);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let isa = Isa::parse(&xml::parse(&text)?)?;
        let formatted = rustfmt(&isa.render())?;
        let output = root().join(OUTPUT);
        let current = std::fs::read_to_string(&output).unwrap_or_default();
        if current == formatted {
            println!("{OUTPUT}: up to date");
            return Ok(());
        }
        ensure!(!self.check, "{OUTPUT} differs from {XML}");
        std::fs::write(&output, formatted)
            .with_context(|| format!("cannot write {}", output.display()))?;
        println!("{OUTPUT}: regenerated");
        Ok(())
    }
}

/// An inclusive bit range; a negative position counts from the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    start: i32,
    end: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Bits(Vec<Range>);

impl Bits {
    fn parse(spec: &str) -> Result<Self> {
        let mut ranges = Vec::new();
        for part in spec.split_whitespace() {
            let (start, end) = match part.split_once(':') {
                Some((start, end)) => (start.parse()?, end.parse()?),
                None => {
                    let bit = part.parse()?;
                    (bit, bit)
                }
            };
            ensure!(start <= end, "bit range {part} runs backwards");
            ranges.push(Range { start, end });
        }
        Ok(Bits(ranges))
    }

    /// `isa.py`'s `specialize`: Python's modulo maps negative positions to
    /// the end of a `length`-bit word.
    fn specialize(&self, length: i32) -> Self {
        Bits(
            self.0
                .iter()
                .map(|r| Range {
                    start: r.start.rem_euclid(length),
                    end: r.end.rem_euclid(length),
                })
                .collect(),
        )
    }

    fn mask(&self) -> Result<u128> {
        let mut union = 0u128;
        for r in &self.0 {
            ensure!(
                r.start >= 0 && r.end < 128,
                "bit range {r:?} outside 128 bits"
            );
            let size = (r.end - r.start + 1) as u32;
            let mask = if size == 128 {
                u128::MAX
            } else {
                ((1u128 << size) - 1) << r.start
            };
            ensure!(union & mask == 0, "overlapping bit ranges {:?}", self.0);
            union |= mask;
        }
        Ok(union)
    }

    fn render(&self) -> Result<String> {
        let mut out = String::from("&[");
        for r in &self.0 {
            ensure!(r.start >= 0, "unspecialized negative bit range {r:?}");
            write!(
                out,
                "Range {{ start: {}, size: {} }},",
                r.start,
                r.end - r.start + 1
            )?;
        }
        out.push(']');
        Ok(out)
    }
}

/// `isa.py`'s `parse_bitstring` and `deposit_bits`: the text is written most
/// significant bit first and deposited into the mask's bits in increasing
/// position order.
fn exact(mask: u128, text: &str) -> Result<u128> {
    ensure!(
        text.len() as u32 == mask.count_ones(),
        "exact text {text:?} does not fill its {} bits",
        mask.count_ones()
    );
    let mut value = 0u128;
    let mut bits = text.bytes().rev();
    for position in 0..128 {
        if mask >> position & 1 == 0 {
            continue;
        }
        match bits.next() {
            Some(b'1') => value |= 1 << position,
            Some(b'0') => {}
            other => bail!("exact text {text:?} has {other:?}"),
        }
    }
    Ok(value)
}

#[derive(Debug, Clone, Default)]
struct Exact {
    mask: u128,
    value: u128,
}

impl Exact {
    fn read(element: &Element, substitutions: &BTreeMap<String, String>) -> Result<Self> {
        let mask = Bits::parse(attribute(element, "bit")?)?.mask()?;
        let value = if element.name == "zero" {
            0
        } else {
            let text = element.text();
            let text = text.trim();
            let text = substitutions.get(text).map_or(text, String::as_str);
            exact(mask, text)?
        };
        Ok(Exact { mask, value })
    }

    fn union(&mut self, other: &Exact) {
        self.mask |= other.mask;
        self.value |= other.value;
    }
}

fn attribute<'a>(element: &'a Element, name: &str) -> Result<&'a str> {
    element
        .attribute(name)
        .with_context(|| format!("<{}> lacks {name}", element.name))
}

/// A named bit field: an immediate, a modifier or an operand.
#[derive(Debug, Clone)]
struct Named {
    name: String,
    display: String,
    kind: String,
    bits: Bits,
    shift: u32,
}

impl Named {
    fn read(element: &Element, name: &str) -> Result<Self> {
        Ok(Named {
            name: name.to_owned(),
            display: element.attribute("display").unwrap_or(name).to_owned(),
            kind: element.attribute("kind").unwrap_or("int").to_owned(),
            bits: Bits::parse(attribute(element, "bit")?)?,
            shift: element.attribute("shift").map_or(Ok(0), str::parse)?,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct Case {
    exact: Exact,
    value: Option<Named>,
    modifiers: Vec<Named>,
    properties: Vec<(String, String)>,
}

impl Case {
    fn read(element: &Element) -> Result<Self> {
        let mut case = Case::default();
        for child in element.elements() {
            match child.name.as_str() {
                "exact" | "zero" => case.exact.union(&Exact::read(child, &BTreeMap::new())?),
                "immediate" => {
                    ensure!(case.value.is_none(), "an encoding case with two values");
                    case.value = Some(Named::read(child, attribute(child, "name")?)?);
                }
                "modifier" => case
                    .modifiers
                    .push(Named::read(child, attribute(child, "name")?)?),
                "property" => {
                    let text = child.text();
                    let text = text.trim();
                    case.properties.push((
                        attribute(child, "name")?.to_owned(),
                        if text.is_empty() { "1" } else { text }.to_owned(),
                    ));
                }
                "case" => {}
                other => bail!("unexpected <{other}> in an encoding"),
            }
        }
        Ok(case)
    }

    /// `EncodingCase.union`: the base's exact bits and properties, the base's
    /// modifiers first.
    fn merge(&mut self, base: &Case) {
        self.exact.union(&base.exact);
        let mut modifiers = base.modifiers.clone();
        modifiers.append(&mut self.modifiers);
        self.modifiers = modifiers;
        for (name, value) in &base.properties {
            match self.properties.iter_mut().find(|(n, _)| n == name) {
                Some(slot) => slot.1 = value.clone(),
                None => self.properties.push((name.clone(), value.clone())),
            }
        }
        if self.value.is_none() {
            self.value = base.value.clone();
        }
    }
}

/// An enumeration value and its text: empty for the default value, which
/// prints nothing.
#[derive(Debug, Clone)]
struct EnumValue {
    value: u32,
    display: String,
}

#[derive(Debug, Clone)]
struct Enum {
    kind: String,
    values: Vec<EnumValue>,
}

#[derive(Debug, Clone)]
enum Definition {
    Operand {
        kind: String,
        bits: Bits,
        dest: bool,
    },
    Modifier(Named),
}

#[derive(Debug, Clone)]
struct Operand {
    kind: String,
    bits: Bits,
}

#[derive(Debug, Clone)]
struct Instruction {
    name: String,
    display: String,
    length: Vec<u32>,
    length_bit: u32,
    exact: Exact,
    dests: Vec<Operand>,
    sources: Vec<Operand>,
    immediates: Vec<Named>,
    modifiers: Vec<Named>,
}

impl Instruction {
    fn read(
        xml: &Element,
        name: &str,
        display: Option<&str>,
        substitutions: &BTreeMap<String, String>,
        definitions: &BTreeMap<String, Definition>,
    ) -> Result<Self> {
        let length = attribute(xml, "length")?
            .split('/')
            .map(str::parse)
            .collect::<Result<Vec<u32>, _>>()?;
        let long_bits = *length.last().context("no length")? as i32 * 8;
        let mut instruction = Instruction {
            name: name.to_owned(),
            display: display.unwrap_or(name).to_owned(),
            length: length.clone(),
            length_bit: 0,
            exact: Exact::default(),
            dests: Vec::new(),
            sources: Vec::new(),
            immediates: Vec::new(),
            modifiers: Vec::new(),
        };
        for element in xml.elements() {
            match element.name.as_str() {
                "exact" | "zero" => instruction
                    .exact
                    .union(&Exact::read(element, substitutions)?),
                "immediate" => instruction
                    .immediates
                    .push(Named::read(element, attribute(element, "name")?)?),
                "src" | "dest" => {
                    let operand = Operand {
                        kind: attribute(element, "kind")?.to_owned(),
                        bits: Bits::parse(attribute(element, "bit")?)?,
                    };
                    if element.name == "dest" {
                        instruction.dests.push(operand);
                    } else {
                        instruction.sources.push(operand);
                    }
                }
                "modifier" => instruction
                    .modifiers
                    .push(Named::read(element, attribute(element, "name")?)?),
                "ins" => ensure!(xml.name == "group", "<ins> outside a group"),
                other => match definitions.get(other) {
                    Some(Definition::Operand { kind, bits, dest }) => {
                        let operand = Operand {
                            kind: kind.clone(),
                            bits: bits.specialize(long_bits),
                        };
                        if *dest {
                            instruction.dests.push(operand);
                        } else {
                            instruction.sources.push(operand);
                        }
                    }
                    Some(Definition::Modifier(modifier)) => {
                        instruction.modifiers.push(modifier.clone())
                    }
                    None => bail!("{name}: unknown element <{other}>"),
                },
            }
        }
        if length.len() > 1 && !instruction.modifiers.iter().any(|m| m.name == "length") {
            match definitions.get("length") {
                Some(Definition::Modifier(length)) => instruction.modifiers.push(length.clone()),
                _ => bail!("no length definition"),
            }
        }
        for modifier in &instruction.modifiers {
            if modifier.name == "length" {
                instruction.length_bit = modifier.bits.0[0].start as u32;
            }
        }
        Ok(instruction)
    }

    /// Every bit the description names.
    fn known(&self) -> Result<u128> {
        let mut known = self.exact.mask;
        for bits in self
            .modifiers
            .iter()
            .chain(&self.immediates)
            .map(|named| &named.bits)
            .chain(self.sources.iter().chain(&self.dests).map(|o| &o.bits))
        {
            known |= bits.mask()?;
        }
        Ok(known)
    }
}

struct Isa {
    enums: Vec<Enum>,
    encodings: Vec<(String, Vec<Case>)>,
    instructions: Vec<Instruction>,
}

impl Isa {
    fn parse(root: &Element) -> Result<Self> {
        let isa = root.child("isa").context("no <isa> root")?;
        let mut definitions = BTreeMap::new();
        let mut isa_out = Isa {
            enums: Vec::new(),
            encodings: Vec::new(),
            instructions: Vec::new(),
        };
        for child in isa.elements() {
            match child.name.as_str() {
                "define" => {
                    let bits = Bits::parse(attribute(child, "bit")?)?;
                    let kind = child.attribute("kind").unwrap_or("int").to_owned();
                    if let Some(name) = child.attribute("src") {
                        definitions.insert(
                            name.to_owned(),
                            Definition::Operand {
                                kind,
                                bits,
                                dest: false,
                            },
                        );
                    } else if let Some(name) = child.attribute("dest") {
                        definitions.insert(
                            name.to_owned(),
                            Definition::Operand {
                                kind,
                                bits,
                                dest: true,
                            },
                        );
                    } else if let Some(name) = child.attribute("modifier") {
                        definitions.insert(
                            name.to_owned(),
                            Definition::Modifier(Named::read(child, name)?),
                        );
                    } else {
                        bail!("a <define> of an unknown kind");
                    }
                }
                "encoding" => {
                    let base = Case::read(child)?;
                    let mut cases = child
                        .children_named("case")
                        .map(Case::read)
                        .collect::<Result<Vec<_>>>()?;
                    if cases.is_empty() {
                        cases.push(base);
                    } else {
                        for case in &mut cases {
                            case.merge(&base);
                        }
                    }
                    isa_out
                        .encodings
                        .push((attribute(child, "name")?.to_owned(), cases));
                }
                "enum" => {
                    let mut values = Vec::new();
                    for value in child.children_named("value") {
                        let default = value.attribute("default").is_some();
                        values.push(EnumValue {
                            value: attribute(value, "value")?.parse()?,
                            display: if default {
                                String::new()
                            } else {
                                value.text().trim().to_owned()
                            },
                        });
                    }
                    isa_out.enums.push(Enum {
                        kind: attribute(child, "kind")?.to_owned(),
                        values,
                    });
                }
                "ins" => {
                    let name = attribute(child, "name")?;
                    isa_out.push(Instruction::read(
                        child,
                        name,
                        child.attribute("display"),
                        &BTreeMap::new(),
                        &definitions,
                    )?)?;
                }
                "group" => {
                    let members: Vec<&Element> = child.children_named("ins").collect();
                    ensure!(!members.is_empty(), "a group without instructions");
                    for member in members {
                        let substitutions = member
                            .attributes
                            .iter()
                            .cloned()
                            .collect::<BTreeMap<_, _>>();
                        isa_out.push(Instruction::read(
                            child,
                            attribute(member, "name")?,
                            member.attribute("display"),
                            &substitutions,
                            &definitions,
                        )?)?;
                    }
                }
                other => bail!("unexpected <{other}> in <isa>"),
            }
        }
        Ok(isa_out)
    }

    fn push(&mut self, instruction: Instruction) -> Result<()> {
        ensure!(
            !self.instructions.iter().any(|i| i.name == instruction.name),
            "two instructions named {}",
            instruction.name
        );
        self.instructions.push(instruction);
        Ok(())
    }

    fn render(&self) -> String {
        self.try_render().expect("the parsed description renders")
    }

    fn try_render(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(
            out,
            "//! Generated by `cargo xtask agx-isa` from Mesa's `{XML}` (MIT,\n\
             //! Copyright 2025 Valve Corporation). Do not edit.\n\
             #![allow(clippy::all)]\n\n\
             use super::spec::*;\n"
        )?;
        // Enumerations.
        for e in &self.enums {
            write!(
                out,
                "pub static ENUM_{}: Enum = Enum {{ kind: {:?}, values: &[",
                ident(&e.kind).to_uppercase(),
                e.kind
            )?;
            for v in &e.values {
                write!(out, "({}, {:?}),", v.value, v.display)?;
            }
            writeln!(out, "] }};")?;
        }
        // Operand encodings.
        for (name, cases) in &self.encodings {
            write!(
                out,
                "pub static ENCODING_{}: Encoding = Encoding {{ name: {name:?}, cases: &[",
                ident(name).to_uppercase()
            )?;
            for case in cases {
                ensure!(
                    case.exact.mask >> 64 == 0,
                    "{name}: case exact past 64 bits"
                );
                write!(
                    out,
                    "Case {{ mask: {:#x}, exact: {:#x}, value: ",
                    case.exact.mask, case.exact.value
                )?;
                match &case.value {
                    Some(value) => write!(
                        out,
                        "Some(CaseValue {{ kind: ValueKind::{}, bits: {}, shift: {}, signed: {} }}),",
                        camel(&value.name),
                        value.bits.render()?,
                        value.shift,
                        value.kind == "signed"
                    )?,
                    None => write!(out, "None,")?,
                }
                write!(out, "modifiers: &[")?;
                for modifier in &case.modifiers {
                    write!(
                        out,
                        "CaseModifier {{ attr: Attr::{}, bits: {} }},",
                        camel(&modifier.name),
                        modifier.bits.render()?
                    )?;
                }
                write!(out, "], properties: &[")?;
                for (property, value) in &case.properties {
                    write!(
                        out,
                        "CaseProperty {{ attr: Attr::{}, value: {value} }},",
                        camel(property)
                    )?;
                }
                writeln!(out, "] }},")?;
            }
            writeln!(out, "] }};")?;
        }
        // Names.
        let mut modifiers = Vec::<&str>::new();
        let mut immediates = Vec::<&str>::new();
        for instruction in &self.instructions {
            for m in &instruction.modifiers {
                if !modifiers.contains(&m.name.as_str()) {
                    modifiers.push(&m.name);
                }
            }
            for i in &instruction.immediates {
                if !immediates.contains(&i.name.as_str()) {
                    immediates.push(&i.name);
                }
            }
        }
        writeln!(
            out,
            "/// One instruction of the description, in its order.\n\
             #[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum Op {{"
        )?;
        for instruction in &self.instructions {
            writeln!(out, "{},", camel(&instruction.name))?;
        }
        writeln!(
            out,
            "}}\n\n/// A modifier name.\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum Mod {{"
        )?;
        for name in &modifiers {
            writeln!(out, "{},", camel(name))?;
        }
        writeln!(
            out,
            "}}\n\n/// An immediate name.\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum Imm {{"
        )?;
        for name in &immediates {
            writeln!(out, "{},", camel(name))?;
        }
        writeln!(out, "}}\n")?;
        // Instructions.
        writeln!(
            out,
            "pub static INSTRUCTIONS: [Instruction; {}] = [",
            self.instructions.len()
        )?;
        let enum_kinds: Vec<&str> = self.enums.iter().map(|e| e.kind.as_str()).collect();
        let encoding_names: Vec<&str> = self.encodings.iter().map(|e| e.0.as_str()).collect();
        for instruction in &self.instructions {
            let trivial = instruction.dests.len()
                + instruction.sources.len()
                + instruction.immediates.len()
                + instruction.modifiers.len()
                == 0;
            write!(
                out,
                "Instruction {{ op: Op::{}, display: {:?}, trivial: {trivial}, length_bit: {}, short: {}, long: {}, mask: {:#x}, exact: {:#x}, known: {:#x},",
                camel(&instruction.name),
                instruction.display,
                instruction.length_bit,
                instruction.length[0],
                instruction.length.last().unwrap(),
                instruction.exact.mask,
                instruction.exact.value,
                instruction.known()?
            )?;
            for (field, operands) in [
                ("dests", &instruction.dests),
                ("sources", &instruction.sources),
            ] {
                write!(out, "{field}: &[")?;
                for operand in operands {
                    ensure!(
                        encoding_names.contains(&operand.kind.as_str()),
                        "{}: no encoding {}",
                        instruction.name,
                        operand.kind
                    );
                    write!(
                        out,
                        "OperandSpec {{ encoding: &ENCODING_{}, bits: {} }},",
                        ident(&operand.kind).to_uppercase(),
                        operand.bits.render()?
                    )?;
                }
                write!(out, "],")?;
            }
            write!(out, "immediates: &[")?;
            for immediate in &instruction.immediates {
                write!(
                    out,
                    "ImmediateSpec {{ name: Imm::{}, signed: {}, bits: {} }},",
                    camel(&immediate.name),
                    immediate.kind == "signed",
                    immediate.bits.render()?
                )?;
            }
            write!(out, "], modifiers: &[")?;
            for modifier in &instruction.modifiers {
                let kind = if enum_kinds.contains(&modifier.kind.as_str()) {
                    format!("Some(&ENUM_{})", ident(&modifier.kind).to_uppercase())
                } else {
                    ensure!(
                        modifier.kind == "int",
                        "{}: modifier kind {} is not an enum",
                        instruction.name,
                        modifier.kind
                    );
                    "None".to_owned()
                };
                write!(
                    out,
                    "ModifierSpec {{ name: Mod::{}, display: {:?}, kind: {kind}, bits: {} }},",
                    camel(&modifier.name),
                    modifier.display,
                    modifier.bits.render()?
                )?;
            }
            writeln!(out, "] }},")?;
        }
        writeln!(out, "];")?;
        Ok(out)
    }
}

/// A Rust identifier from a description name.
fn ident(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// A CamelCase Rust variant name from a description name.
fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = true;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if upper {
                out.extend(c.to_uppercase());
            } else {
                out.push(c);
            }
            upper = false;
        } else {
            upper = true;
        }
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, 'N');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_text_deposits_least_significant_last() {
        // `ldimm16`: bits 0:6 and 8 from "01100010".
        let mask = Bits::parse("0:6 8").unwrap().mask().unwrap();
        assert_eq!(exact(mask, "01100010").unwrap(), 0x62);
        // `iadd`: bits 0:5 and 15 from "0001110"; bit 15 is the first char.
        let mask = Bits::parse("0:5 15").unwrap().mask().unwrap();
        assert_eq!(exact(mask, "0001110").unwrap(), 0x0e);
        assert_eq!(exact(mask, "1001110").unwrap(), 0x800e);
        assert!(exact(mask, "01").is_err());
    }

    #[test]
    fn negative_positions_count_from_the_long_end() {
        let bits = Bits::parse("7:14 -4:-3").unwrap().specialize(64);
        assert_eq!(
            bits.0,
            [Range { start: 7, end: 14 }, Range { start: 60, end: 61 }]
        );
        assert!(Bits::parse("1:2 2").unwrap().mask().is_err());
    }

    #[test]
    fn names_become_rust_identifiers() {
        assert_eq!(camel("jmp_exec_any"), "JmpExecAny");
        assert_eq!(camel("image_barrier_1"), "ImageBarrier1");
        assert_eq!(ident("dalu64"), "dalu64");
    }
}
