//! Rust for the System register and System instruction accessors of the
//! profile, from the folded AARCHMRS permission trees. Each accessor becomes
//! one function whose ordered choices are sequential `if` blocks that all
//! return; the runtime supplies the `Context` the generated code calls.
use super::expression::Profile;
use super::fold::{Tree, as_bool, fold, tree};
use anyhow::{Context as _, Result, bail, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

/// Identifier prefixes of the runtime's operation enums.
const ENUMS: [(&str, &str); 10] = [
    ("Regime_", "Regime"),
    ("Broadcast_", "Broadcast"),
    ("TLBILevel_", "TlbiLevel"),
    ("TLBI_", "TlbiAttr"),
    ("CacheType_", "CacheType"),
    ("CacheOpScope_", "CacheScope"),
    ("CacheOp_", "CacheOp"),
    ("ATAccess_", "AtAccess"),
    ("TranslationStage_", "Stage"),
    ("RestrictType_", "Restrict"),
];

/// Decided IMPLEMENTATION DEFINED choices, by the AARCHMRS text.
const IMPDEF: [(&str, bool, &str); 3] = [
    (
        "IMPLEMENTED_ACTLR_ELx accessor behavior",
        true,
        "ACTLR_ELx are storage without effect",
    ),
    (
        "Trapped by MDCR_EL2.TDOSA",
        true,
        "the Arm recommendation for OS lock and debug power registers",
    ),
    (
        "AArch64-AMEVCNTR1_EL0[m] is fixed",
        false,
        "auxiliary activity monitors count",
    ),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ty {
    Bool,
    /// Bits of a known width, or of an unknown width at most 64.
    Bits(Option<u32>),
    Int,
    Enum,
}

/// Field positions per register, from the profile's fieldsets.
pub type Fields = BTreeMap<String, BTreeMap<String, (u32, u32)>>;

pub struct Accessor {
    pub name: String,
    pub register: String,
    pub kind: String,
    pub encoding: Encoding,
    pub tree: Tree,
}

/// A 16-bit `op0:op1:CRn:CRm:op2` key pattern with array index bits.
#[derive(Default, Clone)]
pub struct Encoding {
    pub mask: u16,
    pub value: u16,
    /// (key bit, index bit)
    pub index: Vec<(u32, u32)>,
}

const KEY_FIELDS: [(&str, u32, u32); 5] = [
    ("op0", 14, 2),
    ("op1", 11, 3),
    ("CRn", 7, 4),
    ("CRm", 3, 4),
    ("op2", 0, 3),
];

pub fn encoding(fields: &Value) -> Result<Encoding> {
    let mut out = Encoding::default();
    for (name, shift, width) in KEY_FIELDS {
        let field = &fields[name];
        if field.is_null() {
            bail!("encoding without {name}");
        }
        if field["_type"] == "Values.EquationValue" {
            // `m` sliced into the whole field.
            for bit in 0..width {
                out.index.push((shift + bit, bit));
            }
            continue;
        }
        let text = field["value"].as_str().context("encoding value")?;
        // Parts, most significant first: '011', p[3], m[1:0].
        let mut position = shift + width;
        for part in split_outside_brackets(text) {
            if let Some(bits) = part.strip_prefix('\'') {
                let bits = bits.trim_end_matches('\'');
                for c in bits.chars() {
                    position -= 1;
                    out.mask |= 1 << position;
                    if c == '1' {
                        out.value |= 1 << position;
                    }
                }
            } else {
                let (_, range) = part.split_once('[').context("index part")?;
                let range = range.trim_end_matches(']');
                let (high, low) = match range.split_once(':') {
                    Some((high, low)) => (high.parse::<u32>()?, low.parse::<u32>()?),
                    None => (range.parse()?, range.parse()?),
                };
                for bit in (low..=high).rev() {
                    position -= 1;
                    out.index.push((position, bit));
                }
            }
        }
        ensure!(
            position == shift,
            "{name} pattern {text} is not {width} bits"
        );
    }
    Ok(out)
}

/// Split `'1':m[1:0]` at the colons that are not inside brackets.
fn split_outside_brackets(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (position, c) in text.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ':' if depth == 0 => {
                parts.push(&text[start..position]);
                start = position + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

pub fn rust_name(register: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in register.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 && (c.is_ascii_alphanumeric() || c == '_') => out.push(c),
            _ if depth == 0 => out.push('_'),
            _ => {}
        }
    }
    out
}

pub struct Generator<'a> {
    pub fields: &'a Fields,
    /// Register names the runtime keeps, by AARCHMRS name without index.
    pub registers: &'a BTreeSet<String>,
    pub unknown: BTreeSet<String>,
    pub profile: &'a Profile,
}

fn pattern(value: &str) -> (u64, u64, u32) {
    let bits = value.trim_matches('\'');
    let mut mask = 0;
    let mut out = 0;
    for c in bits.chars() {
        mask <<= 1;
        out <<= 1;
        if c != 'x' {
            mask |= 1;
        }
        if c == '1' {
            out |= 1;
        }
    }
    (mask, out, bits.len() as u32)
}

impl Generator<'_> {
    fn field(&self, register: &str, field: &str) -> Option<(u32, u32)> {
        self.fields
            .get(&rust_name(register))
            .and_then(|fields| fields.get(field))
            .copied()
    }

    fn register_read(&mut self, name: &str, index: Option<&Value>) -> Result<String> {
        let rust = rust_name(name);
        if let Some(record) = error_record(name) {
            let index = match index {
                Some(index) => self.int(index)?,
                None => "0".into(),
            };
            return Ok(format!("c.error_record(ErrorRecord::{record}, {index})"));
        }
        if !self.registers.contains(&rust) {
            self.unknown.insert(format!("register {name}"));
            return Ok(format!("c.missing({:?})", format!("register {name}")));
        }
        let index = match index {
            Some(index) => self.int(index)?,
            None => "0".into(),
        };
        Ok(format!("c.read(Register::{rust}, {index})"))
    }

    fn int(&mut self, node: &Value) -> Result<String> {
        let (code, ty) = self.expr(node)?;
        Ok(match ty {
            Ty::Bool => format!("u64::from({code})"),
            _ => code,
        })
    }

    fn bits(&mut self, node: &Value) -> Result<(String, Option<u32>)> {
        let (code, ty) = self.expr(node)?;
        Ok(match ty {
            Ty::Bits(width) => (code, width),
            Ty::Bool => (format!("u64::from({code})"), Some(1)),
            Ty::Int | Ty::Enum => (code, None),
        })
    }

    fn condition(&mut self, node: &Value) -> Result<String> {
        let (code, ty) = self.expr(node)?;
        Ok(match ty {
            Ty::Bool => code,
            _ => format!("({code}) != 0"),
        })
    }

    fn compare(&mut self, left: &Value, right: &Value) -> Result<String> {
        if right["_type"] == "Values.Value" {
            let (code, _) = self.bits(left)?;
            let (mask, value, _) = pattern(right["value"].as_str().unwrap_or(""));
            return Ok(format!("(({code}) & {mask:#x}) == {value:#x}"));
        }
        if left["_type"] == "Values.Value" {
            return self.compare(right, left);
        }
        let (l, _) = self.bits(left)?;
        let (r, _) = self.bits(right)?;
        Ok(format!("({l}) == ({r})"))
    }

    fn expr(&mut self, node: &Value) -> Result<(String, Ty)> {
        if let Some(value) = as_bool(node) {
            return Ok((value.to_string(), Ty::Bool));
        }
        let kind = node["_type"].as_str().unwrap_or("");
        Ok(match kind {
            "AST.Integer" => (format!("{}u64", node["value"]), Ty::Int),
            "Values.Value" => {
                let (_, value, width) = pattern(node["value"].as_str().unwrap_or(""));
                (format!("{value:#x}"), Ty::Bits(Some(width)))
            }
            "AST.Identifier" => self.identifier(node["value"].as_str().unwrap_or(""))?,
            "AST.DotAtom" => self.dot(node)?,
            "Types.Field" => {
                let register = node["value"]["name"].as_str().unwrap_or("");
                let field = node["value"]["field"].as_str().unwrap_or("");
                self.field_read(register, field, None)?
            }
            "AST.UnaryOp" => {
                let inner = self.condition(&node["expr"])?;
                (format!("!({inner})"), Ty::Bool)
            }
            "AST.BinaryOp" => self.binary(node)?,
            "AST.Function" => self.call(node)?,
            "AST.SquareOp" => {
                let (code, _) = self.bits(&node["var"])?;
                let slice = &node["arguments"][0];
                if slice["_type"] == "AST.Slice" {
                    let bound = |side: &str| {
                        slice[side]["value"]
                            .as_u64()
                            .with_context(|| format!("slice {}", super::render(node)))
                    };
                    let (high, low) = (bound("left")? as u32, bound("right")? as u32);
                    let width = high - low + 1;
                    (
                        format!("bits({code}, {low}, {width})"),
                        Ty::Bits(Some(width)),
                    )
                } else {
                    let bit = self.int(slice)?;
                    (format!("bits({code}, {bit}, 1)"), Ty::Bits(Some(1)))
                }
            }
            "AST.Concat" => {
                let mut code = String::from("0u64");
                let mut total = 0;
                for part in node["values"].as_array().into_iter().flatten() {
                    let (value, width) = self.bits(part)?;
                    let width = width.with_context(|| {
                        format!("concatenation of an unsized value {}", super::render(part))
                    })?;
                    code = format!("(({code}) << {width}) | ({value})");
                    total += width;
                }
                (code, Ty::Bits(Some(total)))
            }
            "Types.RegisterType" => {
                let register = node["value"]["name"].as_str().unwrap_or("");
                (self.register_read(register, None)?, Ty::Bits(Some(64)))
            }
            "AST.TypeAnnotation" if node["var"]["value"] == "ARBITRARY" => {
                ("c.arbitrary()".into(), Ty::Bits(None))
            }
            _ => bail!("unsupported expression {}", super::render(node)),
        })
    }

    fn identifier(&mut self, name: &str) -> Result<(String, Ty)> {
        if let Some(level) = name.strip_prefix("EL").and_then(|n| n.parse::<u8>().ok()) {
            return Ok((level.to_string(), Ty::Bits(Some(2))));
        }
        for (prefix, enumeration) in ENUMS {
            if let Some(variant) = name.strip_prefix(prefix) {
                // TranslationStage_1 and _12 become Stage::S1 and S12.
                let separator = if variant.starts_with(|c: char| c.is_ascii_digit()) {
                    "S"
                } else {
                    ""
                };
                return Ok((format!("{enumeration}::{separator}{variant}"), Ty::Enum));
            }
        }
        Ok(match name {
            "m" => ("m".into(), Ty::Int),
            "ARBITRARY" => ("c.arbitrary()".into(), Ty::Bits(None)),
            "VMID_NONE" => ("None".into(), Ty::Enum),
            "NUM_BREAKPOINTS" => ("c.limit(Limit::Breakpoints)".into(), Ty::Int),
            "NUM_WATCHPOINTS" => ("c.limit(Limit::Watchpoints)".into(), Ty::Int),
            "NUM_AMU_CG1_MONITORS" => ("c.limit(Limit::AuxiliaryMonitors)".into(), Ty::Int),
            "op0" | "op1" | "CRn" | "CRm" | "op2" => {
                (format!("c.encoding().{}", name.to_lowercase()), Ty::Int)
            }
            "t" => ("c.x()".into(), Ty::Bits(Some(64))),
            other => bail!("unsupported identifier {other}"),
        })
    }

    fn field_read(
        &mut self,
        register: &str,
        field: &str,
        value: Option<String>,
    ) -> Result<(String, Ty)> {
        let Some((low, width)) = self.field(register, field) else {
            // A field the profile does not have is RES0.
            return Ok(("0u64".into(), Ty::Bits(None)));
        };
        let value = match value {
            Some(value) => value,
            None => self.register_read(register, None)?,
        };
        Ok((
            format!("bits({value}, {low}, {width})"),
            Ty::Bits(Some(width)),
        ))
    }

    fn dot(&mut self, node: &Value) -> Result<(String, Ty)> {
        let values = node["values"].as_array().context("dot atom")?;
        let head = &values[0];
        let tail = values[1]["value"].as_str().unwrap_or("");
        if head["value"] == "PSTATE" {
            return Ok(match tail {
                "EL" => ("c.el()".into(), Ty::Bits(Some(2))),
                field => (format!("c.pstate(Pstate::{field})"), Ty::Bits(Some(1))),
            });
        }
        if head["_type"] == "AST.Function" {
            let register = head["name"].as_str().unwrap_or("");
            let value = self.register_read(register, head["arguments"].get(0))?;
            return self.field_read(register, tail, Some(value));
        }
        bail!("unsupported dot atom {}", super::render(node))
    }

    fn binary(&mut self, node: &Value) -> Result<(String, Ty)> {
        let op = node["op"].as_str().unwrap_or("");
        let (left, right) = (&node["left"], &node["right"]);
        Ok(match op {
            "&&" | "||" => {
                let l = self.condition(left)?;
                let r = self.condition(right)?;
                (format!("({l}) {op} ({r})"), Ty::Bool)
            }
            "==" => (self.compare(left, right)?, Ty::Bool),
            "!=" => (format!("!({})", self.compare(left, right)?), Ty::Bool),
            "IN" => {
                let (code, _) = self.bits(left)?;
                let alternatives: Vec<String> = right["values"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|value| {
                        let (mask, value, _) = pattern(value["value"].as_str().unwrap_or(""));
                        format!("(v & {mask:#x}) == {value:#x}")
                    })
                    .collect();
                (
                    format!("{{ let v = {code}; {} }}", alternatives.join(" || ")),
                    Ty::Bool,
                )
            }
            ">=" | ">" | "<" | "<=" => {
                let l = self.int(left)?;
                let r = self.int(right)?;
                (format!("({l}) {op} ({r})"), Ty::Bool)
            }
            "+" | "-" | "*" => {
                let (l, _) = self.bits(left)?;
                let (r, _) = self.bits(right)?;
                let method = match op {
                    "+" => "wrapping_add",
                    "-" => "wrapping_sub",
                    _ => "wrapping_mul",
                };
                (format!("({l}).{method}({r})"), Ty::Bits(Some(64)))
            }
            "::" => {
                let (l, _) = self.bits(left)?;
                let (r, width) = self.bits(right)?;
                let width = width.context("concatenation of an unsized value")?;
                (format!("(({l}) << {width}) | ({r})"), Ty::Bits(None))
            }
            _ => bail!("unsupported operator {op}"),
        })
    }

    fn call(&mut self, node: &Value) -> Result<(String, Ty)> {
        let name = node["name"].as_str().unwrap_or("");
        let arguments: Vec<&Value> = node["arguments"].as_array().into_iter().flatten().collect();
        let level = |value: &Value| {
            value["value"]
                .as_str()
                .and_then(|name| name.strip_prefix("EL"))
                .unwrap_or("?")
                .to_owned()
        };
        Ok(match name {
            "X" => ("c.x()".into(), Ty::Bits(Some(64))),
            "EffectivelyAtEL0InHost" => ("at_el0_in_host(c)".into(), Ty::Bool),
            "EffectivelyAtEL0NotInHost" => ("at_el0_not_in_host(c)".into(), Ty::Bool),
            "ELIsInHost" => (format!("is_in_host(c, {})", level(arguments[0])), Ty::Bool),
            "EffectiveHCR_EL2_NVx" => ("hcr_nvx(c)".into(), Ty::Bits(Some(3))),
            "EffectiveTGEforEL0Traps" => ("tge_for_el0_traps(c)".into(), Ty::Bits(Some(1))),
            "IsHighestEL" => {
                let (code, _) = self.bits(arguments[0])?;
                (format!("({code}) == {}", self.profile.highest_el), Ty::Bool)
            }
            "PhysicalCountInt" => ("c.physical_count()".into(), Ty::Bits(Some(64))),
            "VMID" => ("Some(vmid(c))".into(), Ty::Enum),
            "UInt" | "ZeroExtend" => {
                let (code, _) = self.bits(arguments[0])?;
                (code, Ty::Int)
            }
            "SignExtend" => {
                let (code, width) = self.bits(arguments[0])?;
                let width = width.context("sign extension of an unsized value")?;
                (format!("sign_extend({code}, {width})"), Ty::Bits(Some(64)))
            }
            "IsZero" => {
                let (code, _) = self.bits(arguments[0])?;
                (format!("({code}) == 0"), Ty::Bool)
            }
            "Zeros" => (
                "0u64".into(),
                Ty::Bits(
                    node["parameters"][0]["value"]
                        .as_u64()
                        .map(|width| width as u32),
                ),
            ),
            "ImpDefBool" => {
                let text = arguments[0]["value"].as_str().unwrap_or("");
                let (_, value, _) = IMPDEF
                    .iter()
                    .find(|(name, _, _)| *name == text)
                    .with_context(|| format!("undecided ImpDefBool {text:?}"))?;
                (value.to_string(), Ty::Bool)
            }
            "IsG1ActivityMonitorImplemented" | "IsG1ActivityMonitorOffsetImplemented" => {
                let index = self.int(arguments[0])?;
                (format!("c.auxiliary_monitor({index})"), Ty::Bool)
            }
            "AArch64_CanTrapDC"
            | "AArch64_TreatDCAsNOP"
            | "AArch64_CanTrapIC"
            | "AArch64_TreatICAsNOP" => {
                let helper = match name {
                    "AArch64_CanTrapDC" => "can_trap_dc",
                    "AArch64_TreatDCAsNOP" => "treat_dc_as_nop",
                    "AArch64_CanTrapIC" => "can_trap_ic",
                    _ => "treat_ic_as_nop",
                };
                let args: Vec<String> = arguments
                    .iter()
                    .map(|argument| self.expr(argument).map(|(code, _)| code))
                    .collect::<Result<_>>()?;
                (format!("{helper}(c, {})", args.join(", ")), Ty::Bool)
            }
            "Read_DBGDTR_EL0" => {
                let width = node["parameters"][0]["value"].as_u64().unwrap_or(64);
                (format!("c.read_dbgdtr({width})"), Ty::Bits(Some(64)))
            }
            "CNTHCTL_EL2_VHE" => {
                // The bits it makes UNKNOWN keep their stored value.
                let (code, _) = self.bits(arguments[0])?;
                (code, Ty::Bits(Some(64)))
            }
            "NVMem" => {
                let offset = self.int(arguments[0])?;
                (format!("c.nv_mem({offset})?"), Ty::Bits(Some(64)))
            }
            _ if self.registers.contains(&rust_name(name)) || is_register_name(name) => (
                self.register_read(name, arguments.first().copied())?,
                Ty::Bits(Some(64)),
            ),
            _ => {
                self.unknown.insert(format!("function {name}"));
                (
                    format!("c.missing({:?})", format!("function {name}")),
                    Ty::Bits(None),
                )
            }
        })
    }

    fn operation(&mut self, node: &Value) -> Result<Option<String>> {
        let name = node["name"].as_str().unwrap_or("");
        let arguments: Vec<&Value> = node["arguments"].as_array().into_iter().flatten().collect();
        let mut named: BTreeMap<&str, String> = BTreeMap::new();
        let mut operand = None;
        for argument in &arguments {
            let identifier = argument["value"].as_str().unwrap_or("");
            if argument["_type"] == "AST.Function" && argument["name"] == "X" {
                operand = Some("c.x()".to_owned());
                continue;
            }
            if argument["_type"] == "AST.Function" && argument["name"] == "VMID" {
                named.insert("vmid", "Some(vmid(c))".into());
                continue;
            }
            if identifier == "VMID_NONE" {
                named.insert("vmid", "None".into());
                continue;
            }
            if identifier == "SS_NonSecure" {
                continue;
            }
            if let Some(level) = identifier.strip_prefix("EL") {
                named.insert("el", level.to_owned());
                continue;
            }
            let (code, _) = self.expr(argument)?;
            let key = ENUMS
                .iter()
                .find(|(prefix, _)| identifier.starts_with(prefix))
                .map(|(_, enumeration)| *enumeration)
                .with_context(|| format!("operation argument {}", super::render(argument)))?;
            named.insert(key, code);
        }
        let get = |key: &str, default: &str| named.get(key).cloned().unwrap_or(default.into());
        let need = |key: &str| -> Result<String> {
            named
                .get(key)
                .cloned()
                .with_context(|| format!("{name} without {key}"))
        };
        let operand = operand.unwrap_or_else(|| "0".into());
        let code = if let Some(kind) = name.strip_prefix("AArch64_TLBI_") {
            format!(
                "Operation::Tlbi(Tlbi {{ kind: TlbiKind::{kind}, regime: {}, vmid: {}, \
                 broadcast: {}, level: {}, attr: {}, operand: {operand} }})",
                need("Regime")?,
                get("vmid", "None"),
                need("Broadcast")?,
                get("TlbiLevel", "TlbiLevel::Any"),
                get("TlbiAttr", "TlbiAttr::AllAttr"),
            )
        } else {
            match name {
                "AArch64_AT" => format!(
                    "Operation::At {{ stage: {}, el: {}, access: {}, address: {operand} }}",
                    need("Stage")?,
                    need("el")?,
                    need("AtAccess")?
                ),
                "AArch64_DC" => format!(
                    "Operation::Dc {{ kind: {}, op: {}, scope: {}, operand: {operand} }}",
                    need("CacheType")?,
                    need("CacheOp")?,
                    need("CacheScope")?
                ),
                "AArch64_IC" => format!(
                    "Operation::Ic {{ scope: {}, operand: {operand} }}",
                    need("CacheScope")?
                ),
                "AArch64_MemZero" => format!(
                    "Operation::ZeroBlock {{ kind: {}, address: {operand} }}",
                    need("CacheType")?
                ),
                "AArch64_RestrictPrediction" => format!(
                    "Operation::RestrictPrediction {{ kind: {}, context: {operand} }}",
                    need("Restrict")?
                ),
                _ => return Ok(None),
            }
        };
        Ok(Some(format!(
            "{{ let operation = {code}; c.operation(operation)?; }}"
        )))
    }

    fn statement(&mut self, node: &Value, out: &mut String, indent: &str) -> Result<bool> {
        let kind = node["_type"].as_str().unwrap_or("");
        if kind == "AST.Return" {
            writeln!(out, "{indent}return Ok(Effect::Done);")?;
            return Ok(true);
        }
        if kind == "AST.Function" {
            let name = node["name"].as_str().unwrap_or("");
            let arguments: Vec<&Value> =
                node["arguments"].as_array().into_iter().flatten().collect();
            let code = match name {
                "Undefined" => "return Ok(Effect::Undefined);".to_owned(),
                "ExecuteAsNOP" => "return Ok(Effect::Done);".to_owned(),
                "AArch64_SystemAccessTrap" => {
                    let el = self.int(arguments[0])?;
                    let ec = self.int(arguments[1])?;
                    format!("return Ok(Effect::Trap {{ el: {el} as u8, ec: {ec} }});")
                }
                "AArch64_SystemAccessTraptoEL1orEL2" => {
                    let ec = self.int(arguments[0])?;
                    format!("return Ok(trap_el1_or_el2(c, {ec}));")
                }
                "UnimplementedIDRegister" if self.profile.features.contains("FEAT_IDST") => {
                    "return Ok(unimplemented_id_register(c));".to_owned()
                }
                "UnimplementedIDRegister" => "return Ok(Effect::Undefined);".to_owned(),
                "AArch64_ImpDefSysRegRead" | "AArch64_ImpDefSysInstrWithResult" => {
                    "return c.implementation_defined(true);".to_owned()
                }
                "AArch64_ImpDefSysRegWrite" | "AArch64_ImpDefSysInstr" => {
                    "return c.implementation_defined(false);".to_owned()
                }
                "Write_DBGDTR_EL0" => {
                    let width = node["parameters"][0]["value"].as_u64().unwrap_or(64);
                    let (value, _) = self.bits(arguments[0])?;
                    format!("{{ let value = {value}; c.write_dbgdtr({width}, value)?; }}")
                }
                "Halt" => "return Ok(Effect::Refused(\"halting debug\"));".to_owned(),
                _ => match self.operation(node)? {
                    Some(code) => code,
                    None => {
                        self.unknown.insert(format!("statement {name}"));
                        format!(
                            "return Ok(c.missing_effect({:?}));",
                            format!("statement {name}")
                        )
                    }
                },
            };
            writeln!(out, "{indent}{code}")?;
            return Ok(code.starts_with("return"));
        }
        if kind == "AST.Assignment" {
            let (value, _) = self.bits(&node["val"])?;
            let target = &node["var"];
            let code = match target["_type"].as_str().unwrap_or("") {
                "AST.Function" if target["name"] == "X" => {
                    format!("{{ let value = {value}; c.set_x(value); }}")
                }
                "AST.Function" if target["name"] == "NVMem" => {
                    let offset = self.int(&target["arguments"][0])?;
                    format!("{{ let value = {value}; c.set_nv_mem({offset}, value)?; }}")
                }
                "AST.Function" if error_record(target["name"].as_str().unwrap_or("")).is_some() => {
                    let record = error_record(target["name"].as_str().unwrap_or("")).unwrap_or("");
                    let index = match target["arguments"].get(0) {
                        Some(index) => self.int(index)?,
                        None => "0".into(),
                    };
                    format!(
                        "{{ let value = {value}; c.set_error_record(ErrorRecord::{record}, {index}, value)?; }}"
                    )
                }
                "AST.Function" => {
                    let register = target["name"].as_str().unwrap_or("");
                    let rust = rust_name(register);
                    if !self.registers.contains(&rust) {
                        self.unknown.insert(format!("register {register}"));
                        format!(
                            "return Ok(c.missing_effect({:?}));",
                            format!("register {register}")
                        )
                    } else {
                        let index = match target["arguments"].get(0) {
                            Some(index) => self.int(index)?,
                            None => "0".into(),
                        };
                        format!(
                            "{{ let value = {value}; c.write(Register::{rust}, {index}, value)?; }}"
                        )
                    }
                }
                "AST.SquareOp" => {
                    let inner = &target["var"];
                    let register = inner["name"].as_str().unwrap_or("");
                    let slice = &target["arguments"][0];
                    let high = slice["left"]["value"].as_u64().context("slice")?;
                    let low = slice["right"]["value"].as_u64().context("slice")?;
                    let rust = rust_name(register);
                    if high == 63 && low == 0 {
                        format!("{{ let value = {value}; c.write(Register::{rust}, 0, value)?; }}")
                    } else {
                        let width = high - low + 1;
                        format!(
                            "{{ let old = c.read(Register::{rust}, 0); \
                             let value = insert(old, {low}, {width}, {value}); \
                             c.write(Register::{rust}, 0, value)?; }}"
                        )
                    }
                }
                "AST.DotAtom" => {
                    let field = target["values"][1]["value"].as_str().unwrap_or("");
                    format!("{{ let value = {value}; c.set_pstate(Pstate::{field}, value); }}")
                }
                "AST.Concat" => {
                    let parts: Vec<&str> = target["values"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|part| part["values"][1]["value"].as_str().unwrap_or("?"))
                        .collect();
                    let count = parts.len();
                    let mut code = format!("{{ let v = {value}; ");
                    for (position, field) in parts.iter().enumerate() {
                        let shift = count - 1 - position;
                        write!(code, "c.set_pstate(Pstate::{field}, (v >> {shift}) & 1); ")?;
                    }
                    code.push('}');
                    code
                }
                other => bail!("unsupported assignment target {other}"),
            };
            writeln!(out, "{indent}{code}")?;
            return Ok(code.starts_with("return"));
        }
        bail!("unsupported statement {}", super::render(node))
    }

    pub fn tree(&mut self, node: &Tree, out: &mut String, indent: &str) -> Result<bool> {
        match node {
            Tree::Leaf(statements) => {
                for statement in statements {
                    if self.statement(statement, out, indent)? {
                        return Ok(true);
                    }
                }
                writeln!(out, "{indent}return Ok(Effect::Done);")?;
                Ok(true)
            }
            Tree::Choice(choices) => {
                for (condition, subtree) in choices {
                    if as_bool(condition) == Some(true) {
                        return self.tree(subtree, out, indent);
                    }
                    let code = self.condition(condition)?;
                    writeln!(out, "{indent}if {code} {{")?;
                    self.tree(subtree, out, &format!("{indent}    "))?;
                    writeln!(out, "{indent}}}")?;
                }
                Ok(false)
            }
        }
    }
}

/// RAS error record registers (memory-mapped `ERR<n>*`), reached through the
/// ERX*_EL1 window.
fn error_record(name: &str) -> Option<&'static str> {
    Some(match name {
        "ERRADDR" => "Addr",
        "ERRCTLR" => "Ctlr",
        "ERRFR" => "Fr",
        "ERRMISC0" => "Misc0",
        "ERRMISC1" => "Misc1",
        "ERRMISC2" => "Misc2",
        "ERRMISC3" => "Misc3",
        "ERRPFGCDN" => "Pfgcdn",
        "ERRPFGCTL" => "Pfgctl",
        "ERRPFGF" => "Pfgf",
        "ERRSTATUS" => "Status",
        _ => return None,
    })
}

fn is_register_name(name: &str) -> bool {
    name.ends_with("_EL0")
        || name.ends_with("_EL1")
        || name.ends_with("_EL2")
        || name.ends_with("_EL12")
        || name.ends_with("_EL02")
        || name.starts_with("ERR")
}

/// The accessors of one register: folded trees with their encodings.
pub fn accessors(register: &Value, profile: &Profile) -> Result<Vec<Accessor>> {
    let name = register["name"].as_str().unwrap_or("");
    let mut out = Vec::new();
    for accessor in register["accessors"].as_array().into_iter().flatten() {
        let condition = fold(&accessor["condition"], profile);
        if as_bool(&condition) == Some(false) {
            continue;
        }
        let kind = accessor["name"]
            .as_str()
            .unwrap_or("?")
            .trim_start_matches("A64.")
            .to_owned();
        for instance in accessor["encoding"].as_array().into_iter().flatten() {
            if accessor["access"].is_null() {
                continue;
            }
            out.push(Accessor {
                name: format!("{} {}", kind, instance["asmvalue"].as_str().unwrap_or(name)),
                register: name.to_owned(),
                kind: kind.clone(),
                encoding: encoding(&instance["encodings"])
                    .with_context(|| format!("encoding of {name}: {}", instance["encodings"]))?,
                tree: tree(&accessor["access"], profile),
            });
        }
    }
    Ok(out)
}
