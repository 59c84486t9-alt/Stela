//! A test assembler: Mesa's disassembly text back to bytes, through the same
//! generated tables. Each candidate form with the line's display name is
//! tried in description order; operands are encoded case by case and the
//! result is accepted only when it disassembles to the same text, so the
//! assembler can never produce a word the decoder reads differently.

use super::decode::{Operand, Value, decode};
use super::disasm::disassemble;
use super::float::minifloat;
use super::generated::{INSTRUCTIONS, Mod};
use super::spec::{Attr, Instruction, OperandSpec, Range, ValueKind, deposit, width};
use alloc::string::String;
use alloc::vec::Vec;

/// Assemble one line of Mesa text.
pub fn line(text: &str) -> Result<Vec<u8>, String> {
    let text = normalize(text);
    let (display, rest) = text.split_once(' ').unwrap_or((&text, ""));
    let tokens: Vec<&str> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(", ").collect()
    };
    for spec in INSTRUCTIONS.iter().filter(|spec| spec.display == display) {
        let mut found = None;
        search(spec, &tokens, 0, 0, &mut Plan::default(), &mut |plan| {
            if found.is_none() {
                found = encode(spec, plan, &text);
            }
        });
        if let Some(bytes) = found {
            return Ok(bytes);
        }
    }
    Err(alloc::format!("cannot assemble {text:?}"))
}

/// Assemble a program, one instruction per line (blank lines and `#`
/// comments skipped).
pub fn program(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line_text in text.lines() {
        let line_text = line_text.split('#').next().unwrap().trim();
        if line_text.is_empty() {
            continue;
        }
        out.extend(line(line_text).unwrap_or_else(|e| panic!("{e}")));
    }
    out
}

fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Operand texts (or absence) and modifier values chosen for one form.
#[derive(Default, Clone)]
struct Plan<'a> {
    dests: Vec<Option<&'a str>>,
    sources: Vec<Option<&'a str>>,
    immediates: Vec<i64>,
    modifiers: Vec<u32>,
}

/// Enumerate the ways `tokens` fill `spec`'s fields, in print order.
fn search<'a>(
    spec: &Instruction,
    tokens: &[&'a str],
    stage: usize,
    at: usize,
    plan: &mut Plan<'a>,
    visit: &mut dyn FnMut(&Plan<'a>),
) {
    let dests = spec.dests.len();
    let sources = spec.sources.len();
    let immediates = spec.immediates.len();
    if stage < dests {
        let token = tokens.get(at).copied();
        if let Some(token) = token {
            plan.dests.push((token != "_").then_some(token));
            search(spec, tokens, stage + 1, at + 1, plan, visit);
            plan.dests.pop();
        }
    } else if stage < dests + sources {
        if let Some(&token) = tokens.get(at) {
            plan.sources.push(Some(token));
            search(spec, tokens, stage + 1, at + 1, plan, visit);
            plan.sources.pop();
        }
        plan.sources.push(None);
        search(spec, tokens, stage + 1, at, plan, visit);
        plan.sources.pop();
    } else if stage < dests + sources + immediates {
        if let Some(value) = tokens.get(at).and_then(|t| t.parse::<i64>().ok()) {
            plan.immediates.push(value);
            search(spec, tokens, stage + 1, at + 1, plan, visit);
            plan.immediates.pop();
        }
    } else {
        let index = stage - dests - sources - immediates;
        let Some(modifier) = spec.modifiers.get(index) else {
            if at == tokens.len() {
                visit(plan);
            }
            return;
        };
        if modifier.name == Mod::Length {
            plan.modifiers.push(0);
            search(spec, tokens, stage + 1, at, plan, visit);
            plan.modifiers.pop();
            return;
        }
        let token = tokens.get(at).copied();
        match modifier.kind {
            Some(kind) => {
                for &(value, text) in kind.values {
                    let consumes = !text.is_empty();
                    if consumes && token != Some(text) {
                        continue;
                    }
                    plan.modifiers.push(value);
                    search(spec, tokens, stage + 1, at + consumes as usize, plan, visit);
                    plan.modifiers.pop();
                }
            }
            None => {
                if token == Some(modifier.display) {
                    plan.modifiers.push(1);
                    search(spec, tokens, stage + 1, at + 1, plan, visit);
                    plan.modifiers.pop();
                }
                plan.modifiers.push(0);
                search(spec, tokens, stage + 1, at, plan, visit);
                plan.modifiers.pop();
            }
        }
    }
}

/// Encode a plan; `None` unless the word disassembles back to `text`.
fn encode(spec: &Instruction, plan: &Plan<'_>, text: &str) -> Option<Vec<u8>> {
    let mut word = spec.exact;
    for (field, token) in spec.dests.iter().zip(&plan.dests) {
        word = operand_field(spec, field, *token, word)?;
    }
    for (field, token) in spec.sources.iter().zip(&plan.sources) {
        word = operand_field(spec, field, *token, word)?;
    }
    for (immediate, &value) in spec.immediates.iter().zip(&plan.immediates) {
        let width = width(immediate.bits);
        let raw = if width < 64 {
            value as u64 & ((1 << width) - 1)
        } else {
            value as u64
        };
        word = deposit(word, immediate.bits, raw)?;
    }
    for (modifier, &value) in spec.modifiers.iter().zip(&plan.modifiers) {
        if modifier.name != Mod::Length {
            word = deposit(word, modifier.bits, u64::from(value))?;
        }
    }
    let lengths: &[(u8, bool)] = if spec.short == spec.long {
        &[(spec.short, false)]
    } else {
        &[(spec.short, false), (spec.long, true)]
    };
    for &(len, long) in lengths {
        let mut candidate = word;
        if spec.short != spec.long {
            candidate = deposit(
                candidate,
                &[Range {
                    start: spec.length_bit,
                    size: 1,
                }],
                u64::from(long),
            )?;
        }
        if usize::from(len) < 16 && candidate >> (u32::from(len) * 8) != 0 {
            continue;
        }
        let bytes = candidate.to_le_bytes()[..usize::from(len)].to_vec();
        if let Ok(instr) = decode(&bytes)
            && instr.len == bytes.len()
            && matches!(disassemble(&instr), (got, false) if normalize(&got) == text)
        {
            return Some(bytes);
        }
    }
    None
}

/// Encode one operand token into its field of `word`. Only the bits the
/// chosen case names are written, since a field may share a bit with another
/// operand's (`csel`'s two compare operands share their `size32` bit).
fn operand_field(
    spec: &Instruction,
    field: &OperandSpec,
    token: Option<&str>,
    word: u128,
) -> Option<u128> {
    let want = match token {
        Some(token) => parse_operand(token)?,
        None => Operand::default(),
    };
    for case in field.encoding.cases {
        let mut value = u128::from(case.exact);
        let mut care = u128::from(case.mask);
        match (case.value, want.value) {
            (None, Value::None) => {}
            (Some(spec_value), got) => {
                let (kind, raw) = match got {
                    Value::Reg(r) => (ValueKind::Reg, i64::from(r)),
                    Value::Uniform(r) => (ValueKind::Uniform, i64::from(r)),
                    Value::Imm(v) => (ValueKind::Imm, v),
                    Value::Fimm(v) => (ValueKind::Fimm, i64::from(v)),
                    Value::Cf(v) => (ValueKind::Cf, i64::from(v)),
                    Value::Ts(v) => (ValueKind::Ts, i64::from(v)),
                    Value::Ss(v) => (ValueKind::Ss, i64::from(v)),
                    Value::None => continue,
                };
                if kind != spec_value.kind || raw & ((1 << spec_value.shift) - 1) != 0 {
                    continue;
                }
                let bits_wide = width(spec_value.bits);
                let bits = (raw >> spec_value.shift) as u64 & ((1u64 << bits_wide) - 1);
                value = deposit(value, spec_value.bits, bits)?;
                care = deposit(care, spec_value.bits, (1u64 << bits_wide) - 1)?;
            }
            _ => continue,
        }
        // Each attribute's acceptable values, in preference order.
        let choices: Vec<(&[Range], Vec<u64>)> = case
            .modifiers
            .iter()
            .map(|modifier| {
                let values = match modifier.attr {
                    Attr::Cache => alloc::vec![u64::from(want.cache)],
                    Attr::Hint if want.cached() => alloc::vec![2],
                    Attr::Hint if want.last_use() => alloc::vec![3],
                    Attr::Hint => alloc::vec![1],
                    Attr::Lu => alloc::vec![u64::from(want.lu)],
                    Attr::Abs => alloc::vec![u64::from(want.abs)],
                    Attr::Neg => alloc::vec![u64::from(want.neg)],
                    Attr::Sx => alloc::vec![u64::from(want.sx)],
                    Attr::Zx => alloc::vec![u64::from(!want.sx)],
                    // A 64-bit size wins over the 32-bit bit, which is then
                    // free; Mesa's own encodings set both.
                    Attr::Size32 if want.size == 64 => alloc::vec![1, 0],
                    Attr::Size32 => alloc::vec![u64::from(want.size == 32)],
                    Attr::Size64 => alloc::vec![u64::from(want.size == 64)],
                    Attr::Size16 => alloc::vec![0],
                    Attr::Count => alloc::vec![u64::from(want.count) & 3],
                    Attr::Mask => alloc::vec![(1u64 << want.count) - 1],
                };
                (modifier.bits, values)
            })
            .collect();
        let combinations: usize = choices.iter().map(|(_, v)| v.len()).product();
        for combination in 0..combinations {
            let mut candidate = value;
            let mut candidate_care = care;
            let mut rest = combination;
            let mut ok = true;
            for (bits, values) in &choices {
                let pick = values[rest % values.len()];
                rest /= values.len();
                match deposit(candidate, bits, pick) {
                    Some(next) => candidate = next,
                    None => ok = false,
                }
                candidate_care = deposit(candidate_care, bits, (1u64 << width(bits)) - 1)?;
            }
            if !ok {
                continue;
            }
            let Ok(got) = Operand::read(spec.op, field, candidate as u64) else {
                continue;
            };
            if !same(&got, &want) {
                continue;
            }
            // An encoding may describe more bits than the field carries;
            // the ones past it read as zero.
            let field_mask = (1u128 << width(field.bits)) - 1;
            if candidate & !field_mask != 0 {
                continue;
            }
            let mask = deposit(0, field.bits, (candidate_care & field_mask) as u64)?;
            let placed = deposit(0, field.bits, candidate as u64)?;
            return Some(word & !mask | placed);
        }
    }
    None
}

/// Equal as Mesa prints them: registers and uniforms also by size and
/// component count.
fn same(got: &Operand, want: &Operand) -> bool {
    let registers = matches!(got.value, Value::Reg(_) | Value::Uniform(_));
    got.value == want.value
        && (!registers || (got.size == want.size && got.count == want.count))
        && got.abs == want.abs
        && got.neg == want.neg
        && got.sx == want.sx
        && got.cached() == want.cached()
        && got.last_use() == want.last_use()
}

/// Parse Mesa's operand text.
fn parse_operand(token: &str) -> Option<Operand> {
    let mut operand = Operand {
        size: 16,
        count: 1,
        ..Operand::default()
    };
    let mut rest = token;
    if let Some(r) = rest.strip_prefix('^') {
        operand.lu = true;
        rest = r;
    }
    if let Some(r) = rest.strip_prefix('$') {
        operand.cache = true;
        rest = r;
    }
    loop {
        if let Some(r) = rest.strip_suffix(".sx") {
            operand.sx = true;
            rest = r;
        } else if let Some(r) = rest.strip_suffix(".neg") {
            operand.neg = true;
            rest = r;
        } else if let Some(r) = rest.strip_suffix(".abs") {
            operand.abs = true;
            rest = r;
        } else {
            break;
        }
    }
    if let Ok(value) = rest.parse::<i64>() {
        operand.value = Value::Imm(value);
        return Some(operand);
    }
    if rest.contains('.') {
        let wanted: f32 = rest.parse().ok()?;
        let byte = (0..=255u8).find(|&b| {
            let f = minifloat(b);
            f.to_bits() == wanted.to_bits()
        })?;
        operand.value = Value::Fimm(byte);
        return Some(operand);
    }
    for (prefix, make) in [
        ("cf", Value::Cf as fn(u16) -> Value),
        ("ts", Value::Ts),
        ("ss", Value::Ss),
    ] {
        if let Some(n) = rest.strip_prefix(prefix).and_then(|n| n.parse().ok()) {
            operand.value = make(n);
            return Some(operand);
        }
    }
    let parts: Vec<&str> = rest.split('_').collect();
    let mut first = None;
    for part in &parts {
        let (uniform, size, body) = if let Some(b) = part.strip_prefix("dr") {
            (false, 64, b)
        } else if let Some(b) = part.strip_prefix("du") {
            (true, 64, b)
        } else if let Some(b) = part.strip_prefix('r') {
            (false, 0, b)
        } else {
            (true, 0, part.strip_prefix('u')?)
        };
        let (size, index) = if size == 64 {
            (64, body.parse::<u16>().ok()? * 2)
        } else if let Some(n) = body.strip_suffix('l') {
            (16, n.parse::<u16>().ok()? * 2)
        } else if let Some(n) = body.strip_suffix('h') {
            (16, n.parse::<u16>().ok()? * 2 + 1)
        } else {
            (32, body.parse::<u16>().ok()? * 2)
        };
        if first.is_none() {
            first = Some((uniform, size, index));
        }
    }
    let (uniform, size, index) = first?;
    operand.size = size;
    operand.count = parts.len() as u8;
    operand.value = if uniform {
        Value::Uniform(index)
    } else {
        Value::Reg(index)
    };
    Some(operand)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mesa_vector_reassembles_to_the_same_text() {
        let mut failures = Vec::new();
        for text_line in include_str!("cases.txt").lines() {
            let Some((_, text)) = text_line.split_once(' ') else {
                continue;
            };
            let text = text.trim();
            match line(text) {
                Ok(bytes) => {
                    let (again, _) = disassemble(&decode(&bytes).unwrap());
                    if normalize(&again) != normalize(text) {
                        failures.push(alloc::format!("{text}: {again}"));
                    }
                }
                Err(error) => failures.push(error),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
