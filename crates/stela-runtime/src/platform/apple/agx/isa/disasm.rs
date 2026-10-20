//! The text form of a decoded AGX2 instruction, exactly as Mesa's
//! disassembler prints it (`disasm-internal.h` `_print_operand`,
//! `print_immediate`, `print_enum`, `print_modifier` and the generated
//! `print_*` functions): the display name padded to eight columns, then the
//! destinations, sources, immediates and modifiers in description order.
//!
//! It is the decoder's oracle: every vector of Mesa's `isa/test/cases.txt`
//! (pinned with the description; Mesa, MIT) must print identically, which
//! checks each instruction's match, length, fields and operand cases. It is
//! also the engine's diagnostic text for refused instructions.

use super::decode::{Instr, Operand, Value};
use super::float::minifloat;
use super::generated::Mod;
use alloc::string::String;
use core::fmt::Write;

/// The text of `instr`, and whether Mesa's printer would flag an error.
pub fn disassemble(instr: &Instr) -> (String, bool) {
    let spec = instr.spec;
    let mut printer = Printer {
        out: String::new(),
        any: false,
        error: false,
    };
    if spec.trivial {
        printer.out.push_str(spec.display);
        return (printer.out, false);
    }
    let _ = write!(printer.out, "{:<8}", spec.display);
    for dest in instr.dests() {
        printer.operand(dest, false);
    }
    for source in instr.sources() {
        printer.operand(source, true);
    }
    for immediate in spec.immediates {
        let value = instr.immediate(immediate.name).unwrap_or(0);
        printer.introduce();
        let _ = if immediate.signed {
            write!(printer.out, "{}", value as i32)
        } else {
            write!(printer.out, "{}", value as u32)
        };
    }
    for modifier in spec.modifiers {
        if modifier.name == Mod::Length {
            continue;
        }
        let value = instr.modifier(modifier.name).unwrap_or(0);
        match modifier.kind {
            Some(kind) => match kind.display(value) {
                None => {
                    printer.introduce();
                    let _ = write!(printer.out, "XXX: Unknown enum value {value}");
                    printer.error = true;
                }
                Some("") => {}
                Some(text) => {
                    printer.introduce();
                    printer.out.push_str(text);
                }
            },
            None if value != 0 => {
                printer.introduce();
                printer.out.push_str(modifier.display);
            }
            None => {}
        }
    }
    (printer.out, printer.error)
}

struct Printer {
    out: String,
    any: bool,
    error: bool,
}

impl Printer {
    fn introduce(&mut self) {
        self.out.push_str(if self.any { ", " } else { " " });
        self.any = true;
    }

    fn operand(&mut self, operand: &Operand, optional: bool) {
        if operand.hint == Some(0) {
            self.out.push_str("# missing hint");
        }
        if operand.value == Value::None {
            if !optional {
                self.introduce();
                self.out.push('_');
            }
            return;
        }
        self.introduce();
        let (cache, lu) = (operand.cached(), operand.last_use());
        if lu && cache {
            self.out.push_str("XXX invalid cache+lu set\n");
            self.error = true;
        }
        if lu {
            self.out.push('^');
        }
        if cache {
            self.out.push('$');
        }
        let size = u32::from(operand.size);
        let (prefix, base) = match operand.value {
            Value::Imm(value) => {
                let _ = write!(self.out, "{}", value as i32);
                (None, 0)
            }
            Value::Fimm(value) => {
                let f = minifloat(value);
                let _ = if f64::from(f) == super::math::trunc(f64::from(f)) {
                    write!(self.out, "{f}.0")
                } else {
                    write!(self.out, "{f}")
                };
                (None, 0)
            }
            Value::Cf(n) | Value::Ts(n) | Value::Ss(n) => {
                let prefix = match operand.value {
                    Value::Cf(_) => "cf",
                    Value::Ts(_) => "ts",
                    _ => "ss",
                };
                let _ = write!(self.out, "{prefix}{n}");
                (None, 0)
            }
            Value::Reg(reg) => (Some(if size == 64 { "dr" } else { "r" }), reg),
            Value::Uniform(reg) => (Some(if size == 64 { "du" } else { "u" }), reg),
            Value::None => unreachable!("absent operands return above"),
        };
        if let Some(prefix) = prefix {
            for i in 0..u32::from(operand.count) {
                if i != 0 {
                    self.out.push('_');
                }
                let reg = u32::from(base) + i * (size / 16);
                let (whole, part) = (reg >> 1, reg & 1);
                if size == 16 {
                    let half = if part == 0 { 'l' } else { 'h' };
                    let _ = write!(self.out, "{prefix}{whole}{half}");
                } else {
                    if part != 0 {
                        let _ = writeln!(self.out, "# 32-bit must be expected, but got raw {reg}");
                        self.error = true;
                    }
                    let _ = write!(self.out, "{prefix}{whole}");
                }
            }
        }
        if operand.abs {
            self.out.push_str(".abs");
        }
        if operand.neg {
            self.out.push_str(".neg");
        }
        if operand.sx {
            self.out.push_str(".sx");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::decode::decode;
    use super::*;
    use alloc::vec::Vec;

    /// Mesa's disassembler vectors: hex bytes, spaces, the expected text.
    const CASES: &str = include_str!("cases.txt");

    #[test]
    fn every_mesa_vector_prints_identically() {
        let mut failures = Vec::new();
        let mut count = 0;
        for line in CASES.lines().filter(|line| !line.trim().is_empty()) {
            let (hex, text) = line.split_once(' ').unwrap();
            let expected = text.trim_start_matches(' ');
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            count += 1;
            match decode(&bytes) {
                Ok(instr) => {
                    let (got, error) = disassemble(&instr);
                    if got != expected || error || instr.len != bytes.len() {
                        failures.push(alloc::format!(
                            "{hex}: got {got:?} ({} bytes{}), expected {expected:?}",
                            instr.len,
                            if error { ", error" } else { "" }
                        ));
                    }
                }
                Err(error) => failures.push(alloc::format!("{hex}: {error:?}")),
            }
        }
        assert!(count > 500, "{count} vectors");
        assert!(
            failures.is_empty(),
            "{} of {count} vectors differ:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
