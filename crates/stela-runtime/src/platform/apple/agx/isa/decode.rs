//! The table-driven AGX2 decoder: match an instruction against the generated
//! description ([`super::generated::INSTRUCTIONS`], in its order), cut the
//! word to the matched length, and read every field and operand.
//!
//! The rules are Mesa's (`disasm-internal.h`, `_disassemble_instr`): the
//! first instruction whose exact bits match wins, the length bit selects the
//! long form, and an operand's encoding is read case by case. Mesa prints a
//! word with bits no field names, an operand no case matches or an
//! enumeration value the description lacks as an error; the decoder refuses
//! each, so nothing the description does not define reaches execution.

use super::generated::{INSTRUCTIONS, Imm, Mod, Op};
use super::spec::{Attr, Instruction, OperandSpec, ValueKind, extract, width};

/// The longest instruction, in bytes.
pub const MAX_BYTES: usize = 16;
/// Most destinations and sources of one instruction.
const MAX_DESTS: usize = 1;
const MAX_SOURCES: usize = 6;

/// Why a word does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// No instruction of the description matches.
    Unmatched,
    /// The matched form runs past the end of the code.
    Truncated,
    /// The word sets bits no field of the matched instruction names.
    UnknownBits(Op),
    /// No case of the operand's encoding matches its field.
    Operand(Op, &'static str),
    /// A modifier names a value its enumeration lacks.
    Enumeration(Op, Mod),
}

/// An operand's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Value {
    /// The operand is absent (an encoding case without a value).
    #[default]
    None,
    /// A register, as a 16-bit-half index.
    Reg(u16),
    /// A uniform, as a 16-bit-half index.
    Uniform(u16),
    Imm(i64),
    /// An 8-bit minifloat.
    Fimm(u8),
    Cf(u16),
    Ts(u16),
    Ss(u16),
}

/// A decoded operand, with the attributes Mesa's printer reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Operand {
    pub value: Value,
    /// 16, 32 or 64 bits per component.
    pub size: u8,
    /// Components (at least 1).
    pub count: u8,
    /// A write mask, when the encoding carries one.
    pub mask: Option<u8>,
    /// The register hint (1 none, 2 cache, 3 discard), `None` when the
    /// encoding has none.
    pub hint: Option<u8>,
    pub cache: bool,
    pub lu: bool,
    pub abs: bool,
    pub neg: bool,
    pub sx: bool,
}

impl Operand {
    /// Read `field` through `spec`'s encoding.
    pub(crate) fn read(op: Op, spec: &OperandSpec, field: u64) -> Result<Self, DecodeError> {
        let encoding = spec.encoding;
        let case = encoding
            .cases
            .iter()
            .find(|case| field & case.mask == case.exact)
            .ok_or(DecodeError::Operand(op, encoding.name))?;
        let mut operand = Operand::default();
        let (mut size32, mut size64, mut count) = (false, false, 0u8);
        if let Some(value) = case.value {
            let raw = extract(u128::from(field), value.bits) << value.shift;
            let bits = width(value.bits) + u32::from(value.shift);
            let signed = if value.signed && bits < 64 {
                ((raw << (64 - bits)) as i64) >> (64 - bits)
            } else {
                raw as i64
            };
            operand.value = match value.kind {
                ValueKind::Reg => Value::Reg(raw as u16),
                ValueKind::Uniform => Value::Uniform(raw as u16),
                ValueKind::Imm => Value::Imm(signed),
                ValueKind::Fimm => Value::Fimm(raw as u8),
                ValueKind::Cf => Value::Cf(raw as u16),
                ValueKind::Ts => Value::Ts(raw as u16),
                ValueKind::Ss => Value::Ss(raw as u16),
            };
        }
        let mut set = |attr: Attr, value: u64, operand: &mut Operand| match attr {
            Attr::Size16 => {}
            Attr::Size32 => size32 = value != 0,
            Attr::Size64 => size64 = value != 0,
            Attr::Count => count = if value == 0 { 4 } else { value as u8 },
            Attr::Mask => {
                operand.mask = Some(value as u8);
                count = value.count_ones() as u8;
            }
            Attr::Cache => operand.cache = value != 0,
            Attr::Hint => operand.hint = Some(value as u8),
            Attr::Lu => operand.lu = value != 0,
            Attr::Abs => operand.abs = value != 0,
            Attr::Neg => operand.neg = value != 0,
            Attr::Sx => operand.sx = value != 0,
            Attr::Zx => operand.sx = value == 0,
        };
        for modifier in case.modifiers {
            set(
                modifier.attr,
                extract(u128::from(field), modifier.bits),
                &mut operand,
            );
        }
        for property in case.properties {
            set(property.attr, u64::from(property.value), &mut operand);
        }
        operand.size = if size64 {
            64
        } else if size32 {
            32
        } else {
            16
        };
        operand.count = count.max(1);
        Ok(operand)
    }

    /// The register hint's cache flag, as Mesa's printer combines them.
    pub fn cached(&self) -> bool {
        self.cache || self.hint == Some(2)
    }

    /// The register hint's last-use flag.
    pub fn last_use(&self) -> bool {
        self.lu || self.hint == Some(3)
    }
}

/// A decoded instruction.
#[derive(Debug, Clone, Copy)]
pub struct Instr {
    pub spec: &'static Instruction,
    /// Bytes.
    pub len: usize,
    /// The word cut to `len` bytes.
    pub word: u128,
    dests: [Operand; MAX_DESTS],
    sources: [Operand; MAX_SOURCES],
}

impl Instr {
    pub fn op(&self) -> Op {
        self.spec.op
    }

    pub fn dest(&self) -> Operand {
        self.dests[0]
    }

    pub fn dests(&self) -> &[Operand] {
        &self.dests[..self.spec.dests.len()]
    }

    pub fn source(&self, index: usize) -> Operand {
        self.sources[index]
    }

    pub fn sources(&self) -> &[Operand] {
        &self.sources[..self.spec.sources.len()]
    }

    /// A modifier's raw value, `None` when the instruction has none of that
    /// name.
    pub fn modifier(&self, name: Mod) -> Option<u32> {
        self.spec
            .modifiers
            .iter()
            .find(|m| m.name == name)
            .map(|m| extract(self.word, m.bits) as u32)
    }

    /// A flag modifier, false when absent.
    pub fn flag(&self, name: Mod) -> bool {
        self.modifier(name).is_some_and(|value| value != 0)
    }

    /// An immediate's value, sign-extended when the description says so.
    pub fn immediate(&self, name: Imm) -> Option<i64> {
        let spec = self.spec.immediates.iter().find(|i| i.name == name)?;
        let raw = extract(self.word, spec.bits);
        let bits = width(spec.bits);
        Some(if spec.signed && bits < 64 {
            ((raw << (64 - bits)) as i64) >> (64 - bits)
        } else {
            raw as i64
        })
    }
}

/// Decode the instruction at the start of `code`.
pub fn decode(code: &[u8]) -> Result<Instr, DecodeError> {
    let mut bytes = [0u8; MAX_BYTES];
    let available = code.len().min(MAX_BYTES);
    bytes[..available].copy_from_slice(&code[..available]);
    let raw = u128::from_le_bytes(bytes);
    for spec in INSTRUCTIONS.iter() {
        let len = usize::from(if raw >> spec.length_bit & 1 != 0 {
            spec.long
        } else {
            spec.short
        });
        let word = if len >= MAX_BYTES {
            raw
        } else {
            raw & ((1u128 << (len * 8)) - 1)
        };
        if word & spec.mask != spec.exact {
            continue;
        }
        if len > code.len() {
            return Err(DecodeError::Truncated);
        }
        if word & !spec.known != 0 {
            return Err(DecodeError::UnknownBits(spec.op));
        }
        let mut instr = Instr {
            spec,
            len,
            word,
            dests: [Operand::default(); MAX_DESTS],
            sources: [Operand::default(); MAX_SOURCES],
        };
        for (slot, operand) in instr.dests.iter_mut().zip(spec.dests) {
            *slot = Operand::read(spec.op, operand, extract(word, operand.bits))?;
        }
        for (slot, operand) in instr.sources.iter_mut().zip(spec.sources) {
            *slot = Operand::read(spec.op, operand, extract(word, operand.bits))?;
        }
        for modifier in spec.modifiers {
            if let Some(kind) = modifier.kind
                && kind.display(extract(word, modifier.bits) as u32).is_none()
            {
                return Err(DecodeError::Enumeration(spec.op, modifier.name));
            }
        }
        return Ok(instr);
    }
    Err(DecodeError::Unmatched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> alloc::vec::Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_first_matching_form_wins_with_its_length() {
        // `stop` (2 bytes) and `fmul r0, $r1, 0.234375` (4 bytes).
        assert_eq!(decode(&hex("8800")).unwrap().op(), Op::Stop);
        let fmul = decode(&hex("1a0182f2")).unwrap();
        assert_eq!((fmul.op(), fmul.len), (Op::Fmul, 4));
        assert_eq!(fmul.dest().value, Value::Reg(0));
        assert_eq!(fmul.dest().size, 32);
        assert_eq!(fmul.source(0).value, Value::Reg(2));
        assert!(fmul.source(0).cached());
        assert_eq!(fmul.source(1).value, Value::Fimm(0x0f));
        // `imul` is listed before `imadd` and claims its zero-addend form.
        let iadd = decode(&hex("0e01402664000000")).unwrap();
        assert_eq!(iadd.op(), Op::Iadd);
        assert!(iadd.source(0).sx && iadd.source(1).sx);
    }

    #[test]
    fn immediates_and_modifiers_read_their_fields() {
        // `jmp_any -634`: a signed 32-bit offset.
        let jump = decode(&hex("00c086fdffff")).unwrap();
        assert_eq!(jump.op(), Op::JmpAny);
        assert_eq!(jump.immediate(Imm::Offset), Some(-634));
        // `load r0_r1_r2_r3, du8, 0, i32, xyzw, a`.
        let load = decode(&hex("0501000d10c0f200")).unwrap();
        assert_eq!(load.op(), Op::Load);
        assert_eq!(load.dest().count, 4);
        assert_eq!(load.dest().mask, Some(0xf));
        assert_eq!(load.source(0).value, Value::Uniform(16));
        assert_eq!(load.source(0).size, 64);
        assert_eq!(load.source(1).value, Value::Imm(0));
        assert_eq!(load.modifier(Mod::Format), Some(2));
        assert_eq!(load.modifier(Mod::Mask), Some(0xf));
        assert_eq!(load.modifier(Mod::Saturate), None);
    }

    #[test]
    fn undefined_words_refuse() {
        assert_eq!(decode(&[0xff, 0xff]).err(), Some(DecodeError::Unmatched));
        assert_eq!(decode(&hex("0e014026")).err(), Some(DecodeError::Truncated));
        // `stop` with a stray bit is no instruction; `wait` with a bit past
        // its group field names no field.
        assert!(decode(&hex("3802")).is_err());
    }
}
