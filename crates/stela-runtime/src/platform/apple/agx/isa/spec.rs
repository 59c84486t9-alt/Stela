//! The shapes of the generated AGX2 tables ([`super::generated`]): Mesa's
//! `isa.py` model of `AGX2.xml`, flattened to statics.
//!
//! An instruction matches when its `exact` bits equal the word's bits under
//! `mask`, with the word cut to the instruction's length (the long length
//! when the length bit is set). Its fields are bit ranges of that word,
//! concatenated in order, least significant first. An operand field is read
//! through its encoding: the first case whose `exact` bits match gives the
//! operand's value and attributes.

use super::generated::{Imm, Mod, Op};

/// `size` bits starting at bit `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub start: u8,
    pub size: u8,
}

/// A field: ranges concatenated, the first one least significant.
pub type Bits = &'static [Range];

/// Extract a field from an instruction word.
pub fn extract(word: u128, bits: &[Range]) -> u64 {
    let mut value = 0u64;
    let mut at = 0;
    for range in bits {
        let part = (word >> range.start) as u64 & ((1u64 << range.size) - 1);
        value |= part << at;
        at += u32::from(range.size);
    }
    value
}

/// Deposit `value` into a field of `word`, the inverse of [`extract`].
/// `None` when the value does not fit the field.
pub fn deposit(word: u128, bits: &[Range], value: u64) -> Option<u128> {
    let total = width(bits);
    if total < 64 && value >> total != 0 {
        return None;
    }
    let mut word = word;
    let mut at = 0;
    for range in bits {
        let mask = (1u128 << range.size) - 1;
        let part = u128::from(value >> at) & mask;
        word = (word & !(mask << range.start)) | part << range.start;
        at += u32::from(range.size);
    }
    Some(word)
}

/// The total width of a field.
pub fn width(bits: &[Range]) -> u32 {
    bits.iter().map(|range| u32::from(range.size)).sum()
}

/// What an encoding case's value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Reg,
    Uniform,
    Imm,
    /// An 8-bit minifloat.
    Fimm,
    /// A coefficient register.
    Cf,
    /// A texture state register.
    Ts,
    /// A sampler state register.
    Ss,
}

/// An operand attribute an encoding case sets from bits or as a property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attr {
    Size16,
    Size32,
    Size64,
    /// Components, with 0 meaning 4.
    Count,
    /// A write mask; the component count is its population.
    Mask,
    Cache,
    /// The register hint: 1 none, 2 cache, 3 discard.
    Hint,
    /// Last use (discard).
    Lu,
    Abs,
    Neg,
    Sx,
    /// Zero extension, the inverse of `Sx`.
    Zx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseValue {
    pub kind: ValueKind,
    pub bits: Bits,
    /// Left shift applied to the extracted value.
    pub shift: u8,
    /// Sign-extend the shifted value from the field's width.
    pub signed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseModifier {
    pub attr: Attr,
    pub bits: Bits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseProperty {
    pub attr: Attr,
    pub value: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Case {
    pub mask: u64,
    pub exact: u64,
    /// `None` when the case is the absent operand.
    pub value: Option<CaseValue>,
    pub modifiers: &'static [CaseModifier],
    pub properties: &'static [CaseProperty],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Encoding {
    pub name: &'static str,
    pub cases: &'static [Case],
}

/// An enumeration's values and their display text (empty for the default).
#[derive(Debug, PartialEq, Eq)]
pub struct Enum {
    pub kind: &'static str,
    pub values: &'static [(u32, &'static str)],
}

impl Enum {
    /// The display text of `value`, `None` when the enumeration lacks it.
    pub fn display(&self, value: u32) -> Option<&'static str> {
        self.values
            .iter()
            .find(|(v, _)| *v == value)
            .map(|(_, text)| *text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperandSpec {
    pub encoding: &'static Encoding,
    pub bits: Bits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImmediateSpec {
    pub name: Imm,
    pub signed: bool,
    pub bits: Bits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifierSpec {
    pub name: Mod,
    pub display: &'static str,
    /// The enumeration the value names, `None` for a plain flag or number.
    pub kind: Option<&'static Enum>,
    pub bits: Bits,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Instruction {
    pub op: Op,
    pub display: &'static str,
    /// No operands, immediates or modifiers.
    pub trivial: bool,
    pub length_bit: u8,
    /// Short and long lengths in bytes (equal for one-length forms).
    pub short: u8,
    pub long: u8,
    pub mask: u128,
    pub exact: u128,
    /// Every bit some field or exact range names.
    pub known: u128,
    pub dests: &'static [OperandSpec],
    pub sources: &'static [OperandSpec],
    pub immediates: &'static [ImmediateSpec],
    pub modifiers: &'static [ModifierSpec],
}
