//! FCMP/FCCMP and AdvSIMD FCMEQ/FCMGE/FCMGT/FACGE/FACGT.
use crate::aarch64::floating::{Format, comparison::Predicate};

use super::arithmetic::Shape;

const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const VECTOR_Q: u32 = 1 << 30;
const SIMD_DOUBLE: u32 = 1 << 22;
const SIMD_SCALAR_PREFIX: u32 = 0x50000000;
const HALF_REGISTER_ADJUSTMENT: u32 = 0x0060c000;
const HALF_ZERO_ADJUSTMENT: u32 = 0x00580000;

const FLAGS_MASK: u32 = 0xff20fc07;
const FCMP: u32 = 0x1e202000;
const SIGNAL_ALL_NANS: u32 = 1 << 4;
const COMPARE_ZERO: u32 = 1 << 3;
const CONDITIONAL_MASK: u32 = 0xff200c00;
const FCCMP: u32 = 0x1e200400;
const CONDITION_SHIFT: u32 = 12;
const NZCV_MASK: u32 = 15;

const REGISTER_SCALAR_MASK: u32 = 0xffa0fc00;
const REGISTER_VECTOR_MASK: u32 = 0xbfa0fc00;
const REGISTER_SCALAR_HALF_MASK: u32 = 0xffe0fc00;
const REGISTER_VECTOR_HALF_MASK: u32 = 0xbfe0fc00;
const FCMEQ: u32 = 0x0e20e400;
const FCMGE: u32 = 0x2e20e400;
const FCMGT: u32 = 0x2ea0e400;
const FACGE: u32 = 0x2e20ec00;
const FACGT: u32 = 0x2ea0ec00;

const ZERO_SCALAR_MASK: u32 = 0xffbffc00;
const ZERO_VECTOR_MASK: u32 = 0xbfbffc00;
const ZERO_SCALAR_HALF_MASK: u32 = 0xfffffc00;
const ZERO_VECTOR_HALF_MASK: u32 = 0xbffffc00;
const FCMEQ_ZERO: u32 = 0x0ea0d800;
const FCMGE_ZERO: u32 = 0x2ea0c800;
const FCMGT_ZERO: u32 = 0x0ea0c800;
const FCMLE_ZERO: u32 = 0x2ea0d800;
const FCMLT_ZERO: u32 = 0x0ea0e800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareSource {
    Register(u8),
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Flags {
        format: Format,
        left: u8,
        right: CompareSource,
        signal_all_nans: bool,
    },
    ConditionalFlags {
        format: Format,
        left: u8,
        right: u8,
        signal_all_nans: bool,
        condition: u8,
        fallback: u8,
    },
    Predicate {
        operation: Predicate,
        format: Format,
        shape: Shape,
        destination: u8,
        left: u8,
        right: CompareSource,
    },
}

impl Operand {
    pub const fn format(self) -> Format {
        match self {
            Self::Flags { format, .. }
            | Self::ConditionalFlags { format, .. }
            | Self::Predicate { format, .. } => format,
        }
    }
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn scalar_format(word: u32) -> Result<Format, ()> {
    match (word >> FORMAT_SHIFT) & FORMAT_MASK {
        FORMAT_SINGLE => Ok(Format::Single),
        FORMAT_DOUBLE => Ok(Format::Double),
        FORMAT_HALF => Ok(Format::Half),
        _ => Err(()),
    }
}

/// None denotes another family; Err denotes reserved scalar ftype or vector1D.
/// Every register field is an ordinary V register, including V31. The Rm field
/// remains unconstrained and ignored in FCMP/FCMPE zero encodings.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & FLAGS_MASK == FCMP {
        return Some(scalar_format(word).map(|format| Operand::Flags {
            format,
            left: register(word, LEFT_SHIFT),
            right: if word & COMPARE_ZERO == 0 {
                CompareSource::Register(register(word, RIGHT_SHIFT))
            } else {
                CompareSource::Zero
            },
            signal_all_nans: word & SIGNAL_ALL_NANS != 0,
        }));
    }
    if word & CONDITIONAL_MASK == FCCMP {
        return Some(scalar_format(word).map(|format| Operand::ConditionalFlags {
            format,
            left: register(word, LEFT_SHIFT),
            right: register(word, RIGHT_SHIFT),
            signal_all_nans: word & SIGNAL_ALL_NANS != 0,
            condition: ((word >> CONDITION_SHIFT) & NZCV_MASK) as u8,
            fallback: (word & NZCV_MASK) as u8,
        }));
    }
    decode_predicate(word, false).or_else(|| decode_predicate(word, true))
}

fn predicate(opcode: u32, zero: bool) -> Option<Predicate> {
    Some(match (opcode, zero) {
        (FCMEQ, false) | (FCMEQ_ZERO, true) => Predicate::Equal,
        (FCMGE, false) | (FCMGE_ZERO, true) => Predicate::GreaterEqual,
        (FCMGT, false) | (FCMGT_ZERO, true) => Predicate::Greater,
        (FACGE, false) => Predicate::AbsoluteGreaterEqual,
        (FACGT, false) => Predicate::AbsoluteGreater,
        (FCMLE_ZERO, true) => Predicate::LessEqual,
        (FCMLT_ZERO, true) => Predicate::Less,
        _ => return None,
    })
}

fn decode_predicate(word: u32, zero: bool) -> Option<Result<Operand, ()>> {
    let (scalar_mask, vector_mask, scalar_half_mask, vector_half_mask, half_adjustment) = if zero {
        (
            ZERO_SCALAR_MASK,
            ZERO_VECTOR_MASK,
            ZERO_SCALAR_HALF_MASK,
            ZERO_VECTOR_HALF_MASK,
            HALF_ZERO_ADJUSTMENT,
        )
    } else {
        (
            REGISTER_SCALAR_MASK,
            REGISTER_VECTOR_MASK,
            REGISTER_SCALAR_HALF_MASK,
            REGISTER_VECTOR_HALF_MASK,
            HALF_REGISTER_ADJUSTMENT,
        )
    };
    for (mask, adjustment, scalar, half) in [
        (scalar_mask, SIMD_SCALAR_PREFIX, true, false),
        (vector_mask, 0, false, false),
        (
            scalar_half_mask,
            SIMD_SCALAR_PREFIX | half_adjustment,
            true,
            true,
        ),
        (vector_half_mask, half_adjustment, false, true),
    ] {
        let Some(operation) = predicate((word & mask) ^ adjustment, zero) else {
            continue;
        };
        let format = if half {
            Format::Half
        } else if word & SIMD_DOUBLE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        let shape = if scalar {
            Shape::Scalar
        } else if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        };
        if format == Format::Double && shape == Shape::Vector64 {
            return Some(Err(()));
        }
        return Some(Ok(Operand::Predicate {
            operation,
            format,
            shape,
            destination: register(word, 0),
            left: register(word, LEFT_SHIFT),
            right: if zero {
                CompareSource::Zero
            } else {
                CompareSource::Register(register(word, RIGHT_SHIFT))
            },
        }));
    }
    None
}

#[cfg(test)]
mod tests;
