//! FCADD and FCMLA.
use crate::aarch64::floating::{Format, complex::Rotation};

use super::arithmetic::Shape;

const ADD_MASK: u32 = 0xbf20_ec00;
const FCADD: u32 = 0x2e00_e400;
const MULTIPLY_MASK: u32 = 0xbf20_e400;
const FCMLA: u32 = 0x2e00_c400;
const INDEXED_MASK: u32 = 0xbf00_9400;
const INDEXED_FCMLA: u32 = 0x2f00_1000;
const VECTOR_Q: u32 = 1 << 30;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const SIZE_HALF: u32 = 1;
const SIZE_SINGLE: u32 = 2;
const SIZE_DOUBLE: u32 = 3;
const ADD_ROTATION_SHIFT: u32 = 12;
const ADD_ROTATION: u32 = 1 << ADD_ROTATION_SHIFT;
const MULTIPLY_ROTATION_SHIFT: u32 = 11;
const INDEXED_ROTATION_SHIFT: u32 = 13;
const ROTATION_MASK: u32 = 3;
const ROTATION_0: u32 = 0;
const ROTATION_90: u32 = 1;
const ROTATION_180: u32 = 2;
const REGISTER_MASK: u32 = 31;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_BIT_MASK: u32 = 1;
const HALF_PAIR_INDEX_HIGH_SHIFT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Add,
    MultiplyAdd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Vector(u8),
    Indexed { register: u8, index: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub format: Format,
    pub shape: Shape,
    pub rotation: Rotation,
    pub destination: u8,
    pub left: u8,
    pub right: Source,
}

/// None denotes another family; Err denotes reserved size, width or pair index.
/// All register fields, including indexed Half Vm, denote ordinary V0..V31.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (kind, rotation, indexed) = if word & ADD_MASK == FCADD {
        (
            Kind::Add,
            if word & ADD_ROTATION == 0 {
                Rotation::Degrees90
            } else {
                Rotation::Degrees270
            },
            false,
        )
    } else if word & MULTIPLY_MASK == FCMLA {
        (
            Kind::MultiplyAdd,
            rotation(word, MULTIPLY_ROTATION_SHIFT),
            false,
        )
    } else if word & INDEXED_MASK == INDEXED_FCMLA {
        (
            Kind::MultiplyAdd,
            rotation(word, INDEXED_ROTATION_SHIFT),
            true,
        )
    } else {
        return None;
    };
    let shape = if word & VECTOR_Q == 0 {
        Shape::Vector64
    } else {
        Shape::Vector128
    };
    let format = match (word >> SIZE_SHIFT) & SIZE_MASK {
        SIZE_HALF => Format::Half,
        SIZE_SINGLE => Format::Single,
        SIZE_DOUBLE if !indexed && shape == Shape::Vector128 => Format::Double,
        _ => return Some(Err(())),
    };
    let right = register(word, RIGHT_SHIFT);
    let right = if indexed {
        let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
        let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
        // The June indexed FP16 predicate tests size10, despite Half being
        // size01. This decoder's FP16-enabled profile does not resolve or
        // claim disabled-FP16 behavior by silently correcting that source.
        let index = if format == Format::Half {
            if shape == Shape::Vector64 && high != 0 {
                return Some(Err(()));
            }
            (high << HALF_PAIR_INDEX_HIGH_SHIFT) | low
        } else {
            if shape == Shape::Vector64 || low != 0 {
                return Some(Err(()));
            }
            high
        };
        Source::Indexed {
            register: right,
            index: index as u8,
        }
    } else {
        Source::Vector(right)
    };
    Some(Ok(Operand {
        kind,
        format,
        shape,
        rotation,
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
    }))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn rotation(word: u32, shift: u32) -> Rotation {
    match (word >> shift) & ROTATION_MASK {
        ROTATION_0 => Rotation::Degrees0,
        ROTATION_90 => Rotation::Degrees90,
        ROTATION_180 => Rotation::Degrees180,
        _ => Rotation::Degrees270,
    }
}

#[cfg(test)]
mod tests;
