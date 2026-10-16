//! Predicated deinterleaving LD2/LD3/LD4 transfers, including 128-bit elements.
use super::memory::{Address, Offset, Scale};
use crate::aarch64::{
    register,
    scalable::{
        ElementSize, VECTOR_REGISTER_COUNT,
        execution::{GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements},
    },
};
use alloc::boxed::Box;

const IMMEDIATE_MASK: u32 = 0xfe10_e000;
const IMMEDIATE_CLASS: u32 = 0xa400_e000;
const REGISTER_MASK: u32 = 0xfe00_e000;
const REGISTER_CLASS: u32 = 0xa400_c000;
const QUAD_IMMEDIATE_MASK: u32 = 0xfe70_e000;
const QUAD_IMMEDIATE_CLASS: u32 = 0xa410_e000;
const QUAD_REGISTER_MASK: u32 = 0xfe60_e000;
const QUAD_REGISTER_CLASS: u32 = 0xa420_8000;
const ELEMENT_SHIFT: u32 = 23;
const ELEMENT_MASK: u32 = 3;
const QUADWORD_SHIFT: u32 = ElementSize::Quadword.bytes().trailing_zeros();
const TUPLE_SHIFT: u32 = 21;
const QUAD_TUPLE_SHIFT: u32 = 23;
const TUPLE_MASK: u32 = 3;
const REGISTER_BITS: u32 = 5;
const REGISTER_FIELD_MASK: u32 = (1 << REGISTER_BITS) - 1;
const OFFSET_SHIFT: u32 = 16;
const IMMEDIATE_BITS: u32 = 4;
const IMMEDIATE_FIELD_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const IMMEDIATE_SIGN_SHIFT: u32 = i8::BITS - IMMEDIATE_BITS;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_BITS: u32 = 3;
const PREDICATE_MASK: u32 = (1 << PREDICATE_BITS) - 1;
const BASE_SHIFT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub registers: u8,
    pub predicate: u8,
    pub address: Address,
    pub element: ElementSize,
}

impl Operand {
    pub const fn destination_register(self, tuple_index: u8) -> u8 {
        (self.destination + tuple_index) % VECTOR_REGISTER_COUNT
    }

    /// Q forms need FEAT_SVE2p1 or FEAT_SME2p1; the common dispatch checks mode.
    pub const fn requires_sve2p1_or_sme2p1(self) -> bool {
        matches!(self.element, ElementSize::Quadword)
    }
}

/// Tuple writes happen only after every active element read has completed.
/// Predicates select bit `element_index * element_bytes`; inactive lanes zero.
/// Base31 denotes SP. Register-offset forms always enable architectural tag
/// checks, whereas immediate-offset forms enable them only for a GPR base.
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (immediate, quadword) = match word {
        _ if word & IMMEDIATE_MASK == IMMEDIATE_CLASS => (true, false),
        _ if word & REGISTER_MASK == REGISTER_CLASS => (false, false),
        _ if word & QUAD_IMMEDIATE_MASK == QUAD_IMMEDIATE_CLASS => (true, true),
        _ if word & QUAD_REGISTER_MASK == QUAD_REGISTER_CLASS => (false, true),
        _ => return None,
    };
    let tuple_shift = if quadword {
        QUAD_TUPLE_SHIFT
    } else {
        TUPLE_SHIFT
    };
    let tuple = ((word >> tuple_shift) & TUPLE_MASK) as u8;
    if tuple == 0 {
        return None;
    }
    let registers = tuple + 1;
    let element_shift = if quadword {
        QUADWORD_SHIFT
    } else {
        (word >> ELEMENT_SHIFT) & ELEMENT_MASK
    };
    let element = ElementSize::from_bytes(1 << element_shift)?;
    let offset = if immediate {
        let raw = ((word >> OFFSET_SHIFT) & IMMEDIATE_FIELD_MASK) as i8;
        Offset::Immediate {
            value: i16::from((raw << IMMEDIATE_SIGN_SHIFT) >> IMMEDIATE_SIGN_SHIFT),
            scale: Scale::VectorBytes {
                multiply: registers,
                divide: 1,
            },
        }
    } else {
        let index = (word >> OFFSET_SHIFT) & REGISTER_FIELD_MASK;
        if index == REGISTER_FIELD_MASK {
            return Some(Err(()));
        }
        Offset::Register {
            index: register(index, false),
            shift: element_shift as u8,
        }
    };
    let address = Address {
        base: register((word >> BASE_SHIFT) & REGISTER_FIELD_MASK, true),
        offset,
    };
    Some(Ok(Operand {
        destination: (word & REGISTER_FIELD_MASK) as u8,
        registers,
        predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
        address,
        element,
    }))
}

/// All allocated structured-load forms call exactly CheckSVEEnabled(). Nested
/// checks stay with the common authoritative source-control evaluator.
pub(crate) fn execution_access_requirements(_operand: &Operand) -> ScalableAccessRequirements {
    ScalableAccessRequirements::Known(Box::new([ScalableAccessCheck::SveEnabled]))
}

/// One reached guest read transfers exactly one element. Tuple count, total
/// vector bytes, private staging size and host envelopes are separate facts.
pub(crate) const fn guest_memory_quantity(operand: &Operand) -> GuestMemoryQuantity {
    GuestMemoryQuantity::Maximum(operand.element)
}

#[cfg(test)]
mod tests;
