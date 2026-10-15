//! Predicated deinterleaving LD2/LD3/LD4 transfers, including 128-bit elements.
use super::memory::{Address, Offset, Scale};
use crate::aarch64::{
    register,
    scalable::{
        ElementSize, VECTOR_REGISTER_COUNT,
        execution::{GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements},
    },
};

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
mod tests {
    use super::*;

    const FORM_ROWS: [(u32, u8, ElementSize, bool); 30] = [
        (0xa420_e000, 2, ElementSize::Byte, true),
        (0xa420_c000, 2, ElementSize::Byte, false),
        (0xa4a0_e000, 2, ElementSize::Halfword, true),
        (0xa4a0_c000, 2, ElementSize::Halfword, false),
        (0xa520_e000, 2, ElementSize::Word, true),
        (0xa520_c000, 2, ElementSize::Word, false),
        (0xa5a0_e000, 2, ElementSize::Doubleword, true),
        (0xa5a0_c000, 2, ElementSize::Doubleword, false),
        (0xa490_e000, 2, ElementSize::Quadword, true),
        (0xa4a0_8000, 2, ElementSize::Quadword, false),
        (0xa440_e000, 3, ElementSize::Byte, true),
        (0xa440_c000, 3, ElementSize::Byte, false),
        (0xa4c0_e000, 3, ElementSize::Halfword, true),
        (0xa4c0_c000, 3, ElementSize::Halfword, false),
        (0xa540_e000, 3, ElementSize::Word, true),
        (0xa540_c000, 3, ElementSize::Word, false),
        (0xa5c0_e000, 3, ElementSize::Doubleword, true),
        (0xa5c0_c000, 3, ElementSize::Doubleword, false),
        (0xa510_e000, 3, ElementSize::Quadword, true),
        (0xa520_8000, 3, ElementSize::Quadword, false),
        (0xa460_e000, 4, ElementSize::Byte, true),
        (0xa460_c000, 4, ElementSize::Byte, false),
        (0xa4e0_e000, 4, ElementSize::Halfword, true),
        (0xa4e0_c000, 4, ElementSize::Halfword, false),
        (0xa560_e000, 4, ElementSize::Word, true),
        (0xa560_c000, 4, ElementSize::Word, false),
        (0xa5e0_e000, 4, ElementSize::Doubleword, true),
        (0xa5e0_c000, 4, ElementSize::Doubleword, false),
        (0xa590_e000, 4, ElementSize::Quadword, true),
        (0xa5a0_8000, 4, ElementSize::Quadword, false),
    ];

    #[test]
    fn all_forms_preserve_fields_and_tuple_wrap() {
        for (class, registers, width, immediate) in FORM_ROWS {
            for destination in 0..VECTOR_REGISTER_COUNT {
                for predicate in 0..=PREDICATE_MASK {
                    let word = class
                        | REGISTER_FIELD_MASK << BASE_SHIFT
                        | predicate << PREDICATE_SHIFT
                        | u32::from(destination);
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(operand.destination, destination);
                    assert_eq!(operand.registers, registers);
                    assert_eq!(operand.element, width);
                    assert_eq!(operand.predicate, predicate as u8);
                    assert_eq!(operand.address.base, register(REGISTER_FIELD_MASK, true));
                    assert_eq!(
                        matches!(operand.address.offset, Offset::Immediate { .. }),
                        immediate
                    );
                    for index in 0..registers {
                        assert_eq!(
                            operand.destination_register(index),
                            (destination + index) % VECTOR_REGISTER_COUNT
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn signed_immediates_and_reserved_index_registers() {
        for (class, _, _, immediate) in FORM_ROWS {
            if immediate {
                for raw in 0..=IMMEDIATE_FIELD_MASK {
                    let operand = decode(class | raw << OFFSET_SHIFT).unwrap().unwrap();
                    let expected = if raw < 1 << (IMMEDIATE_BITS - 1) {
                        raw as i8
                    } else {
                        raw as i8 - (1 << IMMEDIATE_BITS)
                    };
                    assert_eq!(
                        operand.address.offset,
                        Offset::Immediate {
                            value: i16::from(expected),
                            scale: Scale::VectorBytes {
                                multiply: operand.registers,
                                divide: 1
                            }
                        }
                    );
                }
            } else {
                assert_eq!(
                    decode(class | REGISTER_FIELD_MASK << OFFSET_SHIFT),
                    Some(Err(()))
                );
            }
        }
        assert_eq!(decode(IMMEDIATE_CLASS), None);
        assert_eq!(decode(REGISTER_CLASS), None);
        assert_eq!(decode(QUAD_IMMEDIATE_CLASS), None);
        assert_eq!(decode(QUAD_REGISTER_CLASS), None);
    }
}
