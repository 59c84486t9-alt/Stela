//! SME2/SVE2.1 multi-vector loads and stores governed by predicate-as-counter.
use super::super::{Register, register};
use super::memory::{Address, Offset, Scale};
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::{
    ElementSize,
    execution::{GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements},
};
use alloc::boxed::Box;

const CLASS_MASK: u32 = 0xff80_0000;
const CLASS_VALUE: u32 = 0xa000_0000;
const IMMEDIATE_ADDRESS: u32 = 1 << 22;
const STORE: u32 = 1 << 21;
const IMMEDIATE_RESERVED: u32 = 1 << 20;
const FOUR_REGISTERS: u32 = 1 << 15;
const ELEMENT_SHIFT: u32 = 13;
const ELEMENT_MASK: u32 = 3;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const FIRST_COUNTER_REGISTER: u8 = 8;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const OFFSET_SHIFT: u32 = 16;
const IMMEDIATE_MASK: u32 = 15;
const IMMEDIATE_SIGN: i8 = 8;
const IMMEDIATE_MODULUS: i8 = 16;
const NON_TEMPORAL: u32 = 1;
const QUAD_RESERVED: u32 = 1 << 1;
const PAIR_REGISTER_MASK: u32 = 30;
const QUAD_REGISTER_MASK: u32 = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub loading: bool,
    pub non_temporal: bool,
    pub element: ElementSize,
    pub registers: u8,
    pub first: u8,
    pub predicate: u8,
    pub address: Address,
}

impl Operand {
    /// Register-offset forms check tags even when their base is SP.
    pub const fn tag_checked(self) -> bool {
        matches!(self.address.offset, Offset::Register { .. })
            || !matches!(self.address.base, Register::Sp)
    }
}

/// Both pseudocode branches have the same effect with FEAT_SME and PSTATE.SM
/// set; the owner checks those guards first.
pub(crate) fn execution_access_requirements(_operand: &Operand) -> ScalableAccessRequirements {
    ScalableAccessRequirements::StreamingSmeSpecialization(Box::new([
        ScalableAccessCheck::StreamingSveEnabled,
    ]))
}

/// Maximum guest Mem element, separate from tuple size and host envelopes.
pub(crate) const fn guest_memory_quantity(operand: &Operand) -> GuestMemoryQuantity {
    GuestMemoryQuantity::Maximum(operand.element)
}

/// Reserved tuple alignment and immediate fields decline without another decode.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    if word & CLASS_MASK != CLASS_VALUE {
        return None;
    }
    let immediate = word & IMMEDIATE_ADDRESS != 0;
    let quad = word & FOUR_REGISTERS != 0;
    if (immediate && word & IMMEDIATE_RESERVED != 0) || (quad && word & QUAD_RESERVED != 0) {
        return Some(Err(Unsupported));
    }
    let offset = if immediate {
        let raw = ((word >> OFFSET_SHIFT) & IMMEDIATE_MASK) as i8;
        Offset::Immediate {
            value: i16::from(if raw & IMMEDIATE_SIGN != 0 {
                raw - IMMEDIATE_MODULUS
            } else {
                raw
            }),
            scale: Scale::VectorBytes {
                multiply: if quad { 4 } else { 2 },
                divide: 1,
            },
        }
    } else {
        Offset::Register {
            index: register((word >> OFFSET_SHIFT) & REGISTER_MASK, false),
            shift: ((word >> ELEMENT_SHIFT) & ELEMENT_MASK) as u8,
        }
    };
    Some(Ok(Operand {
        loading: word & STORE == 0,
        non_temporal: word & NON_TEMPORAL != 0,
        element: match (word >> ELEMENT_SHIFT) & ELEMENT_MASK {
            0 => ElementSize::Byte,
            1 => ElementSize::Halfword,
            2 => ElementSize::Word,
            _ => ElementSize::Doubleword,
        },
        registers: if quad { 4 } else { 2 },
        first: (word
            & if quad {
                QUAD_REGISTER_MASK
            } else {
                PAIR_REGISTER_MASK
            }) as u8,
        predicate: FIRST_COUNTER_REGISTER + ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
        address: Address {
            base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
            offset,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_allocated_width_direction_hint_address_and_tuple_combinations() {
        for loading in [false, true] {
            for non_temporal in [false, true] {
                for element in 0..=ELEMENT_MASK {
                    for quad in [false, true] {
                        for immediate in [false, true] {
                            for first in (0..32).step_by(if quad { 4 } else { 2 }) {
                                for predicate in 0..=PREDICATE_MASK {
                                    let word = CLASS_VALUE
                                        | if loading { 0 } else { STORE }
                                        | if non_temporal { NON_TEMPORAL } else { 0 }
                                        | (element << ELEMENT_SHIFT)
                                        | if quad { FOUR_REGISTERS } else { 0 }
                                        | if immediate { IMMEDIATE_ADDRESS } else { 0 }
                                        | (predicate << PREDICATE_SHIFT)
                                        | (REGISTER_MASK << BASE_SHIFT)
                                        | first;
                                    let operand = decode(word).unwrap().unwrap();
                                    assert_eq!(operand.loading, loading);
                                    assert_eq!(operand.non_temporal, non_temporal);
                                    assert_eq!(operand.element.bytes(), 1 << element);
                                    assert_eq!(operand.registers, if quad { 4 } else { 2 });
                                    assert_eq!(operand.first, first as u8);
                                    assert_eq!(
                                        operand.predicate,
                                        FIRST_COUNTER_REGISTER + predicate as u8
                                    );
                                    assert_eq!(operand.address.base, Register::Sp);
                                    assert_eq!(operand.tag_checked(), !immediate);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn signed_tuple_offsets_and_zero_register_offsets_remain_distinct() {
        for raw in 0..=IMMEDIATE_MASK {
            let operand = decode(CLASS_VALUE | IMMEDIATE_ADDRESS | (raw << OFFSET_SHIFT))
                .unwrap()
                .unwrap();
            assert_eq!(
                operand.address.offset,
                Offset::Immediate {
                    value: i16::from(if raw >= IMMEDIATE_SIGN as u32 {
                        raw as i8 - IMMEDIATE_MODULUS
                    } else {
                        raw as i8
                    }),
                    scale: Scale::VectorBytes {
                        multiply: 2,
                        divide: 1
                    },
                }
            );
        }
        let operand = decode(CLASS_VALUE | (REGISTER_MASK << OFFSET_SHIFT))
            .unwrap()
            .unwrap();
        assert_eq!(
            operand.address.offset,
            Offset::Register {
                index: Register::Zero,
                shift: 0
            }
        );
    }

    #[test]
    fn reserved_fields_are_explicit_and_other_classes_do_not_match() {
        assert_eq!(
            decode(CLASS_VALUE | FOUR_REGISTERS | QUAD_RESERVED),
            Some(Err(Unsupported))
        );
        assert_eq!(
            decode(CLASS_VALUE | IMMEDIATE_ADDRESS | IMMEDIATE_RESERVED),
            Some(Err(Unsupported))
        );
        for bit in 23..32 {
            assert_eq!(decode(CLASS_VALUE ^ (1 << bit)), None);
        }
    }
}
