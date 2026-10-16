//! PC-relative literal loads: LDR (literal), LDRSW (literal) and PRFM (literal).
use super::{Register, Width, register};
use crate::GuestAddress;

const CLASS_MASK: u32 = 0x3b000000;
const LITERAL_CLASS: u32 = 0x18000000;
const FORM_MASK: u32 = 0xff000000;
const LDR_W: u32 = 0x18000000;
const LDR_X: u32 = 0x58000000;
const LDRSW: u32 = 0x98000000;
const LDR_S: u32 = 0x1c000000;
const LDR_D: u32 = 0x5c000000;
const LDR_Q: u32 = 0x9c000000;
const REGISTER_MASK: u32 = 31;
const IMMEDIATE_SHIFT: u32 = 5;
const IMMEDIATE_BITS: u32 = 19;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const IMMEDIATE_SIGN_SHIFT: u32 = i64::BITS - IMMEDIATE_BITS;
const INSTRUCTION_BYTES: i64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transfer {
    Integer {
        destination: Register,
        width: Width,
        signed: bool,
    },
    Simd {
        destination: u8,
        bytes: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub address: u64,
    pub transfer: Transfer,
}

/// PRFM (literal) and reserved SIMD opcode 11 are unsupported. The address
/// wraps at 64 bits and uses this instruction's guest PC.
#[allow(clippy::result_unit_err)]
pub fn decode(pc: GuestAddress, word: u32) -> Option<Result<Operand, ()>> {
    if word & CLASS_MASK != LITERAL_CLASS {
        return None;
    }
    let destination = word & REGISTER_MASK;
    let transfer = match word & FORM_MASK {
        LDR_W | LDR_X | LDRSW => Transfer::Integer {
            destination: register(destination, false),
            width: if word & FORM_MASK == LDR_W {
                Width::W32
            } else {
                Width::X64
            },
            signed: word & FORM_MASK == LDRSW,
        },
        LDR_S | LDR_D | LDR_Q => Transfer::Simd {
            destination: destination as u8,
            bytes: match word & FORM_MASK {
                LDR_S => 4,
                LDR_D => 8,
                LDR_Q => 16,
                _ => unreachable!("literal SIMD form is matched above"),
            },
        },
        _ => return Some(Err(())),
    };
    let immediate = i64::from((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK);
    let signed = (immediate << IMMEDIATE_SIGN_SHIFT) >> IMMEDIATE_SIGN_SHIFT;
    Some(Ok(Operand {
        address: pc.0.wrapping_add_signed(signed * INSTRUCTION_BYTES),
        transfer,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(form: u32, immediate: i32, destination: u32) -> u32 {
        form | ((immediate as u32 & IMMEDIATE_MASK) << IMMEDIATE_SHIFT) | destination
    }

    #[test]
    fn all_forms_destinations_and_signed_displacements_decode() {
        for form in [LDR_W, LDR_X, LDRSW, LDR_S, LDR_D, LDR_Q] {
            for destination in 0..=REGISTER_MASK {
                for immediate in [-262144, -1, 0, 1, 262143] {
                    for pc in [0, 0x1004, u64::MAX - 3] {
                        let operand = decode(GuestAddress(pc), word(form, immediate, destination))
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            operand.address,
                            (i128::from(pc) + i128::from(immediate) * 4) as u64
                        );
                        let expected = match form {
                            LDR_W | LDR_X | LDRSW => Transfer::Integer {
                                destination: register(destination, false),
                                width: if form == LDR_W {
                                    Width::W32
                                } else {
                                    Width::X64
                                },
                                signed: form == LDRSW,
                            },
                            _ => Transfer::Simd {
                                destination: destination as u8,
                                bytes: if form == LDR_S {
                                    4
                                } else if form == LDR_D {
                                    8
                                } else {
                                    16
                                },
                            },
                        };
                        assert_eq!(operand.transfer, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn prefetch_reserved_and_neighboring_classes_do_not_become_loads() {
        for unsupported in [0xd8000000, 0xdc000000] {
            assert_eq!(decode(GuestAddress(0), unsupported), Some(Err(())));
        }
        for bit in [24, 25, 27, 28, 29] {
            assert!(decode(GuestAddress(0), LDR_W ^ (1 << bit)).is_none());
        }
    }
}
