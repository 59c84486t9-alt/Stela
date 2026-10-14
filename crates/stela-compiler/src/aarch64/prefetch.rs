//! PRFM/PRFUM address and raw-hint semantics from Arm's pinned 2026-06 reference.
use super::{Register, register, register_offset::IndexExtend};
use crate::GuestAddress;

const HINT_MASK: u32 = 31;
const REGISTER_SHIFT: u32 = 5;
const UNSIGNED_MASK: u32 = 0xffc00000;
const UNSIGNED_FORM: u32 = 0xf9800000;
const UNSCALED_MASK: u32 = 0xffe00c00;
const UNSCALED_FORM: u32 = 0xf8800000;
const REGISTER_MASK: u32 = 0xffe00c00;
const REGISTER_FORM: u32 = 0xf8a00800;
const LITERAL_MASK: u32 = 0xff000000;
const LITERAL_FORM: u32 = 0xd8000000;
const RANGE_HINT_MASK: u32 = 0b11000;
const ADDRESS_SCALE: u8 = 3;
const UNSIGNED_IMMEDIATE_SHIFT: u32 = 10;
const UNSIGNED_IMMEDIATE_MASK: u32 = (1 << 12) - 1;
const UNSCALED_IMMEDIATE_SHIFT: u32 = 12;
const UNSCALED_IMMEDIATE_BITS: u32 = 9;
const UNSCALED_IMMEDIATE_MASK: u32 = (1 << UNSCALED_IMMEDIATE_BITS) - 1;
const LITERAL_IMMEDIATE_SHIFT: u32 = 5;
const LITERAL_IMMEDIATE_BITS: u32 = 19;
const LITERAL_IMMEDIATE_MASK: u32 = (1 << LITERAL_IMMEDIATE_BITS) - 1;
const INSTRUCTION_BYTES: i64 = 4;
const INDEX_SHIFT: u32 = 16;
const EXTEND_SHIFT: u32 = 13;
const EXTEND_MASK: u32 = 7;
const SCALED_BIT: u32 = 1 << 12;

/// Rt encodes a hint, never a data register. Preserve even unallocated values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hint(u8);

impl Hint {
    pub const fn encoding(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address {
    Immediate {
        base: Register,
        displacement: i32,
    },
    Register {
        base: Register,
        index: Register,
        extend: IndexExtend,
        shift: u8,
    },
    Literal(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub hint: Hint,
    pub address: Address,
}

/// No prefetch form checks SP alignment or updates registers. AddressAdd is
/// modulo 64 bits in the ordinary-RAM profile with checked arithmetic disabled.
/// Register Rt=11xxx belongs to RPRFM, whose metadata semantics stay unsupported.
#[allow(clippy::result_unit_err)]
pub fn decode(pc: GuestAddress, word: u32) -> Option<Result<Operand, ()>> {
    let base = register((word >> REGISTER_SHIFT) & HINT_MASK, true);
    let address = if word & UNSIGNED_MASK == UNSIGNED_FORM {
        Address::Immediate {
            base,
            displacement: (((word >> UNSIGNED_IMMEDIATE_SHIFT) & UNSIGNED_IMMEDIATE_MASK)
                << ADDRESS_SCALE) as i32,
        }
    } else if word & UNSCALED_MASK == UNSCALED_FORM {
        Address::Immediate {
            base,
            displacement: sign_extend(
                (word >> UNSCALED_IMMEDIATE_SHIFT) & UNSCALED_IMMEDIATE_MASK,
                UNSCALED_IMMEDIATE_BITS,
            ) as i32,
        }
    } else if word & REGISTER_MASK == REGISTER_FORM {
        if word & RANGE_HINT_MASK == RANGE_HINT_MASK {
            return None;
        }
        let Some(extend) = IndexExtend::decode((word >> EXTEND_SHIFT) & EXTEND_MASK) else {
            return Some(Err(()));
        };
        Address::Register {
            base,
            index: register((word >> INDEX_SHIFT) & HINT_MASK, false),
            extend,
            shift: if word & SCALED_BIT == 0 {
                0
            } else {
                ADDRESS_SCALE
            },
        }
    } else if word & LITERAL_MASK == LITERAL_FORM {
        let displacement = sign_extend(
            (word >> LITERAL_IMMEDIATE_SHIFT) & LITERAL_IMMEDIATE_MASK,
            LITERAL_IMMEDIATE_BITS,
        ) * INSTRUCTION_BYTES;
        Address::Literal(pc.0.wrapping_add_signed(displacement))
    } else {
        return None;
    };
    Some(Ok(Operand {
        hint: Hint((word & HINT_MASK) as u8),
        address,
    }))
}

const fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = i64::BITS - bits;
    ((value as i64) << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_forms_preserve_all_hints_bases_and_boundaries() {
        for hint in 0..32 {
            for base in 0..32 {
                for immediate in [0, 1, 15, 16, 4095] {
                    let operand = decode(
                        GuestAddress(0),
                        UNSIGNED_FORM | (immediate << 10) | (base << 5) | hint,
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(operand.hint.encoding(), hint as u8);
                    assert_eq!(
                        operand.address,
                        Address::Immediate {
                            base: register(base, true),
                            displacement: (immediate * 8) as i32,
                        }
                    );
                }
                for immediate in [-256_i32, -129, -128, -1, 0, 1, 127, 128, 255] {
                    let operand = decode(
                        GuestAddress(0),
                        UNSCALED_FORM | ((immediate as u32 & 0x1ff) << 12) | (base << 5) | hint,
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(operand.hint.encoding(), hint as u8);
                    assert_eq!(
                        operand.address,
                        Address::Immediate {
                            base: register(base, true),
                            displacement: immediate,
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn register_extensions_scales_and_range_neighbors_are_explicit() {
        for hint in 0..32 {
            for option in 0..8 {
                for scaled in [false, true] {
                    for index in [0, 1, 30, 31] {
                        let word = REGISTER_FORM
                            | (index << 16)
                            | (option << 13)
                            | (u32::from(scaled) << 12)
                            | (31 << 5)
                            | hint;
                        let decoded = decode(GuestAddress(0), word);
                        if hint >= 24 {
                            assert_eq!(decoded, None);
                        } else if option & 2 == 0 {
                            assert_eq!(decoded, Some(Err(())));
                        } else {
                            let operand = decoded.unwrap().unwrap();
                            assert_eq!(operand.hint.encoding(), hint as u8);
                            assert_eq!(
                                operand.address,
                                Address::Register {
                                    base: Register::Sp,
                                    index: register(index, false),
                                    extend: IndexExtend::decode(option).unwrap(),
                                    shift: if scaled { 3 } else { 0 },
                                }
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn literals_use_signed_original_pc_offsets_with_modulo_64_wrap() {
        for hint in 0..32 {
            for immediate in [-262144_i32, -1, 0, 1, 262143] {
                for pc in [0, 0x1004, u64::MAX - 3] {
                    let operand = decode(
                        GuestAddress(pc),
                        LITERAL_FORM | ((immediate as u32 & 0x7ffff) << 5) | hint,
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(operand.hint.encoding(), hint as u8);
                    assert_eq!(
                        operand.address,
                        Address::Literal((i128::from(pc) + i128::from(immediate) * 4) as u64)
                    );
                }
            }
        }
    }

    #[test]
    fn other_transfers_and_address_modes_do_not_become_prefetches() {
        for word in [
            0xf9400000, // LDR unsigned
            0xf8400000, // LDUR
            0xf8800400, // reserved post-index prefetch neighbor
            0xf8800800, // reserved unprivileged prefetch neighbor
            0xf8800c00, // reserved pre-index prefetch neighbor
            0xf8a00000, // atomic/address-class neighbor
            0x58000000, // LDR literal
            0xdc000000, // reserved SIMD literal
        ] {
            assert_eq!(decode(GuestAddress(0), word), None);
        }
    }
}
