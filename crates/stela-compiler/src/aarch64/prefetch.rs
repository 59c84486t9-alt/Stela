//! PRFM and PRFUM.
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
mod tests;
