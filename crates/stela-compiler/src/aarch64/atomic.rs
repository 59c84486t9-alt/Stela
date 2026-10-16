//! Scalar and pair LSE operations in the declared coherent Normal-WB memory profile.
use super::{Register, register};

const CAS_MASK: u32 = 0x3fa07c00;
const CAS_CLASS: u32 = 0x08a07c00;
const CASP_MASK: u32 = 0xbfa07c00;
const CASP_CLASS: u32 = 0x08207c00;
const RMW_MASK: u32 = 0x3f200c00;
const RMW_CLASS: u32 = 0x38200000;
const SIZE_SHIFT: u32 = 30;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 16;
const BASE_SHIFT: u32 = 5;
const PAIR_FIRST_ODD_BIT: u32 = 1;
const WORD_PAIR_BYTES: u8 = 8;
const RMW_OPERATION_SHIFT: u32 = 12;
const RMW_OPERATION_MASK: u32 = 15;
const CAS_ACQUIRE: u32 = 1 << 22;
const CAS_RELEASE: u32 = 1 << 15;
const RMW_ACQUIRE: u32 = 1 << 23;
const RMW_RELEASE: u32 = 1 << 22;
const ADD_OPCODE: u32 = 0;
const CLEAR_OPCODE: u32 = 1;
const XOR_OPCODE: u32 = 2;
const SET_OPCODE: u32 = 3;
const SIGNED_MAX_OPCODE: u32 = 4;
const SIGNED_MIN_OPCODE: u32 = 5;
const UNSIGNED_MAX_OPCODE: u32 = 6;
const UNSIGNED_MIN_OPCODE: u32 = 7;
const SWAP_OPCODE: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Relaxed,
    Acquire,
    Release,
    AcquireRelease,
}

impl Order {
    const fn decode(acquire: bool, release: bool) -> Self {
        match (acquire, release) {
            (false, false) => Self::Relaxed,
            (true, false) => Self::Acquire,
            (false, true) => Self::Release,
            (true, true) => Self::AcquireRelease,
        }
    }

    /// LSE acquisition is suppressed when its returned-old register is ZR.
    pub const fn acquires(self, result: Register) -> bool {
        !matches!(result, Register::Zero) && matches!(self, Self::Acquire | Self::AcquireRelease)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rmw {
    Add,
    Clear,
    Xor,
    Set,
    SignedMax,
    SignedMin,
    UnsignedMax,
    UnsignedMin,
    Swap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    CompareExchange {
        compare: Register,
        source: Register,
    },
    CompareExchangePair {
        compare: [Register; 2],
        source: [Register; 2],
    },
    ReadModifyWrite {
        operation: Rmw,
        source: Register,
        destination: Register,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub bytes: u8,
    pub base: Register,
    pub order: Order,
    pub kind: Kind,
}

/// Reserved RMW operations and odd CASP first registers decline explicitly.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let source = register((word >> SOURCE_SHIFT) & REGISTER_MASK, false);
    let destination = register(word & REGISTER_MASK, false);
    let (kind, order, bytes) = if word & CASP_MASK == CASP_CLASS {
        let first_compare = (word >> SOURCE_SHIFT) & REGISTER_MASK;
        let first_source = word & REGISTER_MASK;
        if (first_compare | first_source) & PAIR_FIRST_ODD_BIT != 0 {
            return Some(Err(()));
        }
        (
            Kind::CompareExchangePair {
                compare: [source, register(first_compare + 1, false)],
                source: [destination, register(first_source + 1, false)],
            },
            Order::decode(word & CAS_ACQUIRE != 0, word & CAS_RELEASE != 0),
            WORD_PAIR_BYTES << (word >> SIZE_SHIFT),
        )
    } else if word & CAS_MASK == CAS_CLASS {
        (
            Kind::CompareExchange {
                compare: source,
                source: destination,
            },
            Order::decode(word & CAS_ACQUIRE != 0, word & CAS_RELEASE != 0),
            1 << (word >> SIZE_SHIFT),
        )
    } else if word & RMW_MASK == RMW_CLASS {
        let operation = match (word >> RMW_OPERATION_SHIFT) & RMW_OPERATION_MASK {
            ADD_OPCODE => Rmw::Add,
            CLEAR_OPCODE => Rmw::Clear,
            XOR_OPCODE => Rmw::Xor,
            SET_OPCODE => Rmw::Set,
            SIGNED_MAX_OPCODE => Rmw::SignedMax,
            SIGNED_MIN_OPCODE => Rmw::SignedMin,
            UNSIGNED_MAX_OPCODE => Rmw::UnsignedMax,
            UNSIGNED_MIN_OPCODE => Rmw::UnsignedMin,
            SWAP_OPCODE => Rmw::Swap,
            _ => return Some(Err(())),
        };
        (
            Kind::ReadModifyWrite {
                operation,
                source,
                destination,
            },
            Order::decode(word & RMW_ACQUIRE != 0, word & RMW_RELEASE != 0),
            1 << (word >> SIZE_SHIFT),
        )
    } else {
        return None;
    };
    Some(Ok(Operand {
        bytes,
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        order,
        kind,
    }))
}

#[cfg(test)]
mod tests;
