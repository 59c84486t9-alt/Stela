//! Exclusive loads and stores (LDXR/STXR, LDAXR/STLXR, pairs) and CLREX.
use super::{Register, register};

const SCALAR_MASK: u32 = 0x3fa0_0000;
const SCALAR_CLASS: u32 = 0x0800_0000;
const PAIR_MASK: u32 = 0xbfa0_0000;
const PAIR_CLASS: u32 = 0x8820_0000;
const CLEAR_MASK: u32 = 0xffff_f0ff;
const CLEAR_CLASS: u32 = 0xd503_305f;
const SIZE_SHIFT: u32 = 30;
const LOAD_BIT: u32 = 1 << 22;
const ACQUIRE_RELEASE_BIT: u32 = 1 << 15;
const STATUS_SHIFT: u32 = 16;
const SECOND_SHIFT: u32 = 10;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const PAIR_ELEMENT_BYTES: u8 = 4;
const PAIR_SIZE_MASK: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Data {
    Scalar(Register),
    Pair([Register; 2]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Load { acquire: bool },
    Store { release: bool, status: Register },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Clear,
    Transfer {
        element_bytes: u8,
        base: Register,
        data: Data,
        kind: Kind,
    },
}

/// These constrained aliases select the architectural UNDEF alternative.
/// A caller must deliver that exception or decline translation explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstrainedUndefined {
    PairLoadOutputs,
    StoreStatusData,
    StoreStatusBase,
    StoreStatusDataAndBase,
}

/// `None` is a class miss, including CASP, rather than a reserved exclusive.
/// All scalar size/L/o0 and pair sz/L/o0 combinations are allocated. CLREX
/// ignores every CRm value. Parenthesized Rs/Rt2 SBO fields select execute-as-one
/// and never become operands. Base31 is SP; all data/status31 operands are ZR.
/// LDAX* acquisition remains enabled when its output is discarded into ZR.
pub fn decode(word: u32) -> Option<Result<Operand, ConstrainedUndefined>> {
    if word & CLEAR_MASK == CLEAR_CLASS {
        return Some(Ok(Operand::Clear));
    }
    let first = word & REGISTER_MASK;
    let second = (word >> SECOND_SHIFT) & REGISTER_MASK;
    let (element_bytes, data) = if word & SCALAR_MASK == SCALAR_CLASS {
        (
            1 << (word >> SIZE_SHIFT),
            Data::Scalar(register(first, false)),
        )
    } else if word & PAIR_MASK == PAIR_CLASS {
        (
            PAIR_ELEMENT_BYTES << ((word >> SIZE_SHIFT) & PAIR_SIZE_MASK),
            Data::Pair([register(first, false), register(second, false)]),
        )
    } else {
        return None;
    };
    let base = (word >> BASE_SHIFT) & REGISTER_MASK;
    let ordered = word & ACQUIRE_RELEASE_BIT != 0;
    let kind = if word & LOAD_BIT != 0 {
        if matches!(data, Data::Pair(_)) && first == second {
            return Some(Err(ConstrainedUndefined::PairLoadOutputs));
        }
        Kind::Load { acquire: ordered }
    } else {
        let status = (word >> STATUS_SHIFT) & REGISTER_MASK;
        let data_overlap = status == first || matches!(data, Data::Pair(_)) && status == second;
        let base_overlap = status == base && base != REGISTER_MASK;
        let constraint = match (data_overlap, base_overlap) {
            (true, true) => Some(ConstrainedUndefined::StoreStatusDataAndBase),
            (true, false) => Some(ConstrainedUndefined::StoreStatusData),
            (false, true) => Some(ConstrainedUndefined::StoreStatusBase),
            (false, false) => None,
        };
        if let Some(constraint) = constraint {
            return Some(Err(constraint));
        }
        Kind::Store {
            release: ordered,
            status: register(status, false),
        }
    };
    Some(Ok(Operand::Transfer {
        element_bytes,
        base: register(base, true),
        data,
        kind,
    }))
}

#[cfg(test)]
mod tests;
