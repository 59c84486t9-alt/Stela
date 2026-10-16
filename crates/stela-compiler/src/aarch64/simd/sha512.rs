//! Four classic SHA512 forms from the pinned Arm A64 2026-06 reference.
//! Profile: FEAT_SHA512, FP/AdvSIMD enabled, nonstreaming, 128-bit V state.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hash,
    Hash2,
    Schedule0,
    Schedule1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    /// Read/write V register; V31 is ordinary data in every role.
    pub destination: u8,
    pub left: u8,
    /// SHA512SU0 has no third operand.
    pub right: Option<u8>,
}

const THREE_REGISTER_MASK: u32 = 0xffe0fc00;
const TWO_REGISTER_MASK: u32 = 0xfffffc00;
const HASH: u32 = 0xce608000;
const HASH2: u32 = 0xce608400;
const SCHEDULE0: u32 = 0xcec08000;
const SCHEDULE1: u32 = 0xce608800;
const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;

/// Exact allocated forms only: all register aliases are legal and no size/Q
/// variants exist. Other members of the crypto classes belong to other families.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let kind = if word & TWO_REGISTER_MASK == SCHEDULE0 {
        Kind::Schedule0
    } else {
        match word & THREE_REGISTER_MASK {
            HASH => Kind::Hash,
            HASH2 => Kind::Hash2,
            SCHEDULE1 => Kind::Schedule1,
            _ => return None,
        }
    };
    Some(Ok(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        left: ((word >> LEFT_SHIFT) & REGISTER_MASK) as u8,
        right: if kind == Kind::Schedule0 {
            None
        } else {
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8)
        },
    }))
}

#[cfg(test)]
mod tests;
