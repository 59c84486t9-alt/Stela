//! Bitfield moves: SBFM, BFM and UBFM with their shift, extend and insert aliases.
//! Register 31 is ZR. BFM also reads its old destination.
use super::{Register, Width, register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Signed,
    Insert,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub width: Width,
    pub kind: Kind,
    pub destination: Register,
    pub source: Register,
    pub rotation: u8,
    pub mask_end: u8,
}

pub fn decode(word: u32) -> Option<Operand> {
    if word & 0x1f800000 != 0x13000000 {
        return None;
    }
    let sf = word >> 31;
    let n = (word >> 22) & 1;
    let rotation = ((word >> 16) & 63) as u8;
    let mask_end = ((word >> 10) & 63) as u8;
    if n != sf || (sf == 0 && (rotation >= 32 || mask_end >= 32)) {
        return None;
    }
    let kind = match (word >> 29) & 3 {
        0 => Kind::Signed,
        1 => Kind::Insert,
        2 => Kind::Unsigned,
        _ => return None,
    };
    Some(Operand {
        width: if sf == 0 { Width::W32 } else { Width::X64 },
        kind,
        destination: register(word & 31, false),
        source: register((word >> 5) & 31, false),
        rotation,
        mask_end,
    })
}

#[cfg(test)]
mod tests;
