//! The seven fixed-width SM3 instructions (Arm FEAT_SM3).
use crate::aarch64::Unsupported;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Schedule1,
    Schedule2,
    Sum {
        third: u8,
    },
    Round {
        second: bool,
        nonlinear: bool,
        lane: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

/// These masks cover exactly the allocated AdvSIMD forms. V31 is data,
/// every register alias is legal, and the indexed round selects one of four words.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let kind = match word & 0xffe0fc00 {
        0xce60c000 => Kind::Schedule1,
        0xce60c400 => Kind::Schedule2,
        _ if word & 0xffe08000 == 0xce400000 => Kind::Sum {
            third: ((word >> 10) & 31) as u8,
        },
        _ if word & 0xffe0c000 == 0xce408000 => Kind::Round {
            second: word & 0x800 != 0,
            nonlinear: word & 0x400 != 0,
            lane: ((word >> 12) & 3) as u8,
        },
        _ => return None,
    };
    Some(Ok(Operand {
        kind,
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right: ((word >> 16) & 31) as u8,
    }))
}

#[cfg(test)]
mod tests;
