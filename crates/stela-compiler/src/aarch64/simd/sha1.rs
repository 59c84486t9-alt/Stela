//! Six exact SHA1 forms from Arm ISA_A64_xml_A_profile-2026-06.
//! FEAT_SHA1 and enabled non-streaming FP/AdvSIMD are execution requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Choose,
    Parity,
    Majority,
    Rotate,
    Schedule0,
    Schedule1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    /// Read/write except SHA1H, whose S result clears destination bits 127:32.
    pub destination: u8,
    pub left: u8,
    /// Ignored for SHA1H/SHA1SU1. V31 is ordinary data in every role.
    pub right: u8,
}

const REGISTER_MASK: u32 = 31;
const LEFT_REGISTER_SHIFT: u8 = 5;
const RIGHT_REGISTER_SHIFT: u8 = 16;

const THREE_REGISTER_MASK: u32 = 0xffe0fc00;
const TWO_REGISTER_MASK: u32 = 0xfffffc00;
const SHA1C: u32 = 0x5e000000;
const SHA1P: u32 = 0x5e001000;
const SHA1M: u32 = 0x5e002000;
const SHA1SU0: u32 = 0x5e003000;
const SHA1H: u32 = 0x5e280800;
const SHA1SU1: u32 = 0x5e281800;

pub fn decode(word: u32) -> Option<Operand> {
    let kind = match word & THREE_REGISTER_MASK {
        SHA1C => Kind::Choose,
        SHA1P => Kind::Parity,
        SHA1M => Kind::Majority,
        SHA1SU0 => Kind::Schedule0,
        _ => match word & TWO_REGISTER_MASK {
            SHA1H => Kind::Rotate,
            SHA1SU1 => Kind::Schedule1,
            _ => return None,
        },
    };
    Some(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        left: ((word >> LEFT_REGISTER_SHIFT) & REGISTER_MASK) as u8,
        right: ((word >> RIGHT_REGISTER_SHIFT) & REGISTER_MASK) as u8,
    })
}

#[cfg(test)]
mod tests;
