//! SME2 destructive grouped absolute extrema and integer exponent scaling.
//!
//! H/S/D groups are aligned pairs/quartets; broadcast scales name Z0..Z15.
//! Execution requires streaming SVE access, without ZA access. Decode grants no
//! permission: extrema also require FAMINMAX and scaling requires FP8.
use crate::aarch64::floating::{Format, absolute_minmax::AbsoluteMinMaxOperation};

const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const RIGHT_SHIFT: u32 = 16;
const REGISTER_MASK: u32 = 31;
const BROADCAST_REGISTER_MASK: u32 = 15;
const GROUP_PAIR_MASK: u32 = 0xff21_ffe1;
const GROUP_QUARTET_MASK: u32 = 0xff23_ffe3;
const BROADCAST_PAIR_MASK: u32 = 0xff30_ffe1;
const BROADCAST_QUARTET_MASK: u32 = 0xff30_ffe3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Pair,
    Quartet,
}
impl Group {
    pub const fn count(self) -> u8 {
        match self {
            Self::Pair => 2,
            Self::Quartet => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    AbsoluteMinMax(AbsoluteMinMaxOperation),
    Scale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub right: u8,
    pub group: Group,
    pub format: Format,
    pub right_grouped: bool,
}

#[derive(Clone, Copy)]
struct Encoding {
    mask: u32,
    opcode: u32,
    kind: Kind,
    group: Group,
    right_grouped: bool,
}

const ENCODINGS: [Encoding; 8] = [
    Encoding {
        mask: GROUP_PAIR_MASK,
        opcode: 0xc120_b140,
        kind: Kind::AbsoluteMinMax(AbsoluteMinMaxOperation::Maximum),
        group: Group::Pair,
        right_grouped: true,
    },
    Encoding {
        mask: GROUP_QUARTET_MASK,
        opcode: 0xc120_b940,
        kind: Kind::AbsoluteMinMax(AbsoluteMinMaxOperation::Maximum),
        group: Group::Quartet,
        right_grouped: true,
    },
    Encoding {
        mask: GROUP_PAIR_MASK,
        opcode: 0xc120_b141,
        kind: Kind::AbsoluteMinMax(AbsoluteMinMaxOperation::Minimum),
        group: Group::Pair,
        right_grouped: true,
    },
    Encoding {
        mask: GROUP_QUARTET_MASK,
        opcode: 0xc120_b941,
        kind: Kind::AbsoluteMinMax(AbsoluteMinMaxOperation::Minimum),
        group: Group::Quartet,
        right_grouped: true,
    },
    Encoding {
        mask: BROADCAST_PAIR_MASK,
        opcode: 0xc120_a180,
        kind: Kind::Scale,
        group: Group::Pair,
        right_grouped: false,
    },
    Encoding {
        mask: BROADCAST_QUARTET_MASK,
        opcode: 0xc120_a980,
        kind: Kind::Scale,
        group: Group::Quartet,
        right_grouped: false,
    },
    Encoding {
        mask: GROUP_PAIR_MASK,
        opcode: 0xc120_b180,
        kind: Kind::Scale,
        group: Group::Pair,
        right_grouped: true,
    },
    Encoding {
        mask: GROUP_QUARTET_MASK,
        opcode: 0xc120_b980,
        kind: Kind::Scale,
        group: Group::Quartet,
        right_grouped: true,
    },
];

pub fn decode(word: u32) -> Option<Operand> {
    let encoding = ENCODINGS
        .iter()
        .find(|encoding| word & encoding.mask == encoding.opcode)?;
    let format = match (word >> SIZE_SHIFT) & SIZE_MASK {
        1 => Format::Half,
        2 => Format::Single,
        3 => Format::Double,
        // Size zero belongs to other instructions (including BFSCALE).
        _ => return None,
    };
    Some(Operand {
        kind: encoding.kind,
        destination: (word & REGISTER_MASK) as u8 & !(encoding.group.count() - 1),
        right: if encoding.right_grouped {
            ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8 & !(encoding.group.count() - 1)
        } else {
            ((word >> RIGHT_SHIFT) & BROADCAST_REGISTER_MASK) as u8
        },
        group: encoding.group,
        format,
        right_grouped: encoding.right_grouped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_form_width_and_group_register_combination_decodes_exactly() {
        for encoding in ENCODINGS {
            let count = encoding.group.count();
            for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
                for destination in (0..32).step_by(usize::from(count)) {
                    let right_count = if encoding.right_grouped { count } else { 1 };
                    let right_limit = if encoding.right_grouped { 32 } else { 16 };
                    for right in (0..right_limit).step_by(usize::from(right_count)) {
                        let word = encoding.opcode
                            | size << SIZE_SHIFT
                            | destination
                            | right << RIGHT_SHIFT;
                        assert_eq!(
                            decode(word),
                            Some(Operand {
                                kind: encoding.kind,
                                destination: destination as u8,
                                right: right as u8,
                                group: encoding.group,
                                format,
                                right_grouped: encoding.right_grouped,
                            })
                        );
                    }
                }
            }
            assert_eq!(decode(encoding.opcode), None);
        }
    }

    #[test]
    fn fixed_register_alignment_and_neighbor_operation_bits_are_not_ignored() {
        for encoding in ENCODINGS {
            let word = encoding.opcode | 1 << SIZE_SHIFT;
            assert!(decode(word ^ 1 << 10).is_none());
            if encoding.group == Group::Quartet {
                assert!(decode(word | 1 << 1).is_none());
                if encoding.right_grouped {
                    assert!(decode(word | 1 << 17).is_none());
                }
            }
            if !encoding.right_grouped {
                assert!(decode(word | 1 << 20).is_none());
            }
        }
    }
}
