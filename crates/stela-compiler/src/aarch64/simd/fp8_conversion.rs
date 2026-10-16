//! AdvSIMD FP8 conversions: F1CVTL/F2CVTL, BF1CVTL/BF2CVTL, FCVTN.
use crate::aarch64::floating::fp8::ConversionFormat;

const WIDEN_MASK: u32 = 0xbfff_fc00;
const NARROW_MASK: u32 = 0xbfe0_fc00;
const BF1CVTL: u32 = 0x2ea1_7800;
const BF2CVTL: u32 = 0x2ee1_7800;
const F1CVTL: u32 = 0x2e21_7800;
const F2CVTL: u32 = 0x2e61_7800;
const FCVTN_HALF: u32 = 0x0e40_f400;
const FCVTN_SINGLE: u32 = 0x0e00_f400;
const Q: u32 = 1 << 30;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const SECOND_SOURCE_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Widen {
        destination: ConversionFormat,
        source2: bool,
        upper: bool,
    },
    NarrowHalf {
        vector128: bool,
    },
    NarrowSingle {
        upper: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub source: u8,
    pub second_source: u8,
}

/// Every register/Q combination is allocated; exact fixed bits keep ordinary
/// narrowing, BF16 and other FP8 arithmetic families outside this decoder.
pub fn decode(word: u32) -> Option<Operand> {
    let upper = word & Q != 0;
    let kind = match word & WIDEN_MASK {
        BF1CVTL => Kind::Widen {
            destination: ConversionFormat::BFloat16,
            source2: false,
            upper,
        },
        BF2CVTL => Kind::Widen {
            destination: ConversionFormat::BFloat16,
            source2: true,
            upper,
        },
        F1CVTL => Kind::Widen {
            destination: ConversionFormat::Half,
            source2: false,
            upper,
        },
        F2CVTL => Kind::Widen {
            destination: ConversionFormat::Half,
            source2: true,
            upper,
        },
        _ => match word & NARROW_MASK {
            FCVTN_HALF => Kind::NarrowHalf { vector128: upper },
            FCVTN_SINGLE => Kind::NarrowSingle { upper },
            _ => return None,
        },
    };
    Some(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
        second_source: if matches!(kind, Kind::Widen { .. }) {
            0
        } else {
            ((word >> SECOND_SOURCE_SHIFT) & REGISTER_MASK) as u8
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fixed_arrangements_and_register_aliases_decode() {
        for base in [BF1CVTL, BF2CVTL, F1CVTL, F2CVTL, FCVTN_HALF, FCVTN_SINGLE] {
            for q in [0, Q] {
                for register in 0..32 {
                    let fields = register
                        | register << SOURCE_SHIFT
                        | if matches!(base, FCVTN_HALF | FCVTN_SINGLE) {
                            register << SECOND_SOURCE_SHIFT
                        } else {
                            0
                        };
                    let operand = decode(base | q | fields).unwrap();
                    assert_eq!(operand.destination, register as u8);
                    assert_eq!(operand.source, register as u8);
                }
            }
        }
    }

    #[test]
    fn allocated_neighbors_are_not_claimed() {
        for word in [
            0x0e21_6800,
            0x0ea1_6800,
            0x1e63_4000,
            0x0fc0_0000,
            0x2e21_7000,
        ] {
            assert_eq!(decode(word), None);
        }
    }
}
