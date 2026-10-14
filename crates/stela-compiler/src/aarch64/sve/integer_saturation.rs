//! Streaming-SVE saturating, halving and absolute-difference arithmetic.
//! Saturation does not change FPSR.QC in these SVE forms. All forms preserve NZCV.
//! Encoding/semantics: Arm ISA_A64_xml_A_profile-2026-06; Apple M4/M5 candidate set.

use crate::aarch64::scalable::{ElementSize, Predication};

const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const IMMEDIATE_MASK: u32 = 255;
const IMMEDIATE_SCALE_FLAG: u32 = 1 << 13;
const IMMEDIATE_SCALE_SHIFT: u32 = 8;
const COMPLEX_ROTATION_FLAG: u32 = 1 << 10;
const PREDICATED_MASK: u32 = 0xff3f_e000;
const REGISTER_OPCODE_MASK: u32 = 0xff20_fc00;
const IMMEDIATE_OPCODE_MASK: u32 = 0xff3f_c000;
const COMPLEX_OPCODE_MASK: u32 = 0xff3f_f800;

const SABA_Z_ZZZ: u32 = 0x4500_f800;
const SABALB_Z_ZZZ: u32 = 0x4500_c000;
const SABALT_Z_ZZZ: u32 = 0x4500_c400;
const SABD_Z_P_ZZ: u32 = 0x040c_0000;
const SABDLB_Z_ZZ: u32 = 0x4500_3000;
const SABDLT_Z_ZZ: u32 = 0x4500_3400;
const SHADD_Z_P_ZZ: u32 = 0x4410_8000;
const SHSUB_Z_P_ZZ: u32 = 0x4412_8000;
const SHSUBR_Z_P_ZZ: u32 = 0x4416_8000;
const SQABS_Z_P_Z: u32 = 0x4408_a000;
const SQADD_Z_P_ZZ: u32 = 0x4418_8000;
const SQADD_Z_ZI: u32 = 0x2524_c000;
const SQADD_Z_ZZ: u32 = 0x0420_1000;
const SQCADD_Z_ZZ: u32 = 0x4501_d800;
const SQNEG_Z_P_Z: u32 = 0x4409_a000;
const SQSUB_Z_P_ZZ: u32 = 0x441a_8000;
const SQSUB_Z_ZI: u32 = 0x2526_c000;
const SQSUB_Z_ZZ: u32 = 0x0420_1800;
const SQSUBR_Z_P_ZZ: u32 = 0x441e_8000;
const SRHADD_Z_P_ZZ: u32 = 0x4414_8000;
const SUQADD_Z_P_ZZ: u32 = 0x441c_8000;
const UABA_Z_ZZZ: u32 = 0x4500_fc00;
const UABALB_Z_ZZZ: u32 = 0x4500_c800;
const UABALT_Z_ZZZ: u32 = 0x4500_cc00;
const UABD_Z_P_ZZ: u32 = 0x040d_0000;
const UABDLB_Z_ZZ: u32 = 0x4500_3800;
const UABDLT_Z_ZZ: u32 = 0x4500_3c00;
const UHADD_Z_P_ZZ: u32 = 0x4411_8000;
const UHSUB_Z_P_ZZ: u32 = 0x4413_8000;
const UHSUBR_Z_P_ZZ: u32 = 0x4417_8000;
const UQADD_Z_P_ZZ: u32 = 0x4419_8000;
const UQADD_Z_ZI: u32 = 0x2525_c000;
const UQADD_Z_ZZ: u32 = 0x0420_1400;
const UQSUB_Z_P_ZZ: u32 = 0x441b_8000;
const UQSUB_Z_ZI: u32 = 0x2527_c000;
const UQSUB_Z_ZZ: u32 = 0x0420_1c00;
const UQSUBR_Z_P_ZZ: u32 = 0x441f_8000;
const URHADD_Z_P_ZZ: u32 = 0x4415_8000;
const USQADD_Z_P_ZZ: u32 = 0x441d_8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signedness {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arithmetic {
    Add,
    Subtract,
    ReverseSubtract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    Bottom,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    Vector(u8),
    Immediate(u16),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Saturating {
        signedness: Signedness,
        arithmetic: Arithmetic,
    },
    MixedSaturatingAdd {
        signed_destination: bool,
    },
    Halving {
        signedness: Signedness,
        arithmetic: Arithmetic,
        round: bool,
    },
    AbsoluteDifference {
        signedness: Signedness,
        widening: Option<Half>,
        accumulate: bool,
    },
    Absolute,
    Negate,
    ComplexAdd {
        rotate_270: bool,
    },
}

/// Vector register 31 is ordinary Z31. Immediate operands are unsigned magnitudes.
/// Widening `element_size` describes the destination, twice the input width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub left: u8,
    pub right: Input,
    pub element_size: ElementSize,
    pub predication: Predication,
    pub kind: Kind,
}

fn saturating(signedness: Signedness, arithmetic: Arithmetic) -> Kind {
    Kind::Saturating {
        signedness,
        arithmetic,
    }
}

fn halving(signedness: Signedness, arithmetic: Arithmetic, round: bool) -> Kind {
    Kind::Halving {
        signedness,
        arithmetic,
        round,
    }
}

fn difference(signedness: Signedness, widening: Option<Half>, accumulate: bool) -> Kind {
    Kind::AbsoluteDifference {
        signedness,
        widening,
        accumulate,
    }
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    use Arithmetic::{Add, ReverseSubtract, Subtract};
    use Half::{Bottom, Top};
    use Signedness::{Signed, Unsigned};
    let destination = (word & REGISTER_MASK) as u8;
    let source = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let right = ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8;
    let element_size = match (word >> SIZE_SHIFT) & SIZE_MASK {
        0 => ElementSize::Byte,
        1 => ElementSize::Halfword,
        2 => ElementSize::Word,
        3 => ElementSize::Doubleword,
        _ => unreachable!(),
    };
    let predicate = ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8;
    let predicated = match word & PREDICATED_MASK {
        SABD_Z_P_ZZ => Some(difference(Signed, None, false)),
        SHADD_Z_P_ZZ => Some(halving(Signed, Add, false)),
        SHSUB_Z_P_ZZ => Some(halving(Signed, Subtract, false)),
        SHSUBR_Z_P_ZZ => Some(halving(Signed, ReverseSubtract, false)),
        SQABS_Z_P_Z => Some(Kind::Absolute),
        SQADD_Z_P_ZZ => Some(saturating(Signed, Add)),
        SQNEG_Z_P_Z => Some(Kind::Negate),
        SQSUB_Z_P_ZZ => Some(saturating(Signed, Subtract)),
        SQSUBR_Z_P_ZZ => Some(saturating(Signed, ReverseSubtract)),
        SRHADD_Z_P_ZZ => Some(halving(Signed, Add, true)),
        SUQADD_Z_P_ZZ => Some(Kind::MixedSaturatingAdd {
            signed_destination: true,
        }),
        UABD_Z_P_ZZ => Some(difference(Unsigned, None, false)),
        UHADD_Z_P_ZZ => Some(halving(Unsigned, Add, false)),
        UHSUB_Z_P_ZZ => Some(halving(Unsigned, Subtract, false)),
        UHSUBR_Z_P_ZZ => Some(halving(Unsigned, ReverseSubtract, false)),
        UQADD_Z_P_ZZ => Some(saturating(Unsigned, Add)),
        UQSUB_Z_P_ZZ => Some(saturating(Unsigned, Subtract)),
        UQSUBR_Z_P_ZZ => Some(saturating(Unsigned, ReverseSubtract)),
        URHADD_Z_P_ZZ => Some(halving(Unsigned, Add, true)),
        USQADD_Z_P_ZZ => Some(Kind::MixedSaturatingAdd {
            signed_destination: false,
        }),
        _ => None,
    };
    if let Some(kind) = predicated {
        let unary = matches!(kind, Kind::Absolute | Kind::Negate);
        return Some(Ok(Operand {
            destination,
            left: if unary { source } else { destination },
            right: if unary {
                Input::None
            } else {
                Input::Vector(source)
            },
            element_size,
            predication: Predication::Merging(predicate),
            kind,
        }));
    }
    let immediate = match word & IMMEDIATE_OPCODE_MASK {
        SQADD_Z_ZI => Some(saturating(Signed, Add)),
        SQSUB_Z_ZI => Some(saturating(Signed, Subtract)),
        UQADD_Z_ZI => Some(saturating(Unsigned, Add)),
        UQSUB_Z_ZI => Some(saturating(Unsigned, Subtract)),
        _ => None,
    };
    if let Some(kind) = immediate {
        let scaled = word & IMMEDIATE_SCALE_FLAG != 0;
        if element_size == ElementSize::Byte && scaled {
            return Some(Err(()));
        }
        let immediate = ((word >> SOURCE_SHIFT) & IMMEDIATE_MASK)
            << if scaled { IMMEDIATE_SCALE_SHIFT } else { 0 };
        return Some(Ok(Operand {
            destination,
            left: destination,
            right: Input::Immediate(immediate as u16),
            element_size,
            predication: Predication::Unpredicated,
            kind,
        }));
    }
    if word & COMPLEX_OPCODE_MASK == SQCADD_Z_ZZ {
        return Some(Ok(Operand {
            destination,
            left: destination,
            right: Input::Vector(source),
            element_size,
            predication: Predication::Unpredicated,
            kind: Kind::ComplexAdd {
                rotate_270: word & COMPLEX_ROTATION_FLAG != 0,
            },
        }));
    }
    let kind = match word & REGISTER_OPCODE_MASK {
        SABA_Z_ZZZ => difference(Signed, None, true),
        SABALB_Z_ZZZ => difference(Signed, Some(Bottom), true),
        SABALT_Z_ZZZ => difference(Signed, Some(Top), true),
        SABDLB_Z_ZZ => difference(Signed, Some(Bottom), false),
        SABDLT_Z_ZZ => difference(Signed, Some(Top), false),
        SQADD_Z_ZZ => saturating(Signed, Add),
        SQSUB_Z_ZZ => saturating(Signed, Subtract),
        UABA_Z_ZZZ => difference(Unsigned, None, true),
        UABALB_Z_ZZZ => difference(Unsigned, Some(Bottom), true),
        UABALT_Z_ZZZ => difference(Unsigned, Some(Top), true),
        UABDLB_Z_ZZ => difference(Unsigned, Some(Bottom), false),
        UABDLT_Z_ZZ => difference(Unsigned, Some(Top), false),
        UQADD_Z_ZZ => saturating(Unsigned, Add),
        UQSUB_Z_ZZ => saturating(Unsigned, Subtract),
        _ => return None,
    };
    if matches!(
        kind,
        Kind::AbsoluteDifference {
            widening: Some(_),
            ..
        }
    ) && element_size == ElementSize::Byte
    {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        destination,
        left: source,
        right: Input::Vector(right),
        element_size,
        predication: Predication::Unpredicated,
        kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturation_preserves_register_aliases_and_all_element_widths() {
        for opcode in [SQADD_Z_ZZ, UQADD_Z_ZZ, SQSUB_Z_ZZ, UQSUB_Z_ZZ] {
            for size in 0..=SIZE_MASK {
                for destination in 0..=REGISTER_MASK {
                    for source in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = opcode
                                | (size << SIZE_SHIFT)
                                | destination
                                | (source << SOURCE_SHIFT)
                                | (right << RIGHT_SHIFT);
                            let operand = decode(word).unwrap().unwrap();
                            assert_eq!(operand.destination, destination as u8);
                            assert_eq!(operand.left, source as u8);
                            assert_eq!(operand.right, Input::Vector(right as u8));
                            assert_eq!(operand.element_size.bytes(), 1 << size);
                            assert_eq!(operand.predication, Predication::Unpredicated);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn predication_uses_low_eight_predicates_and_destructive_destination() {
        for predicate in 0..=PREDICATE_MASK {
            let operand =
                decode(SUQADD_Z_P_ZZ | (predicate << PREDICATE_SHIFT) | (31 << SOURCE_SHIFT) | 31)
                    .unwrap()
                    .unwrap();
            assert_eq!(operand.destination, 31);
            assert_eq!(operand.left, 31);
            assert_eq!(operand.right, Input::Vector(31));
            assert_eq!(operand.predication, Predication::Merging(predicate as u8));
            assert_eq!(
                operand.kind,
                Kind::MixedSaturatingAdd {
                    signed_destination: true
                }
            );
        }
    }

    #[test]
    fn immediate_scaling_and_widening_reserved_sizes_are_explicit() {
        for opcode in [SQADD_Z_ZI, UQADD_Z_ZI, SQSUB_Z_ZI, UQSUB_Z_ZI] {
            assert_eq!(decode(opcode | IMMEDIATE_SCALE_FLAG), Some(Err(())));
            for size in 1..=SIZE_MASK {
                let operand = decode(
                    opcode
                        | (size << SIZE_SHIFT)
                        | IMMEDIATE_SCALE_FLAG
                        | (IMMEDIATE_MASK << SOURCE_SHIFT),
                )
                .unwrap()
                .unwrap();
                assert_eq!(operand.right, Input::Immediate(u16::MAX - 255));
            }
        }
        for opcode in [
            SABDLB_Z_ZZ,
            SABDLT_Z_ZZ,
            UABDLB_Z_ZZ,
            UABDLT_Z_ZZ,
            SABALB_Z_ZZZ,
            SABALT_Z_ZZZ,
            UABALB_Z_ZZZ,
            UABALT_Z_ZZZ,
        ] {
            assert_eq!(decode(opcode), Some(Err(())));
            for size in 1..=SIZE_MASK {
                assert!(decode(opcode | (size << SIZE_SHIFT)).unwrap().is_ok());
            }
        }
    }

    #[test]
    fn complex_rotation_and_noninventory_zeroing_are_distinct() {
        for rotate_270 in [false, true] {
            let word = SQCADD_Z_ZZ | if rotate_270 { COMPLEX_ROTATION_FLAG } else { 0 };
            assert_eq!(
                decode(word).unwrap().unwrap().kind,
                Kind::ComplexAdd { rotate_270 }
            );
        }
        const SQABS_ZEROING: u32 = 0x440a_a000;
        const SQNEG_ZEROING: u32 = 0x440b_a000;
        assert!(decode(SQABS_ZEROING).is_none());
        assert!(decode(SQNEG_ZEROING).is_none());
        assert!(decode(0).is_none());
    }
}
