//! SVE saturating, halving and absolute-difference arithmetic. Saturation does
//! not set FPSR.QC.

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

impl Operand {
    /// MOVPRFX requirements of the follower word. Call before normalizing
    /// destructive operands; the typed operand must still match the word.
    #[allow(clippy::result_unit_err)]
    pub fn prefix_requirement(
        self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        use crate::aarch64::sve::prefix::{PredicatedPrefixRequirement, PrefixRequirement};

        if decode(original_word) != Some(Ok(self)) {
            return Err(());
        }
        let vector = |predicated, other_vector_sources| PrefixRequirement::Vector {
            destination: self.destination,
            predicated,
            other_vector_sources,
        };
        let source_bit = |register: u8| 1_u32 << register;
        if matches!(
            original_word & PREDICATED_MASK,
            SABD_Z_P_ZZ
                | SHADD_Z_P_ZZ
                | SHSUB_Z_P_ZZ
                | SHSUBR_Z_P_ZZ
                | SQABS_Z_P_Z
                | SQADD_Z_P_ZZ
                | SQNEG_Z_P_Z
                | SQSUB_Z_P_ZZ
                | SQSUBR_Z_P_ZZ
                | SRHADD_Z_P_ZZ
                | SUQADD_Z_P_ZZ
                | UABD_Z_P_ZZ
                | UHADD_Z_P_ZZ
                | UHSUB_Z_P_ZZ
                | UHSUBR_Z_P_ZZ
                | UQADD_Z_P_ZZ
                | UQSUB_Z_P_ZZ
                | UQSUBR_Z_P_ZZ
                | URHADD_Z_P_ZZ
                | USQADD_Z_P_ZZ
        ) {
            let Predication::Merging(predicate) = self.predication else {
                return Err(());
            };
            let source = match self.right {
                Input::None => self.left,
                Input::Vector(source) => source,
                Input::Immediate(_) => return Err(()),
            };
            // All twenty forms use equal destination and first-source widths.
            return Ok(Some(vector(
                Some(PredicatedPrefixRequirement {
                    predicate,
                    element: self.element_size,
                }),
                source_bit(source),
            )));
        }
        if matches!(
            original_word & IMMEDIATE_OPCODE_MASK,
            SQADD_Z_ZI | SQSUB_Z_ZI | UQADD_Z_ZI | UQSUB_Z_ZI
        ) {
            return Ok(Some(vector(None, 0)));
        }
        if original_word & COMPLEX_OPCODE_MASK == SQCADD_Z_ZZ {
            let Input::Vector(source) = self.right else {
                return Err(());
            };
            return Ok(Some(vector(None, source_bit(source))));
        }
        let requirement = match original_word & REGISTER_OPCODE_MASK {
            SABA_Z_ZZZ | SABALB_Z_ZZZ | SABALT_Z_ZZZ | UABA_Z_ZZZ | UABALB_Z_ZZZ | UABALT_Z_ZZZ => {
                let Input::Vector(right) = self.right else {
                    return Err(());
                };
                Some(vector(None, source_bit(self.left) | source_bit(right)))
            }
            // Exact constructive pages have no old-destination input. The June
            // MOVPRFX descriptions require a destructive binary/ternary follower
            // or a merging unary follower; these eight forms satisfy neither.
            SABDLB_Z_ZZ | SABDLT_Z_ZZ | UABDLB_Z_ZZ | UABDLT_Z_ZZ | SQADD_Z_ZZ | SQSUB_Z_ZZ
            | UQADD_Z_ZZ | UQSUB_Z_ZZ => Some(PrefixRequirement::Forbidden),
            _ => None,
        };
        Ok(requirement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod prefix_requirement {
        use super::*;
        use crate::aarch64::sve::prefix::{
            DecodedPrefix, PredicatedPrefixRequirement, PrefixRequirement, PrefixViolation,
            validate,
        };

        #[derive(Clone, Copy)]
        struct Fact {
            word: u32,
            allowed: bool,
            predicated: bool,
            sources: u8,
            minimum_size: u32,
        }

        // Independent table extracted from exact June XML fixed bits, operational
        // notes, vector register fields, and the general MOVPRFX follower contract.
        const FACTS: [Fact; 39] = [
            Fact {
                word: 0x4500f800,
                allowed: true,
                predicated: false,
                sources: 2,
                minimum_size: 0,
            }, // saba_z_zzz_
            Fact {
                word: 0x4500c000,
                allowed: true,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // sabalb_z_zzz_
            Fact {
                word: 0x4500c400,
                allowed: true,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // sabalt_z_zzz_
            Fact {
                word: 0x040c0000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // sabd_z_p_zz_
            Fact {
                word: 0x45003000,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // sabdlb_z_zz_
            Fact {
                word: 0x45003400,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // sabdlt_z_zz_
            Fact {
                word: 0x44108000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // shadd_z_p_zz_
            Fact {
                word: 0x44128000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // shsub_z_p_zz_
            Fact {
                word: 0x44168000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // shsubr_z_p_zz_
            Fact {
                word: 0x4408a000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // sqabs_z_p_z_m
            Fact {
                word: 0x44188000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // sqadd_z_p_zz_
            Fact {
                word: 0x2524c000,
                allowed: true,
                predicated: false,
                sources: 0,
                minimum_size: 0,
            }, // sqadd_z_zi_
            Fact {
                word: 0x04201000,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 0,
            }, // sqadd_z_zz_
            Fact {
                word: 0x4501d800,
                allowed: true,
                predicated: false,
                sources: 1,
                minimum_size: 0,
            }, // sqcadd_z_zz_
            Fact {
                word: 0x4409a000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // sqneg_z_p_z_m
            Fact {
                word: 0x441a8000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // sqsub_z_p_zz_
            Fact {
                word: 0x2526c000,
                allowed: true,
                predicated: false,
                sources: 0,
                minimum_size: 0,
            }, // sqsub_z_zi_
            Fact {
                word: 0x04201800,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 0,
            }, // sqsub_z_zz_
            Fact {
                word: 0x441e8000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // sqsubr_z_p_zz_
            Fact {
                word: 0x44148000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // srhadd_z_p_zz_
            Fact {
                word: 0x441c8000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // suqadd_z_p_zz_
            Fact {
                word: 0x4500fc00,
                allowed: true,
                predicated: false,
                sources: 2,
                minimum_size: 0,
            }, // uaba_z_zzz_
            Fact {
                word: 0x4500c800,
                allowed: true,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // uabalb_z_zzz_
            Fact {
                word: 0x4500cc00,
                allowed: true,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // uabalt_z_zzz_
            Fact {
                word: 0x040d0000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // uabd_z_p_zz_
            Fact {
                word: 0x45003800,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // uabdlb_z_zz_
            Fact {
                word: 0x45003c00,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 1,
            }, // uabdlt_z_zz_
            Fact {
                word: 0x44118000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // uhadd_z_p_zz_
            Fact {
                word: 0x44138000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // uhsub_z_p_zz_
            Fact {
                word: 0x44178000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // uhsubr_z_p_zz_
            Fact {
                word: 0x44198000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // uqadd_z_p_zz_
            Fact {
                word: 0x2525c000,
                allowed: true,
                predicated: false,
                sources: 0,
                minimum_size: 0,
            }, // uqadd_z_zi_
            Fact {
                word: 0x04201400,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 0,
            }, // uqadd_z_zz_
            Fact {
                word: 0x441b8000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // uqsub_z_p_zz_
            Fact {
                word: 0x2527c000,
                allowed: true,
                predicated: false,
                sources: 0,
                minimum_size: 0,
            }, // uqsub_z_zi_
            Fact {
                word: 0x04201c00,
                allowed: false,
                predicated: false,
                sources: 2,
                minimum_size: 0,
            }, // uqsub_z_zz_
            Fact {
                word: 0x441f8000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // uqsubr_z_p_zz_
            Fact {
                word: 0x44158000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // urhadd_z_p_zz_
            Fact {
                word: 0x441d8000,
                allowed: true,
                predicated: true,
                sources: 1,
                minimum_size: 0,
            }, // usqadd_z_p_zz_
        ];

        const ELEMENTS: [ElementSize; 4] = [
            ElementSize::Byte,
            ElementSize::Halfword,
            ElementSize::Word,
            ElementSize::Doubleword,
        ];

        fn expected(
            fact: Fact,
            destination: u8,
            source: u8,
            right: u8,
            predicate: u8,
            size: u32,
        ) -> PrefixRequirement {
            if !fact.allowed {
                return PrefixRequirement::Forbidden;
            }
            let other_vector_sources = match fact.sources {
                0 => 0,
                1 => 1_u32 << source,
                2 => (1_u32 << source) | (1_u32 << right),
                _ => panic!("bad independently extracted source count"),
            };
            PrefixRequirement::Vector {
                destination,
                predicated: fact.predicated.then_some(PredicatedPrefixRequirement {
                    predicate,
                    element: ELEMENTS[size as usize],
                }),
                other_vector_sources,
            }
        }

        fn canonical_word(
            fact: Fact,
            destination: u8,
            source: u8,
            right: u8,
            predicate: u8,
            size: u32,
        ) -> u32 {
            let mut word = fact.word | u32::from(destination) | (size << 22);
            if fact.sources >= 1 {
                word |= u32::from(source) << 5;
            }
            if fact.sources == 2 {
                word |= u32::from(right) << 16;
            }
            if fact.predicated {
                word |= u32::from(predicate) << 10;
            }
            word
        }

        #[test]
        fn all_39_canonical_policies_widths_predicates_and_register_roles_match_independent_table()
        {
            let mut cases = 0;
            for fact in FACTS {
                for size in fact.minimum_size..4 {
                    for predicate in 0..if fact.predicated { 8 } else { 1 } {
                        for destination in 0..32 {
                            for source in 0..32 {
                                let right = 31 - source;
                                let word = canonical_word(
                                    fact,
                                    destination,
                                    source,
                                    right,
                                    predicate,
                                    size,
                                );
                                let operand = decode(word)
                                    .expect("canonical word")
                                    .expect("allocated fields");
                                let requirement = operand
                                    .prefix_requirement(word)
                                    .expect("matching operand")
                                    .expect("audited form");
                                assert_eq!(
                                    requirement,
                                    expected(fact, destination, source, right, predicate, size),
                                    "word={word:08x}"
                                );
                                cases += 1;
                            }
                        }
                    }
                }
            }
            assert_eq!(cases, 724992);
        }

        #[test]
        fn actual_prefix_validator_observes_aliasing_predicates_elements_and_forbidden_forms() {
            for fact in FACTS {
                for size in fact.minimum_size..4 {
                    for predicate in 0..if fact.predicated { 8 } else { 1 } {
                        for (destination, source, right) in
                            [(3, 5, 7), (31, 0, 30), (3, 3, 7), (3, 5, 3), (31, 31, 31)]
                        {
                            let word =
                                canonical_word(fact, destination, source, right, predicate, size);
                            let operand = decode(word).unwrap().unwrap();
                            let requirement = operand.prefix_requirement(word).unwrap().unwrap();
                            let alias = fact.sources >= 1 && source == destination
                                || fact.sources == 2 && right == destination;
                            let prior_error = if !fact.allowed {
                                Some(PrefixViolation::FollowerNotAuthorized)
                            } else if alias {
                                Some(PrefixViolation::OtherSourceAlias)
                            } else {
                                None
                            };
                            let base = DecodedPrefix {
                                destination,
                                source: 9,
                                predication: Predication::Unpredicated,
                                element: None,
                            };
                            assert_eq!(
                                validate(base, requirement),
                                prior_error.map_or(Ok(()), Err)
                            );
                            let changed_destination = DecodedPrefix {
                                destination: (destination + 1) % 32,
                                ..base
                            };
                            assert_eq!(
                                validate(changed_destination, requirement),
                                Err(if fact.allowed {
                                    PrefixViolation::DestinationMismatch
                                } else {
                                    PrefixViolation::FollowerNotAuthorized
                                })
                            );
                            for mode in [
                                Predication::Merging(predicate),
                                Predication::Zeroing(predicate),
                            ] {
                                for element in ELEMENTS {
                                    let prefix = DecodedPrefix {
                                        predication: mode,
                                        element: Some(element),
                                        ..base
                                    };
                                    let error = prior_error.or(if !fact.predicated {
                                        Some(PrefixViolation::PredicatedPrefixForbidden)
                                    } else if element != ELEMENTS[size as usize] {
                                        Some(PrefixViolation::ElementMismatch)
                                    } else {
                                        None
                                    });
                                    assert_eq!(
                                        validate(prefix, requirement),
                                        error.map_or(Ok(()), Err)
                                    );
                                }
                            }
                            let different_predicate = DecodedPrefix {
                                predication: Predication::Merging((predicate + 1) % 8),
                                element: Some(ELEMENTS[size as usize]),
                                ..base
                            };
                            let error = prior_error.or(Some(if fact.predicated {
                                PrefixViolation::PredicateMismatch
                            } else {
                                PrefixViolation::PredicatedPrefixForbidden
                            }));
                            assert_eq!(
                                validate(different_predicate, requirement),
                                error.map_or(Ok(()), Err)
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn source_word_or_any_typed_operand_mismatch_is_an_error_before_authorization() {
            for fact in FACTS {
                let word = canonical_word(fact, 3, 5, 7, 2, fact.minimum_size);
                let operand = decode(word).unwrap().unwrap();
                let mut forged = operand;
                forged.destination = 4;
                assert_eq!(forged.prefix_requirement(word), Err(()));
                forged = operand;
                forged.left ^= 1;
                assert_eq!(forged.prefix_requirement(word), Err(()));
                forged = operand;
                forged.right = match operand.right {
                    Input::Vector(v) => Input::Vector(v ^ 1),
                    Input::Immediate(v) => Input::Immediate(v ^ 1),
                    Input::None => Input::Vector(0),
                };
                assert_eq!(forged.prefix_requirement(word), Err(()));
                forged = operand;
                forged.element_size = ElementSize::Quadword;
                assert_eq!(forged.prefix_requirement(word), Err(()));
                forged = operand;
                forged.predication = Predication::Zeroing(2);
                assert_eq!(forged.prefix_requirement(word), Err(()));
                forged = operand;
                forged.kind = if operand.kind == Kind::Absolute {
                    Kind::Negate
                } else {
                    Kind::Absolute
                };
                assert_eq!(forged.prefix_requirement(word), Err(()));
                assert_eq!(operand.prefix_requirement(word ^ (1 << 31)), Err(()));
                assert_eq!(operand.prefix_requirement(0), Err(()));
            }
        }

        #[test]
        fn immediate_scaling_rotation_and_reserved_fields_remain_exact() {
            for fact in FACTS {
                if fact.sources == 0 {
                    for size in 0..4 {
                        for immediate in [0, 1, 127, 128, 255] {
                            for shifted in [false, true] {
                                let word = fact.word
                                    | (size << 22)
                                    | (immediate << 5)
                                    | 31
                                    | if shifted { 1 << 13 } else { 0 };
                                if size == 0 && shifted {
                                    assert_eq!(decode(word), Some(Err(())));
                                    let operand = decode(fact.word).unwrap().unwrap();
                                    assert_eq!(operand.prefix_requirement(word), Err(()));
                                } else {
                                    let operand = decode(word).unwrap().unwrap();
                                    assert_eq!(
                                        operand.prefix_requirement(word),
                                        Ok(Some(PrefixRequirement::Vector {
                                            destination: 31,
                                            predicated: None,
                                            other_vector_sources: 0
                                        }))
                                    );
                                }
                            }
                        }
                    }
                }
                if fact.minimum_size == 1 {
                    assert_eq!(decode(fact.word), Some(Err(())));
                    let operand = decode(fact.word | (1 << 22)).unwrap().unwrap();
                    assert_eq!(operand.prefix_requirement(fact.word), Err(()));
                }
            }
            for size in 0..4 {
                for rotation in [0, 1 << 10] {
                    let word = 0x4501d800 | (size << 22) | rotation | (31 << 5) | 3;
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(
                        operand.prefix_requirement(word),
                        Ok(Some(PrefixRequirement::Vector {
                            destination: 3,
                            predicated: None,
                            other_vector_sources: 1_u32 << 31
                        }))
                    );
                }
            }
            for zeroing in [0x440aa000, 0x440ba000] {
                assert_eq!(decode(zeroing), None);
                let operand = decode(0x4408a000).unwrap().unwrap();
                assert_eq!(operand.prefix_requirement(zeroing), Err(()));
            }
        }

        #[test]
        fn malformed_prefix_metadata_is_rejected_by_the_actual_frozen_validator() {
            let word = 0x44188000 | (7 << 10) | (5 << 5) | 3;
            let requirement = decode(word)
                .unwrap()
                .unwrap()
                .prefix_requirement(word)
                .unwrap()
                .unwrap();
            let base = DecodedPrefix {
                destination: 3,
                source: 9,
                predication: Predication::Merging(7),
                element: Some(ElementSize::Byte),
            };
            assert_eq!(
                validate(DecodedPrefix { source: 32, ..base }, requirement),
                Err(PrefixViolation::InvalidPrefixSource(32))
            );
            assert_eq!(
                validate(
                    DecodedPrefix {
                        destination: 32,
                        ..base
                    },
                    requirement
                ),
                Err(PrefixViolation::InvalidPrefixDestination(32))
            );
            assert_eq!(
                validate(
                    DecodedPrefix {
                        predication: Predication::Zeroing(8),
                        ..base
                    },
                    requirement
                ),
                Err(PrefixViolation::InvalidPrefixPredicate(8))
            );
            assert_eq!(
                validate(
                    DecodedPrefix {
                        element: None,
                        ..base
                    },
                    requirement
                ),
                Err(PrefixViolation::MissingPrefixElement)
            );
            assert_eq!(
                validate(
                    DecodedPrefix {
                        element: Some(ElementSize::Quadword),
                        ..base
                    },
                    requirement
                ),
                Err(PrefixViolation::UnallocatedPrefixElement(
                    ElementSize::Quadword
                ))
            );
        }
    }

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
