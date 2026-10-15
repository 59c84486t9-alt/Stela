//! Streaming-SVE extension, pair arithmetic and narrowing-high operand decoding.
//! Feature/mode and MOVPRFX checks belong to the shared scalable boundary.
use crate::aarch64::scalable::{ElementSize, Predication};

const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const PREDICATE_SHIFT: u32 = 10;
const REGISTER_MASK: u32 = 31;
const PREDICATE_MASK: u32 = 7;
const UNPACK_MASK: u32 = 0xff3f_fc00;
const PREDICATED_MASK: u32 = 0xff3f_e000;
const NARROW_HIGH_MASK: u32 = 0xff20_fc00;

const SUNPKLO: u32 = 0x0530_3800;
const SUNPKHI: u32 = 0x0531_3800;
const UUNPKLO: u32 = 0x0532_3800;
const UUNPKHI: u32 = 0x0533_3800;
const SXTB: u32 = 0x0410_a000;
const UXTB: u32 = 0x0411_a000;
const SXTH: u32 = 0x0412_a000;
const UXTH: u32 = 0x0413_a000;
const SXTW: u32 = 0x0414_a000;
const UXTW: u32 = 0x0415_a000;
const SADALP: u32 = 0x4404_a000;
const UADALP: u32 = 0x4405_a000;
const ADDP: u32 = 0x4411_a000;
const SMAXP: u32 = 0x4414_a000;
const UMAXP: u32 = 0x4415_a000;
const SMINP: u32 = 0x4416_a000;
const UMINP: u32 = 0x4417_a000;
const ADDHNB: u32 = 0x4520_6000;
const ADDHNT: u32 = 0x4520_6400;
const RADDHNB: u32 = 0x4520_6800;
const RADDHNT: u32 = 0x4520_6c00;
const SUBHNB: u32 = 0x4520_7000;
const SUBHNT: u32 = 0x4520_7400;
const RSUBHNB: u32 = 0x4520_7800;
const RSUBHNT: u32 = 0x4520_7c00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signedness {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    Bottom,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arithmetic {
    Add,
    Subtract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairOperation {
    Add,
    Minimum(Signedness),
    Maximum(Signedness),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Unpack {
        source: u8,
        signedness: Signedness,
        half: Half,
    },
    Extend {
        source: u8,
        input_size: ElementSize,
        signedness: Signedness,
    },
    NarrowHigh {
        left: u8,
        right: u8,
        arithmetic: Arithmetic,
        round: bool,
        half: Half,
    },
    Pair {
        right: u8,
        operation: PairOperation,
    },
    PairAccumulate {
        source: u8,
        signedness: Signedness,
    },
}

/// NarrowHigh uses the wide source size. Other kinds use the result size.
/// Pair and PairAccumulate read the old destination before any destination write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub element_size: ElementSize,
    pub predication: Predication,
    pub kind: Kind,
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    use Arithmetic::{Add, Subtract};
    use Half::{Bottom, Top};
    use Signedness::{Signed, Unsigned};
    let source = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let right = ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8;
    let kind = match word & UNPACK_MASK {
        SUNPKLO => Some(Kind::Unpack {
            source,
            signedness: Signed,
            half: Bottom,
        }),
        SUNPKHI => Some(Kind::Unpack {
            source,
            signedness: Signed,
            half: Top,
        }),
        UUNPKLO => Some(Kind::Unpack {
            source,
            signedness: Unsigned,
            half: Bottom,
        }),
        UUNPKHI => Some(Kind::Unpack {
            source,
            signedness: Unsigned,
            half: Top,
        }),
        _ => None,
    }
    .or(match word & PREDICATED_MASK {
        SXTB => Some(Kind::Extend {
            source,
            input_size: ElementSize::Byte,
            signedness: Signed,
        }),
        UXTB => Some(Kind::Extend {
            source,
            input_size: ElementSize::Byte,
            signedness: Unsigned,
        }),
        SXTH => Some(Kind::Extend {
            source,
            input_size: ElementSize::Halfword,
            signedness: Signed,
        }),
        UXTH => Some(Kind::Extend {
            source,
            input_size: ElementSize::Halfword,
            signedness: Unsigned,
        }),
        SXTW => Some(Kind::Extend {
            source,
            input_size: ElementSize::Word,
            signedness: Signed,
        }),
        UXTW => Some(Kind::Extend {
            source,
            input_size: ElementSize::Word,
            signedness: Unsigned,
        }),
        SADALP => Some(Kind::PairAccumulate {
            source,
            signedness: Signed,
        }),
        UADALP => Some(Kind::PairAccumulate {
            source,
            signedness: Unsigned,
        }),
        ADDP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Add,
        }),
        SMAXP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Maximum(Signed),
        }),
        UMAXP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Maximum(Unsigned),
        }),
        SMINP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Minimum(Signed),
        }),
        UMINP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Minimum(Unsigned),
        }),
        _ => None,
    })
    .or(match word & NARROW_HIGH_MASK {
        ADDHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: false,
            half: Bottom,
        }),
        ADDHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: false,
            half: Top,
        }),
        RADDHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: true,
            half: Bottom,
        }),
        RADDHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: true,
            half: Top,
        }),
        SUBHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: false,
            half: Bottom,
        }),
        SUBHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: false,
            half: Top,
        }),
        RSUBHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: true,
            half: Bottom,
        }),
        RSUBHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: true,
            half: Top,
        }),
        _ => None,
    })?;
    let element_size = ElementSize::from_bytes(1 << ((word >> SIZE_SHIFT) & SIZE_MASK))
        .expect("a two-bit element size is always a valid integer size");
    let minimum_bits = match kind {
        Kind::Pair { .. } => ElementSize::Byte.bits(),
        Kind::Extend { input_size, .. } => input_size.bits() * 2,
        _ => ElementSize::Halfword.bits(),
    };
    if element_size.bits() < minimum_bits {
        return Some(Err(()));
    }
    let predication = match kind {
        Kind::Extend { .. } | Kind::Pair { .. } | Kind::PairAccumulate { .. } => {
            Predication::Merging(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8)
        }
        _ => Predication::Unpredicated,
    };
    Some(Ok(Operand {
        destination: (word & REGISTER_MASK) as u8,
        element_size,
        predication,
        kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_SIZE: u32 = 1;
    const WORD_SIZE: u32 = 2;
    const DOUBLEWORD_SIZE: u32 = 3;
    const ENCODINGS: [(u32, u32); 25] = [
        (SUNPKLO, FIRST_SIZE),
        (SUNPKHI, FIRST_SIZE),
        (UUNPKLO, FIRST_SIZE),
        (UUNPKHI, FIRST_SIZE),
        (SXTB, FIRST_SIZE),
        (UXTB, FIRST_SIZE),
        (SXTH, WORD_SIZE),
        (UXTH, WORD_SIZE),
        (SXTW, DOUBLEWORD_SIZE),
        (UXTW, DOUBLEWORD_SIZE),
        (SADALP, FIRST_SIZE),
        (UADALP, FIRST_SIZE),
        (ADDP, 0),
        (SMAXP, 0),
        (UMAXP, 0),
        (SMINP, 0),
        (UMINP, 0),
        (ADDHNB, FIRST_SIZE),
        (ADDHNT, FIRST_SIZE),
        (RADDHNB, FIRST_SIZE),
        (RADDHNT, FIRST_SIZE),
        (SUBHNB, FIRST_SIZE),
        (SUBHNT, FIRST_SIZE),
        (RSUBHNB, FIRST_SIZE),
        (RSUBHNT, FIRST_SIZE),
    ];

    #[test]
    fn size_allocations_are_complete_and_reserved_sizes_decline() {
        for (encoding, minimum_size) in ENCODINGS {
            for size in 0..=SIZE_MASK {
                let result = decode(encoding | size << SIZE_SHIFT).unwrap();
                assert_eq!(result.is_ok(), size >= minimum_size);
                if let Ok(operand) = result {
                    assert_eq!(operand.element_size.bytes(), 1 << size);
                }
            }
        }
    }

    #[test]
    fn all_vector_registers_and_governing_predicates_decode() {
        for (encoding, minimum_size) in ENCODINGS {
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    for predicate in 0..=PREDICATE_MASK {
                        let template = decode(encoding | minimum_size << SIZE_SHIFT)
                            .unwrap()
                            .unwrap();
                        let narrow = matches!(template.kind, Kind::NarrowHigh { .. });
                        let predicated = matches!(template.predication, Predication::Merging(_));
                        let right = REGISTER_MASK - source;
                        let word = encoding
                            | minimum_size << SIZE_SHIFT
                            | destination
                            | source << SOURCE_SHIFT
                            | if narrow { right << RIGHT_SHIFT } else { 0 }
                            | if predicated {
                                predicate << PREDICATE_SHIFT
                            } else {
                                0
                            };
                        let operand = decode(word).unwrap().unwrap();
                        assert_eq!(operand.destination, destination as u8);
                        assert_eq!(
                            operand.predication,
                            if predicated {
                                Predication::Merging(predicate as u8)
                            } else {
                                Predication::Unpredicated
                            }
                        );
                        match operand.kind {
                            Kind::Unpack { source: actual, .. }
                            | Kind::Extend { source: actual, .. }
                            | Kind::PairAccumulate { source: actual, .. } => {
                                assert_eq!(actual, source as u8);
                            }
                            Kind::Pair { right: actual, .. } => assert_eq!(actual, source as u8),
                            Kind::NarrowHigh {
                                left: actual_left,
                                right: actual_right,
                                ..
                            } => {
                                assert_eq!(actual_left, source as u8);
                                assert_eq!(actual_right, right as u8);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn distinct_families_and_zeroing_extension_forms_are_not_claimed() {
        const ZEROING_EXTENSION_BIT: u32 = 1 << 20;
        assert!(decode(0).is_none());
        for encoding in [SXTB, UXTB, SXTH, UXTH, SXTW, UXTW] {
            assert!(
                decode((encoding & !ZEROING_EXTENSION_BIT) | DOUBLEWORD_SIZE << SIZE_SHIFT)
                    .is_none()
            );
        }
    }
}
