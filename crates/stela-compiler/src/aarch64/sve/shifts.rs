//! SVE shifts, shift-accumulates, shift-inserts and XAR.
use crate::aarch64::scalable::{ElementSize, Predication};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    ArithmeticRight,
    DivideSigned,
    LogicalLeft,
    LogicalRight,
    InsertLeft,
    InsertRight,
    SaturatingSigned,
    SaturatingUnsigned,
    SaturatingSignedToUnsigned,
    RoundingSigned,
    RoundingUnsigned,
    SaturatingRoundingSigned,
    SaturatingRoundingUnsigned,
    RoundRightSigned,
    RoundRightUnsigned,
    AccumulateSigned,
    AccumulateUnsigned,
    RoundAccumulateSigned,
    RoundAccumulateUnsigned,
    XorRotate,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Count {
    Immediate(u8),
    Elements(u8),
    Doublewords(u8),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operand {
    pub kind: Kind,
    pub element_size: ElementSize,
    pub destination: u8,
    pub source: u8,
    pub predication: Predication,
    pub second_source: Option<u8>,
    pub count: Count,
    /// Canonical DIT obligation under SVE2 or SME, before operand normalization.
    pub has_dit_guarantee: bool,
}
#[derive(Clone, Copy)]
enum Format {
    PredicatedImmediate,
    Immediate,
    PredicatedElements,
    ReverseElements,
    PredicatedDoublewords,
    Doublewords,
    XorRotate,
}
struct Encoding {
    mask: u32,
    value: u32,
    kind: Kind,
    format: Format,
}
impl Encoding {
    fn has_dit_guarantee(&self) -> bool {
        match self.kind {
            Kind::SaturatingSigned
            | Kind::SaturatingUnsigned
            | Kind::SaturatingSignedToUnsigned
            | Kind::SaturatingRoundingSigned
            | Kind::SaturatingRoundingUnsigned => false,
            Kind::RoundingSigned | Kind::RoundingUnsigned => {
                !matches!(self.format, Format::ReverseElements)
            }
            _ => true,
        }
    }
}

const REGISTER_MASK: u32 = 31;
const PREDICATE_MASK: u32 = 7;
const SIZE_MASK: u32 = 3;
const SIZE_SHIFT: u32 = 22;
const PREDICATE_SHIFT: u32 = 10;
const SOURCE_SHIFT: u32 = 5;
const WIDE_SOURCE_SHIFT: u32 = 16;
const PREDICATED_TSIZE_LOW_SHIFT: u32 = 8;
const PREDICATED_IMMEDIATE_SHIFT: u32 = 5;
const TSIZE_LOW_SHIFT: u32 = 19;
const IMMEDIATE_SHIFT: u32 = 16;
const IMMEDIATE_MASK: u32 = 7;
const BYTE_BITS: u8 = 8;

const PREDICATED_OPCODE_MASK: u32 = 0xff3f_e000;
const UNPREDICATED_OPCODE_MASK: u32 = 0xff20_fc00;
const ASR_Z_P_ZI: u32 = 0x04008000;
const ASR_Z_P_ZW: u32 = 0x04188000;
const ASR_Z_P_ZZ: u32 = 0x04108000;
const ASR_Z_ZI: u32 = 0x04209000;
const ASR_Z_ZW: u32 = 0x04208000;
const ASRD_Z_P_ZI: u32 = 0x04048000;
const LSL_Z_P_ZI: u32 = 0x04038000;
const LSL_Z_P_ZW: u32 = 0x041b8000;
const LSL_Z_P_ZZ: u32 = 0x04138000;
const LSL_Z_ZI: u32 = 0x04209c00;
const LSL_Z_ZW: u32 = 0x04208c00;
const LSR_Z_P_ZI: u32 = 0x04018000;
const LSR_Z_P_ZW: u32 = 0x04198000;
const LSR_Z_P_ZZ: u32 = 0x04118000;
const LSR_Z_ZI: u32 = 0x04209400;
const LSR_Z_ZW: u32 = 0x04208400;
const SLI_Z_ZZI: u32 = 0x4500f400;
const SQRSHL_Z_P_ZZ: u32 = 0x440a8000;
const SQSHL_Z_P_ZI: u32 = 0x04068000;
const SQSHL_Z_P_ZZ: u32 = 0x44088000;
const SQSHLU_Z_P_ZI: u32 = 0x040f8000;
const SRI_Z_ZZI: u32 = 0x4500f000;
const SRSHL_Z_P_ZZ: u32 = 0x44028000;
const SRSHR_Z_P_ZI: u32 = 0x040c8000;
const SRSRA_Z_ZI: u32 = 0x4500e800;
const SSRA_Z_ZI: u32 = 0x4500e000;
const UQRSHL_Z_P_ZZ: u32 = 0x440b8000;
const UQSHL_Z_P_ZI: u32 = 0x04078000;
const UQSHL_Z_P_ZZ: u32 = 0x44098000;
const URSHL_Z_P_ZZ: u32 = 0x44038000;
const URSHR_Z_P_ZI: u32 = 0x040d8000;
const URSRA_Z_ZI: u32 = 0x4500ec00;
const USRA_Z_ZI: u32 = 0x4500e400;
const XAR_Z_ZZI: u32 = 0x04203400;

const ASRR_Z_P_ZZ: u32 = 0x04148000;
const LSLR_Z_P_ZZ: u32 = 0x04178000;
const LSRR_Z_P_ZZ: u32 = 0x04158000;
const SQRSHLR_Z_P_ZZ: u32 = 0x440e8000;
const SQSHLR_Z_P_ZZ: u32 = 0x440c8000;
const SRSHLR_Z_P_ZZ: u32 = 0x44068000;
const UQRSHLR_Z_P_ZZ: u32 = 0x440f8000;
const UQSHLR_Z_P_ZZ: u32 = 0x440d8000;
const URSHLR_Z_P_ZZ: u32 = 0x44078000;

const ENCODINGS: &[Encoding] = &[
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: ASRR_Z_P_ZZ,
        kind: Kind::ArithmeticRight,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSLR_Z_P_ZZ,
        kind: Kind::LogicalLeft,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSRR_Z_P_ZZ,
        kind: Kind::LogicalRight,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SQRSHLR_Z_P_ZZ,
        kind: Kind::SaturatingRoundingSigned,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SQSHLR_Z_P_ZZ,
        kind: Kind::SaturatingSigned,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SRSHLR_Z_P_ZZ,
        kind: Kind::RoundingSigned,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: UQRSHLR_Z_P_ZZ,
        kind: Kind::SaturatingRoundingUnsigned,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: UQSHLR_Z_P_ZZ,
        kind: Kind::SaturatingUnsigned,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: URSHLR_Z_P_ZZ,
        kind: Kind::RoundingUnsigned,
        format: Format::ReverseElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: ASR_Z_P_ZI,
        kind: Kind::ArithmeticRight,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: ASR_Z_P_ZW,
        kind: Kind::ArithmeticRight,
        format: Format::PredicatedDoublewords,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: ASR_Z_P_ZZ,
        kind: Kind::ArithmeticRight,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: ASR_Z_ZI,
        kind: Kind::ArithmeticRight,
        format: Format::Immediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: ASR_Z_ZW,
        kind: Kind::ArithmeticRight,
        format: Format::Doublewords,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: ASRD_Z_P_ZI,
        kind: Kind::DivideSigned,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSL_Z_P_ZI,
        kind: Kind::LogicalLeft,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSL_Z_P_ZW,
        kind: Kind::LogicalLeft,
        format: Format::PredicatedDoublewords,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSL_Z_P_ZZ,
        kind: Kind::LogicalLeft,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: LSL_Z_ZI,
        kind: Kind::LogicalLeft,
        format: Format::Immediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: LSL_Z_ZW,
        kind: Kind::LogicalLeft,
        format: Format::Doublewords,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSR_Z_P_ZI,
        kind: Kind::LogicalRight,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSR_Z_P_ZW,
        kind: Kind::LogicalRight,
        format: Format::PredicatedDoublewords,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: LSR_Z_P_ZZ,
        kind: Kind::LogicalRight,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: LSR_Z_ZI,
        kind: Kind::LogicalRight,
        format: Format::Immediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: LSR_Z_ZW,
        kind: Kind::LogicalRight,
        format: Format::Doublewords,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: SLI_Z_ZZI,
        kind: Kind::InsertLeft,
        format: Format::Immediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SQRSHL_Z_P_ZZ,
        kind: Kind::SaturatingRoundingSigned,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SQSHL_Z_P_ZI,
        kind: Kind::SaturatingSigned,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SQSHL_Z_P_ZZ,
        kind: Kind::SaturatingSigned,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SQSHLU_Z_P_ZI,
        kind: Kind::SaturatingSignedToUnsigned,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: SRI_Z_ZZI,
        kind: Kind::InsertRight,
        format: Format::Immediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SRSHL_Z_P_ZZ,
        kind: Kind::RoundingSigned,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: SRSHR_Z_P_ZI,
        kind: Kind::RoundRightSigned,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: SRSRA_Z_ZI,
        kind: Kind::RoundAccumulateSigned,
        format: Format::Immediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: SSRA_Z_ZI,
        kind: Kind::AccumulateSigned,
        format: Format::Immediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: UQRSHL_Z_P_ZZ,
        kind: Kind::SaturatingRoundingUnsigned,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: UQSHL_Z_P_ZI,
        kind: Kind::SaturatingUnsigned,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: UQSHL_Z_P_ZZ,
        kind: Kind::SaturatingUnsigned,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: URSHL_Z_P_ZZ,
        kind: Kind::RoundingUnsigned,
        format: Format::PredicatedElements,
    },
    Encoding {
        mask: PREDICATED_OPCODE_MASK,
        value: URSHR_Z_P_ZI,
        kind: Kind::RoundRightUnsigned,
        format: Format::PredicatedImmediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: URSRA_Z_ZI,
        kind: Kind::RoundAccumulateUnsigned,
        format: Format::Immediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: USRA_Z_ZI,
        kind: Kind::AccumulateUnsigned,
        format: Format::Immediate,
    },
    Encoding {
        mask: UNPREDICATED_OPCODE_MASK,
        value: XAR_Z_ZZI,
        kind: Kind::XorRotate,
        format: Format::XorRotate,
    },
];

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = ENCODINGS
        .iter()
        .find(|entry| word & entry.mask == entry.value)?;
    let destination = (word & REGISTER_MASK) as u8;
    let predicated = matches!(
        encoding.format,
        Format::PredicatedImmediate
            | Format::PredicatedElements
            | Format::PredicatedDoublewords
            | Format::ReverseElements
    );
    let predicate = predicated.then_some(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8);
    let source = if matches!(encoding.format, Format::ReverseElements) {
        ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8
    } else if predicated || matches!(encoding.format, Format::XorRotate) {
        destination
    } else {
        ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8
    };
    let immediate = matches!(
        encoding.format,
        Format::PredicatedImmediate | Format::Immediate | Format::XorRotate
    );
    let size = (word >> SIZE_SHIFT) & SIZE_MASK;
    let (element_bits, count) = if immediate {
        let (size_low_shift, immediate_shift) = if predicated {
            (PREDICATED_TSIZE_LOW_SHIFT, PREDICATED_IMMEDIATE_SHIFT)
        } else {
            (TSIZE_LOW_SHIFT, IMMEDIATE_SHIFT)
        };
        let tsize = (size << 2) | ((word >> size_low_shift) & SIZE_MASK);
        if tsize == 0 {
            return Some(Err(()));
        }
        let element_bits = BYTE_BITS << (u32::BITS - 1 - tsize.leading_zeros());
        let encoded = ((tsize << 3) | ((word >> immediate_shift) & IMMEDIATE_MASK)) as u8;
        let left = matches!(
            encoding.kind,
            Kind::LogicalLeft
                | Kind::InsertLeft
                | Kind::SaturatingSigned
                | Kind::SaturatingUnsigned
                | Kind::SaturatingSignedToUnsigned
        );
        let amount = if left {
            encoded - element_bits
        } else {
            2 * element_bits - encoded
        };
        (element_bits, Count::Immediate(amount))
    } else {
        let wide = matches!(
            encoding.format,
            Format::PredicatedDoublewords | Format::Doublewords
        );
        if wide && size == SIZE_MASK {
            return Some(Err(()));
        }
        let register_shift = if matches!(encoding.format, Format::Doublewords) {
            WIDE_SOURCE_SHIFT
        } else {
            SOURCE_SHIFT
        };
        let register = if matches!(encoding.format, Format::ReverseElements) {
            destination
        } else {
            ((word >> register_shift) & REGISTER_MASK) as u8
        };
        (
            BYTE_BITS << size,
            if wide {
                Count::Doublewords(register)
            } else {
                Count::Elements(register)
            },
        )
    };
    let second_source = matches!(encoding.format, Format::XorRotate)
        .then_some(((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8);
    let Some(element_size) = ElementSize::from_bytes(usize::from(element_bits / BYTE_BITS)) else {
        return Some(Err(()));
    };
    let predication = predicate.map_or(Predication::Unpredicated, Predication::Merging);
    Some(Ok(Operand {
        kind: encoding.kind,
        has_dit_guarantee: encoding.has_dit_guarantee(),
        element_size,
        destination,
        source,
        predication,
        second_source,
        count,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_size_allocations_and_boundaries() {
        for encoding in ENCODINGS {
            let predicated = matches!(encoding.format, Format::PredicatedImmediate);
            if !matches!(
                encoding.format,
                Format::PredicatedImmediate | Format::Immediate | Format::XorRotate
            ) {
                continue;
            }
            let (low_shift, immediate_shift) = if predicated {
                (PREDICATED_TSIZE_LOW_SHIFT, PREDICATED_IMMEDIATE_SHIFT)
            } else {
                (TSIZE_LOW_SHIFT, IMMEDIATE_SHIFT)
            };
            for tsize in 0_u32..16 {
                for immediate in 0..=IMMEDIATE_MASK {
                    let word = encoding.value
                        | (tsize >> 2) << SIZE_SHIFT
                        | (tsize & SIZE_MASK) << low_shift
                        | immediate << immediate_shift
                        | REGISTER_MASK;
                    let result = decode(word).expect("owned immediate encoding");
                    if tsize == 0 {
                        assert_eq!(result, Err(()));
                        continue;
                    }
                    let operand = result.unwrap();
                    let expected_bits =
                        usize::from(BYTE_BITS) << (u32::BITS - 1 - tsize.leading_zeros());
                    assert_eq!(operand.element_size.bits(), expected_bits);
                    assert_eq!(operand.destination, REGISTER_MASK as u8);
                    let Count::Immediate(amount) = operand.count else {
                        panic!("immediate operand");
                    };
                    let left = matches!(
                        operand.kind,
                        Kind::LogicalLeft
                            | Kind::InsertLeft
                            | Kind::SaturatingSigned
                            | Kind::SaturatingUnsigned
                            | Kind::SaturatingSignedToUnsigned
                    );
                    assert!(
                        usize::from(amount) < expected_bits
                            || !left && usize::from(amount) == expected_bits
                    );
                    assert!(left || amount != 0);
                }
            }
        }
    }

    #[test]
    fn register_forms_preserve_count_shape_and_aliases() {
        for encoding in ENCODINGS {
            if !matches!(
                encoding.format,
                Format::PredicatedElements | Format::PredicatedDoublewords | Format::Doublewords
            ) {
                continue;
            }
            let wide = matches!(
                encoding.format,
                Format::PredicatedDoublewords | Format::Doublewords
            );
            let unpredicated = matches!(encoding.format, Format::Doublewords);
            for size in 0..=SIZE_MASK {
                let count_shift = if unpredicated {
                    WIDE_SOURCE_SHIFT
                } else {
                    SOURCE_SHIFT
                };
                let word = encoding.value
                    | size << SIZE_SHIFT
                    | REGISTER_MASK << count_shift
                    | REGISTER_MASK
                    | if unpredicated {
                        0
                    } else {
                        PREDICATE_MASK << PREDICATE_SHIFT
                    };
                let result = decode(word).expect("owned register encoding");
                if wide && size == SIZE_MASK {
                    assert_eq!(result, Err(()));
                    continue;
                }
                let operand = result.unwrap();
                assert_eq!(operand.destination, REGISTER_MASK as u8);
                assert_eq!(
                    operand.count,
                    if wide {
                        Count::Doublewords(REGISTER_MASK as u8)
                    } else {
                        Count::Elements(REGISTER_MASK as u8)
                    }
                );
                assert_eq!(
                    operand.predication,
                    if unpredicated {
                        Predication::Unpredicated
                    } else {
                        Predication::Merging(PREDICATE_MASK as u8)
                    }
                );
            }
        }
    }

    #[test]
    fn xor_rotate_retains_both_inputs_and_width_rotation() {
        let word = XAR_Z_ZZI | 1 << TSIZE_LOW_SHIFT | 9 << SOURCE_SHIFT | 31;
        let operand = decode(word).unwrap().unwrap();
        assert_eq!(operand.kind, Kind::XorRotate);
        assert_eq!(operand.element_size, ElementSize::Byte);
        assert_eq!(operand.source, 31);
        assert_eq!(operand.second_source, Some(9));
        assert_eq!(operand.count, Count::Immediate(BYTE_BITS));
    }
}
