//! SVE FCM* and FAC* comparisons into predicates.
use crate::aarch64::Unsupported;
use crate::aarch64::flags::{NZCV_V, NZCV_Z};
use crate::aarch64::floating::{
    Format, UnsupportedControl,
    comparison::{self, Predicate},
};

const REGISTER_MASK: u32 = 31;
const PREDICATE_MASK: u32 = 15;
const GOVERNING_MASK: u32 = 7;
const SOURCE_SHIFT: u32 = 5;
const GOVERNING_SHIFT: u32 = 10;
const RIGHT_SHIFT: u32 = 16;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const REGISTER_COMPARE_MASK: u32 = 0xff20_e010;
const ZERO_COMPARE_MASK: u32 = 0xff3f_e010;
const FCMEQ_REG: u32 = 0x6500_6000;
const FCMGE_REG: u32 = 0x6500_4000;
const FCMGT_REG: u32 = 0x6500_4010;
const FCMNE_REG: u32 = 0x6500_6010;
const FCMUO_REG: u32 = 0x6500_c000;
const FACGE_REG: u32 = 0x6500_c010;
const FACGT_REG: u32 = 0x6500_e010;
const FCMEQ_ZERO: u32 = 0x6512_2000;
const FCMGE_ZERO: u32 = 0x6510_2000;
const FCMGT_ZERO: u32 = 0x6510_2010;
const FCMLE_ZERO: u32 = 0x6511_2010;
const FCMLT_ZERO: u32 = 0x6511_2000;
const FCMNE_ZERO: u32 = 0x6513_2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Equal,
    GreaterEqual,
    Greater,
    LessEqual,
    Less,
    NotEqual,
    Unordered,
    AbsoluteGreaterEqual,
    AbsoluteGreater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub format: Format,
    pub destination: u8,
    pub governing: u8,
    pub left: u8,
    /// `None` denotes the instruction's positive-zero operand.
    pub right: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub predicate: bool,
    pub exceptions: u32,
}

/// Evaluate one active lane. Inactive lanes must never call this helper: they
/// clear their predicate group without evaluating numerical controls or inputs.
pub fn evaluate(
    kind: Kind,
    format: Format,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let predicate = match kind {
        Kind::Equal => Predicate::Equal,
        Kind::GreaterEqual => Predicate::GreaterEqual,
        Kind::Greater => Predicate::Greater,
        Kind::LessEqual => Predicate::LessEqual,
        Kind::Less => Predicate::Less,
        Kind::AbsoluteGreaterEqual => Predicate::AbsoluteGreaterEqual,
        Kind::AbsoluteGreater => Predicate::AbsoluteGreater,
        Kind::NotEqual | Kind::Unordered => {
            // FPCompareNE/UN use the same unpacking, SNaN signaling and numeric
            // denormal processing as quiet flags comparison. No NZCV is written.
            let result = comparison::flags(format, false, fpcr, left, right)?;
            return Ok(Outcome {
                predicate: if kind == Kind::NotEqual {
                    result.nzcv & NZCV_Z == 0
                } else {
                    result.nzcv & NZCV_V != 0
                },
                exceptions: result.exceptions,
            });
        }
    };
    let result = comparison::predicate(format, predicate, fpcr, left, right)?;
    Ok(Outcome {
        predicate: result.bits != 0,
        exceptions: result.exceptions,
    })
}

/// All Z registers and P destinations are ordinary storage. Pg is P0..P7;
/// Pd is P0..P15. An allocated byte-size encoding is architecturally reserved.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let (kind, right) = match word & REGISTER_COMPARE_MASK {
        FCMEQ_REG => (
            Kind::Equal,
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8),
        ),
        FCMGE_REG => (
            Kind::GreaterEqual,
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8),
        ),
        FCMGT_REG => (
            Kind::Greater,
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8),
        ),
        FCMNE_REG => (
            Kind::NotEqual,
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8),
        ),
        FCMUO_REG => (
            Kind::Unordered,
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8),
        ),
        FACGE_REG => (
            Kind::AbsoluteGreaterEqual,
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8),
        ),
        FACGT_REG => (
            Kind::AbsoluteGreater,
            Some(((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8),
        ),
        _ => {
            let kind = match word & ZERO_COMPARE_MASK {
                FCMEQ_ZERO => Kind::Equal,
                FCMGE_ZERO => Kind::GreaterEqual,
                FCMGT_ZERO => Kind::Greater,
                FCMLE_ZERO => Kind::LessEqual,
                FCMLT_ZERO => Kind::Less,
                FCMNE_ZERO => Kind::NotEqual,
                _ => return None,
            };
            (kind, None)
        }
    };
    let format = match (word >> SIZE_SHIFT) & SIZE_MASK {
        1 => Format::Half,
        2 => Format::Single,
        3 => Format::Double,
        _ => return Some(Err(Unsupported)),
    };
    Some(Ok(Operand {
        kind,
        format,
        destination: (word & PREDICATE_MASK) as u8,
        governing: ((word >> GOVERNING_SHIFT) & GOVERNING_MASK) as u8,
        left: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
        right,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocated_widths_and_full_predicate_fields() {
        for (opcode, kind) in [
            (FCMEQ_REG, Kind::Equal),
            (FCMGE_REG, Kind::GreaterEqual),
            (FCMGT_REG, Kind::Greater),
            (FCMNE_REG, Kind::NotEqual),
            (FCMUO_REG, Kind::Unordered),
            (FACGE_REG, Kind::AbsoluteGreaterEqual),
            (FACGT_REG, Kind::AbsoluteGreater),
        ] {
            assert_eq!(decode(opcode), Some(Err(Unsupported)));
            for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
                for governing in 0..=GOVERNING_MASK {
                    for destination in 0..=PREDICATE_MASK {
                        let word = opcode
                            | (size << SIZE_SHIFT)
                            | (REGISTER_MASK << RIGHT_SHIFT)
                            | (governing << GOVERNING_SHIFT)
                            | (REGISTER_MASK << SOURCE_SHIFT)
                            | destination;
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand {
                                kind,
                                format,
                                destination: destination as u8,
                                governing: governing as u8,
                                left: REGISTER_MASK as u8,
                                right: Some(REGISTER_MASK as u8),
                            }))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn zero_comparisons_and_unordered_nan_signaling() {
        for opcode in [
            FCMEQ_ZERO, FCMGE_ZERO, FCMGT_ZERO, FCMLE_ZERO, FCMLT_ZERO, FCMNE_ZERO,
        ] {
            assert_eq!(decode(opcode), Some(Err(Unsupported)));
            assert!(
                decode(opcode | (2 << SIZE_SHIFT) | (31 << SOURCE_SHIFT) | 15)
                    .unwrap()
                    .unwrap()
                    .right
                    .is_none()
            );
        }
        const QUIET_NAN: u64 = 0x7fc0_0001;
        const SIGNALING_NAN: u64 = 0x7f80_0001;
        for kind in [Kind::NotEqual, Kind::Unordered] {
            assert_eq!(
                evaluate(kind, Format::Single, 0, QUIET_NAN, 0),
                Ok(Outcome {
                    predicate: true,
                    exceptions: 0
                })
            );
            assert_eq!(
                evaluate(kind, Format::Single, 0, SIGNALING_NAN, 0),
                Ok(Outcome {
                    predicate: true,
                    exceptions: crate::aarch64::floating::INVALID
                })
            );
        }
        assert_eq!(decode(0), None);
    }
}
