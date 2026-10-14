//! Classic Arm A64 June 2026 FEAT_I8MM matrix and mixed-sign dot products.
use super::arithmetic::Shape;

const REGISTER_MASK: u32 = 31;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const VECTOR_Q: u32 = 1 << 30;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_BIT_MASK: u32 = 1;
const INDEX_HIGH_SHIFT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixKind {
    Signed,
    Unsigned,
    UnsignedSigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotKind {
    UnsignedSigned,
    SignedUnsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Matrix(MatrixKind),
    Dot(DotKind),
}

impl Kind {
    pub fn signedness(self) -> (bool, bool) {
        match self {
            Self::Matrix(MatrixKind::Signed) => (true, true),
            Self::Matrix(MatrixKind::Unsigned) => (false, false),
            Self::Matrix(MatrixKind::UnsignedSigned) | Self::Dot(DotKind::UnsignedSigned) => {
                (false, true)
            }
            Self::Dot(DotKind::SignedUnsigned) => (true, false),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
    pub shape: Shape,
    pub index: Option<u8>,
}

#[derive(Clone, Copy)]
enum Encoding {
    Smmla,
    Ummla,
    Usmmla,
    Usdot,
    UsdotIndexed,
    SudotIndexed,
}

impl Encoding {
    const ALL: &'static [Self] = &[
        Self::Smmla,
        Self::Ummla,
        Self::Usmmla,
        Self::Usdot,
        Self::UsdotIndexed,
        Self::SudotIndexed,
    ];

    fn facts(self) -> (u32, u32, Kind, bool) {
        match self {
            Self::Smmla => (
                0xffe0fc00,
                0x4e80a400,
                Kind::Matrix(MatrixKind::Signed),
                false,
            ),
            Self::Ummla => (
                0xffe0fc00,
                0x6e80a400,
                Kind::Matrix(MatrixKind::Unsigned),
                false,
            ),
            Self::Usmmla => (
                0xffe0fc00,
                0x4e80ac00,
                Kind::Matrix(MatrixKind::UnsignedSigned),
                false,
            ),
            Self::Usdot => (
                0xbfe0fc00,
                0x0e809c00,
                Kind::Dot(DotKind::UnsignedSigned),
                false,
            ),
            Self::UsdotIndexed => (
                0xbfc0f400,
                0x0f80f000,
                Kind::Dot(DotKind::UnsignedSigned),
                true,
            ),
            Self::SudotIndexed => (
                0xbfc0f400,
                0x0f00f000,
                Kind::Dot(DotKind::SignedUnsigned),
                true,
            ),
        }
    }
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (_, _, kind, indexed) = Encoding::ALL
        .iter()
        .map(|encoding| encoding.facts())
        .find(|(mask, value, _, _)| word & *mask == *value)?;
    Some(Ok(Operand {
        kind,
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        // M is the high register bit; H:L alone selects the dword group.
        right: register(word, RIGHT_SHIFT),
        shape: if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        },
        index: indexed.then_some(
            ((((word >> INDEX_H_SHIFT) & INDEX_BIT_MASK) << INDEX_HIGH_SHIFT)
                | ((word >> INDEX_L_SHIFT) & INDEX_BIT_MASK)) as u8,
        ),
    }))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX_COUNT: u32 = 4;

    #[test]
    fn exact_forms_cover_every_register_width_and_index() {
        for encoding in Encoding::ALL {
            let (_, base, kind, indexed) = encoding.facts();
            let shapes: &[(u32, Shape)] = if matches!(kind, Kind::Matrix(_)) {
                &[(VECTOR_Q, Shape::Vector128)]
            } else {
                &[(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)]
            };
            for &(q, shape) in shapes {
                for index in 0..if indexed { INDEX_COUNT } else { 1 } {
                    for register in 0..=REGISTER_MASK {
                        for (d, n, m) in [
                            (register, 31, 16),
                            (31, register, 16),
                            (31, 16, register),
                            (register, register, register),
                        ] {
                            let word = base
                                | q
                                | d
                                | n << LEFT_SHIFT
                                | m << RIGHT_SHIFT
                                | (index & INDEX_BIT_MASK) << INDEX_L_SHIFT
                                | (index >> INDEX_HIGH_SHIFT) << INDEX_H_SHIFT;
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand {
                                    kind,
                                    destination: d as u8,
                                    left: n as u8,
                                    right: m as u8,
                                    shape,
                                    index: indexed.then_some(index as u8),
                                }))
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn fixed_bits_never_accept_another_arrangement_or_scalar_form() {
        for encoding in Encoding::ALL {
            let (mask, base, _, _) = encoding.facts();
            for bit in 0..32 {
                if mask & (1 << bit) != 0 {
                    let changed = base ^ (1 << bit);
                    if let Some(Ok(other)) = decode(changed) {
                        // A changed opcode can select another canonical I8MM form,
                        // but must not retain the original semantic kind.
                        assert_ne!(other.kind, decode(base).unwrap().unwrap().kind);
                    }
                }
            }
        }
        assert!(decode(0x0e80a400).is_none()); // Matrix Q=0 is unallocated.
        assert!(decode(0x5f80f000).is_none()); // No scalar mixed dot form.
        assert!(decode(0x0e009c00).is_none()); // No vector SUDOT canonical form.
    }
}
