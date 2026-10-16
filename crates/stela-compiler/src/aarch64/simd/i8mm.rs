//! FEAT_I8MM: SMMLA, UMMLA, USMMLA, USDOT and SUDOT.
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
mod tests;
