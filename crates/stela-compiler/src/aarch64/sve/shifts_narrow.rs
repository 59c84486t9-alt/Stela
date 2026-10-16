//! SVE2 unpredicated widening and narrowing shifts with bottom/top placement.
use crate::aarch64::scalable::ElementSize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    WidenSigned,
    WidenUnsigned,
    ShiftRight,
    RoundRight,
    SaturatingRightSigned,
    SaturatingRightUnsigned,
    SaturatingRightSignedToUnsigned,
    SaturatingRoundRightSigned,
    SaturatingRoundRightUnsigned,
    SaturatingRoundRightSignedToUnsigned,
    SaturatingExtractSigned,
    SaturatingExtractUnsigned,
    SaturatingExtractSignedToUnsigned,
}

impl Kind {
    pub const fn is_widening(self) -> bool {
        matches!(self, Self::WidenSigned | Self::WidenUnsigned)
    }

    pub const fn is_extract(self) -> bool {
        matches!(
            self,
            Self::SaturatingExtractSigned
                | Self::SaturatingExtractUnsigned
                | Self::SaturatingExtractSignedToUnsigned
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Bottom,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    /// The smaller width: source for widening, destination for narrowing.
    pub element_size: ElementSize,
    pub part: Part,
    pub source: u8,
    pub destination: u8,
    /// Extract forms use zero; right-narrowing shifts range 1..=element bits.
    pub shift: u8,
}

struct Encoding {
    mask: u32,
    value: u32,
    kind: Kind,
    part: Part,
}

const SHIFT_MASK: u32 = 0xffa0fc00;
const EXTRACT_MASK: u32 = 0xffa7fc00;
const REGISTER_MASK: u32 = 0b11111;
const SOURCE_SHIFT: u32 = 5;
const TSIZE_HIGH_SHIFT: u32 = 22;
const TSIZE_LOW_SHIFT: u32 = 19;
const TSIZE_LOW_MASK: u32 = 0b11;
const TSIZE_HIGH_OFFSET: u32 = 2;
const IMMEDIATE_SHIFT: u32 = 16;
const IMMEDIATE_BITS: u32 = 3;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const BYTE_BITS: u8 = 8;

const RSHRNB_Z_ZI: u32 = 0x45201800;
const RSHRNT_Z_ZI: u32 = 0x45201c00;
const SHRNB_Z_ZI: u32 = 0x45201000;
const SHRNT_Z_ZI: u32 = 0x45201400;
const SQRSHRNB_Z_ZI: u32 = 0x45202800;
const SQRSHRNT_Z_ZI: u32 = 0x45202c00;
const SQRSHRUNB_Z_ZI: u32 = 0x45200800;
const SQRSHRUNT_Z_ZI: u32 = 0x45200c00;
const SQSHRNB_Z_ZI: u32 = 0x45202000;
const SQSHRNT_Z_ZI: u32 = 0x45202400;
const SQSHRUNB_Z_ZI: u32 = 0x45200000;
const SQSHRUNT_Z_ZI: u32 = 0x45200400;
const SQXTNB_Z_ZZ: u32 = 0x45204000;
const SQXTNT_Z_ZZ: u32 = 0x45204400;
const SQXTUNB_Z_ZZ: u32 = 0x45205000;
const SQXTUNT_Z_ZZ: u32 = 0x45205400;
const SSHLLB_Z_ZI: u32 = 0x4500a000;
const SSHLLT_Z_ZI: u32 = 0x4500a400;
const UQRSHRNB_Z_ZI: u32 = 0x45203800;
const UQRSHRNT_Z_ZI: u32 = 0x45203c00;
const UQSHRNB_Z_ZI: u32 = 0x45203000;
const UQSHRNT_Z_ZI: u32 = 0x45203400;
const UQXTNB_Z_ZZ: u32 = 0x45204800;
const UQXTNT_Z_ZZ: u32 = 0x45204c00;
const USHLLB_Z_ZI: u32 = 0x4500a800;
const USHLLT_Z_ZI: u32 = 0x4500ac00;

const ENCODINGS: &[Encoding] = &[
    Encoding {
        mask: SHIFT_MASK,
        value: RSHRNB_Z_ZI,
        kind: Kind::RoundRight,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: RSHRNT_Z_ZI,
        kind: Kind::RoundRight,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SHRNB_Z_ZI,
        kind: Kind::ShiftRight,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SHRNT_Z_ZI,
        kind: Kind::ShiftRight,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQRSHRNB_Z_ZI,
        kind: Kind::SaturatingRoundRightSigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQRSHRNT_Z_ZI,
        kind: Kind::SaturatingRoundRightSigned,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQRSHRUNB_Z_ZI,
        kind: Kind::SaturatingRoundRightSignedToUnsigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQRSHRUNT_Z_ZI,
        kind: Kind::SaturatingRoundRightSignedToUnsigned,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQSHRNB_Z_ZI,
        kind: Kind::SaturatingRightSigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQSHRNT_Z_ZI,
        kind: Kind::SaturatingRightSigned,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQSHRUNB_Z_ZI,
        kind: Kind::SaturatingRightSignedToUnsigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SQSHRUNT_Z_ZI,
        kind: Kind::SaturatingRightSignedToUnsigned,
        part: Part::Top,
    },
    Encoding {
        mask: EXTRACT_MASK,
        value: SQXTNB_Z_ZZ,
        kind: Kind::SaturatingExtractSigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: EXTRACT_MASK,
        value: SQXTNT_Z_ZZ,
        kind: Kind::SaturatingExtractSigned,
        part: Part::Top,
    },
    Encoding {
        mask: EXTRACT_MASK,
        value: SQXTUNB_Z_ZZ,
        kind: Kind::SaturatingExtractSignedToUnsigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: EXTRACT_MASK,
        value: SQXTUNT_Z_ZZ,
        kind: Kind::SaturatingExtractSignedToUnsigned,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SSHLLB_Z_ZI,
        kind: Kind::WidenSigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: SSHLLT_Z_ZI,
        kind: Kind::WidenSigned,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: UQRSHRNB_Z_ZI,
        kind: Kind::SaturatingRoundRightUnsigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: UQRSHRNT_Z_ZI,
        kind: Kind::SaturatingRoundRightUnsigned,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: UQSHRNB_Z_ZI,
        kind: Kind::SaturatingRightUnsigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: UQSHRNT_Z_ZI,
        kind: Kind::SaturatingRightUnsigned,
        part: Part::Top,
    },
    Encoding {
        mask: EXTRACT_MASK,
        value: UQXTNB_Z_ZZ,
        kind: Kind::SaturatingExtractUnsigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: EXTRACT_MASK,
        value: UQXTNT_Z_ZZ,
        kind: Kind::SaturatingExtractUnsigned,
        part: Part::Top,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: USHLLB_Z_ZI,
        kind: Kind::WidenUnsigned,
        part: Part::Bottom,
    },
    Encoding {
        mask: SHIFT_MASK,
        value: USHLLT_Z_ZI,
        kind: Kind::WidenUnsigned,
        part: Part::Top,
    },
];

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = ENCODINGS
        .iter()
        .find(|entry| word & entry.mask == entry.value)?;
    let tsize = (((word >> TSIZE_HIGH_SHIFT) & 1) << TSIZE_HIGH_OFFSET)
        | ((word >> TSIZE_LOW_SHIFT) & TSIZE_LOW_MASK);
    if tsize == 0 || (encoding.kind.is_extract() && !tsize.is_power_of_two()) {
        return Some(Err(()));
    }
    let size_log = u32::BITS - 1 - tsize.leading_zeros();
    let element_bits = BYTE_BITS << size_log;
    let element_size = ElementSize::from_bytes(usize::from(element_bits / BYTE_BITS))?;
    let encoded = ((tsize << IMMEDIATE_BITS) | ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK)) as u8;
    let shift = if encoding.kind.is_extract() {
        0
    } else if encoding.kind.is_widening() {
        encoded - element_bits
    } else {
        2 * element_bits - encoded
    };
    Some(Ok(Operand {
        kind: encoding.kind,
        element_size,
        part: encoding.part,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
        destination: (word & REGISTER_MASK) as u8,
        shift,
    }))
}

#[cfg(test)]
mod tests;
