//! SME2 multi-vector FP8 conversions.
use super::fp_vector::VectorGroup;

const SOURCE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const PAIR_COUNT: u8 = 2;
const QUARTET_COUNT: u8 = 4;
const WIDEN_MASK: u32 = 0xffff_fc01;
const NARROW_PAIR_MASK: u32 = 0xffff_fc20;
const NARROW_QUARTET_MASK: u32 = 0xffff_fc60;

pub const BF1CVT_MZ2_Z8: u32 = 0xc166_e000;
pub const BF1CVTL_MZ2_Z8: u32 = 0xc166_e001;
pub const BF2CVT_MZ2_Z8: u32 = 0xc1e6_e000;
pub const BF2CVTL_MZ2_Z8: u32 = 0xc1e6_e001;
pub const BFCVT_Z8_MZ2: u32 = 0xc164_e000;
pub const F1CVT_MZ2_Z8: u32 = 0xc126_e000;
pub const F1CVTL_MZ2_Z8: u32 = 0xc126_e001;
pub const F2CVT_MZ2_Z8: u32 = 0xc1a6_e000;
pub const F2CVTL_MZ2_Z8: u32 = 0xc1a6_e001;
pub const FCVT_Z8_MZ2: u32 = 0xc124_e000;
pub const FCVT_Z8_MZ4: u32 = 0xc134_e000;
pub const FCVTN_Z8_MZ4: u32 = 0xc134_e020;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementFormat {
    Half,
    BFloat16,
    Single,
}

impl ElementFormat {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Half | Self::BFloat16 => 2,
            Self::Single => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conversion {
    Widen { source2: bool, deinterleaved: bool },
    Narrow { interleaved: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub canonical_id: &'static str,
    pub conversion: Conversion,
    pub format: ElementFormat,
    pub destination: VectorGroup,
    pub source: VectorGroup,
}

#[derive(Clone, Copy)]
struct Encoding {
    id: &'static str,
    mask: u32,
    opcode: u32,
    conversion: Conversion,
    format: ElementFormat,
    count: u8,
}

const fn widen(
    id: &'static str,
    opcode: u32,
    format: ElementFormat,
    source2: bool,
    deinterleaved: bool,
) -> Encoding {
    Encoding {
        id,
        mask: WIDEN_MASK,
        opcode,
        conversion: Conversion::Widen {
            source2,
            deinterleaved,
        },
        format,
        count: PAIR_COUNT,
    }
}

const fn narrow(
    id: &'static str,
    opcode: u32,
    format: ElementFormat,
    count: u8,
    interleaved: bool,
) -> Encoding {
    Encoding {
        id,
        mask: if count == PAIR_COUNT {
            NARROW_PAIR_MASK
        } else {
            NARROW_QUARTET_MASK
        },
        opcode,
        conversion: Conversion::Narrow { interleaved },
        format,
        count,
    }
}

const ENCODINGS: &[Encoding] = &[
    widen(
        "bf1cvt_mz2_z8_",
        BF1CVT_MZ2_Z8,
        ElementFormat::BFloat16,
        false,
        false,
    ),
    widen(
        "bf1cvtl_mz2_z8_",
        BF1CVTL_MZ2_Z8,
        ElementFormat::BFloat16,
        false,
        true,
    ),
    widen(
        "bf2cvt_mz2_z8_",
        BF2CVT_MZ2_Z8,
        ElementFormat::BFloat16,
        true,
        false,
    ),
    widen(
        "bf2cvtl_mz2_z8_",
        BF2CVTL_MZ2_Z8,
        ElementFormat::BFloat16,
        true,
        true,
    ),
    narrow(
        "bfcvt_z8_mz2_",
        BFCVT_Z8_MZ2,
        ElementFormat::BFloat16,
        PAIR_COUNT,
        false,
    ),
    widen(
        "f1cvt_mz2_z8_",
        F1CVT_MZ2_Z8,
        ElementFormat::Half,
        false,
        false,
    ),
    widen(
        "f1cvtl_mz2_z8_",
        F1CVTL_MZ2_Z8,
        ElementFormat::Half,
        false,
        true,
    ),
    widen(
        "f2cvt_mz2_z8_",
        F2CVT_MZ2_Z8,
        ElementFormat::Half,
        true,
        false,
    ),
    widen(
        "f2cvtl_mz2_z8_",
        F2CVTL_MZ2_Z8,
        ElementFormat::Half,
        true,
        true,
    ),
    narrow(
        "fcvt_z8_mz2_",
        FCVT_Z8_MZ2,
        ElementFormat::Half,
        PAIR_COUNT,
        false,
    ),
    narrow(
        "fcvt_z8_mz4_",
        FCVT_Z8_MZ4,
        ElementFormat::Single,
        QUARTET_COUNT,
        false,
    ),
    narrow(
        "fcvtn_z8_mz4_",
        FCVTN_Z8_MZ4,
        ElementFormat::Single,
        QUARTET_COUNT,
        true,
    ),
];

pub fn decode(word: u32) -> Option<Operand> {
    let encoding = ENCODINGS
        .iter()
        .find(|entry| word & entry.mask == entry.opcode)?;
    let (source_count, destination_count) = match encoding.conversion {
        Conversion::Widen { .. } => (1, encoding.count),
        Conversion::Narrow { .. } => (encoding.count, 1),
    };
    Some(Operand {
        canonical_id: encoding.id,
        conversion: encoding.conversion,
        format: encoding.format,
        source: VectorGroup {
            first: ((word >> SOURCE_SHIFT) & (REGISTER_MASK + 1 - u32::from(source_count))) as u8,
            count: source_count,
        },
        destination: VectorGroup {
            first: (word & (REGISTER_MASK + 1 - u32::from(destination_count))) as u8,
            count: destination_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_allocated_operands_have_exact_identity_and_nonwrapping_groups() {
        for encoding in ENCODINGS {
            let base = decode(encoding.opcode).unwrap();
            for source in (0..32).step_by(usize::from(base.source.count)) {
                for destination in (0..32).step_by(usize::from(base.destination.count)) {
                    let word = encoding.opcode | source << SOURCE_SHIFT | destination;
                    let operand = decode(word).unwrap();
                    assert_eq!(operand.canonical_id, encoding.id);
                    assert_eq!(operand.conversion, encoding.conversion);
                    assert_eq!(operand.format, encoding.format);
                    assert_eq!(u32::from(operand.source.first), source);
                    assert_eq!(u32::from(operand.destination.first), destination);
                    assert!(operand.source.first + operand.source.count <= 32);
                    assert!(operand.destination.first + operand.destination.count <= 32);
                    assert_eq!(
                        ENCODINGS
                            .iter()
                            .filter(|entry| word & entry.mask == entry.opcode)
                            .count(),
                        1
                    );
                }
            }
        }
    }

    #[test]
    fn reserved_group_bits_and_neighboring_families_are_rejected() {
        for word in [
            FCVT_Z8_MZ2 | (1 << SOURCE_SHIFT),
            FCVT_Z8_MZ4 | (1 << 6),
            FCVTN_Z8_MZ4 | (1 << 6),
            0xc160_e000,
            0xc1a0_e000,
            0xd503_201f,
        ] {
            assert_eq!(decode(word), None, "{word:#010x}");
        }
    }
}
