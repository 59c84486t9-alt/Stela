//! AESE, AESD, AESMC and AESIMC.
use crate::aarch64::Unsupported;

const FORM_MASK: u32 = 0xffff_fc00;
const AESE: u32 = 0x4e28_4800;
const AESD: u32 = 0x4e28_5800;
const AESMC: u32 = 0x4e28_6800;
const AESIMC: u32 = 0x4e28_7800;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Encrypt,
    Decrypt,
    MixColumns,
    InverseMixColumns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub source: u8,
}

/// Only the exact .16B encodings are accepted. Other classes and reserved size
/// encodings decline and keep the shared decoder's unsupported failure.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let kind = match word & FORM_MASK {
        AESE => Kind::Encrypt,
        AESD => Kind::Decrypt,
        AESMC => Kind::MixColumns,
        AESIMC => Kind::InverseMixColumns,
        _ => return None,
    };
    Some(Ok(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_register_pair_including_v31_and_aliases_is_ordinary_data() {
        for (base, kind) in [
            (AESE, Kind::Encrypt),
            (AESD, Kind::Decrypt),
            (AESMC, Kind::MixColumns),
            (AESIMC, Kind::InverseMixColumns),
        ] {
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    assert_eq!(
                        decode(base | (source << SOURCE_SHIFT) | destination),
                        Some(Ok(Operand {
                            kind,
                            destination: destination as u8,
                            source: source as u8,
                        }))
                    );
                }
            }
            for size in 1..4 {
                assert!(decode(base | (size << 22)).is_none());
            }
            assert!(decode(base & !(1 << 30)).is_none()); // No .8B form.
            assert!(decode(base | (1 << 28)).is_none()); // No scalar form.
        }
    }
}
