//! Explicit original gen3 RAM descriptor encodings.
//!
//! T8152 SPTM d3610/d18e0 constructs PA>>4 descriptors. J873g mBoot
//! 20457.1.29 file1593ac..1593c0 and15a5f0..15a60c select PA>>8 above
//! revision3.0. Its native TTBR write at158df8..158e00 still uses PA>>12.
//! Choosing a software encoding does not check the native mode/revision,
//! security, filter or context contracts needed for profile admission.
use {crate::platform::apple::dart::descriptor::Format, stela_contracts::dma::DmaError};

const COMPACT_ADDRESS: u64 = 0x0000_0003_ffff_ffc0;
const ATTRIBUTES: u64 = 0xfff << 52 | 0xfff << 40 | 0xf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Shift4,
    Shift8,
}

impl Encoding {
    /// The recovered SPTM handoff and native driver agree on revision3.0.
    /// Other firmware builder encodings remain explicit software forms until
    /// their handoff mode is checked; a compatible string cannot select it.
    pub fn handoff_revision(revision: u16) -> Result<Self, &'static str> {
        match revision {
            0x300 => Ok(Self::Shift4),
            0x302 | 0x303 => Err("gen3 DART compact descriptor handoff mode is unqualified"),
            _ => Err("gen3 DART handoff revision is outside the recovered native contract"),
        }
    }

    /// The original mBoot builder's choice for the revisions also named by
    /// SPTM's gen3 validator. The SPTM builder itself uses Shift4, so this
    /// is source-specific construction metadata, not native mode admission.
    pub fn mboot_revision(revision: u16) -> Result<Self, &'static str> {
        match revision {
            0x300 => Ok(Self::Shift4),
            0x302 | 0x303 => Ok(Self::Shift8),
            _ => Err("gen3 DART descriptor revision is outside the recovered source set"),
        }
    }

    pub(super) fn target(
        self,
        entry: u64,
        pa_bits: u32,
        page: u64,
        leaf: bool,
    ) -> Result<u64, DmaError> {
        let canonical = match self {
            Self::Shift4 => entry,
            Self::Shift8 => {
                if entry & !(COMPACT_ADDRESS | ATTRIBUTES) != 0 {
                    return Err(DmaError::Unsupported(
                        "gen3 DART compact descriptor contains unmodeled attributes",
                    ));
                }
                // Both original builders share the attribute/subpage word;
                // only the PA field changes. Validate before moving it so
                // unknown bits cannot turn into accepted address attributes.
                (entry & COMPACT_ADDRESS) << 4 | entry & ATTRIBUTES
            }
        };
        Format::Dart2.target(canonical, pa_bits, page, leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_compact_address_fields_keep_all_pa_bits_and_table_attributes() {
        for physical in [0, 0x4000, 0x8_0000_4000, (1 << 42) - 0x4000] {
            let compact = physical >> 8 | 1;
            let original = physical >> 4 | 1;
            for leaf in [false, true] {
                assert_eq!(
                    Encoding::Shift8.target(compact, 42, 0x4000, leaf),
                    Ok(physical)
                );
                assert_eq!(
                    Encoding::Shift4.target(original, 42, 0x4000, leaf),
                    Ok(physical)
                );
            }
        }
        assert!(
            Encoding::Shift8
                .target(1 << 33 | 1, 41, 0x4000, false)
                .is_err()
        );
        for bit in [4, 5, 34, 35, 36, 37, 38, 39] {
            for leaf in [false, true] {
                assert!(
                    Encoding::Shift8
                        .target(1 << bit | 1, 42, 0x4000, leaf)
                        .is_err()
                );
            }
        }
        for attributes in [1 << 2, 1 << 3, 1 << 40, 1 << 52] {
            assert!(
                Encoding::Shift8
                    .target(attributes | 1, 42, 0x4000, false)
                    .is_err()
            );
            assert!(
                Encoding::Shift8
                    .target(attributes | 1, 42, 0x4000, true)
                    .is_ok()
            );
        }
    }

    #[test]
    fn original_revision_selection_does_not_alias_unrecovered_revisions() {
        assert_eq!(Encoding::mboot_revision(0x300), Ok(Encoding::Shift4));
        assert_eq!(Encoding::handoff_revision(0x300), Ok(Encoding::Shift4));
        for revision in [0x302, 0x303] {
            assert_eq!(Encoding::mboot_revision(revision), Ok(Encoding::Shift8));
            assert_eq!(
                Encoding::handoff_revision(revision),
                Err("gen3 DART compact descriptor handoff mode is unqualified")
            );
        }
        for revision in [0, 0x101, 0x204, 0x301, 0x304, u16::MAX] {
            assert!(Encoding::mboot_revision(revision).is_err());
            assert!(Encoding::handoff_revision(revision).is_err());
        }
    }
}
