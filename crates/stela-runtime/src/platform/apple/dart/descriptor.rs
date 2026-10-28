//! DART descriptors independently of each generation's register layout.
//!
//! Linux v6.17 io-pgtable-dart.c defines APPLE_DART and APPLE_DART2 leaf
//! permissions, subpage bounds and valid bits. m1n1's dart8020.py names the
//! wider address fields through bit39. A profile's smaller PA width must
//! reject those high address bits rather than silently truncate them.
use stela_contracts::dma::DmaError;

const VALID: u64 = 1;
/// DART1: subpage protection disable. DART2: no-cache. Neither adds an
/// address bit; the latter has no cache to affect in a cacheless model.
const MODE: u64 = 1 << 1;
const SUBPAGE_BOUNDS: u64 = 0xfff << 52 | 0xfff << 40;
const DART1_ADDRESS: u64 = 0x0000_00ff_ffff_c000;
const DART1_PERMISSIONS: u64 = 1 << 8 | 1 << 7;
const DART2_ADDRESS: u64 = 0x0000_00ff_ffff_fc00;
const DART2_PERMISSIONS: u64 = 1 << 3 | 1 << 2;

#[derive(Clone, Copy)]
pub(super) enum Format {
    Dart1,
    Dart2,
}

impl Format {
    /// Validate a valid descriptor before extracting its address. Bounds and
    /// permissions are leaf fields; accepting them on an intermediate entry
    /// would discard effects whose table-level meaning is not recovered.
    pub(super) fn target(
        self,
        entry: u64,
        pa_bits: u32,
        page: u64,
        leaf: bool,
    ) -> Result<u64, DmaError> {
        let (address, shift, permissions) = match self {
            Self::Dart1 => (DART1_ADDRESS, 0, DART1_PERMISSIONS),
            Self::Dart2 => (DART2_ADDRESS, 4, DART2_PERMISSIONS),
        };
        let known = address
            | VALID
            | MODE
            | if leaf {
                permissions | SUBPAGE_BOUNDS
            } else {
                0
            };
        if entry & !known != 0 {
            return Err(DmaError::Unsupported(
                "DART descriptor contains unmodeled attributes",
            ));
        }
        let target = (entry & address) << shift;
        if target >> pa_bits != 0 {
            return Err(DmaError::Unsupported(
                "DART descriptor target exceeds its native profile",
            ));
        }
        if target & (page - 1) != 0 {
            return Err(DmaError::Unsupported("unaligned DART descriptor target"));
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_address_bits_are_checked_before_narrowing_to_the_native_pa_width() {
        for (format, bits, shift) in [(Format::Dart1, 36, 0), (Format::Dart2, 42, 4)] {
            for address_bit in bits..40 + shift {
                let entry = VALID | 1 << (address_bit - shift);
                for leaf in [false, true] {
                    assert_eq!(
                        format.target(entry, bits, 0x4000, leaf),
                        Err(DmaError::Unsupported(
                            "DART descriptor target exceeds its native profile"
                        ))
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_attributes_and_table_level_leaf_fields_are_not_discarded() {
        for format in [Format::Dart1, Format::Dart2] {
            for reserved_bit in [4, 5, 6, 9] {
                for leaf in [false, true] {
                    assert_eq!(
                        format.target(VALID | 1 << reserved_bit, 42, 0x4000, leaf),
                        Err(DmaError::Unsupported(
                            "DART descriptor contains unmodeled attributes"
                        ))
                    );
                }
            }
            assert!(
                format
                    .target(VALID | SUBPAGE_BOUNDS, 42, 0x4000, false)
                    .is_err()
            );
            assert!(
                format
                    .target(VALID | SUBPAGE_BOUNDS, 42, 0x4000, true)
                    .is_ok()
            );
            assert!(format.target(VALID | MODE, 42, 0x4000, false).is_ok());
        }
    }

    #[test]
    fn low_address_bits_cannot_turn_an_unaligned_table_into_an_aligned_one() {
        for (format, bits) in [(Format::Dart1, [12, 13]), (Format::Dart2, [8, 9])] {
            for bit in bits {
                assert_eq!(
                    format.target(VALID | 1 << bit, 42, 0x4000, false),
                    Err(DmaError::Unsupported(
                        "DART descriptor contains unmodeled attributes"
                    ))
                );
            }
        }
    }
}
