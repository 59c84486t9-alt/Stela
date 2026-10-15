//! Immutable architectural numerical capabilities, separate from host features.
//! ID/control provenance belongs to the selected guest execution profile.

use serde::Serialize;

const ID_FIELD_MASK: u64 = 0xf;
const ISAR1_BF16_SHIFT: u32 = 44;
const ISAR2_RPRES_SHIFT: u32 = 4;
const SMFR0_FA64_SHIFT: u32 = 63;
const BF16_ABSENT: u64 = 0;
const BF16_STANDARD: u64 = 1;
const BF16_EXTENDED: u64 = 2;
const RPRES_ABSENT: u64 = 0;
const RPRES_IMPLEMENTED: u64 = 1;

/// Availability is immutable during an entry/cache specialization. Stored FPCR
/// remains separate: EBF selects extended BF16 when available, and AH selects
/// feature-dependent reciprocal estimates. RPRES is an ID feature, not an FPCR
/// bit. Full A64 combines FA64 availability with applicable SMCR controls.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct NumericalFeatures {
    full_a64: bool,
    ebf16: bool,
    rpres: bool,
}

impl NumericalFeatures {
    /// Construct an explicit declared software profile. This does not establish
    /// hardware availability; retain the profile's feature/control evidence.
    pub const fn new(full_a64: bool, ebf16: bool, rpres: bool) -> Self {
        Self {
            full_a64,
            ebf16,
            rpres,
        }
    }

    /// Decode reviewed ID fields. The final argument is the combined applicable
    /// privileged-control enable, not a host CPU feature or raw FPCR bit.
    /// Unreviewed ID values fail explicitly instead of guessing future behavior.
    pub const fn from_id_registers(
        id_aa64isar1: u64,
        id_aa64isar2: u64,
        id_aa64smfr0: u64,
        full_a64_control_enabled: bool,
    ) -> Option<Self> {
        let ebf16 = match (id_aa64isar1 >> ISAR1_BF16_SHIFT) & ID_FIELD_MASK {
            BF16_ABSENT | BF16_STANDARD => false,
            BF16_EXTENDED => true,
            _ => return None,
        };
        let rpres = match (id_aa64isar2 >> ISAR2_RPRES_SHIFT) & ID_FIELD_MASK {
            RPRES_ABSENT => false,
            RPRES_IMPLEMENTED => true,
            _ => return None,
        };
        let fa64 = (id_aa64smfr0 >> SMFR0_FA64_SHIFT) & 1 != 0;
        Some(Self::new(fa64 && full_a64_control_enabled, ebf16, rpres))
    }

    pub const fn full_a64(self) -> bool {
        self.full_a64
    }

    pub const fn ebf16(self) -> bool {
        self.ebf16
    }

    pub const fn rpres(self) -> bool {
        self.rpres
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_availability_and_control_enable_remain_distinct() {
        let extended = NumericalFeatures::from_id_registers(
            BF16_EXTENDED << ISAR1_BF16_SHIFT,
            RPRES_IMPLEMENTED << ISAR2_RPRES_SHIFT,
            1 << SMFR0_FA64_SHIFT,
            true,
        )
        .unwrap();
        assert_eq!(extended, NumericalFeatures::new(true, true, true));
        let disabled = NumericalFeatures::from_id_registers(
            BF16_EXTENDED << ISAR1_BF16_SHIFT,
            RPRES_IMPLEMENTED << ISAR2_RPRES_SHIFT,
            1 << SMFR0_FA64_SHIFT,
            false,
        )
        .unwrap();
        assert_eq!(disabled, NumericalFeatures::new(false, true, true));
        let absent =
            NumericalFeatures::from_id_registers(BF16_STANDARD << ISAR1_BF16_SHIFT, 0, 0, true)
                .unwrap();
        assert_eq!(absent, NumericalFeatures::default());
        assert!(!absent.full_a64());
        assert!(!absent.ebf16());
        assert!(!absent.rpres());
    }

    #[test]
    fn unrelated_id_bits_do_not_enable_numerical_capabilities() {
        let isar1 = !(ID_FIELD_MASK << ISAR1_BF16_SHIFT);
        let isar2 = !(ID_FIELD_MASK << ISAR2_RPRES_SHIFT);
        let smfr0 = !(1 << SMFR0_FA64_SHIFT);
        assert_eq!(
            NumericalFeatures::from_id_registers(isar1, isar2, smfr0, true),
            Some(NumericalFeatures::default())
        );
        for value in BF16_EXTENDED + 1..=ID_FIELD_MASK {
            assert!(
                NumericalFeatures::from_id_registers(value << ISAR1_BF16_SHIFT, 0, 0, false)
                    .is_none()
            );
        }
        for value in RPRES_IMPLEMENTED + 1..=ID_FIELD_MASK {
            assert!(
                NumericalFeatures::from_id_registers(0, value << ISAR2_RPRES_SHIFT, 0, false)
                    .is_none()
            );
        }
    }
}
