//! Guest floating-point features, independent of host CPU features.

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
mod tests;
