//! BranchAddr for the EL1 translation regime.
use super::{ControlError, Presence, TranslationControls, fields::tcr};
use crate::system::access::ExceptionLevel;

const TOP_BYTE_BITS: u32 = u8::BITS;
const ADDRESS_RANGE_BIT: u32 = u64::BITS - TOP_BYTE_BITS - 1;

impl TranslationControls {
    /// Normalize with the destination regime's TCR and features; the exception
    /// plan binds the target EL, and fetching the target happens afterwards.
    pub(crate) fn branch_address(
        &self,
        target: u64,
        destination: ExceptionLevel,
    ) -> Result<u64, ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        if !matches!(destination, ExceptionLevel::El0 | ExceptionLevel::El1) {
            return Err(ControlError::Unavailable(
                "BranchAddr needs the destination translation regime",
            ));
        }
        let control = self.profile.consumers(self.readbacks).tcr_el1;
        let (tbi, tbid) = if target & (1_u64 << ADDRESS_RANGE_BIT) == 0 {
            (tcr::TBI0, tcr::TBID0)
        } else {
            (tcr::TBI1, tcr::TBID1)
        };
        let ignore_top_byte = control & tbi != 0
            && (self.profile.facts.pauth == Presence::Absent || control & tbid == 0);
        if ignore_top_byte {
            // EL0/EL1 BranchAddr sign-extends bit55, including upper-range
            // targets. It does not canonicalize the lower virtual-address size.
            Ok(((target << TOP_BYTE_BITS) as i64 >> TOP_BYTE_BITS) as u64)
        } else {
            Ok(target)
        }
    }
}
