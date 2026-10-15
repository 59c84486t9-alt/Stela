//! Resolved CPA2 arithmetic effects, supplied by the architectural control owner.
//!
//! This value is neither a CPU-feature witness nor an owner/generation lease.
//! It has no default: context admission must obtain the actual effective controls.

const TOP_BYTE_SHIFT: u32 = 56;
const POINTER_SIGN_BIT: u32 = 55;
const DETECTION_BIT: u32 = 54;
const LOW_RESULT_MASK: u64 = (1 << DETECTION_BIT) - 1;
const PRESERVED_BASE_MASK: u64 = !((1 << POINTER_SIGN_BIT) - 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EffectivePointerChecks {
    Unchecked,
    Addition,
    AdditionAndMultiplication,
}

/// The two requested check levels supported by the bounded EL10 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AccessEl {
    El0,
    El1,
}

/// CPU feature and exact arithmetic specialization required by a reached CPA
/// instruction. A discarded destination still requires the feature and mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PointerArithmeticRequirement {
    access_el: AccessEl,
    checks: EffectivePointerChecks,
}

impl PointerArithmeticRequirement {
    pub const fn new(access_el: AccessEl, checks: EffectivePointerChecks) -> Self {
        Self { access_el, checks }
    }
    pub const fn access_el(self) -> AccessEl {
        self.access_el
    }
    pub const fn checks(self) -> EffectivePointerChecks {
        self.checks
    }
}

impl EffectivePointerChecks {
    /// Validates resolved effects only; the caller retains their authority lease.
    pub const fn from_effective(cpta: bool, cptm: bool) -> Option<Self> {
        match (cpta, cptm) {
            (false, false) => Some(Self::Unchecked),
            (true, false) => Some(Self::Addition),
            (true, true) => Some(Self::AdditionAndMultiplication),
            (false, true) => None,
        }
    }

    /// PointerCheckAtEL after the owner resolves the requested EL and regime.
    /// Detection marks the result; it does not raise an arithmetic exception.
    pub fn apply(self, result: u64, base: u64, multiplication_overflow: bool) -> u64 {
        if self == Self::Unchecked {
            return result;
        }
        let previous_detection = ((base >> POINTER_SIGN_BIT) ^ (base >> DETECTION_BIT)) & 1 != 0;
        let addition_detection =
            (result >> TOP_BYTE_SHIFT) != (base >> TOP_BYTE_SHIFT) || previous_detection;
        let multiplication_detection =
            self == Self::AdditionAndMultiplication && multiplication_overflow;
        if addition_detection || multiplication_detection {
            let poison = (!(base >> POINTER_SIGN_BIT) & 1) << DETECTION_BIT;
            (result & LOW_RESULT_MASK) | (base & PRESERVED_BASE_MASK) | poison
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_check_requires_addition_check() {
        assert_eq!(EffectivePointerChecks::from_effective(false, true), None);
        for (cpta, cptm, expected) in [
            (false, false, EffectivePointerChecks::Unchecked),
            (true, false, EffectivePointerChecks::Addition),
            (
                true,
                true,
                EffectivePointerChecks::AdditionAndMultiplication,
            ),
        ] {
            assert_eq!(
                EffectivePointerChecks::from_effective(cpta, cptm),
                Some(expected)
            );
        }
    }

    #[test]
    fn checks_preserve_base_high_bits_and_mark_bit_54() {
        let base = 0x1280_0000_0000_0000;
        let changed_top_byte = 0x1380_0000_0000_0005;
        assert_eq!(
            EffectivePointerChecks::Unchecked.apply(changed_top_byte, base, true),
            changed_top_byte
        );
        assert_eq!(
            EffectivePointerChecks::Addition.apply(changed_top_byte, base, false),
            0x1280_0000_0000_0005
        );
        // Base bits55/54 differ: detection persists even without a top-byte change.
        assert_eq!(
            EffectivePointerChecks::Addition.apply(base | 5, base, false),
            base | 5
        );
        let ordinary_base = 0x1200_0000_0000_0000;
        let ordinary_result = ordinary_base | 5;
        assert_eq!(
            EffectivePointerChecks::Addition.apply(ordinary_result, ordinary_base, true),
            ordinary_result
        );
        assert_eq!(
            EffectivePointerChecks::AdditionAndMultiplication.apply(
                ordinary_result,
                ordinary_base,
                true
            ),
            0x1240_0000_0000_0005
        );
    }
}
