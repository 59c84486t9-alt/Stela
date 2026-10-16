//! Address specializations for checked memory access.

use crate::context::memory::{
    SpAlignmentRequirement,
    address::{
        AccessEl, AddressAddChecks, AddressCheckRequirements, EffectiveAddressChecks,
        IncrementChoice,
    },
};

/// Access levels follow the instruction's privilege rules. The runtime
/// validates these choices and both resolved CPTA effects before entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct CheckedAddressProfile {
    sp_alignment: SpAlignmentRequirement,
    ordinary_access_el: AccessEl,
    unprivileged_access_el: AccessEl,
    checks: EffectiveAddressChecks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointer_arithmetic: Option<crate::context::pointer::EffectivePointerChecks>,
}

impl CheckedAddressProfile {
    pub(super) const fn new(
        sp_alignment: SpAlignmentRequirement,
        ordinary_access_el: AccessEl,
        unprivileged_access_el: AccessEl,
        checks: EffectiveAddressChecks,
    ) -> Self {
        assert!(!matches!(sp_alignment, SpAlignmentRequirement::Any));
        Self {
            sp_alignment,
            ordinary_access_el,
            unprivileged_access_el,
            checks,
            pointer_arithmetic: None,
        }
    }

    pub(super) fn with_pointer_arithmetic(
        mut self,
        checks: crate::context::pointer::EffectivePointerChecks,
    ) -> Option<Self> {
        let addition = match checks {
            crate::context::pointer::EffectivePointerChecks::Unchecked => {
                AddressAddChecks::Disabled
            }
            crate::context::pointer::EffectivePointerChecks::Addition
            | crate::context::pointer::EffectivePointerChecks::AdditionAndMultiplication => {
                AddressAddChecks::Enabled
            }
        };
        if addition != self.checks.at(self.ordinary_access_el) {
            return None;
        }
        self.pointer_arithmetic = Some(checks);
        Some(self)
    }

    pub(super) fn pointer_arithmetic(
        self,
    ) -> Option<crate::context::pointer::PointerArithmeticRequirement> {
        self.pointer_arithmetic.map(|checks| {
            crate::context::pointer::PointerArithmeticRequirement::new(
                self.ordinary_access_el,
                checks,
            )
        })
    }

    pub(super) const fn sp_requirement(self) -> SpAlignmentRequirement {
        self.sp_alignment
    }

    const fn access_el(self, unprivileged: bool) -> AccessEl {
        if unprivileged {
            self.unprivileged_access_el
        } else {
            self.ordinary_access_el
        }
    }

    pub(super) const fn checks(self, unprivileged: bool) -> AddressAddChecks {
        self.checks.at(self.access_el(unprivileged))
    }

    pub(super) fn requirements(self, unprivileged: bool) -> AddressCheckRequirements {
        AddressCheckRequirements::for_access(
            self.access_el(unprivileged),
            self.checks(unprivileged),
        )
        .with_increment_choice(IncrementChoice::Unchecked)
    }

    pub(super) fn direct_requirements(self) -> AddressCheckRequirements {
        AddressCheckRequirements::default().with_increment_choice(IncrementChoice::Unchecked)
    }
}

#[cfg(test)]
mod tests;
