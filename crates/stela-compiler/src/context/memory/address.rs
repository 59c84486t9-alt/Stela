//! Access levels and resolved FEAT_CPA2 address arithmetic.

use crate::context::pointer::EffectivePointerChecks;

pub use crate::context::pointer::AccessEl;

/// Effective AddressAdd checking after the architectural owner resolves CPTA.
/// AddressIncrement uses the explicit unchecked CPACHECK implementation choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AddressAddChecks {
    Disabled,
    Enabled,
}

/// Explicit constrained AddressIncrement implementation choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IncrementChoice {
    Unchecked,
    Checked,
}

impl AddressAddChecks {
    /// PointerAddCheckAtEL changes a result, without raising an arithmetic fault.
    pub fn apply(self, result: u64, base: u64) -> u64 {
        match self {
            Self::Disabled => result,
            Self::Enabled => EffectivePointerChecks::Addition.apply(result, base, false),
        }
    }
}

/// Both access levels remain independently resolved within one consumed body.
/// Normal and unprivileged accesses need not select the same access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EffectiveAddressChecks {
    el0: AddressAddChecks,
    el1: AddressAddChecks,
}

impl EffectiveAddressChecks {
    pub const fn new(el0: AddressAddChecks, el1: AddressAddChecks) -> Self {
        Self { el0, el1 }
    }

    pub const fn at(self, access_el: AccessEl) -> AddressAddChecks {
        match access_el {
            AccessEl::El0 => self.el0,
            AccessEl::El1 => self.el1,
        }
    }
}

/// An absent requirement means this body performs no specialized AddressAdd at
/// that access level; it does not mean that CPA2 is disabled on the machine.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AddressCheckRequirements {
    el0: Option<AddressAddChecks>,
    el1: Option<AddressAddChecks>,
    increment: Option<IncrementChoice>,
}

impl AddressCheckRequirements {
    pub const fn for_access(access_el: AccessEl, checks: AddressAddChecks) -> Self {
        match access_el {
            AccessEl::El0 => Self {
                el0: Some(checks),
                el1: None,
                increment: None,
            },
            AccessEl::El1 => Self {
                el0: None,
                el1: Some(checks),
                increment: None,
            },
        }
    }

    pub fn compatible_arithmetic(
        self,
        required: crate::context::pointer::PointerArithmeticRequirement,
    ) -> bool {
        let addition = match required.checks() {
            EffectivePointerChecks::Unchecked => AddressAddChecks::Disabled,
            EffectivePointerChecks::Addition
            | EffectivePointerChecks::AdditionAndMultiplication => AddressAddChecks::Enabled,
        };
        self.merge(Self::for_access(required.access_el(), addition))
            .is_some()
    }

    pub const fn with_increment_choice(mut self, choice: IncrementChoice) -> Self {
        self.increment = Some(choice);
        self
    }

    pub const fn is_empty(&self) -> bool {
        self.el0.is_none() && self.el1.is_none() && self.increment.is_none()
    }

    /// Opposite specializations at the same access level cannot silently merge.
    pub fn merge(self, other: Self) -> Option<Self> {
        Some(Self {
            el0: merge_level(self.el0, other.el0)?,
            el1: merge_level(self.el1, other.el1)?,
            increment: merge_level(self.increment, other.increment)?,
        })
    }

    pub fn matches(self, resolved: EffectiveAddressChecks, increment: IncrementChoice) -> bool {
        self.increment.is_none_or(|required| required == increment)
            && [AccessEl::El0, AccessEl::El1].into_iter().all(|access_el| {
                let required = match access_el {
                    AccessEl::El0 => self.el0,
                    AccessEl::El1 => self.el1,
                };
                required.is_none_or(|checks| checks == resolved.at(access_el))
            })
    }
}

fn merge_level<T: PartialEq>(first: Option<T>, second: Option<T>) -> Option<Option<T>> {
    match (first, second) {
        (None, required) | (required, None) => Some(required),
        (Some(first), Some(second)) if first == second => Some(Some(first)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
