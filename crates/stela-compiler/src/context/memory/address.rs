//! Source access levels and resolved CPA2 address arithmetic specialization.
//!
//! These values describe emitted effects, never feature/control authority.
//! The execution owner must resolve and retain the same actual controls through
//! invocation and retirement. Unprivileged access EL is resolved from the source
//! descriptor's privilege rules, including UAO/NV/host state when applicable.

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
mod tests {
    use super::*;

    #[test]
    fn mixed_access_levels_retain_opposite_effects_and_reject_same_level_conflicts() {
        let resolved =
            EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Enabled);
        let el0 = AddressCheckRequirements::for_access(AccessEl::El0, AddressAddChecks::Disabled);
        let el1 = AddressCheckRequirements::for_access(AccessEl::El1, AddressAddChecks::Enabled);
        let mixed = el0.merge(el1).expect("different access levels compose");
        assert!(mixed.matches(resolved, IncrementChoice::Unchecked));
        assert!(!mixed.matches(
            EffectiveAddressChecks::new(AddressAddChecks::Enabled, AddressAddChecks::Enabled,),
            IncrementChoice::Unchecked
        ));
        assert_eq!(
            mixed.merge(AddressCheckRequirements::default()),
            Some(mixed)
        );
        assert!(
            mixed
                .merge(AddressCheckRequirements::for_access(
                    AccessEl::El0,
                    AddressAddChecks::Enabled,
                ))
                .is_none()
        );
        assert!(
            mixed
                .merge(AddressCheckRequirements::for_access(
                    AccessEl::El1,
                    AddressAddChecks::Disabled,
                ))
                .is_none()
        );
    }

    #[test]
    fn secondary_increment_choice_is_independent_and_cannot_silently_merge() {
        let unchecked =
            AddressCheckRequirements::default().with_increment_choice(IncrementChoice::Unchecked);
        let checked =
            AddressCheckRequirements::default().with_increment_choice(IncrementChoice::Checked);
        assert!(unchecked.merge(checked).is_none());
        let resolved =
            EffectiveAddressChecks::new(AddressAddChecks::Enabled, AddressAddChecks::Disabled);
        assert!(unchecked.matches(resolved, IncrementChoice::Unchecked));
        assert!(!unchecked.matches(resolved, IncrementChoice::Checked));
        assert!(AddressCheckRequirements::default().is_empty());
        assert!(!unchecked.is_empty());
    }

    #[test]
    fn enabled_addition_marks_top_byte_change_and_is_idempotent_for_zero_offset() {
        let base = 0x1200_0000_0000_1000;
        let result = 0x1300_0000_0000_1000;
        let marked = 0x1240_0000_0000_1000;
        assert_eq!(AddressAddChecks::Disabled.apply(result, base), result);
        assert_eq!(AddressAddChecks::Enabled.apply(result, base), marked);
        assert_eq!(AddressAddChecks::Enabled.apply(base, base), base);
        assert_eq!(AddressAddChecks::Enabled.apply(marked, marked), marked);
    }
}
