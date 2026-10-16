//! MOVPRFX compatibility of each follower encoding: which vector sources the
//! follower reads besides its destructive destination.

use crate::aarch64::scalable::{ElementSize, Predication, is_predicate_register, is_z_register};

const GOVERNING_PREDICATE_REGISTER_COUNT: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredicatedPrefixRequirement {
    pub predicate: u8,
    /// Effective size from the follower's operational requirements, including
    /// widening/narrowing rules; not necessarily its destination element size.
    pub element: ElementSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixRequirement {
    Forbidden,
    Vector {
        destination: u8,
        /// None permits only an unpredicated prefix.
        predicated: Option<PredicatedPrefixRequirement>,
        /// Explicit vector sources other than the implicit old destination.
        other_vector_sources: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedPrefix {
    pub destination: u8,
    pub source: u8,
    pub predication: Predication,
    /// Predicated encodings require B/H/S/D. An unpredicated encoding has no
    /// element-size field; this value is ignored for that encoding.
    pub element: Option<ElementSize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixViolation {
    InvalidPrefixDestination(u8),
    InvalidPrefixSource(u8),
    InvalidFollowerDestination(u8),
    InvalidPrefixPredicate(u8),
    InvalidFollowerPredicate(u8),
    MissingPrefixElement,
    UnallocatedPrefixElement(ElementSize),
    FollowerNotAuthorized,
    DestinationMismatch,
    OtherSourceAlias,
    PredicatedPrefixForbidden,
    PredicateMismatch,
    ElementMismatch,
}

fn allocated_element(element: ElementSize) -> bool {
    matches!(
        element,
        ElementSize::Byte | ElementSize::Halfword | ElementSize::Word | ElementSize::Doubleword
    )
}

/// Validate operands and the predictable-pair requirements for an allocated
/// follower. Malformed metadata remains explicit; the caller must not convert
/// missing source or unsupported decoding into a known pair violation.
pub fn validate(
    prefix: DecodedPrefix,
    requirement: PrefixRequirement,
) -> Result<(), PrefixViolation> {
    if !is_z_register(prefix.destination) {
        return Err(PrefixViolation::InvalidPrefixDestination(
            prefix.destination,
        ));
    }
    if !is_z_register(prefix.source) {
        return Err(PrefixViolation::InvalidPrefixSource(prefix.source));
    }
    let prefix_predicate = match prefix.predication {
        Predication::Unpredicated => None,
        Predication::Merging(predicate) | Predication::Zeroing(predicate) => {
            if predicate >= GOVERNING_PREDICATE_REGISTER_COUNT {
                return Err(PrefixViolation::InvalidPrefixPredicate(predicate));
            }
            let element = prefix
                .element
                .ok_or(PrefixViolation::MissingPrefixElement)?;
            if !allocated_element(element) {
                return Err(PrefixViolation::UnallocatedPrefixElement(element));
            }
            Some((predicate, element))
        }
    };
    let PrefixRequirement::Vector {
        destination,
        predicated,
        other_vector_sources,
    } = requirement
    else {
        return Err(PrefixViolation::FollowerNotAuthorized);
    };
    if !is_z_register(destination) {
        return Err(PrefixViolation::InvalidFollowerDestination(destination));
    }
    if let Some(required) = predicated
        && !is_predicate_register(required.predicate)
    {
        return Err(PrefixViolation::InvalidFollowerPredicate(
            required.predicate,
        ));
    }
    if prefix.destination != destination {
        return Err(PrefixViolation::DestinationMismatch);
    }
    if other_vector_sources & (1_u32 << destination) != 0 {
        return Err(PrefixViolation::OtherSourceAlias);
    }
    if let Some((predicate, element)) = prefix_predicate {
        let required = predicated.ok_or(PrefixViolation::PredicatedPrefixForbidden)?;
        if predicate != required.predicate {
            return Err(PrefixViolation::PredicateMismatch);
        }
        if element != required.element {
            return Err(PrefixViolation::ElementMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
