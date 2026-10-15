//! MOVPRFX compatibility supplied by each follower's exact decoded encoding.
//!
//! Vector source masks identify shared V/Z storage, excluding the follower's
//! implicit destructive destination. GPR operands never enter this mask. Source
//! adjacency, incomplete windows, unsupported followers and exception policy
//! belong to the caller; this module neither decodes nor executes either word.

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
mod tests {
    use super::*;

    const DESTINATION: u8 = 3;
    const SOURCE: u8 = 5;
    const PREDICATE: u8 = 2;
    const ELEMENTS: [ElementSize; 4] = [
        ElementSize::Byte,
        ElementSize::Halfword,
        ElementSize::Word,
        ElementSize::Doubleword,
    ];

    fn prefix(predication: Predication, element: Option<ElementSize>) -> DecodedPrefix {
        DecodedPrefix {
            destination: DESTINATION,
            source: SOURCE,
            predication,
            element,
        }
    }

    fn requirement(predicated: Option<PredicatedPrefixRequirement>) -> PrefixRequirement {
        PrefixRequirement::Vector {
            destination: DESTINATION,
            predicated,
            other_vector_sources: 1_u32 << SOURCE,
        }
    }

    fn predicated(predicate: u8, element: ElementSize) -> PredicatedPrefixRequirement {
        PredicatedPrefixRequirement { predicate, element }
    }

    #[test]
    fn both_predicated_modes_accept_all_allocated_predicates_and_sizes() {
        for predicate in 0..GOVERNING_PREDICATE_REGISTER_COUNT {
            for element in ELEMENTS {
                let requirement = requirement(Some(predicated(predicate, element)));
                for mode in [
                    Predication::Merging(predicate),
                    Predication::Zeroing(predicate),
                ] {
                    assert_eq!(validate(prefix(mode, Some(element)), requirement), Ok(()));
                }
            }
        }
    }

    #[test]
    fn unpredicated_prefix_has_no_predicate_or_element_match() {
        for predicate in 0..GOVERNING_PREDICATE_REGISTER_COUNT {
            for element in ELEMENTS {
                assert_eq!(
                    validate(
                        prefix(Predication::Unpredicated, None),
                        requirement(Some(predicated(predicate, element))),
                    ),
                    Ok(())
                );
            }
        }
        assert_eq!(
            validate(
                prefix(Predication::Unpredicated, Some(ElementSize::Quadword)),
                requirement(None),
            ),
            Ok(())
        );
    }

    #[test]
    fn forbidden_and_unpredicated_only_followers_are_distinct() {
        assert_eq!(
            validate(
                prefix(Predication::Unpredicated, None),
                PrefixRequirement::Forbidden
            ),
            Err(PrefixViolation::FollowerNotAuthorized)
        );
        assert_eq!(
            validate(prefix(Predication::Unpredicated, None), requirement(None)),
            Ok(())
        );
        for mode in [
            Predication::Merging(PREDICATE),
            Predication::Zeroing(PREDICATE),
        ] {
            assert_eq!(
                validate(prefix(mode, Some(ElementSize::Byte)), requirement(None)),
                Err(PrefixViolation::PredicatedPrefixForbidden)
            );
        }
    }

    #[test]
    fn predicate_and_effective_element_must_match_independently() {
        let requirement = requirement(Some(predicated(PREDICATE, ElementSize::Word)));
        assert_eq!(
            validate(
                prefix(Predication::Merging(PREDICATE + 1), Some(ElementSize::Word)),
                requirement
            ),
            Err(PrefixViolation::PredicateMismatch)
        );
        assert_eq!(
            validate(
                prefix(Predication::Zeroing(PREDICATE), Some(ElementSize::Halfword)),
                requirement
            ),
            Err(PrefixViolation::ElementMismatch)
        );
        assert_eq!(
            validate(
                prefix(Predication::Zeroing(PREDICATE), Some(ElementSize::Word)),
                requirement
            ),
            Ok(())
        );
    }

    #[test]
    fn destination_identity_and_other_vector_alias_are_separate_rules() {
        let mut decoded = prefix(Predication::Unpredicated, None);
        decoded.destination = SOURCE;
        assert_eq!(
            validate(decoded, requirement(None)),
            Err(PrefixViolation::DestinationMismatch)
        );
        let aliases_destination = PrefixRequirement::Vector {
            destination: DESTINATION,
            predicated: None,
            // A V/Q/D/S/H/B source aliases the same numbered Z storage.
            other_vector_sources: 1_u32 << DESTINATION,
        };
        assert_eq!(
            validate(prefix(Predication::Unpredicated, None), aliases_destination),
            Err(PrefixViolation::OtherSourceAlias)
        );
    }

    #[test]
    fn prefix_source_identity_imposes_no_extra_pair_restriction() {
        for source in 0..32 {
            let mut decoded = prefix(Predication::Unpredicated, None);
            decoded.source = source;
            assert_eq!(validate(decoded, requirement(None)), Ok(()));
        }
    }

    #[test]
    fn same_numbered_gpr_is_excluded_by_the_family_source_mask() {
        // X3/W3 do not alias Z3. The family excludes them from this vector mask.
        let gpr_source = PrefixRequirement::Vector {
            destination: DESTINATION,
            predicated: None,
            other_vector_sources: 0,
        };
        assert_eq!(
            validate(prefix(Predication::Unpredicated, None), gpr_source),
            Ok(())
        );
    }

    #[test]
    fn vector_boundaries_are_checked_before_mask_shifts() {
        let mut decoded = prefix(Predication::Unpredicated, None);
        decoded.destination = 32;
        assert_eq!(
            validate(decoded, requirement(None)),
            Err(PrefixViolation::InvalidPrefixDestination(32))
        );
        decoded.destination = DESTINATION;
        decoded.source = 32;
        assert_eq!(
            validate(decoded, requirement(None)),
            Err(PrefixViolation::InvalidPrefixSource(32))
        );
        let invalid_follower = PrefixRequirement::Vector {
            destination: 32,
            predicated: None,
            other_vector_sources: 0,
        };
        assert_eq!(
            validate(prefix(Predication::Unpredicated, None), invalid_follower),
            Err(PrefixViolation::InvalidFollowerDestination(32))
        );
        decoded.destination = 31;
        decoded.source = 31;
        let boundary = PrefixRequirement::Vector {
            destination: 31,
            predicated: None,
            other_vector_sources: 0,
        };
        assert_eq!(validate(decoded, boundary), Ok(()));
        let alias = PrefixRequirement::Vector {
            destination: 31,
            predicated: None,
            other_vector_sources: 1_u32 << 31,
        };
        assert_eq!(
            validate(decoded, alias),
            Err(PrefixViolation::OtherSourceAlias)
        );
    }

    #[test]
    fn prefix_and_follower_predicate_bounds_are_distinct() {
        for mode in [Predication::Merging(8), Predication::Zeroing(8)] {
            assert_eq!(
                validate(prefix(mode, Some(ElementSize::Byte)), requirement(None)),
                Err(PrefixViolation::InvalidPrefixPredicate(8))
            );
        }
        assert_eq!(
            validate(
                prefix(Predication::Unpredicated, None),
                requirement(Some(predicated(16, ElementSize::Byte)))
            ),
            Err(PrefixViolation::InvalidFollowerPredicate(16))
        );
    }

    #[test]
    fn wide_follower_predicates_allow_unpredicated_cpy_style_pairs() {
        let wide_follower = requirement(Some(predicated(15, ElementSize::Byte)));
        assert_eq!(
            validate(prefix(Predication::Unpredicated, None), wide_follower),
            Ok(())
        );
        for mode in [Predication::Merging(7), Predication::Zeroing(7)] {
            assert_eq!(
                validate(prefix(mode, Some(ElementSize::Byte)), wide_follower),
                Err(PrefixViolation::PredicateMismatch)
            );
        }
    }

    #[test]
    fn follower_quadword_size_does_not_constrain_unpredicated_prefix() {
        let wide_follower = requirement(Some(predicated(PREDICATE, ElementSize::Quadword)));
        assert_eq!(
            validate(prefix(Predication::Unpredicated, None), wide_follower),
            Ok(())
        );
        assert_eq!(
            validate(
                prefix(
                    Predication::Merging(PREDICATE),
                    Some(ElementSize::Doubleword)
                ),
                wide_follower,
            ),
            Err(PrefixViolation::ElementMismatch)
        );
    }

    #[test]
    fn predicated_prefix_requires_allocated_sizes() {
        assert_eq!(
            validate(
                prefix(Predication::Merging(PREDICATE), None),
                requirement(None)
            ),
            Err(PrefixViolation::MissingPrefixElement)
        );
        assert_eq!(
            validate(
                prefix(Predication::Zeroing(PREDICATE), Some(ElementSize::Quadword)),
                requirement(None)
            ),
            Err(PrefixViolation::UnallocatedPrefixElement(
                ElementSize::Quadword
            ))
        );
    }
}
