//! Allocation-tag values and the IRG tag generator.

/// Architectural allocation-tag granule size, independent of SCA and ERG.
pub const TAG_GRANULE_BYTES: usize = 16;

const ALLOCATION_TAG_BITS: u32 = 4;
const ALLOCATION_TAG_COUNT: u8 = 1 << ALLOCATION_TAG_BITS;
const ALLOCATION_TAG_MASK: u8 = ALLOCATION_TAG_COUNT - 1;
const LOGICAL_TAG_SHIFT: u32 = 56;
const LOGICAL_TAG_MASK: u64 = (ALLOCATION_TAG_MASK as u64) << LOGICAL_TAG_SHIFT;
const LFSR_FEEDBACK_TAP_2: u32 = 2;
const LFSR_FEEDBACK_TAP_3: u32 = 3;
const LFSR_FEEDBACK_TAP_5: u32 = 5;
const LFSR_INSERT_SHIFT: u32 = u16::BITS - ALLOCATION_TAG_BITS;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocationTag(u8);

impl AllocationTag {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u8) -> Option<Self> {
        if value < ALLOCATION_TAG_COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn value(self) -> u8 {
        self.0
    }

    pub const fn from_address(address: u64) -> Self {
        Self(((address >> LOGICAL_TAG_SHIFT) as u8) & ALLOCATION_TAG_MASK)
    }

    pub const fn apply_to_address(self, address: u64) -> u64 {
        (address & !LOGICAL_TAG_MASK) | ((self.0 as u64) << LOGICAL_TAG_SHIFT)
    }

    const fn excluded_by(self, excluded_tags: u16) -> bool {
        excluded_tags & (1 << self.0) != 0
    }

    const fn next(self) -> Self {
        Self((self.0 + 1) & ALLOCATION_TAG_MASK)
    }
}

/// GCR_EL1.RRND selection. External randomness is supplied by the caller;
/// this module never substitutes an unseeded or constant entropy source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagRandomization {
    ArchitecturalLfsr,
    External,
}

/// Effective allocation-tag access and the relevant GCR_EL1 fields.
/// Broader exception-level and translation controls have their own owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagGenerationControls {
    pub allocation_access_enabled: bool,
    pub excluded_tags: u16,
    pub randomization: TagRandomization,
}

/// RGSR_EL1.SEED[15:0] and RGSR_EL1.TAG for FEAT_MTE without FEAT_MTE_EIRG.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TagGenerationState {
    pub seed: u16,
    pub tag: AllocationTag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagGenerationError {
    EntropyUnavailable,
    ExcludedRandomTag,
}

impl TagGenerationState {
    /// Execute AArch64_ChooseTagOrZero for IRG.
    ///
    /// `register_exclude` supplies Xm; only its low sixteen bits participate.
    /// In External mode the caller must supply a random non-excluded selection,
    /// preferably uniformly distributed. Preserving RGSR in this mode is an
    /// architectural implementation choice. Invalid/missing entropy leaves it
    /// unchanged. An all-excluded mask requires no external entropy.
    pub fn generate_tag(
        &mut self,
        controls: TagGenerationControls,
        register_exclude: u64,
        external_tag: Option<AllocationTag>,
    ) -> Result<AllocationTag, TagGenerationError> {
        if !controls.allocation_access_enabled {
            return Ok(AllocationTag::ZERO);
        }
        let excluded_tags = controls.excluded_tags | register_exclude as u16;
        if controls.randomization == TagRandomization::External {
            if excluded_tags == u16::MAX {
                return Ok(AllocationTag::ZERO);
            }
            let tag = external_tag.ok_or(TagGenerationError::EntropyUnavailable)?;
            if tag.excluded_by(excluded_tags) {
                return Err(TagGenerationError::ExcludedRandomTag);
            }
            return Ok(tag);
        }
        let offset = self.random_offset();
        self.tag = choose_non_excluded_tag(self.tag, offset, excluded_tags);
        Ok(self.tag)
    }

    /// Four consecutive AArch64_NextRandomTagBit steps, computed together.
    fn random_offset(&mut self) -> u8 {
        let feedback = (self.seed
            ^ (self.seed >> LFSR_FEEDBACK_TAP_2)
            ^ (self.seed >> LFSR_FEEDBACK_TAP_3)
            ^ (self.seed >> LFSR_FEEDBACK_TAP_5))
            & u16::from(ALLOCATION_TAG_MASK);
        self.seed = (self.seed >> ALLOCATION_TAG_BITS) | (feedback << LFSR_INSERT_SHIFT);
        feedback as u8
    }
}

fn choose_non_excluded_tag(
    mut tag: AllocationTag,
    mut offset: u8,
    excluded_tags: u16,
) -> AllocationTag {
    if excluded_tags == u16::MAX {
        return AllocationTag::ZERO;
    }
    if offset == 0 {
        while tag.excluded_by(excluded_tags) {
            tag = tag.next();
        }
    }
    while offset != 0 {
        offset -= 1;
        tag = tag.next();
        while tag.excluded_by(excluded_tags) {
            tag = tag.next();
        }
    }
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controls(randomization: TagRandomization) -> TagGenerationControls {
        TagGenerationControls {
            allocation_access_enabled: true,
            excluded_tags: 0,
            randomization,
        }
    }

    #[test]
    fn logical_tag_replacement_preserves_every_other_address_bit() {
        for value in 0..ALLOCATION_TAG_COUNT {
            let tag = AllocationTag::new(value).unwrap();
            for address in [0, u64::MAX, 0xa123_4567_89ab_cdef, 0x0123_4567_89ab_cdef] {
                let result = tag.apply_to_address(address);
                assert_eq!(AllocationTag::from_address(result), tag);
                assert_eq!(result & !LOGICAL_TAG_MASK, address & !LOGICAL_TAG_MASK);
            }
        }
        assert!(AllocationTag::new(ALLOCATION_TAG_COUNT).is_none());
        assert!(AllocationTag::new(u8::MAX).is_none());
    }

    #[test]
    fn parallel_feedback_equals_four_architectural_steps_for_every_seed() {
        for initial_seed in 0..=u16::MAX {
            let mut seed = initial_seed;
            let mut offset = 0;
            for bit in 0..ALLOCATION_TAG_BITS {
                let feedback = (seed
                    ^ (seed >> LFSR_FEEDBACK_TAP_2)
                    ^ (seed >> LFSR_FEEDBACK_TAP_3)
                    ^ (seed >> LFSR_FEEDBACK_TAP_5))
                    & 1;
                seed = (seed >> 1) | (feedback << (u16::BITS - 1));
                offset |= (feedback as u8) << bit;
            }
            let mut state = TagGenerationState {
                seed: initial_seed,
                tag: AllocationTag::ZERO,
            };
            assert_eq!(state.random_offset(), offset);
            assert_eq!(state.seed, seed);
        }
    }

    #[test]
    fn selection_counts_allowed_tags_and_wraps() {
        let start = AllocationTag::new(14).unwrap();
        let excluded = !(1 << 1 | 1 << 7 | 1 << 14);
        let expected = [14, 1, 7, 14, 1, 7, 14, 1, 7, 14, 1, 7, 14, 1, 7, 14];
        for (offset, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                choose_non_excluded_tag(start, offset as u8, excluded).value(),
                expected
            );
        }
        assert_eq!(
            choose_non_excluded_tag(AllocationTag::ZERO, 0, excluded).value(),
            1
        );
        assert_eq!(
            choose_non_excluded_tag(start, ALLOCATION_TAG_MASK, u16::MAX),
            AllocationTag::ZERO
        );
    }

    #[test]
    fn disabled_access_and_external_randomness_preserve_rgsr() {
        let mut state = TagGenerationState {
            seed: 0x1234,
            tag: AllocationTag::new(7).unwrap(),
        };
        let before = state;
        let mut disabled = controls(TagRandomization::ArchitecturalLfsr);
        disabled.allocation_access_enabled = false;
        assert_eq!(
            state.generate_tag(disabled, 0, None),
            Ok(AllocationTag::ZERO)
        );
        let external = controls(TagRandomization::External);
        assert_eq!(
            state.generate_tag(external, 0, None),
            Err(TagGenerationError::EntropyUnavailable)
        );
        let tag = AllocationTag::new(3).unwrap();
        assert_eq!(
            state.generate_tag(external, 1 << tag.value(), Some(tag)),
            Err(TagGenerationError::ExcludedRandomTag)
        );
        assert_eq!(state.generate_tag(external, 0, Some(tag)), Ok(tag));
        assert_eq!(
            state.generate_tag(external, u64::from(u16::MAX), None),
            Ok(AllocationTag::ZERO)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn deterministic_generation_advances_seed_even_when_every_tag_is_excluded() {
        let mut state = TagGenerationState {
            seed: 0x1234,
            tag: AllocationTag::new(7).unwrap(),
        };
        let mut expected = state;
        expected.random_offset();
        expected.tag = AllocationTag::ZERO;
        assert_eq!(
            state.generate_tag(
                controls(TagRandomization::ArchitecturalLfsr),
                u64::from(u16::MAX),
                None
            ),
            Ok(AllocationTag::ZERO)
        );
        assert_eq!(state, expected);
    }

    #[test]
    fn both_exclusion_sources_apply_and_high_register_bits_do_not() {
        let mut control = controls(TagRandomization::ArchitecturalLfsr);
        control.excluded_tags = u16::MAX ^ (1 << 5) ^ (1 << 9);
        let mut state = TagGenerationState::default();
        let mut high = state;
        let mask = 1 << 5;
        let result = state.generate_tag(control, mask, None);
        assert_eq!(result, Ok(AllocationTag::new(9).unwrap()));
        assert_eq!(
            high.generate_tag(control, mask | 0xffff_ffff_ffff_0000, None),
            result
        );
        assert_eq!(state, high);
    }
}
