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
mod tests;
