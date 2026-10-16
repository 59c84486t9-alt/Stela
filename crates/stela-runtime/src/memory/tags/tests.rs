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
