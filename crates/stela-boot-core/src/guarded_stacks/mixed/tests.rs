use super::*;
fn linux() -> Geometry {
    Geometry::new(16 * 1024, 16 * 1024).unwrap()
}
fn rust() -> Geometry {
    Geometry::new(128 * 1024, PAGE).unwrap()
}
#[test]
fn mixed_native_profile_has_real_aligned_c_stacks_and_separate_rust_extents() {
    let mut specs = [linux(); 32];
    // Linux service index2; other seven reserved roles have Rust geometry.
    for index in [0, 1, 3, 4, 5, 6, 7, 28, 29, 30, 31] {
        specs[index] = rust();
    }
    let layout = MixedLayout::new(0xffff_8008_0000_0000, &specs).unwrap();
    assert_eq!(layout.count(), 32);
    assert_eq!(layout.physical_alignment(), 16 * 1024);
    assert_eq!(layout.physical_bytes(), 21 * 16 * 1024 + 11 * 128 * 1024);
    let raw = PAGE..PAGE + layout.raw_allocation_bytes();
    let (mut virtual_end, mut physical_end) = (layout.virtual_range().start, raw.start);
    for (index, spec) in specs.iter().enumerate() {
        let slot = layout.slot(index).unwrap();
        let backing = layout.backing(raw.clone(), index).unwrap();
        assert!(slot.lower_guard.start >= virtual_end);
        assert_eq!(slot.lower_guard.end, slot.usable.start);
        assert_eq!(slot.upper_guard.start, slot.usable.end);
        assert_eq!(slot.lower_guard.end - slot.lower_guard.start, PAGE);
        assert_eq!(slot.upper_guard.end - slot.upper_guard.start, PAGE);
        assert_eq!(slot.usable.end - slot.usable.start, spec.bytes());
        assert_eq!(slot.usable.start % spec.alignment(), 0);
        assert_eq!(backing.start % spec.alignment(), 0);
        assert_eq!(backing.end - backing.start, spec.bytes());
        assert!(backing.start >= physical_end && backing.end <= raw.end);
        virtual_end = slot.upper_guard.end;
        physical_end = backing.end;
    }
    assert_eq!(virtual_end, layout.virtual_range().end);
    assert_eq!(layout.slot(32), Err(Error::Slot));
    assert_eq!(layout.backing(raw, 32), Err(Error::Slot));
}
#[test]
fn physical_alignment_keeps_all_prefix_and_per_slot_padding() {
    let specs = [Geometry::new(PAGE, PAGE).unwrap(), linux(), rust()];
    let layout = MixedLayout::new(PAGE, &specs).unwrap();
    assert_eq!(layout.physical_offset(1), Ok(16 * 1024));
    assert_eq!(layout.physical_offset(2), Ok(32 * 1024));
    for page in 0..4 {
        let start = page * PAGE;
        let raw = start..start + layout.raw_allocation_bytes();
        for index in 0..specs.len() {
            let backing = layout.backing(raw.clone(), index).unwrap();
            assert!(backing.start >= raw.start && backing.end <= raw.end);
        }
    }
    let too_short = PAGE..PAGE + layout.raw_allocation_bytes() - PAGE;
    assert_eq!(layout.backing(too_short, 0), Err(Error::Capacity));
}
#[test]
fn invalid_counts_alignment_and_wrapping_extents_refuse_transactionally() {
    assert!(matches!(MixedLayout::new(0, &[]), Err(Error::Capacity)));
    assert!(matches!(
        MixedLayout::new(0, &[linux(); 65]),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        MixedLayout::new(1, &[linux()]),
        Err(Error::Alignment)
    ));
    for (bytes, alignment) in [
        (0, PAGE),
        (PAGE - 1, PAGE),
        (PAGE, 0),
        (PAGE, PAGE / 2),
        (PAGE, 3 * PAGE),
    ] {
        assert_eq!(Geometry::new(bytes, alignment), Err(Error::Alignment));
    }
    assert!(matches!(
        MixedLayout::new(!(PAGE - 1), &[linux()]),
        Err(Error::Overflow)
    ));
    assert!(matches!(
        MixedLayout::new(0, &[Geometry::new(1 << 63, PAGE).unwrap(); 2]),
        Err(Error::Overflow)
    ));
    let layout = MixedLayout::new(0, &[linux()]).unwrap();
    assert_eq!(
        layout.backing(1..1 + layout.raw_allocation_bytes(), 0),
        Err(Error::Alignment)
    );
    assert_eq!(
        layout.backing(
            Range {
                start: PAGE,
                end: 0
            },
            0
        ),
        Err(Error::Overflow)
    );
    assert_eq!(
        layout.backing((!(PAGE - 1)) - PAGE..!(PAGE - 1), 0),
        Err(Error::Capacity)
    );
}
#[test]
fn every_supported_count_and_geometry_keeps_adjacent_guard_pages_distinct() {
    for count in 1..=MAX_STACKS {
        let specs =
            core::array::from_fn::<_, MAX_STACKS, _>(|i| if i % 3 == 0 { linux() } else { rust() });
        let layout = MixedLayout::new(3 * PAGE, &specs[..count]).unwrap();
        let mut previous = layout.virtual_range().start;
        for index in 0..count {
            let slot = layout.slot(index).unwrap();
            assert!(slot.lower_guard.start >= previous);
            previous = slot.upper_guard.end;
        }
        assert_eq!(previous, layout.virtual_range().end);
    }
}
