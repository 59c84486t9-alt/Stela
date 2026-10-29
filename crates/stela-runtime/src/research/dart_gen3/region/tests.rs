use super::*;

fn property(
    select: u32,
    config: u32,
    regions: [[u32; 3]; 3],
    dead_page: u64,
) -> [u8; TAG_PROPERTY_BYTES] {
    let mut bytes = [0; TAG_PROPERTY_BYTES];
    let words = [
        select,
        config,
        regions[0][0],
        regions[0][1],
        regions[0][2],
        regions[1][0],
        regions[1][1],
        regions[1][2],
        regions[2][0],
        regions[2][1],
        regions[2][2],
        0x1234_5678,
        dead_page as u32,
        (dead_page >> 32) as u32,
    ];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[test]
fn native_dead_index_guard_projects_each_enabled_zone_at_every_lookup_level() {
    let bytes = property(1, 4, [[0; 3], [0; 3], [0x1040_8040, 0x1040_807c, 0]], 0);
    let original = Tagger::parse(&bytes, false).unwrap();
    let inclusive = Tagger::parse(&bytes, true).unwrap();
    for (level, first, last) in [
        (DeadIndexLevel::Root, 0, 0),
        (DeadIndexLevel::Context, 16, 16),
        (DeadIndexLevel::Segment, 0x204, 0x204),
        (DeadIndexLevel::Page, 0x10, 0x1f),
    ] {
        original.validate_dead_index(first, level).unwrap();
        original.validate_dead_index(last, level).unwrap();
        assert!(original.validate_dead_index(last + 1, level).is_err());
        if first != 0 {
            assert!(original.validate_dead_index(first - 1, level).is_err());
        }
        assert!(original.validate_dead_index(u32::MAX, level).is_err());
    }
    inclusive
        .validate_dead_index(0x20, DeadIndexLevel::Page)
        .unwrap();
    assert!(
        inclusive
            .validate_dead_index(0x21, DeadIndexLevel::Page)
            .is_err()
    );
    assert_eq!(original.property(), bytes);

    // No enabled regions means no reserved dead index, including zero.
    // Selector choice does not change this software predicate.
    for select in [0, 1] {
        let absent = Tagger::parse(&property(select, 0, [[0; 3]; 3], 0), false).unwrap();
        for level in [
            DeadIndexLevel::Root,
            DeadIndexLevel::Context,
            DeadIndexLevel::Segment,
            DeadIndexLevel::Page,
        ] {
            assert!(absent.validate_dead_index(0, level).is_err());
        }
    }
}

#[test]
fn native_dead_index_end_adjustment_wraps_before_projection_without_range_repair() {
    let bytes = property(
        0,
        1,
        [[0xffff_ff00, 0xffff_fffc, 0], [0; 3], [0; 3]],
        u64::MAX,
    );
    let exclusive = Tagger::parse(&bytes, false).unwrap();
    let inclusive = Tagger::parse(&bytes, true).unwrap();
    for (level, last) in [
        (DeadIndexLevel::Context, 63),
        (DeadIndexLevel::Segment, 2047),
        (DeadIndexLevel::Page, 2047),
    ] {
        exclusive.validate_dead_index(last, level).unwrap();
        assert!(inclusive.validate_dead_index(last, level).is_err());
        assert!(inclusive.validate_dead_index(0, level).is_err());
    }
    // Root projection is zero at both endpoints even after wrapping.
    inclusive
        .validate_dead_index(0, DeadIndexLevel::Root)
        .unwrap();
    // A successful supplied-index guard does not validate this address.
    assert_eq!(inclusive.dead_page(), u64::MAX);

    let bytes = property(0, 1, [[0x1ffc, 0x2000, 0], [0; 3], [0; 3]], 0);
    let tagger = Tagger::parse(&bytes, false).unwrap();
    // Projection across an 11-bit index wrap does not become a union.
    assert!(
        tagger
            .validate_dead_index(2047, DeadIndexLevel::Page)
            .is_err()
    );
    assert!(tagger.validate_dead_index(0, DeadIndexLevel::Page).is_err());
    tagger
        .validate_dead_index(0, DeadIndexLevel::Segment)
        .unwrap();
    tagger
        .validate_dead_index(1, DeadIndexLevel::Segment)
        .unwrap();
}

#[test]
fn complete_tz_handoff_preserves_opaque_bytes_and_verifies_actual_register_observations() {
    let regions = [[0x1000, 0x2000, 0], [0x8000, 0xc000, 0], [0; 3]];
    let bytes = property(1, 3, regions, 0x8_0000_4000);
    let tagger = Tagger::parse(&bytes, false).unwrap();
    assert_eq!(tagger.select(), 1);
    assert_eq!(tagger.config(), 3);
    assert_eq!(tagger.regions().map(TagRegion::words), regions);
    assert_eq!(tagger.dead_page(), 0x8_0000_4000);
    assert!(!tagger.inclusive());
    assert_eq!(tagger.property(), bytes);
    let mut actual = TagRegisters {
        select: 1,
        config: 3,
        regions,
        protect: 0x18,
        lock: 0x18,
    };
    tagger.verify(4, Some(&actual), true).unwrap();
    for index in 0..3 {
        for field in 0..3 {
            let mut changed = actual;
            changed.regions[index][field] ^= 4;
            assert!(tagger.verify(4, Some(&changed), true).is_err());
        }
    }
    let mut ignored_bits = actual;
    ignored_bits.select |= 0xffff_fffe;
    ignored_bits.config |= 0xffff_fff8;
    ignored_bits.regions = regions.map(|region| region.map(|word| word | !REGION_ADDRESS));
    tagger.verify(4, Some(&ignored_bits), true).unwrap();
    assert!(tagger.verify(4, None, true).is_err());
    assert!(tagger.verify(0, None, true).is_err());
    actual.lock = 0;
    assert!(tagger.verify(4, Some(&actual), true).is_err());
    tagger.verify(4, Some(&actual), false).unwrap();
    actual.protect = 8;
    assert!(tagger.verify(4, Some(&actual), false).is_err());
    actual.protect = 0x18;
    actual.regions[1][1] += 4;
    assert!(tagger.verify(4, Some(&actual), false).is_err());
    actual.regions = regions;
    actual.select = 0;
    assert!(tagger.verify(4, Some(&actual), false).is_err());
    actual.select = 1;
    actual.config = 7;
    assert!(tagger.verify(4, Some(&actual), false).is_err());
    // This is the source verifier's no-tagger branch, not permission
    // to expose invented zero registers or perform active region DMA.
    Tagger::parse(&property(1, 3, regions, 0), false)
        .unwrap()
        .verify(0, None, true)
        .unwrap();
}

#[test]
fn tz_validation_checks_every_enabled_and_disabled_region_without_inventing_an_absent_image() {
    for length in [0, 52, 55, 57, 60] {
        assert!(Tagger::parse(&[0; 60][..length], false).is_err());
    }
    assert!(Tagger::parse(&property(2, 0, [[0; 3]; 3], 0), false).is_err());
    assert!(Tagger::parse(&property(0, 8, [[0; 3]; 3], 0), false).is_err());
    for index in 0..3 {
        for field in 0..3 {
            let mut regions = [[0; 3]; 3];
            regions[index][field] = 4;
            assert!(Tagger::parse(&property(0, 0, regions, 0), false).is_err());
        }
        for region in [
            [0, 8, 0],
            [4, 0, 0],
            [4, 8, 4],
            [8, 4, 0],
            [4, 4, 0],
            [4, u32::MAX, 0],
        ] {
            let mut regions = [[0; 3]; 3];
            regions[index] = region;
            let inclusive = region[1] == u32::MAX;
            assert!(Tagger::parse(&property(0, 1 << index, regions, 0), inclusive).is_err());
        }
        let mut regions = [[0; 3]; 3];
        regions[index] = [4, 4, 0];
        assert!(Tagger::parse(&property(0, 1 << index, regions, 0), false).is_err());
        assert!(Tagger::parse(&property(0, 1 << index, regions, 0), true).is_ok());
    }
    // Software bounds validation does not silently normalize bits which
    // the native masked readback cannot reproduce.
    let regions = [[0x4000_0000, 0x4000_0004, 0], [0; 3], [0; 3]];
    let tagger = Tagger::parse(&property(0, 1, regions, 0), false).unwrap();
    let actual = TagRegisters {
        select: 0,
        config: 1,
        regions,
        protect: 0x18,
        lock: 0x18,
    };
    assert!(tagger.verify(4, Some(&actual), true).is_err());
}

fn observations(region: AddressRegion) -> AddressRegisters {
    let [control, start, last, offset] = region.words();
    AddressRegisters {
        control,
        start,
        last,
        offset: offset & REGION_ADDRESS,
        enable: 1,
        lock: 0,
    }
}

#[test]
fn address_region_construction_retains_signed_offsets_and_final_page_inclusion() {
    let region = AddressRegion::construct(AddressRequest::Range {
        input: 1 << 40,
        output: 0x8_0000_0000,
        bytes: 2 * PAGE,
    })
    .unwrap();
    assert_eq!(region.words(), [3, 0x1000_0000, 0x1000_0004, 0xf080_0000]);
    let actual = observations(region);
    assert_eq!(actual.offset, 0x3080_0000);
    assert_eq!(region.prepare(&actual, 0, 0), Ok(AddressAction::Verify));
    region.verify(&actual, false).unwrap();
    let last = AddressRegion::construct(AddressRequest::Range {
        input: ADDRESS_LIMIT - PAGE,
        output: ADDRESS_LIMIT - PAGE,
        bytes: PAGE,
    })
    .unwrap();
    assert_eq!(last.words(), [3, REGION_ADDRESS, REGION_ADDRESS, 0]);
    for bad in [1, 2, PAGE - 1, ADDRESS_LIMIT + PAGE, u64::MAX] {
        for request in [
            AddressRequest::Range {
                input: bad,
                output: 0,
                bytes: PAGE,
            },
            AddressRequest::Range {
                input: 0,
                output: bad,
                bytes: PAGE,
            },
            AddressRequest::Range {
                input: 0,
                output: 0,
                bytes: bad,
            },
        ] {
            assert!(AddressRegion::construct(request).is_err());
        }
    }
    assert!(
        AddressRegion::construct(AddressRequest::Range {
            input: ADDRESS_LIMIT - PAGE,
            output: 0,
            bytes: 2 * PAGE,
        })
        .is_err()
    );
    assert!(
        AddressRegion::construct(AddressRequest::Range {
            input: 0,
            output: ADDRESS_LIMIT - PAGE,
            bytes: 2 * PAGE,
        })
        .is_err()
    );
    assert_eq!(
        AddressRegion::construct(AddressRequest::Zero)
            .unwrap()
            .words(),
        [2, 0, 0, 0]
    );
    assert_eq!(
        AddressRegion::construct(AddressRequest::Range {
            input: 0,
            output: 0,
            bytes: 0
        })
        .unwrap()
        .words(),
        [3, 0, 0, 0]
    );
    assert!(
        AddressRegion::construct(AddressRequest::Range {
            input: 0,
            output: 0,
            bytes: (1 << 32) + PAGE,
        })
        .is_err()
    );
    assert_eq!(
        AddressRegion::construct(AddressRequest::Range {
            input: 0,
            output: 0,
            bytes: 1 << 32,
        })
        .unwrap()
        .words(),
        [3, 0, 0x000f_fffc, 0]
    );
    assert!(AddressRegion::register_offset(0, 0).is_err());
    assert_eq!(AddressRegion::register_offset(14, 15 << 28), Ok(0x4780));
    assert!(AddressRegion::register_offset(15, 15 << 28).is_err());
}

#[test]
fn address_region_inspection_never_rewrites_a_frozen_record_or_invents_publication() {
    let region = AddressRegion::construct(AddressRequest::Range {
        input: 0x4000,
        output: 0x8000,
        bytes: PAGE,
    })
    .unwrap();
    let mut actual = observations(region);
    for (protect, lock) in [(2, 0), (0, 2), (2, 2)] {
        assert!(region.prepare(&actual, protect, lock).is_err());
    }
    actual.control = 0;
    assert_eq!(region.prepare(&actual, 0, 0), Ok(AddressAction::Rewrite));
    assert!(region.verify(&actual, false).is_err());
    actual = observations(region);
    actual.enable = 0;
    assert_eq!(region.prepare(&actual, 0, 0), Ok(AddressAction::Verify));
    assert!(region.verify(&actual, false).is_err());
    actual.enable = 1;
    assert!(region.verify(&actual, true).is_err());
    actual.lock = 1;
    region.verify(&actual, true).unwrap();
    assert_eq!(region.prepare(&actual, 2, 2), Ok(AddressAction::Frozen));
    let saved = actual;
    actual.control = 0;
    actual.enable = 0;
    assert_eq!(region.prepare(&actual, 2, 2), Ok(AddressAction::Frozen));
    assert!(region.verify(&actual, true).is_err());
    actual = saved;
    actual.offset ^= 4;
    assert!(region.prepare(&actual, 0, 0).is_err());
    actual = saved;
    actual.start ^= 4;
    assert!(region.verify(&actual, true).is_err());
    actual = saved;
    actual.last ^= 4;
    assert!(region.verify(&actual, true).is_err());
    assert_eq!(
        saved,
        AddressRegisters {
            control: 3,
            start: 4,
            last: 4,
            offset: 4,
            enable: 1,
            lock: 1
        }
    );
}
