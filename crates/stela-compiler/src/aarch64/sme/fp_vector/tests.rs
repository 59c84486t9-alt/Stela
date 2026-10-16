use super::*;

#[test]
fn all_conversion_allocations_decode_without_overlap() {
    for encoding in CONVERSIONS {
        let operation = decode(encoding.opcode).unwrap();
        assert!(
            matches!(operation.kind, Kind::Convert { operation, .. } if operation == encoding.operation)
        );
        assert_eq!(
            CONVERSIONS
                .iter()
                .filter(|entry| encoding.opcode & entry.mask == entry.opcode)
                .count(),
            1
        );
    }
}

#[test]
fn arithmetic_formats_and_group_bounds_are_exact() {
    for (base, count, grouped) in [
        (MINMAX_BROADCAST_PAIR, PAIR_REGISTER_COUNT, false),
        (MINMAX_BROADCAST_QUARTET, QUARTET_REGISTER_COUNT, false),
        (MINMAX_GROUP_PAIR, PAIR_REGISTER_COUNT, true),
        (MINMAX_GROUP_QUARTET, QUARTET_REGISTER_COUNT, true),
    ] {
        for size in 0..=SIZE_MASK {
            for op in [0, MINIMUM_SELECT, NUMBER_SELECT, MINMAX_OPERATION_MASK] {
                let right = if grouped {
                    REGISTER_MASK + 1 - u32::from(count)
                } else {
                    BROADCAST_REGISTER_MASK
                };
                let word = base
                    | (size << SIZE_SHIFT)
                    | op
                    | (right << RIGHT_SHIFT)
                    | (REGISTER_MASK + 1 - u32::from(count));
                let decoded = decode(word).unwrap();
                assert_eq!(decoded.destination.first + count, (REGISTER_MASK + 1) as u8);
                assert_eq!(decoded.feature == Feature::Sme2SveB16B16, size == 0);
                assert!(
                    matches!(decoded.kind, Kind::MinMax { right: value, .. } if value.first == right as u8 && value.count == if grouped { count } else { 1 })
                );
            }
        }
    }
}

#[test]
fn clamp_sources_can_alias_any_destination_register() {
    for count in [PAIR_REGISTER_COUNT, QUARTET_REGISTER_COUNT] {
        let base = if count == PAIR_REGISTER_COUNT {
            CLAMP_PAIR
        } else {
            CLAMP_QUARTET
        };
        for destination in (0..=REGISTER_MASK).step_by(usize::from(count)) {
            for lower in 0..=REGISTER_MASK {
                let upper = REGISTER_MASK - lower;
                let decoded =
                    decode(base | destination | (lower << SOURCE_SHIFT) | (upper << RIGHT_SHIFT))
                        .unwrap();
                assert_eq!(decoded.destination, group(destination as u8, count));
                assert_eq!(
                    decoded.kind,
                    Kind::Clamp {
                        lower: lower as u8,
                        upper: upper as u8
                    }
                );
            }
        }
    }
}

#[test]
fn reserved_group_alignment_bits_do_not_decode() {
    assert!(decode(MINMAX_BROADCAST_QUARTET | 2).is_none());
    assert!(decode(MINMAX_GROUP_QUARTET | (1 << RIGHT_SHIFT)).is_none());
    assert!(decode(CLAMP_QUARTET | 1).is_none());
}
