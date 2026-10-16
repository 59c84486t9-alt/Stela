use super::*;

#[test]
fn every_allocated_word_preserves_all_register_roles_and_aliases() {
    let mut count = 0;
    for (base, kind) in [
        (HASH, Kind::Hash),
        (HASH2, Kind::Hash2),
        (SCHEDULE1, Kind::Schedule1),
    ] {
        for destination in 0..32u8 {
            for left in 0..32u8 {
                for right in 0..32u8 {
                    let word = base
                        | u32::from(destination)
                        | (u32::from(left) << LEFT_SHIFT)
                        | (u32::from(right) << RIGHT_SHIFT);
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand {
                            kind,
                            destination,
                            left,
                            right: Some(right),
                        }))
                    );
                    count += 1;
                }
            }
        }
    }
    for destination in 0..32u8 {
        for left in 0..32u8 {
            assert_eq!(
                decode(SCHEDULE0 | u32::from(destination) | (u32::from(left) << LEFT_SHIFT)),
                Some(Ok(Operand {
                    kind: Kind::Schedule0,
                    destination,
                    left,
                    right: None,
                }))
            );
            count += 1;
        }
    }
    assert_eq!(count, 99_328);
}

#[test]
fn fixed_field_changes_do_not_create_widths_or_consume_other_crypto_forms() {
    for (base, mask) in [
        (HASH, THREE_REGISTER_MASK),
        (HASH2, THREE_REGISTER_MASK),
        (SCHEDULE0, TWO_REGISTER_MASK),
        (SCHEDULE1, THREE_REGISTER_MASK),
    ] {
        for bit in 0..32 {
            if mask & (1 << bit) != 0 {
                let changed = base ^ (1 << bit);
                // One opcode-bit change can legitimately select a sibling.
                if ![HASH, HASH2, SCHEDULE0, SCHEDULE1].contains(&changed) {
                    assert!(decode(changed).is_none(), "{changed:08x}");
                }
            }
        }
    }
    for other in [0xce608c00, 0xce60c000, 0xce60c400, 0xcec08400] {
        assert!(decode(other).is_none()); // RAX1, SM3PARTW1/2, SM4E
    }
}
