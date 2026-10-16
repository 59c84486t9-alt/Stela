use super::*;

#[test]
fn every_register_role_preserves_v31_and_source_aliases() {
    for encoding in Encoding::ALL {
        let (_, base) = encoding.facts();
        for register in 0..32 {
            let word = base | register | (register << LEFT_SHIFT) | (register << RIGHT_SHIFT);
            let decoded = decode(word).unwrap().unwrap();
            assert_eq!(decoded.destination, register as u8);
            assert_eq!(decoded.left, register as u8);
            assert_eq!(decoded.right, register as u8);
        }
    }
    // Independently sweep all four fields, including third sources and V31.
    for base in [0xce000000, 0xce200000] {
        for destination in 0..32 {
            for source in 0..32 {
                for (left, right, third) in [(source, 2, 3), (1, source, 3), (1, 2, source)] {
                    let operand = decode(
                        base | destination
                            | (left << LEFT_SHIFT)
                            | (right << RIGHT_SHIFT)
                            | (third << THIRD_SHIFT),
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(operand.destination, destination as u8);
                    assert_eq!(operand.left, left as u8);
                    assert_eq!(operand.right, right as u8);
                    assert_eq!(
                        operand.kind,
                        if base == 0xce000000 {
                            Kind::Eor3 { third: third as u8 }
                        } else {
                            Kind::Bcax { third: third as u8 }
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn known_words_decode_distinct_operand_roles_and_fourth_field() {
    for (word, kind) in [
        (0xce020c20, Kind::Eor3 { third: 3 }),
        (0xce220c20, Kind::Bcax { third: 3 }),
        (0xce628c20, Kind::Rax1),
        (0xce82fc20, Kind::Xar { rotation: 63 }),
    ] {
        assert_eq!(
            decode(word),
            Some(Ok(Operand {
                kind,
                destination: 0,
                left: 1,
                right: 2
            }))
        );
    }
    for encoding in Encoding::ALL {
        let (_, base) = encoding.facts();
        for register in 0..32 {
            for (destination, left, right) in [(register, 1, 2), (0, register, 2), (0, 1, register)]
            {
                let operand =
                    decode(base | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT))
                        .unwrap()
                        .unwrap();
                assert_eq!(
                    (operand.destination, operand.left, operand.right),
                    (destination as u8, left as u8, right as u8)
                );
            }
        }
    }
}

#[test]
fn xar_immediate_is_direct_zero_through_sixty_three() {
    for rotation in 0..64 {
        let operand = decode(
            0xce800000
                | (rotation << XAR_ROTATION_SHIFT)
                | (31 << RIGHT_SHIFT)
                | (31 << LEFT_SHIFT)
                | 31,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            operand.kind,
            Kind::Xar {
                rotation: rotation as u8
            }
        );
        assert_eq!(
            (operand.destination, operand.left, operand.right),
            (31, 31, 31)
        );
    }
}

#[test]
fn fixed_bits_are_exact_and_sve_forms_are_not_classic_sha3() {
    for word in [0x04203800, 0x04603800, 0x4520f400, 0x04203400, 0xce600000] {
        assert!(decode(word).is_none(), "{word:08x}");
    }
    for encoding in Encoding::ALL {
        let (mask, base) = encoding.facts();
        for bit in 0..32 {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let changed = base ^ (1 << bit);
            let belongs_to_another_form = Encoding::ALL.iter().any(|other| {
                let (other_mask, other_value) = other.facts();
                changed & other_mask == other_value
            });
            assert_eq!(
                decode(changed).is_some(),
                belongs_to_another_form,
                "{changed:08x}"
            );
        }
    }
}
