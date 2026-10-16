use super::*;

#[test]
fn integer_admission_excludes_every_numerical_allocation() {
    for encoding in ENCODINGS {
        let word = if matches!(encoding.size, SizeShape::Variable) {
            encoding.value | (2 << SIZE_SHIFT)
        } else {
            encoding.value
        };
        if matches!(encoding.kind, Kind::Integer { .. } | Kind::Complex { .. }) {
            assert_eq!(decode_integer(word), decode(word));
        } else {
            assert_eq!(decode_integer(word), None);
        }
    }
    const CDOT_RESERVED_BYTE: u32 = 0x4400_1000;
    assert_eq!(decode_integer(CDOT_RESERVED_BYTE), Some(Err(())));
    assert_eq!(decode_integer(0), None);
}

#[test]
fn mixed_signedness_allocations_require_guest_i8mm() {
    let mut count = 0;
    for encoding in ENCODINGS {
        let word = if matches!(encoding.size, SizeShape::Variable) {
            encoding.value | (2 << SIZE_SHIFT)
        } else {
            encoding.value
        };
        if let Some(Ok(operand)) = decode_integer(word) {
            let mixed = matches!(
                encoding.kind,
                Kind::Integer {
                    signedness: Signedness::UnsignedSigned | Signedness::SignedUnsigned,
                    ..
                }
            );
            assert_eq!(operand.requires_i8mm(), mixed);
            count += usize::from(mixed);
        }
    }
    assert_eq!(count, 3);
}

#[test]
fn every_source_and_destination_register_including_z31_is_data() {
    for encoding in ENCODINGS {
        let base = if matches!(encoding.size, SizeShape::Variable) {
            encoding.value | (2 << SIZE_SHIFT)
        } else {
            encoding.value
        };
        for destination in 0..32 {
            for left in 0..32 {
                let operand = decode(base | destination | (left << LEFT_SHIFT))
                    .unwrap()
                    .unwrap();
                assert_eq!(operand.destination, destination as u8);
                assert_eq!(operand.left, left as u8);
            }
        }
        let maximum = match encoding.source {
            SourceShape::Vector => REGISTER_MASK,
            SourceShape::IndexedDoubleWord => INDEXED_DOUBLE_REGISTER_MASK,
            _ => INDEXED_WORD_REGISTER_MASK,
        };
        for right in 0..=maximum {
            let operand = decode(base | (right << RIGHT_SHIFT)).unwrap().unwrap();
            assert_eq!(
                match operand.right {
                    RightOperand::Vector(register) | RightOperand::Indexed { register, .. } =>
                        register,
                },
                right as u8
            );
        }
    }
}

#[test]
fn indexed_register_width_and_split_half_index_are_independent() {
    for index in 0..8 {
        let operand = decode(
            0x64a04000
                | ((index >> 1) << WORD_INDEX_SHIFT)
                | ((index & HALF_INDEX_LOW_MASK) << HALF_INDEX_LOW_SHIFT)
                | (INDEXED_WORD_REGISTER_MASK << RIGHT_SHIFT),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            operand.right,
            RightOperand::Indexed {
                register: 7,
                index: index as u8
            }
        );
    }
    for index in 0..2 {
        let operand = decode(
            0x44e00000
                | (index << DOUBLE_INDEX_SHIFT)
                | (INDEXED_DOUBLE_REGISTER_MASK << RIGHT_SHIFT),
        )
        .unwrap()
        .unwrap();
        assert_eq!(operand.element_size, ElementSize::Doubleword);
        assert_eq!(
            operand.right,
            RightOperand::Indexed {
                register: 15,
                index: index as u8
            }
        );
    }
}

#[test]
fn complex_reserved_sizes_decline_and_rotations_keep_exact_components() {
    for size in 0..2 {
        assert_eq!(decode(0x44001000 | (size << SIZE_SHIFT)), Some(Err(())));
    }
    for (rotation, expected) in [
        (Rotation::Zero, (0, 1, true)),
        (Rotation::Ninety, (1, 0, false)),
        (Rotation::OneEighty, (0, 1, false)),
        (Rotation::TwoSeventy, (1, 0, true)),
    ] {
        assert_eq!(rotation.component_selection(), expected);
    }
    for rotation in 0..4 {
        let operand = decode(0x44a04000 | (rotation << ROTATION_SHIFT))
            .unwrap()
            .unwrap();
        assert_eq!(
            operand.kind,
            Kind::Complex {
                rotation: [
                    Rotation::Zero,
                    Rotation::Ninety,
                    Rotation::OneEighty,
                    Rotation::TwoSeventy
                ][rotation as usize]
            }
        );
    }
}

#[test]
fn two_product_forms_are_half_to_word_not_future_byte_to_half() {
    for base in [0x4400c800, 0x4400cc00, 0x4480c800, 0x4480cc00] {
        let operand = decode(base).unwrap().unwrap();
        assert_eq!(operand.element_size, ElementSize::Word);
        assert!(matches!(
            operand.kind,
            Kind::Integer {
                products: Products::Two,
                ..
            }
        ));
    }
    assert_eq!(decode(0x44200000), None);
    assert_eq!(decode(0x44000000), None);
}
