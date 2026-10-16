use super::*;

#[test]
fn every_form_width_and_group_register_combination_decodes_exactly() {
    for encoding in ENCODINGS {
        let count = encoding.group.count();
        for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
            for destination in (0..32).step_by(usize::from(count)) {
                let right_count = if encoding.right_grouped { count } else { 1 };
                let right_limit = if encoding.right_grouped { 32 } else { 16 };
                for right in (0..right_limit).step_by(usize::from(right_count)) {
                    let word =
                        encoding.opcode | size << SIZE_SHIFT | destination | right << RIGHT_SHIFT;
                    assert_eq!(
                        decode(word),
                        Some(Operand {
                            kind: encoding.kind,
                            destination: destination as u8,
                            right: right as u8,
                            group: encoding.group,
                            format,
                            right_grouped: encoding.right_grouped,
                        })
                    );
                }
            }
        }
        assert_eq!(decode(encoding.opcode), None);
    }
}

#[test]
fn fixed_register_alignment_and_neighbor_operation_bits_are_not_ignored() {
    for encoding in ENCODINGS {
        let word = encoding.opcode | 1 << SIZE_SHIFT;
        assert!(decode(word ^ 1 << 10).is_none());
        if encoding.group == Group::Quartet {
            assert!(decode(word | 1 << 1).is_none());
            if encoding.right_grouped {
                assert!(decode(word | 1 << 17).is_none());
            }
        }
        if !encoding.right_grouped {
            assert!(decode(word | 1 << 20).is_none());
        }
    }
}
