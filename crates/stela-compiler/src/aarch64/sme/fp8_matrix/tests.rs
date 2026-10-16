use super::*;

fn vector(word: u32) -> VectorOperand {
    let Some(Operand::Vector(operand)) = decode(word) else {
        panic!("expected vector operand for {word:08x}");
    };
    operand
}

#[test]
fn all_canonical_forms_have_disjoint_fixed_bits() {
    assert_eq!(ENCODINGS.len() + 2, 33);
    for (index, encoding) in ENCODINGS.iter().enumerate() {
        assert_eq!(encoding.value & encoding.mask, encoding.value);
        for other in &ENCODINGS[index + 1..] {
            assert_ne!(
                (encoding.value ^ other.value) & encoding.mask & other.mask,
                0
            );
        }
        for variable in [0, !encoding.mask] {
            let operand = vector(encoding.value | variable);
            assert_eq!(operand.operation, encoding.operation);
            assert_eq!(operand.accumulator, encoding.accumulator);
            assert_eq!(operand.groups, encoding.groups);
            assert_eq!(operand.vector_select, if variable == 0 { 8 } else { 11 });
            let source_groups = if matches!(encoding.operation, VectorOperation::VerticalDot { .. })
            {
                2
            } else {
                encoding.groups
            };
            assert_eq!(
                operand.left,
                if variable == 0 {
                    0
                } else if matches!(encoding.layout, Layout::Vector) {
                    31
                } else {
                    32 - source_groups
                }
            );
            match operand.right {
                RightSource::Indexed { register, index } => {
                    assert_eq!(register, if variable == 0 { 0 } else { 15 });
                    let maximum = match (encoding.operation, encoding.accumulator) {
                        (VectorOperation::MultiplyAdd, _) => 15,
                        (_, Format::Half) => 7,
                        _ => 3,
                    };
                    assert_eq!(index, if variable == 0 { 0 } else { maximum });
                }
                RightSource::Vector(register) => {
                    assert_eq!(register, if variable == 0 { 0 } else { 15 })
                }
                RightSource::Group(register) => {
                    assert_eq!(register, if variable == 0 { 0 } else { 32 - source_groups })
                }
            }
        }
    }
}

#[test]
fn split_immediates_and_implicit_offset_bits() {
    // Each source-index bit independently; the selector and ZA offset do not overlap.
    for (word, bits) in [
        (0xc1c0_0000, [3, 10, 11, 15]),
        (0xc190_1030, [2, 3, 10, 11]),
        (0xc140_0000, [10, 11, 12, 15]),
        (0xc190_0020, [1, 2, 10, 11]),
    ] {
        for index in 0..16 {
            let word = bits.iter().enumerate().fold(word, |word, (bit, shift)| {
                word | ((index >> bit & 1) << shift)
            });
            assert_eq!(
                vector(word).right,
                RightSource::Indexed {
                    register: 0,
                    index: index as u8
                }
            );
            assert_eq!(vector(word).offset, 0);
        }
    }
    for (word, maximum) in [
        (0xc130_0c00, 14),
        (0xc120_0804, 6),
        (0xc130_0400, 12),
        (0xc120_0002, 4),
    ] {
        let encoding = ENCODINGS.iter().find(|e| e.value == word).unwrap();
        assert_eq!(vector(word | !encoding.mask).offset, maximum);
    }
}

#[test]
fn outer_tile_register_and_predicate_fields() {
    for (word, format, tile_mask) in [
        (0x80a0_0008, Format::Half, 1),
        (0x80a0_0000, Format::Single, 3),
    ] {
        for tile in 0..=tile_mask {
            let Some(Operand::Outer(operand)) =
                decode(word | (31 << 16) | (6 << 13) | (5 << 10) | (29 << 5) | tile)
            else {
                panic!()
            };
            assert_eq!(
                operand,
                OuterOperand {
                    accumulator: format,
                    tile: tile as u8,
                    left: 29,
                    right: 31,
                    row_predicate: 5,
                    column_predicate: 6
                }
            );
        }
    }
}

#[test]
fn long_rows_align_after_mathematical_selector_addition() {
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for encoding in ENCODINGS {
            let operand = vector(encoding.value | !encoding.mask);
            for selector in [0, 1, 3, u32::MAX] {
                let rows = operand.rows(length, selector);
                let stride = bytes / usize::from(operand.groups);
                let adjacent = usize::from(operand.rows_per_group());
                let base =
                    ((u64::from(selector) + u64::from(operand.offset)) % stride as u64) as usize;
                let base = base / adjacent * adjacent;
                for group in 0..usize::from(operand.groups) {
                    for row in 0..adjacent {
                        assert_eq!(
                            usize::from(rows[group * adjacent + row]),
                            base + group * stride + row
                        );
                    }
                }
                assert!(
                    rows[..usize::from(operand.row_count())]
                        .iter()
                        .all(|&row| usize::from(row) < bytes)
                );
            }
        }
    }
}

#[test]
fn vector_sources_wrap_and_aligned_sources_end_at_z31() {
    let operand = vector(0xc130_1008 | (31 << 5) | (15 << 16));
    for group in 0..4 {
        let (left, right) = operand.source_bytes(group, 0, 0, 0).unwrap();
        assert_eq!(left.register, (31 + group) % 32);
        assert_eq!(right.register, 15);
    }
    let operand = vector(0xc1a1_1030 | (28 << 5) | (28 << 16));
    assert_eq!(operand.source_bytes(3, 0, 0, 0).unwrap().0.register, 31);
    assert_eq!(operand.source_bytes(3, 0, 0, 0).unwrap().1.register, 31);
}

#[test]
fn indexed_sources_repeat_within_each_128_bit_segment() {
    let half_dot = vector(0xc1d0_0020 | (3 << 10) | (1 << 3));
    assert_eq!(half_dot.source_bytes(0, 0, 8, 1).unwrap().1.byte, 31);
    let single_dot = vector(0xc150_0038 | (3 << 10));
    assert_eq!(single_dot.source_bytes(0, 0, 4, 3).unwrap().1.byte, 31);
    let half_long = vector(0xc190_1030 | (3 << 10) | (3 << 2));
    assert_eq!(half_long.source_bytes(0, 1, 8, 0).unwrap().0.byte, 17);
    assert_eq!(half_long.source_bytes(0, 1, 8, 0).unwrap().1.byte, 31);
    let single_long = vector(0xc190_0020 | (3 << 10) | (3 << 1));
    assert_eq!(single_long.source_bytes(0, 3, 4, 0).unwrap().0.byte, 19);
    assert_eq!(single_long.source_bytes(0, 3, 4, 0).unwrap().1.byte, 31);
}

#[test]
fn vertical_pair_gathers_and_bottom_top_select_distinct_pairs() {
    for (word, groups, bytes, top) in [
        (0xc1d0_1020, 2, 2, false),
        (0xc1d0_0800, 4, 4, false),
        (0xc1d0_0810, 4, 4, true),
    ] {
        let operand = vector(word | (30 << 5) | (1 << 3));
        assert_eq!(operand.groups, groups);
        assert_eq!(operand.row_count(), groups);
        assert_eq!(operand.terms(), 2);
        for group in 0..groups {
            for term in 0..2 {
                let (left, right) = operand.source_bytes(group, 0, 16 / bytes, term).unwrap();
                assert_eq!(
                    left,
                    SourceByte {
                        register: 30 + term,
                        byte: 16 + usize::from(group)
                    }
                );
                assert_eq!(
                    right.byte,
                    16 + bytes + if top { 2 } else { 0 } + usize::from(term)
                );
            }
        }
    }
}

#[test]
fn invalid_source_coordinates_and_reserved_encodings_are_explicit() {
    let operand = vector(0xc1a1_0020);
    assert_eq!(operand.row_count(), 16);
    assert_eq!(operand.source_bytes(4, 0, 0, 0), None);
    assert_eq!(operand.source_bytes(0, 4, 0, 0), None);
    assert_eq!(operand.source_bytes(0, 0, 0, 1), None);
    for word in [
        0,
        u32::MAX,
        0x80a0_0018,
        0x80a0_0004,
        0xc1d0_0030,
        0xc1d0_1800,
    ] {
        assert_eq!(decode(word), None, "reserved {word:08x}");
    }
}
