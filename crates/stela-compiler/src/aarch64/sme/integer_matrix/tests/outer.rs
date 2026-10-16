use super::*;

#[test]
fn canonical_classes_do_not_overlap() {
    for (index, lhs) in OUTER_ENCODINGS.iter().enumerate() {
        for rhs in &OUTER_ENCODINGS[index + 1..] {
            let common_mask = lhs.mask & rhs.mask;
            assert_ne!(lhs.value & common_mask, rhs.value & common_mask);
        }
    }
}

#[test]
fn complete_operand_boundaries_and_fixed_bits() {
    for encoding in OUTER_ENCODINGS {
        let tile_count = encoding.accumulator_size.bytes() as u8;
        let has_m = !matches!(
            encoding.kind,
            OuterKind::AddHorizontal | OuterKind::AddVertical
        );
        for tile in 0..tile_count {
            for predicate_n in 0..=OUTER_PREDICATE_REGISTER_MASK {
                for predicate_m in 0..=OUTER_PREDICATE_REGISTER_MASK {
                    for (vector_n, vector_m) in [(0, 31), (31, 0), (17, 17)] {
                        let mut word = encoding.value
                            | u32::from(tile)
                            | (predicate_n << OUTER_PREDICATE_N_SHIFT)
                            | (predicate_m << OUTER_PREDICATE_M_SHIFT)
                            | (vector_n << OUTER_VECTOR_N_SHIFT);
                        if has_m {
                            word |= vector_m << OUTER_VECTOR_M_SHIFT;
                        }
                        let operation = decode_outer(word).unwrap();
                        assert_eq!(operation.kind, encoding.kind);
                        assert_eq!(operation.accumulator_size, encoding.accumulator_size);
                        assert_eq!(operation.subtract, encoding.subtract);
                        assert_eq!(operation.tile, tile);
                        assert_eq!(u32::from(operation.predicate_n), predicate_n);
                        assert_eq!(u32::from(operation.predicate_m), predicate_m);
                        assert_eq!(u32::from(operation.vector_n), vector_n);
                        assert_eq!(operation.vector_m, has_m.then_some(vector_m as u8));
                    }
                }
            }
        }
    }
}
