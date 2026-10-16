use super::*;
#[test]
fn scalar_lane_widths_narrowing_halves_and_vector_reserved_forms_are_exact() {
    for base in [
        SIGNED_ADD,
        UNSIGNED_SUB,
        SIGNED_ABS,
        UNSIGNED_MIXED_ADD,
        SIGNED_NARROW,
        UNSIGNED_NARROW,
        SIGNED_TO_UNSIGNED_NARROW,
    ] {
        let narrow = [SIGNED_NARROW, UNSIGNED_NARROW, SIGNED_TO_UNSIGNED_NARROW].contains(&base);
        for scalar in [false, true] {
            for q in [false, true] {
                for size in 0..4 {
                    let word = base
                        | (u32::from(scalar) << 28)
                        | (u32::from(q) << 30)
                        | (size << 22)
                        | (31 << 5)
                        | 31;
                    if scalar && !q {
                        assert!(decode(word).is_none());
                        continue;
                    }
                    let valid = if narrow {
                        size != 3
                    } else {
                        scalar || q || size != 3
                    };
                    assert_eq!(decode(word).unwrap().is_ok(), valid, "{word:08x}");
                    if let Some(Ok(operand)) = decode(word) {
                        assert_eq!(
                            operand.bytes,
                            if scalar {
                                1 << size
                            } else if narrow || !q {
                                8
                            } else {
                                16
                            }
                        );
                        if let Kind::Narrow { upper, .. } = operand.kind {
                            assert_eq!(upper, !scalar && q);
                        }
                    }
                }
            }
        }
    }
}
