use super::*;

const INDEX_COUNT: u32 = 4;

#[test]
fn exact_forms_cover_every_register_width_and_index() {
    for encoding in Encoding::ALL {
        let (_, base, kind, indexed) = encoding.facts();
        let shapes: &[(u32, Shape)] = if matches!(kind, Kind::Matrix(_)) {
            &[(VECTOR_Q, Shape::Vector128)]
        } else {
            &[(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)]
        };
        for &(q, shape) in shapes {
            for index in 0..if indexed { INDEX_COUNT } else { 1 } {
                for register in 0..=REGISTER_MASK {
                    for (d, n, m) in [
                        (register, 31, 16),
                        (31, register, 16),
                        (31, 16, register),
                        (register, register, register),
                    ] {
                        let word = base
                            | q
                            | d
                            | n << LEFT_SHIFT
                            | m << RIGHT_SHIFT
                            | (index & INDEX_BIT_MASK) << INDEX_L_SHIFT
                            | (index >> INDEX_HIGH_SHIFT) << INDEX_H_SHIFT;
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand {
                                kind,
                                destination: d as u8,
                                left: n as u8,
                                right: m as u8,
                                shape,
                                index: indexed.then_some(index as u8),
                            }))
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn fixed_bits_never_accept_another_arrangement_or_scalar_form() {
    for encoding in Encoding::ALL {
        let (mask, base, _, _) = encoding.facts();
        for bit in 0..32 {
            if mask & (1 << bit) != 0 {
                let changed = base ^ (1 << bit);
                if let Some(Ok(other)) = decode(changed) {
                    // A changed opcode may select another I8MM form, but never
                    // the same kind.
                    assert_ne!(other.kind, decode(base).unwrap().unwrap().kind);
                }
            }
        }
    }
    assert!(decode(0x0e80a400).is_none()); // Matrix Q=0 is unallocated.
    assert!(decode(0x5f80f000).is_none()); // No scalar mixed dot form.
    assert!(decode(0x0e009c00).is_none()); // No vector SUDOT canonical form.
}
