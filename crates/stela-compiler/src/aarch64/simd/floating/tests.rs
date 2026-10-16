use super::*;

#[test]
fn full_scalar_types_conditions_and_vector_allocations() {
    for (ftype, bytes) in [(0, 4), (1, 8), (3, 2)] {
        for condition in 0..16 {
            assert_eq!(
                decode(SELECT | (ftype << 22) | (31 << 16) | (condition << 12) | (29 << 5) | 31),
                Some(Ok(Operand::Select {
                    destination: 31,
                    left: 29,
                    right: 31,
                    lane_bytes: bytes,
                    condition: condition as u8,
                }))
            );
        }
        for (base, operation) in [
            (SCALAR_ABS, SignOperation::Abs),
            (SCALAR_NEG, SignOperation::Neg),
        ] {
            assert_eq!(
                decode(base | (ftype << 22) | (31 << 5)),
                Some(Ok(Operand::Sign {
                    operation,
                    destination: 0,
                    source: 31,
                    lane_bytes: bytes,
                    bytes,
                    scalar: true,
                }))
            );
        }
    }
    for base in [SELECT, SCALAR_ABS, SCALAR_NEG] {
        assert_eq!(decode(base | (2 << 22)), Some(Err(())));
    }
    for base in [VECTOR_FLOAT_ABS, VECTOR_FLOAT_NEG] {
        assert_eq!(decode(base | (1 << 22)), Some(Err(())));
        assert!(matches!(
            decode(base | (1 << 22) | (1 << 30)),
            Some(Ok(Operand::Sign {
                lane_bytes: 8,
                bytes: 16,
                scalar: false,
                ..
            }))
        ));
    }
    assert_eq!(decode(0x1e20_4000), None); // FMOV remains in its own family.
    assert_eq!(decode(0x1e20_2800), None); // Numerical FADD is still unsupported.
}
