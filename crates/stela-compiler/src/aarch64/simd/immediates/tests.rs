use super::*;
#[test]
fn float_one_constants_have_exact_ieee_width_and_upper_clearing() {
    for (base, bytes, value) in [
        (SCALAR_HALF, 2, 0x3c00),
        (SCALAR_SINGLE, 4, 0x3f800000),
        (SCALAR_DOUBLE, 8, 0x3ff0000000000000),
    ] {
        assert_eq!(
            decode(base | (0x70 << 13) | 31),
            Some(Ok(Operand::Constant {
                destination: 31,
                value,
                bytes,
                operation: ConstantOperation::Move
            }))
        );
    }
    assert_eq!(decode(0x2f00f400), Some(Err(()))); // vector double requires Q=1
    assert!(decode(0x1ea01000).is_none()); // reserved scalar ftype
    assert!(decode(0x9e260000).is_none()); // numerical conversion is not a bit move
}
#[test]
fn modified_fields_are_not_accidentally_vector_shift_or_polynomial_forms() {
    for cmode in 0..16 {
        for op in 0..2 {
            let word = MODIFIED_BASE | (cmode << 12) | (op << 29);
            if cmode == 14 && op == 1 {
                assert!(decode(word).is_none());
            } else if cmode == 15 && op == 1 {
                assert_eq!(decode(word), Some(Err(())));
            } else {
                assert!(decode(word).unwrap().is_ok());
            }
            let half = decode(word | (1 << 11));
            assert_eq!(half.unwrap().is_ok(), cmode == 15 && op == 0);
        }
    }
    assert!(decode(0x0f080400).is_none()); // SSHR has nonzero immh
}
