use super::*;

#[test]
fn allocated_widths_and_full_predicate_fields() {
    for (opcode, kind) in [
        (FCMEQ_REG, Kind::Equal),
        (FCMGE_REG, Kind::GreaterEqual),
        (FCMGT_REG, Kind::Greater),
        (FCMNE_REG, Kind::NotEqual),
        (FCMUO_REG, Kind::Unordered),
        (FACGE_REG, Kind::AbsoluteGreaterEqual),
        (FACGT_REG, Kind::AbsoluteGreater),
    ] {
        assert_eq!(decode(opcode), Some(Err(())));
        for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
            for governing in 0..=GOVERNING_MASK {
                for destination in 0..=PREDICATE_MASK {
                    let word = opcode
                        | (size << SIZE_SHIFT)
                        | (REGISTER_MASK << RIGHT_SHIFT)
                        | (governing << GOVERNING_SHIFT)
                        | (REGISTER_MASK << SOURCE_SHIFT)
                        | destination;
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand {
                            kind,
                            format,
                            destination: destination as u8,
                            governing: governing as u8,
                            left: REGISTER_MASK as u8,
                            right: Some(REGISTER_MASK as u8),
                        }))
                    );
                }
            }
        }
    }
}

#[test]
fn zero_comparisons_and_unordered_nan_signaling() {
    for opcode in [
        FCMEQ_ZERO, FCMGE_ZERO, FCMGT_ZERO, FCMLE_ZERO, FCMLT_ZERO, FCMNE_ZERO,
    ] {
        assert_eq!(decode(opcode), Some(Err(())));
        assert!(
            decode(opcode | (2 << SIZE_SHIFT) | (31 << SOURCE_SHIFT) | 15)
                .unwrap()
                .unwrap()
                .right
                .is_none()
        );
    }
    const QUIET_NAN: u64 = 0x7fc0_0001;
    const SIGNALING_NAN: u64 = 0x7f80_0001;
    for kind in [Kind::NotEqual, Kind::Unordered] {
        assert_eq!(
            evaluate(kind, Format::Single, 0, QUIET_NAN, 0),
            Ok(Outcome {
                predicate: true,
                exceptions: 0
            })
        );
        assert_eq!(
            evaluate(kind, Format::Single, 0, SIGNALING_NAN, 0),
            Ok(Outcome {
                predicate: true,
                exceptions: crate::aarch64::floating::INVALID
            })
        );
    }
    assert_eq!(decode(0), None);
}
