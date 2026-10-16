use super::*;
#[test]
fn sizes_widths_and_half_selection_distinguish_all_form_groups() {
    for base in [
        SIGNED_HALF_ADD,
        UNSIGNED_HALF_SUB,
        ROUND_ADD_HIGH_NARROW,
        SIGNED_ACC_PAIR_LONG,
        TRUNCATE,
        SHIFT_LONG,
    ] {
        for q in 0..2 {
            for size in 0..4 {
                let word = base | (q << 30) | (size << 22) | (31 << 5) | 31;
                let decoded = decode(word).unwrap();
                if size == 3 {
                    assert!(decoded.is_err());
                    continue;
                }
                let operand = decoded.unwrap();
                assert_eq!(operand.lane_bytes, 1 << size);
                match operand.kind {
                    Kind::Truncate { upper } | Kind::HighNarrow { upper, .. } => {
                        assert_eq!(upper, q != 0);
                        assert_eq!(operand.bytes, 8);
                    }
                    Kind::ShiftLong { upper } => {
                        assert_eq!(upper, q != 0);
                        assert_eq!(operand.bytes, 16);
                    }
                    _ => assert_eq!(operand.bytes, 8 << q),
                }
            }
        }
    }
    assert!(decode(0x5e200400).is_none()); // vector forms only
    assert!(matches!(
        decode(SIGNED_ACC_PAIR_LONG),
        Some(Ok(Operand {
            kind: Kind::PairLong {
                accumulate: true,
                ..
            },
            ..
        }))
    ));
}
