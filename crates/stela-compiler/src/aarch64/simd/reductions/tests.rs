use super::*;
#[test]
fn allocated_sizes_shapes_and_fixed_fields_are_distinct() {
    for q in 0..2 {
        for size in 0..4 {
            for (base, across) in [
                (0x0e206c00, false),
                (0x2e20a400, false),
                (0x0e31b800, true),
                (0x2e303800, true),
            ] {
                let word = base | (q << 30) | (size << 22) | (31 << 5) | 31;
                let expected = size != 3 && (!across || q != 0 || size != 2);
                assert_eq!(decode(word).unwrap().is_ok(), expected, "{word:08x}");
            }
            assert_eq!(
                decode(0x0e205800 | (q << 30) | (size << 22))
                    .unwrap()
                    .is_ok(),
                size == 0
            );
            assert_eq!(
                decode(0x0e20bc00 | (q << 30) | (size << 22))
                    .unwrap()
                    .is_ok(),
                q != 0 || size != 3
            );
        }
    }
    assert!(decode(0x5ef1b800).unwrap().is_ok());
    assert!(decode(0x5ef0b800).is_none());
    assert!(matches!(
        decode(0x2e605800),
        Some(Ok(Operand {
            kind: Kind::Bits(BitCount::Reverse),
            lane_bytes: 1,
            ..
        }))
    ));
}
