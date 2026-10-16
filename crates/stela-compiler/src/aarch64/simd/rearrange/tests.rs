use super::*;
#[test]
fn lane_reserved_sizes_and_ignored_bits_follow_the_source_spec() {
    for imm5 in 0..32 {
        for q in 0..2 {
            for base in [0x0e000c00, 0x0e000400, 0x0e002c00, 0x0e003c00] {
                let word = base | (q << 30) | (imm5 << 16) | (31 << 5) | 31;
                let size = (imm5 & 15u32).trailing_zeros();
                let valid = imm5 & 15 != 0
                    && match base {
                        0x0e002c00 => size < 2 + q,
                        0x0e003c00 => {
                            if q == 0 {
                                size < 3
                            } else {
                                size == 3
                            }
                        }
                        _ => q == 1 || size != 3,
                    };
                assert_eq!(decode(word).unwrap().is_ok(), valid, "{word:08x}");
            }
        }
    }
    // INS ignores low imm4 bits below the selected element size.
    assert_eq!(decode(0x6e080400), decode(0x6e083c00));
    assert_eq!(decode(0x2e004000), Some(Err(()))); // EXT 8B offset 8
    assert_eq!(decode(0x0e601800), Some(Err(()))); // REV16 halfword
    assert!(decode(0x0e800000).is_none()); // adjacent table fixed bit
}
