use super::*;

#[test]
fn lookup_pair_is_byte_only_and_groups_never_wrap() {
    for (base, stride) in [(0xc08b_0000, 1), (0xc09b_0000, 4)] {
        for size in 0..4 {
            for source in (0..32).step_by(2) {
                for first in 0..32 {
                    let aligned = if stride == 1 {
                        first % 4 == 0
                    } else {
                        first & 12 == 0
                    };
                    if !aligned {
                        continue;
                    }
                    let result =
                        decode(base | (size << SIZE_SHIFT) | (source << SOURCE_SHIFT) | first);
                    if size != 0 {
                        assert_eq!(result, None);
                        continue;
                    }
                    let Operand::LookupPair {
                        destination,
                        source: decoded_source,
                    } = result.unwrap()
                    else {
                        panic!()
                    };
                    assert_eq!(
                        destination,
                        VectorGroup {
                            first: first as u8,
                            count: 4,
                            stride
                        }
                    );
                    assert_eq!(decoded_source, source as u8);
                    assert!(destination.register(3) < 32);
                }
            }
        }
    }
}

#[test]
fn move_offsets_wrap_and_only_encoded_zero_clears_the_tail() {
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for immediate in 0..4 {
            let operand = decode(0xc04f_03e0 | (immediate << SIZE_SHIFT) | 31).unwrap();
            let transfer = bytes.min(LOOKUP_TABLE_BYTES);
            assert_eq!(
                operand.table_transfer(length),
                Some((
                    immediate as usize % (64 / transfer) * transfer,
                    transfer,
                    immediate == 0
                ))
            );
        }
    }
}
