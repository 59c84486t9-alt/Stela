use super::*;

const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];

#[test]
fn z_storage_segments_cover_each_register_without_overlap() {
    assert_eq!(core::mem::offset_of!(GuestState, v), 264);
    for bytes in LENGTHS {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for register in 0..32 {
            assert_eq!(vector_offset(register), 264 + u32::from(register) * 16);
            for chunk in 1..length.chunks() {
                assert_eq!(
                    upper_offset(register, chunk, length) as usize,
                    usize::from(register) * (bytes - 16) + (chunk - 1) * 16
                );
            }
        }
    }
}

#[test]
fn mask_patterns_select_first_bit_of_each_element() {
    assert_eq!(
        predicate_bit_pattern(ElementSize::Byte),
        0x8040_2010_0804_0201
    );
    assert_eq!(
        predicate_bit_pattern(ElementSize::Halfword),
        0x4040_1010_0404_0101
    );
    assert_eq!(
        predicate_bit_pattern(ElementSize::Word),
        0x1010_1010_0101_0101
    );
    assert_eq!(
        predicate_bit_pattern(ElementSize::Doubleword),
        0x0101_0101_0101_0101
    );
}
