use super::*;

#[test]
fn every_arrangement_segment_and_register_role_decodes() {
    for encoding in ENCODINGS {
        for raw_segment in 0..8 {
            let word = encoding.value | (raw_segment << HALFWORD_SEGMENT_SHIFT);
            if word & encoding.mask != encoding.value {
                continue;
            }
            for register in 0..32 {
                let operand =
                    decode(word | register | (register << TABLE_SHIFT) | (register << INDEX_SHIFT))
                        .unwrap();
                assert_eq!(operand.canonical_id, encoding.canonical_id);
                assert_eq!(operand.destination, register as u8);
                assert_eq!(operand.table, register as u8);
                assert_eq!(operand.indices, register as u8);
                assert!(
                    operand.index_byte_offset()
                        + 16 / operand.element_bytes as usize * operand.index_bits as usize / 8
                        <= 16
                );
            }
        }
    }
}

#[test]
fn fixed_q_and_reserved_byte_encodings_decline() {
    for word in [
        0,
        u32::MAX,
        0x0e80_1000,
        0x0ec0_0000,
        0x0e40_2000,
        0x0e40_1000,
        0x4e80_0000,
        0x4e40_0000,
        0x4e40_4000,
    ] {
        assert_eq!(decode(word), None, "{word:08x}");
    }
}
