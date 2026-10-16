use super::*;

#[test]
fn all_allocated_operands_have_exact_identity_and_nonwrapping_groups() {
    for encoding in ENCODINGS {
        let base = decode(encoding.opcode).unwrap();
        for source in (0..32).step_by(usize::from(base.source.count)) {
            for destination in (0..32).step_by(usize::from(base.destination.count)) {
                let word = encoding.opcode | source << SOURCE_SHIFT | destination;
                let operand = decode(word).unwrap();
                assert_eq!(operand.canonical_id, encoding.id);
                assert_eq!(operand.conversion, encoding.conversion);
                assert_eq!(operand.format, encoding.format);
                assert_eq!(u32::from(operand.source.first), source);
                assert_eq!(u32::from(operand.destination.first), destination);
                assert!(operand.source.first + operand.source.count <= 32);
                assert!(operand.destination.first + operand.destination.count <= 32);
                assert_eq!(
                    ENCODINGS
                        .iter()
                        .filter(|entry| word & entry.mask == entry.opcode)
                        .count(),
                    1
                );
            }
        }
    }
}

#[test]
fn reserved_group_bits_and_neighboring_families_are_rejected() {
    for word in [
        FCVT_Z8_MZ2 | (1 << SOURCE_SHIFT),
        FCVT_Z8_MZ4 | (1 << 6),
        FCVTN_Z8_MZ4 | (1 << 6),
        0xc160_e000,
        0xc1a0_e000,
        0xd503_201f,
    ] {
        assert_eq!(decode(word), None, "{word:#010x}");
    }
}
