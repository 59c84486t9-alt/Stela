use super::*;

#[test]
fn all_allocations_decode_every_register_and_alias() {
    for encoding in ENCODINGS {
        for source in 0..32 {
            for destination in 0..32 {
                let word = encoding.value | (source << SOURCE_SHIFT) | destination;
                if matches!(encoding.kind, Kind::Narrow { .. }) && source & 1 != 0 {
                    assert_eq!(decode(word), None);
                    continue;
                }
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.kind, encoding.kind);
                assert_eq!(operand.source, source as u8);
                assert_eq!(operand.destination, destination as u8);
                assert_eq!(canonical_id(word), Some(encoding.id));
            }
        }
    }
}

#[test]
fn fixed_neighbors_are_unclaimed() {
    for encoding in ENCODINGS {
        for bit in 10..32 {
            let word = encoding.value ^ (1 << bit);
            if !ENCODINGS.iter().any(|other| other.value == word) {
                assert_eq!(decode(word), None);
            }
        }
    }
}
