use super::*;

#[test]
fn every_register_pair_including_v31_and_aliases_is_ordinary_data() {
    for (base, kind) in [
        (AESE, Kind::Encrypt),
        (AESD, Kind::Decrypt),
        (AESMC, Kind::MixColumns),
        (AESIMC, Kind::InverseMixColumns),
    ] {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                assert_eq!(
                    decode(base | (source << SOURCE_SHIFT) | destination),
                    Some(Ok(Operand {
                        kind,
                        destination: destination as u8,
                        source: source as u8,
                    }))
                );
            }
        }
        for size in 1..4 {
            assert!(decode(base | (size << 22)).is_none());
        }
        assert!(decode(base & !(1 << 30)).is_none()); // No .8B form.
        assert!(decode(base | (1 << 28)).is_none()); // No scalar form.
    }
}
