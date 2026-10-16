use super::*;

#[test]
fn register_banks_are_bounded() {
    for index in 0..=u8::MAX {
        assert_eq!(is_z_register(index), index < VECTOR_REGISTER_COUNT);
        assert_eq!(
            is_predicate_register(index),
            index < PREDICATE_REGISTER_COUNT
        );
    }
}

#[test]
fn streaming_lengths_reject_non_power_two_sve_lengths() {
    for bytes in 0..=MAX_VECTOR_BYTES + VECTOR_CHUNK_BYTES {
        let expected =
            (MIN_VECTOR_BYTES..=MAX_VECTOR_BYTES).contains(&bytes) && bytes.is_power_of_two();
        assert_eq!(VectorLength::from_bytes(bytes).is_some(), expected);
        if let Some(length) = VectorLength::from_bytes(bytes) {
            assert_eq!(length.predicate_bytes() * BITS_PER_BYTE, bytes);
            assert_eq!(length.chunks() * VECTOR_CHUNK_BYTES, bytes);
            for size in [
                ElementSize::Byte,
                ElementSize::Halfword,
                ElementSize::Word,
                ElementSize::Doubleword,
                ElementSize::Quadword,
            ] {
                assert_eq!(length.lanes(size) * size.bytes(), bytes);
            }
        }
    }
}

#[test]
fn mode_bits_are_independent_and_reserved_bits_decline() {
    for bits in 0..=SVCR_MASK {
        assert_eq!(ScalableMode::from_svcr(bits).unwrap().svcr(), bits);
    }
    for bit in 2..u64::BITS {
        assert!(ScalableMode::from_svcr(1 << bit).is_none());
    }
}
