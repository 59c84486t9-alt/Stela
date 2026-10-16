use super::*;

#[test]
fn all_sizes_polynomials_and_register_triples_preserve_zero_roles() {
    for polynomial in [Polynomial::Ieee, Polynomial::Castagnoli] {
        for (size_field, size) in [
            DataSize::Byte,
            DataSize::Halfword,
            DataSize::Word,
            DataSize::Doubleword,
        ]
        .into_iter()
        .enumerate()
        {
            let base = CLASS_VALUE
                | ((size_field as u32) << SIZE_SHIFT)
                | if polynomial == Polynomial::Castagnoli {
                    CASTAGNOLI_BIT
                } else {
                    0
                }
                | if size == DataSize::Doubleword {
                    DOUBLEWORD_BIT
                } else {
                    0
                };
            for destination in 0..=REGISTER_MASK {
                for accumulator in 0..=REGISTER_MASK {
                    for data in 0..=REGISTER_MASK {
                        assert_eq!(
                            decode(
                                base | (data << DATA_SHIFT)
                                    | (accumulator << ACCUMULATOR_SHIFT)
                                    | destination
                            ),
                            Some(Ok(Operand {
                                size,
                                polynomial,
                                destination: register(destination, false),
                                accumulator: register(accumulator, false),
                                data: register(data, false)
                            }))
                        );
                    }
                }
            }
            assert_eq!(decode(base ^ DOUBLEWORD_BIT), Some(Err(())));
            for bit in 0..32 {
                if CLASS_MASK & (1 << bit) != 0 {
                    assert!(decode(base ^ (1 << bit)).is_none());
                }
            }
        }
    }
}
