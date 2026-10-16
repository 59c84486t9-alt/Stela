use super::*;

const SBO_STATUS: u32 = REGISTER_MASK << STATUS_SHIFT;
const SBO_SECOND: u32 = REGISTER_MASK << SECOND_SHIFT;
const CLEAR_OPTION_SHIFT: u32 = 8;
const CLEAR_OPTION_MASK: u32 = 15;

fn constraint(data: bool, base: bool) -> Result<(), ConstrainedUndefined> {
    match (data, base) {
        (true, true) => Err(ConstrainedUndefined::StoreStatusDataAndBase),
        (true, false) => Err(ConstrainedUndefined::StoreStatusData),
        (false, true) => Err(ConstrainedUndefined::StoreStatusBase),
        (false, false) => Ok(()),
    }
}

#[test]
fn scalar_widths_orders_and_every_register_alias_are_explicit() {
    for size in 0..4 {
        for ordered in [false, true] {
            let class =
                SCALAR_CLASS | (size << SIZE_SHIFT) | if ordered { ACQUIRE_RELEASE_BIT } else { 0 };
            for first in 0..=REGISTER_MASK {
                for base in 0..=REGISTER_MASK {
                    let fields = (base << BASE_SHIFT) | first;
                    let expected = Operand::Transfer {
                        element_bytes: 1 << size,
                        base: register(base, true),
                        data: Data::Scalar(register(first, false)),
                        kind: Kind::Load { acquire: ordered },
                    };
                    assert_eq!(
                        decode(class | LOAD_BIT | SBO_STATUS | SBO_SECOND | fields),
                        Some(Ok(expected))
                    );
                    for status in 0..=REGISTER_MASK {
                        let expected =
                            constraint(status == first, status == base && base != REGISTER_MASK)
                                .map(|()| Operand::Transfer {
                                    element_bytes: 1 << size,
                                    base: register(base, true),
                                    data: Data::Scalar(register(first, false)),
                                    kind: Kind::Store {
                                        release: ordered,
                                        status: register(status, false),
                                    },
                                });
                        assert_eq!(
                            decode(class | (status << STATUS_SHIFT) | SBO_SECOND | fields),
                            Some(expected)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn pair_widths_orders_and_every_register_alias_are_explicit() {
    for size in 0..2 {
        for ordered in [false, true] {
            let class =
                PAIR_CLASS | (size << SIZE_SHIFT) | if ordered { ACQUIRE_RELEASE_BIT } else { 0 };
            for first in 0..=REGISTER_MASK {
                for second in 0..=REGISTER_MASK {
                    for base in 0..=REGISTER_MASK {
                        let fields = (second << SECOND_SHIFT) | (base << BASE_SHIFT) | first;
                        let data = Data::Pair([register(first, false), register(second, false)]);
                        let expected = if first == second {
                            Err(ConstrainedUndefined::PairLoadOutputs)
                        } else {
                            Ok(Operand::Transfer {
                                element_bytes: PAIR_ELEMENT_BYTES << size,
                                base: register(base, true),
                                data,
                                kind: Kind::Load { acquire: ordered },
                            })
                        };
                        assert_eq!(
                            decode(class | LOAD_BIT | SBO_STATUS | fields),
                            Some(expected)
                        );
                        for status in 0..=REGISTER_MASK {
                            let expected = constraint(
                                status == first || status == second,
                                status == base && base != REGISTER_MASK,
                            )
                            .map(|()| Operand::Transfer {
                                element_bytes: PAIR_ELEMENT_BYTES << size,
                                base: register(base, true),
                                data,
                                kind: Kind::Store {
                                    release: ordered,
                                    status: register(status, false),
                                },
                            });
                            assert_eq!(
                                decode(class | (status << STATUS_SHIFT) | fields),
                                Some(expected)
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn soft_fixed_fields_ignore_noncanonical_register_encodings() {
    for size in 0..4 {
        for ordered in [false, true] {
            let class =
                SCALAR_CLASS | (size << SIZE_SHIFT) | if ordered { ACQUIRE_RELEASE_BIT } else { 0 };
            for ignored_status in 0..=REGISTER_MASK {
                for ignored_second in 0..=REGISTER_MASK {
                    let word = class
                        | LOAD_BIT
                        | (ignored_status << STATUS_SHIFT)
                        | (ignored_second << SECOND_SHIFT)
                        | (REGISTER_MASK << BASE_SHIFT)
                        | REGISTER_MASK;
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand::Transfer {
                            element_bytes: 1 << size,
                            base: Register::Sp,
                            data: Data::Scalar(Register::Zero),
                            kind: Kind::Load { acquire: ordered },
                        }))
                    );
                    let store = class | (1 << BASE_SHIFT);
                    assert_eq!(
                        decode(store | (ignored_second << SECOND_SHIFT)),
                        decode(store | SBO_SECOND)
                    );
                }
            }
        }
    }
    for size in 0..2 {
        for ignored_status in 0..=REGISTER_MASK {
            let word = PAIR_CLASS | (size << SIZE_SHIFT) | LOAD_BIT | (1 << SECOND_SHIFT);
            assert_eq!(
                decode(word | (ignored_status << STATUS_SHIFT)),
                decode(word | SBO_STATUS)
            );
        }
    }
}

#[test]
fn clear_options_and_neighboring_classes_do_not_overlap() {
    for option in 0..=CLEAR_OPTION_MASK {
        assert_eq!(
            decode(CLEAR_CLASS | (option << CLEAR_OPTION_SHIFT)),
            Some(Ok(Operand::Clear))
        );
    }
    // Bit31=0 pair encodings belong to CASP, including its acquire bit22.
    for size in 0..2 {
        for acquire in [0, LOAD_BIT] {
            for release in [0, ACQUIRE_RELEASE_BIT] {
                assert_eq!(
                    decode(
                        (PAIR_CLASS & !(1 << 31))
                            | (size << SIZE_SHIFT)
                            | acquire
                            | release
                            | SBO_SECOND
                    ),
                    None
                );
            }
        }
    }
    // Ordered, limited-order, LSUI exclusives, LSE, and other barriers.
    for word in [
        0xc8df_fc20,
        0xc89f_fc20,
        0xc8df_7c20,
        0xc95f_7c20,
        0xc8a0_7c20,
        0xf820_8021,
        0xd503_3fbf,
        0xd503_3f9f,
        0xd503_3fdf,
    ] {
        assert_eq!(decode(word), None, "neighbor {word:08x}");
    }
}
