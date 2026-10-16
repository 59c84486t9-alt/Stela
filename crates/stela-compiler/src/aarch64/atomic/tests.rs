use super::*;

#[test]
fn widths_orders_and_all_register_roles_preserve_aliases() {
    for size in 0..4 {
        for acquire in [false, true] {
            for release in [false, true] {
                for index in 0..=REGISTER_MASK {
                    let fields = (index << SOURCE_SHIFT) | (index << BASE_SHIFT) | index;
                    let cas = decode(
                        CAS_CLASS
                            | (size << SIZE_SHIFT)
                            | fields
                            | if acquire { CAS_ACQUIRE } else { 0 }
                            | if release { CAS_RELEASE } else { 0 },
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(cas.bytes, 1 << size);
                    assert_eq!(cas.base, register(index, true));
                    assert_eq!(cas.order, Order::decode(acquire, release));
                    assert_eq!(
                        cas.kind,
                        Kind::CompareExchange {
                            compare: register(index, false),
                            source: register(index, false),
                        }
                    );
                    assert_eq!(
                        cas.order.acquires(register(index, false)),
                        acquire && index != 31
                    );
                    for operation in 0..=8 {
                        let rmw = decode(
                            RMW_CLASS
                                | (size << SIZE_SHIFT)
                                | fields
                                | (operation << RMW_OPERATION_SHIFT)
                                | if acquire { RMW_ACQUIRE } else { 0 }
                                | if release { RMW_RELEASE } else { 0 },
                        )
                        .unwrap()
                        .unwrap();
                        assert_eq!(rmw.bytes, cas.bytes);
                        assert_eq!(rmw.base, cas.base);
                        assert_eq!(rmw.order, cas.order);
                        assert!(
                            matches!(rmw.kind, Kind::ReadModifyWrite { source, destination, .. }
                            if source == register(index, false) && destination == source)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn pair_widths_orders_even_inputs_and_every_base_preserve_aliases() {
    for size in 0..2 {
        for acquire in [false, true] {
            for release in [false, true] {
                for compare in 0..=REGISTER_MASK {
                    for source in 0..=REGISTER_MASK {
                        for base in 0..=REGISTER_MASK {
                            let word = CASP_CLASS
                                | (size << SIZE_SHIFT)
                                | (compare << SOURCE_SHIFT)
                                | (base << BASE_SHIFT)
                                | source
                                | if acquire { CAS_ACQUIRE } else { 0 }
                                | if release { CAS_RELEASE } else { 0 };
                            let decoded = decode(word).unwrap();
                            if (compare | source) & PAIR_FIRST_ODD_BIT != 0 {
                                assert_eq!(decoded, Err(()));
                            } else {
                                assert_eq!(
                                    decoded,
                                    Ok(Operand {
                                        bytes: WORD_PAIR_BYTES << size,
                                        base: register(base, true),
                                        order: Order::decode(acquire, release),
                                        kind: Kind::CompareExchangePair {
                                            compare: [
                                                register(compare, false),
                                                register(compare + 1, false)
                                            ],
                                            source: [
                                                register(source, false),
                                                register(source + 1, false)
                                            ],
                                        },
                                    })
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    // Bit 31 selects a different allocated/reserved class, never a wider CASP.
    assert_eq!(decode(CASP_CLASS | (1 << 31)), None);
}

#[test]
fn reserved_operations_and_neighbor_classes_remain_explicit() {
    for operation in 9..=RMW_OPERATION_MASK {
        assert_eq!(
            decode(RMW_CLASS | (operation << RMW_OPERATION_SHIFT)),
            Some(Err(()))
        );
    }
    for word in [
        0xc85f7c00, 0xc8007c00, 0xc8dffc00, 0xf8606800, 0xf8400800, 0xf9800000,
    ] {
        assert_eq!(decode(word), None, "{word:#x}");
    }
}
