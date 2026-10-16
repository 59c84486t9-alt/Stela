use super::*;
#[test]
fn dots_validate_dword_groups_full_index_registers_and_vector_only_forms() {
    for encoding in DotEncoding::ALL {
        let (register, indexed, signed) = encoding.facts();
        for base in [register, indexed] {
            for q in 0..2 {
                for size in 0..4 {
                    for fields in 0..8 {
                        let h = fields >> 2;
                        let l = fields >> 1 & 1;
                        let m = fields & 1;
                        let word = base
                            | (q << 30)
                            | (size << 22)
                            | (m << 20)
                            | (15 << 16)
                            | (31 << 5)
                            | 31
                            | if base == indexed {
                                (h << 11) | (l << 21)
                            } else {
                                0
                            };
                        let decoded = decode(word).unwrap();
                        if size != 2 {
                            assert!(decoded.is_err());
                            continue;
                        }
                        let operand = decoded.unwrap();
                        assert_eq!(operand.kind, Kind::Dot { signed });
                        assert_eq!((operand.destination, operand.left), (31, 31));
                        assert_eq!(operand.right, 15 | (m << 4) as u8);
                        assert_eq!(operand.lane_bytes, 4);
                        assert_eq!(operand.bytes, if q != 0 { 16 } else { 8 });
                        assert_eq!(
                            operand.index,
                            (base == indexed).then_some((h << 1 | l) as u8)
                        );
                        assert!(!operand.upper);
                        assert!(decode(word | (1 << 28)).is_none());
                    }
                }
            }
        }
    }
}

#[test]
fn ordinary_indexed_products_validate_every_index_and_register_role() {
    for encoding in IndexedProductEncoding::ALL {
        let (base, kind) = encoding.facts();
        for q in 0..2 {
            for size in 0..4 {
                for fields in 0..8 {
                    let h = fields >> 2;
                    let l = fields >> 1 & 1;
                    let m = fields & 1;
                    let word = base
                        | (q << 30)
                        | (size << 22)
                        | (h << 11)
                        | (l << 21)
                        | (m << 20)
                        | (15 << 16)
                        | (31 << 5)
                        | 31;
                    let decoded = decode(word).unwrap();
                    if !matches!(size, 1 | 2) {
                        assert!(decoded.is_err());
                        continue;
                    }
                    let operand = decoded.unwrap();
                    assert_eq!(operand.kind, kind);
                    assert_eq!((operand.destination, operand.left), (31, 31));
                    assert_eq!(
                        operand.right,
                        if size == 1 { 15 } else { 15 | (m << 4) as u8 }
                    );
                    assert_eq!(
                        operand.index,
                        Some(if size == 1 {
                            fields as u8
                        } else {
                            (h << 1 | l) as u8
                        })
                    );
                    assert_eq!(operand.upper, kind.widened() && q != 0);
                    assert_eq!(operand.bytes, if kind.widened() || q != 0 { 16 } else { 8 });
                    assert!(
                        decode(word | (1 << 28)).is_none(),
                        "ordinary integer products have no scalar form"
                    );
                    assert!(
                        decode(word | (1 << 10)).is_none(),
                        "reserved neighboring opcode"
                    );
                }
            }
        }
    }
}
#[test]
fn doubling_encodings_validate_scalar_width_and_index_register_roles() {
    for encoding in DoublingEncoding::ALL {
        let (register, indexed, kind) = encoding.facts();
        for scalar in [false, true] {
            for q in [false, true] {
                for size in 0..4 {
                    for element in [false, true] {
                        let base = if element { indexed } else { register };
                        let word = base
                            | (u32::from(scalar) << 28)
                            | (u32::from(q) << 30)
                            | (size << 22)
                            | (31 << 16)
                            | if element { 1 << 11 } else { 0 }
                            | (31 << 5)
                            | 31;
                        let decoded = decode(word).unwrap();
                        if !matches!(size, 1 | 2) || scalar && !q {
                            assert!(decoded.is_err());
                            continue;
                        }
                        let operand = decoded.unwrap();
                        assert_eq!(operand.kind, kind);
                        assert_eq!(operand.right, if element && size == 1 { 15 } else { 31 });
                        assert_eq!(
                            operand.index,
                            if element {
                                Some(if size == 1 { 5 } else { 2 })
                            } else {
                                None
                            }
                        );
                        assert_eq!(operand.upper, kind.widened() && q && !scalar);
                        assert_eq!(
                            operand.bytes,
                            if scalar {
                                (1 << size) * if kind.widened() { 2 } else { 1 }
                            } else if kind.widened() || q {
                                16
                            } else {
                                8
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn polynomial_encoding_widths_are_explicit() {
    for q in 0..2 {
        for size in 0..4 {
            for (base, valid) in [
                (0x2e209c00, size == 0),
                (0x0e20e000, size == 0 || size == 3),
            ] {
                assert_eq!(
                    decode(base | (q << 30) | (size << 22)).unwrap().is_ok(),
                    valid
                );
            }
        }
    }
}

#[test]
fn every_named_form_validates_lanes_source_half_and_vector_roles() {
    for encoding in Encoding::ALL {
        let (base, kind) = encoding.facts();
        for q in 0..2 {
            for size in 0..4 {
                let word = base | (q << 30) | (size << 22) | (31 << 16) | (31 << 5) | 31;
                let decoded = decode(word).unwrap();
                if size == 3 {
                    assert!(decoded.is_err());
                    continue;
                }
                let operand = decoded.unwrap();
                assert_eq!(operand.kind, kind);
                assert_eq!(
                    (operand.destination, operand.left, operand.right),
                    (31, 31, 31)
                );
                assert_eq!(operand.bytes, if kind.widened() || q != 0 { 16 } else { 8 });
                assert_eq!(operand.upper, kind.widened() && q != 0);
            }
        }
    }
    assert!(matches!(
        decode(0x2e209c00),
        Some(Ok(Operand {
            kind: Kind::Polynomial { widen: false },
            ..
        }))
    ));
    assert!(decode(0x5e209c00).is_none()); // these are vector forms only
}
