use super::*;
#[test]
fn saturating_narrow_allocations_cover_every_count_and_reserved_shape() {
    for opcode in [
        SATURATING_NARROW_SIGNED,
        SATURATING_ROUND_NARROW_SIGNED,
        SATURATING_NARROW_UNSIGNED,
        SATURATING_ROUND_NARROW_UNSIGNED,
        SATURATING_NARROW_SIGNED_TO_UNSIGNED,
        SATURATING_ROUND_NARROW_SIGNED_TO_UNSIGNED,
    ] {
        for immediate in 0..128 {
            for scalar in [false, true] {
                for q in [false, true] {
                    let word = opcode
                        | (immediate << 16)
                        | (31 << 5)
                        | 31
                        | if scalar { SCALAR } else { 0 }
                        | if q { Q } else { 0 };
                    let decoded = decode(word);
                    if immediate < 8 {
                        assert_eq!(decoded, None, "{word:08x}");
                        continue;
                    }
                    let result = decoded.expect("saturating narrow family");
                    let valid = immediate < 64 && (!scalar || q);
                    assert_eq!(result.is_ok(), valid, "{word:08x}");
                    if let Ok(operand) = result {
                        let bits = 1 << (31 - immediate.leading_zeros());
                        let lane = bits / 8;
                        assert_eq!(u32::from(operand.lane_bytes), lane);
                        assert_eq!(u32::from(operand.amount), bits * 2 - immediate);
                        assert_eq!(u32::from(operand.bytes), if scalar { lane } else { 16 });
                        assert_eq!((operand.source, operand.destination), (31, 31));
                        assert_eq!(
                            operand.kind,
                            Kind::SaturatingNarrow {
                                signed_source: !matches!(
                                    opcode,
                                    SATURATING_NARROW_UNSIGNED | SATURATING_ROUND_NARROW_UNSIGNED
                                ),
                                unsigned_result: !matches!(
                                    opcode,
                                    SATURATING_NARROW_SIGNED | SATURATING_ROUND_NARROW_SIGNED
                                ),
                                round: opcode & ROUND_NARROW != 0,
                                upper: !scalar && q,
                            }
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn register_allocations_keep_counts_and_scalar_saturation_widths() {
    for opcode in [
        REGISTER_SHIFT_SIGNED,
        REGISTER_SHIFT_UNSIGNED,
        REGISTER_ROUND_SIGNED,
        REGISTER_ROUND_UNSIGNED,
        REGISTER_SATURATING_SIGNED,
        REGISTER_SATURATING_UNSIGNED,
        REGISTER_SATURATING_ROUND_SIGNED,
        REGISTER_SATURATING_ROUND_UNSIGNED,
    ] {
        for size in 0..4 {
            for scalar in [false, true] {
                for q in [false, true] {
                    let word = opcode
                        | (size << 22)
                        | (31 << 16)
                        | (29 << 5)
                        | 30
                        | if scalar { SCALAR } else { 0 }
                        | if q { Q } else { 0 };
                    let saturating = opcode & (1 << 11) != 0;
                    let valid = if scalar {
                        q && (saturating || size == 3)
                    } else {
                        q || size != 3
                    };
                    let result = decode(word).expect("shift family must be recognized");
                    assert_eq!(result.is_ok(), valid, "{word:08x}");
                    if let Ok(op) = result {
                        assert_eq!(op.lane_bytes, 1 << size);
                        assert_eq!(
                            op.bytes,
                            if scalar {
                                1 << size
                            } else if q {
                                16
                            } else {
                                8
                            }
                        );
                        assert_eq!((op.destination, op.source), (30, 29));
                        assert_eq!(
                            op.kind,
                            Kind::Register {
                                signed: opcode & (1 << 29) == 0,
                                round: opcode & (1 << 12) != 0,
                                saturating,
                                counts: 31
                            }
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn saturating_immediate_all_counts_allocate_scalar_b_h_s_d() {
    for opcode in [
        SATURATING_LEFT_SIGNED,
        SATURATING_LEFT_UNSIGNED,
        SATURATING_LEFT_SIGNED_TO_UNSIGNED,
    ] {
        for size in 0..4 {
            let bits = 8 << size;
            for amount in 0..bits {
                for scalar in [false, true] {
                    for q in [false, true] {
                        let word = opcode
                            | ((bits + amount) << 16)
                            | if scalar { SCALAR } else { 0 }
                            | if q { Q } else { 0 };
                        let result = decode(word).expect("saturating shift family");
                        assert_eq!(result.is_ok(), if scalar { q } else { q || size != 3 });
                        if let Ok(op) = result {
                            assert_eq!(u32::from(op.amount), amount);
                            assert_eq!(
                                u32::from(op.bytes),
                                if scalar {
                                    1 << size
                                } else if q {
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
}
#[test]
fn every_immediate_has_exact_size_count_and_reserved_width() {
    for immediate in 0..128 {
        for q in [false, true] {
            for scalar in [false, true] {
                for opcode in [
                    SHIFT_LEFT,
                    SHIFT_RIGHT_SIGNED,
                    SHIFT_RIGHT_UNSIGNED,
                    SHIFT_RIGHT_INSERT,
                    SHIFT_NARROW,
                    SHIFT_WIDEN_SIGNED,
                ] {
                    let word = opcode
                        | (immediate << 16)
                        | if q { Q } else { 0 }
                        | if scalar { SCALAR } else { 0 };
                    let decoded = decode(word);
                    let immh = immediate >> 3;
                    if immh == 0 || (scalar && [SHIFT_NARROW, SHIFT_WIDEN_SIGNED].contains(&opcode))
                    {
                        assert!(decoded.is_none());
                        continue;
                    }
                    let size = 31 - immh.leading_zeros();
                    let lane = 1 << size;
                    let changed = [SHIFT_NARROW, SHIFT_WIDEN_SIGNED].contains(&opcode);
                    let valid = if scalar {
                        q && lane == 8
                    } else if changed {
                        lane < 8
                    } else {
                        q || lane < 8
                    };
                    assert_eq!(decoded.unwrap().is_ok(), valid, "{word:08x}");
                    if let Some(Ok(operand)) = decoded {
                        assert_eq!(operand.lane_bytes, u8::try_from(lane).unwrap());
                        let left = [SHIFT_LEFT, SHIFT_WIDEN_SIGNED].contains(&opcode);
                        assert_eq!(
                            u32::from(operand.amount),
                            if left {
                                immediate - lane * 8
                            } else {
                                lane * 16 - immediate
                            }
                        );
                    }
                }
            }
        }
    }
}
