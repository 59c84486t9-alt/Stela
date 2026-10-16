//! AdvSIMD shifts by immediate and register: same-width, narrowing and widening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Register {
        signed: bool,
        round: bool,
        saturating: bool,
        counts: u8,
    },
    SaturatingImmediate {
        signed_source: bool,
        unsigned_result: bool,
    },
    Left {
        insert: bool,
    },
    Right {
        signed: bool,
        round: bool,
        accumulate: bool,
        insert: bool,
    },
    Narrow {
        round: bool,
        upper: bool,
    },
    SaturatingNarrow {
        signed_source: bool,
        unsigned_result: bool,
        round: bool,
        upper: bool,
    },
    Widen {
        signed: bool,
        upper: bool,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub source: u8,
    /// Same-width lane size; destination for narrowing, source for widening.
    pub lane_bytes: u8,
    pub amount: u8,
    /// Active result bytes, except narrowing always produces one 64-bit half.
    pub bytes: u8,
}

// Q and bit28 distinguish vector/scalar variants. Both use the same operands.
const SCALAR: u32 = 1 << 28;
const Q: u32 = 1 << 30;
const IMMEDIATE_SHIFT_MASK: u32 = 0xbf80fc00;
const REGISTER_SHIFT_MASK: u32 = 0xbf20fc00;
const REGISTER_SHIFT_SIGNED: u32 = 0x0e204400;
const REGISTER_SHIFT_UNSIGNED: u32 = 0x2e204400;
const REGISTER_ROUND_SIGNED: u32 = 0x0e205400;
const REGISTER_ROUND_UNSIGNED: u32 = 0x2e205400;
const REGISTER_SATURATING_SIGNED: u32 = 0x0e204c00;
const REGISTER_SATURATING_UNSIGNED: u32 = 0x2e204c00;
const REGISTER_SATURATING_ROUND_SIGNED: u32 = 0x0e205c00;
const REGISTER_SATURATING_ROUND_UNSIGNED: u32 = 0x2e205c00;
const SATURATING_LEFT_SIGNED: u32 = 0x0f007400;
const SATURATING_LEFT_UNSIGNED: u32 = 0x2f007400;
const SATURATING_LEFT_SIGNED_TO_UNSIGNED: u32 = 0x2f006400;
const SHIFT_LEFT: u32 = 0x0f005400;
const SHIFT_LEFT_INSERT: u32 = 0x2f005400;
const SHIFT_RIGHT_INSERT: u32 = 0x2f004400;
const SHIFT_RIGHT_SIGNED: u32 = 0x0f000400;
const SHIFT_RIGHT_UNSIGNED: u32 = 0x2f000400;
const SHIFT_RIGHT_ROUND_SIGNED: u32 = 0x0f002400;
const SHIFT_RIGHT_ROUND_UNSIGNED: u32 = 0x2f002400;
const SHIFT_ACCUMULATE_SIGNED: u32 = 0x0f001400;
const SHIFT_ACCUMULATE_UNSIGNED: u32 = 0x2f001400;
const SHIFT_ROUND_ACCUMULATE_SIGNED: u32 = 0x0f003400;
const SHIFT_ROUND_ACCUMULATE_UNSIGNED: u32 = 0x2f003400;
const SHIFT_NARROW: u32 = 0x0f008400;
const SHIFT_ROUND_NARROW: u32 = 0x0f008c00;
const SATURATING_NARROW_SIGNED: u32 = 0x0f009400;
const SATURATING_ROUND_NARROW_SIGNED: u32 = 0x0f009c00;
const SATURATING_NARROW_UNSIGNED: u32 = 0x2f009400;
const SATURATING_ROUND_NARROW_UNSIGNED: u32 = 0x2f009c00;
const SATURATING_NARROW_SIGNED_TO_UNSIGNED: u32 = 0x2f008400;
const SATURATING_ROUND_NARROW_SIGNED_TO_UNSIGNED: u32 = 0x2f008c00;
const ROUND_NARROW: u32 = 1 << 11;
const SHIFT_WIDEN_SIGNED: u32 = 0x0f00a400;
const SHIFT_WIDEN_UNSIGNED: u32 = 0x2f00a400;

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let scalar = word & SCALAR != 0;
    let q = word & Q != 0;
    if let Some(result) = decode_register(word, scalar, q) {
        return Some(result);
    }
    let opcode = (word & !SCALAR) & IMMEDIATE_SHIFT_MASK;
    let kind = match opcode {
        SATURATING_LEFT_SIGNED | SATURATING_LEFT_UNSIGNED | SATURATING_LEFT_SIGNED_TO_UNSIGNED => {
            Kind::SaturatingImmediate {
                signed_source: opcode != SATURATING_LEFT_UNSIGNED,
                unsigned_result: opcode != SATURATING_LEFT_SIGNED,
            }
        }
        SHIFT_LEFT | SHIFT_LEFT_INSERT => Kind::Left {
            insert: opcode == SHIFT_LEFT_INSERT,
        },
        SHIFT_RIGHT_SIGNED
        | SHIFT_RIGHT_UNSIGNED
        | SHIFT_RIGHT_ROUND_SIGNED
        | SHIFT_RIGHT_ROUND_UNSIGNED
        | SHIFT_ACCUMULATE_SIGNED
        | SHIFT_ACCUMULATE_UNSIGNED
        | SHIFT_ROUND_ACCUMULATE_SIGNED
        | SHIFT_ROUND_ACCUMULATE_UNSIGNED
        | SHIFT_RIGHT_INSERT => Kind::Right {
            signed: word & (1 << 29) == 0,
            round: word & (1 << 13) != 0,
            accumulate: word & (1 << 12) != 0,
            insert: opcode == SHIFT_RIGHT_INSERT,
        },
        SHIFT_NARROW | SHIFT_ROUND_NARROW if !scalar => Kind::Narrow {
            round: opcode == SHIFT_ROUND_NARROW,
            upper: q,
        },
        SATURATING_NARROW_SIGNED
        | SATURATING_ROUND_NARROW_SIGNED
        | SATURATING_NARROW_UNSIGNED
        | SATURATING_ROUND_NARROW_UNSIGNED
        | SATURATING_NARROW_SIGNED_TO_UNSIGNED
        | SATURATING_ROUND_NARROW_SIGNED_TO_UNSIGNED => Kind::SaturatingNarrow {
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
        },
        SHIFT_WIDEN_SIGNED | SHIFT_WIDEN_UNSIGNED if !scalar => Kind::Widen {
            signed: opcode == SHIFT_WIDEN_SIGNED,
            upper: q,
        },
        _ => return None,
    };
    let immediate = ((word >> 16) & 127) as u8;
    let immh = immediate >> 3;
    if immh == 0 {
        return None;
    } // modified-immediate class, not a shift
    let size = 7 - immh.leading_zeros() as u8;
    let lane_bytes = 1 << size;
    let changes_width = matches!(
        kind,
        Kind::Narrow { .. } | Kind::SaturatingNarrow { .. } | Kind::Widen { .. }
    );
    let scalar_any_width = matches!(
        kind,
        Kind::SaturatingImmediate { .. } | Kind::SaturatingNarrow { .. }
    );
    if (scalar && (!q || (lane_bytes != 8 && !scalar_any_width)))
        || (changes_width && lane_bytes == 8)
        || (!scalar && !changes_width && !q && lane_bytes == 8)
    {
        return Some(Err(()));
    }
    let bits = lane_bytes * 8;
    let amount = if matches!(
        kind,
        Kind::Left { .. } | Kind::Widen { .. } | Kind::SaturatingImmediate { .. }
    ) {
        immediate - bits
    } else {
        (u16::from(bits) * 2 - u16::from(immediate)) as u8
    };
    Some(Ok(Operand {
        kind,
        destination: (word & 31) as u8,
        source: ((word >> 5) & 31) as u8,
        lane_bytes,
        amount,
        bytes: if scalar {
            lane_bytes
        } else if changes_width || q {
            16
        } else {
            8
        },
    }))
}

fn decode_register(word: u32, scalar: bool, q: bool) -> Option<Result<Operand, ()>> {
    let opcode = (word & !SCALAR) & REGISTER_SHIFT_MASK;
    if ![
        REGISTER_SHIFT_SIGNED,
        REGISTER_SHIFT_UNSIGNED,
        REGISTER_ROUND_SIGNED,
        REGISTER_ROUND_UNSIGNED,
        REGISTER_SATURATING_SIGNED,
        REGISTER_SATURATING_UNSIGNED,
        REGISTER_SATURATING_ROUND_SIGNED,
        REGISTER_SATURATING_ROUND_UNSIGNED,
    ]
    .contains(&opcode)
    {
        return None;
    }
    let saturating = word & (1 << 11) != 0;
    let lane_bytes = 1 << ((word >> 22) & 3);
    if (scalar && (!q || (!saturating && lane_bytes != 8))) || (!scalar && !q && lane_bytes == 8) {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        kind: Kind::Register {
            signed: word & (1 << 29) == 0,
            round: word & (1 << 12) != 0,
            saturating,
            counts: ((word >> 16) & 31) as u8,
        },
        destination: (word & 31) as u8,
        source: ((word >> 5) & 31) as u8,
        lane_bytes,
        amount: 0,
        bytes: if scalar { lane_bytes } else { 8 << u8::from(q) },
    }))
}

#[cfg(test)]
mod tests {
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
                                        SATURATING_NARROW_UNSIGNED
                                            | SATURATING_ROUND_NARROW_UNSIGNED
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
                        if immh == 0
                            || (scalar && [SHIFT_NARROW, SHIFT_WIDEN_SIGNED].contains(&opcode))
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
}
