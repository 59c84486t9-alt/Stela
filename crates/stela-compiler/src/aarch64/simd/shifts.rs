//! Non-saturating AdvSIMD immediate shifts: Arm A64 2026-06 shift XML facts.
//! The semantic operation distinguishes same-width, narrowing and widening lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
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
const SHIFT_WIDEN_SIGNED: u32 = 0x0f00a400;
const SHIFT_WIDEN_UNSIGNED: u32 = 0x2f00a400;

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let scalar = word & SCALAR != 0;
    let q = word & Q != 0;
    let opcode = (word & !SCALAR) & IMMEDIATE_SHIFT_MASK;
    let kind = match opcode {
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
    let changes_width = matches!(kind, Kind::Narrow { .. } | Kind::Widen { .. });
    if (scalar && (!q || lane_bytes != 8))
        || (changes_width && lane_bytes == 8)
        || (!scalar && !changes_width && !q && lane_bytes == 8)
    {
        return Some(Err(()));
    }
    let bits = lane_bytes * 8;
    let amount = if matches!(kind, Kind::Left { .. } | Kind::Widen { .. }) {
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
        bytes: if changes_width || (!scalar && q) {
            16
        } else {
            8
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
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
