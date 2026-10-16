//! Halving arithmetic (SHADD, URHADD, ...), narrowing and pairwise widening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Half {
        signed: bool,
        subtract: bool,
        round: bool,
    },
    HighNarrow {
        subtract: bool,
        round: bool,
        upper: bool,
    },
    PairLong {
        signed: bool,
        accumulate: bool,
    },
    Truncate {
        upper: bool,
    },
    ShiftLong {
        upper: bool,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
    /// Halving/pair source lane size; narrowing output lane size.
    pub lane_bytes: u8,
    pub bytes: u8,
}
const SAME_MASK: u32 = 0xbf20fc00;
const UNARY_MASK: u32 = 0xbf3ffc00;
const SIGNED_HALF_ADD: u32 = 0x0e200400;
const UNSIGNED_HALF_ADD: u32 = 0x2e200400;
const SIGNED_ROUND_HALF_ADD: u32 = 0x0e201400;
const UNSIGNED_ROUND_HALF_ADD: u32 = 0x2e201400;
const SIGNED_HALF_SUB: u32 = 0x0e202400;
const UNSIGNED_HALF_SUB: u32 = 0x2e202400;
const ADD_HIGH_NARROW: u32 = 0x0e204000;
const ROUND_ADD_HIGH_NARROW: u32 = 0x2e204000;
const SUB_HIGH_NARROW: u32 = 0x0e206000;
const ROUND_SUB_HIGH_NARROW: u32 = 0x2e206000;
const SIGNED_PAIR_LONG: u32 = 0x0e202800;
const UNSIGNED_PAIR_LONG: u32 = 0x2e202800;
const SIGNED_ACC_PAIR_LONG: u32 = 0x0e206800;
const UNSIGNED_ACC_PAIR_LONG: u32 = 0x2e206800;
const TRUNCATE: u32 = 0x0e212800;
const SHIFT_LONG: u32 = 0x2e213800;

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let q = word & (1 << 30) != 0;
    let opcode = word & SAME_MASK;
    let kind = match opcode {
        SIGNED_HALF_ADD
        | UNSIGNED_HALF_ADD
        | SIGNED_ROUND_HALF_ADD
        | UNSIGNED_ROUND_HALF_ADD
        | SIGNED_HALF_SUB
        | UNSIGNED_HALF_SUB => Some(Kind::Half {
            signed: word & (1 << 29) == 0,
            subtract: opcode == SIGNED_HALF_SUB || opcode == UNSIGNED_HALF_SUB,
            round: opcode == SIGNED_ROUND_HALF_ADD || opcode == UNSIGNED_ROUND_HALF_ADD,
        }),
        ADD_HIGH_NARROW | ROUND_ADD_HIGH_NARROW | SUB_HIGH_NARROW | ROUND_SUB_HIGH_NARROW => {
            Some(Kind::HighNarrow {
                subtract: opcode == SUB_HIGH_NARROW || opcode == ROUND_SUB_HIGH_NARROW,
                round: word & (1 << 29) != 0,
                upper: q,
            })
        }
        _ => None,
    }
    .or(match word & UNARY_MASK {
        SIGNED_PAIR_LONG | UNSIGNED_PAIR_LONG | SIGNED_ACC_PAIR_LONG | UNSIGNED_ACC_PAIR_LONG => {
            Some(Kind::PairLong {
                signed: word & (1 << 29) == 0,
                accumulate: word & (1 << 14) != 0,
            })
        }
        TRUNCATE => Some(Kind::Truncate { upper: q }),
        SHIFT_LONG => Some(Kind::ShiftLong { upper: q }),
        _ => None,
    })?;
    let size = (word >> 22) & 3;
    if size == 3 {
        return Some(Err(()));
    }
    let bytes = if matches!(kind, Kind::HighNarrow { .. } | Kind::Truncate { .. })
        || (!q && !matches!(kind, Kind::ShiftLong { .. }))
    {
        8
    } else {
        16
    };
    Some(Ok(Operand {
        kind,
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right: ((word >> 16) & 31) as u8,
        lane_bytes: 1 << size,
        bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizes_widths_and_half_selection_distinguish_all_form_groups() {
        for base in [
            SIGNED_HALF_ADD,
            UNSIGNED_HALF_SUB,
            ROUND_ADD_HIGH_NARROW,
            SIGNED_ACC_PAIR_LONG,
            TRUNCATE,
            SHIFT_LONG,
        ] {
            for q in 0..2 {
                for size in 0..4 {
                    let word = base | (q << 30) | (size << 22) | (31 << 5) | 31;
                    let decoded = decode(word).unwrap();
                    if size == 3 {
                        assert!(decoded.is_err());
                        continue;
                    }
                    let operand = decoded.unwrap();
                    assert_eq!(operand.lane_bytes, 1 << size);
                    match operand.kind {
                        Kind::Truncate { upper } | Kind::HighNarrow { upper, .. } => {
                            assert_eq!(upper, q != 0);
                            assert_eq!(operand.bytes, 8);
                        }
                        Kind::ShiftLong { upper } => {
                            assert_eq!(upper, q != 0);
                            assert_eq!(operand.bytes, 16);
                        }
                        _ => assert_eq!(operand.bytes, 8 << q),
                    }
                }
            }
        }
        assert!(decode(0x5e200400).is_none()); // vector forms only
        assert!(matches!(
            decode(SIGNED_ACC_PAIR_LONG),
            Some(Ok(Operand {
                kind: Kind::PairLong {
                    accumulate: true,
                    ..
                },
                ..
            }))
        ));
    }
}
