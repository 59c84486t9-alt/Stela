//! AdvSIMD shifts: Arm A64 2026-06 immediate/register shift XML facts.
//! The semantic operation distinguishes same-width, narrowing and widening lanes.
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
mod tests;
