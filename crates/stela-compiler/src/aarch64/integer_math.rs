//! Integer data processing: MADD/MSUB, SMADDL/SMSUBL/UMADDL/UMSUBL, SMULH/UMULH,
//! SDIV/UDIV, LSLV/LSRV/ASRV/RORV, EXTR, CLZ, CLS, RBIT and REV*. Register 31 is ZR.
use super::{Register, Shift, Width, register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    VariableShift { width: Width, shift: Shift },
    Extract { width: Width, amount: u8 },
    LeadingZeros { width: Width },
    LeadingSignBits { width: Width },
    ReverseBits { width: Width },
    ReverseBytes { width: Width, group_bytes: u8 },
    Divide { signed: bool, width: Width },
    Low { width: Width },
    Long { signed: bool },
    High { signed: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub subtract: bool,
    pub destination: Register,
    pub left: Register,
    pub right: Register,
    pub accumulator: Register,
}

/// Match scalar SDIV/UDIV and the product three-source class. Reserved product class
/// members return Err, so they cannot accidentally become a nearby multiply.
/// MUL/MNEG and long aliases are represented by an ordinary ZR accumulator.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let width = if word >> 31 == 0 {
        Width::W32
    } else {
        Width::X64
    };
    let scalar = if word & 0x7fe0f000 == 0x1ac02000 {
        Some(Kind::VariableShift {
            width,
            shift: match (word >> 10) & 3 {
                0 => Shift::Lsl,
                1 => Shift::Lsr,
                2 => Shift::Asr,
                _ => Shift::Ror,
            },
        })
    } else if word & 0x7fa00000 == 0x13800000 {
        let amount = ((word >> 10) & 63) as u8;
        if ((word >> 22) & 1) != word >> 31 || (width == Width::W32 && amount >= 32) {
            return Some(Err(()));
        }
        Some(Kind::Extract { width, amount })
    } else {
        None
    };
    if let Some(kind) = scalar {
        return Some(Ok(Operand {
            kind,
            subtract: false,
            destination: register(word & 31, false),
            left: register((word >> 5) & 31, false),
            right: register((word >> 16) & 31, false),
            accumulator: Register::Zero,
        }));
    }
    let unary = match word & 0xfffffc00 {
        0x5ac01000 => Some(Kind::LeadingZeros { width: Width::W32 }),
        0xdac01000 => Some(Kind::LeadingZeros { width: Width::X64 }),
        0x5ac01400 => Some(Kind::LeadingSignBits { width: Width::W32 }),
        0xdac01400 => Some(Kind::LeadingSignBits { width: Width::X64 }),
        0x5ac00000 => Some(Kind::ReverseBits { width: Width::W32 }),
        0xdac00000 => Some(Kind::ReverseBits { width: Width::X64 }),
        0x5ac00800 => Some(Kind::ReverseBytes {
            width: Width::W32,
            group_bytes: 4,
        }),
        0x5ac00400 => Some(Kind::ReverseBytes {
            width: Width::W32,
            group_bytes: 2,
        }),
        0xdac00c00 => Some(Kind::ReverseBytes {
            width: Width::X64,
            group_bytes: 8,
        }),
        0xdac00800 => Some(Kind::ReverseBytes {
            width: Width::X64,
            group_bytes: 4,
        }),
        0xdac00400 => Some(Kind::ReverseBytes {
            width: Width::X64,
            group_bytes: 2,
        }),
        _ => None,
    };
    if let Some(kind) = unary {
        return Some(Ok(Operand {
            kind,
            subtract: false,
            destination: register(word & 31, false),
            left: register((word >> 5) & 31, false),
            right: Register::Zero,
            accumulator: Register::Zero,
        }));
    }
    if matches!(word & 0x7fe0fc00, 0x1ac00800 | 0x1ac00c00) {
        return Some(Ok(Operand {
            kind: Kind::Divide {
                signed: word & (1 << 10) != 0,
                width: if word >> 31 != 0 {
                    Width::X64
                } else {
                    Width::W32
                },
            },
            subtract: false,
            destination: register(word & 31, false),
            left: register((word >> 5) & 31, false),
            right: register((word >> 16) & 31, false),
            accumulator: Register::Zero,
        }));
    }
    if word & 0x7f000000 != 0x1b000000 {
        return None;
    }
    let sf = word >> 31 != 0;
    let subtract = word & (1 << 15) != 0;
    let kind = match ((word >> 21) & 7, sf, subtract) {
        (0, _, _) => Kind::Low {
            width: if sf { Width::X64 } else { Width::W32 },
        },
        (1, true, _) => Kind::Long { signed: true },
        (5, true, _) => Kind::Long { signed: false },
        (2, true, false) => Kind::High { signed: true },
        (6, true, false) => Kind::High { signed: false },
        _ => return Some(Err(())),
    };
    Some(Ok(Operand {
        kind,
        subtract,
        destination: register(word & 31, false),
        left: register((word >> 5) & 31, false),
        right: register((word >> 16) & 31, false),
        // SMULH/UMULH encode Ra as (11111): architecturally ignored,
        // including noncanonical values. They never read an accumulator.
        accumulator: if matches!(kind, Kind::High { .. }) {
            Register::Zero
        } else {
            register((word >> 10) & 31, false)
        },
    }))
}

#[cfg(test)]
mod tests;
