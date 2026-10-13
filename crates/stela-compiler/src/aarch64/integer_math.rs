//! Apple A64 scalar integer math encodings; register 31 is ZR.
//!
//! Semantics and fixed bits follow the pinned Arm 2026-06 MADD/MSUB,
//! SMADDL/SMSUBL, UMADDL/UMSUBL, SMULH/UMULH, SDIV/UDIV and scalar unary XML.
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
mod tests {
    use super::*;

    #[test]
    fn scalar_shifts_and_extract_validate_width_immediates_and_zero_roles() {
        for (sf, width) in [(0, Width::W32), (1u32 << 31, Width::X64)] {
            for (op, shift) in [Shift::Lsl, Shift::Lsr, Shift::Asr, Shift::Ror]
                .into_iter()
                .enumerate()
            {
                let base = sf | 0x1ac02000 | ((op as u32) << 10);
                let operand = decode(base | (31 << 16) | (31 << 5) | 31).unwrap().unwrap();
                assert_eq!(operand.kind, Kind::VariableShift { width, shift });
                assert_eq!(
                    (operand.destination, operand.left, operand.right),
                    (Register::Zero, Register::Zero, Register::Zero)
                );
                for bit in 0..32 {
                    if 0x7fe0f000 & (1 << bit) != 0 {
                        assert!(!matches!(
                            decode(base ^ (1 << bit)),
                            Some(Ok(Operand {
                                kind: Kind::VariableShift { .. },
                                ..
                            }))
                        ));
                    }
                }
            }
            let base = if width == Width::X64 {
                0x93c00000
            } else {
                0x13800000
            };
            for amount in 0..64 {
                let decoded = decode(base | (amount << 10) | (31 << 16) | (31 << 5) | 31).unwrap();
                if width == Width::W32 && amount >= 32 {
                    assert_eq!(decoded, Err(()));
                } else {
                    let operand = decoded.unwrap();
                    assert_eq!(
                        operand.kind,
                        Kind::Extract {
                            width,
                            amount: amount as u8
                        }
                    );
                    assert_eq!(
                        (operand.destination, operand.left, operand.right),
                        (Register::Zero, Register::Zero, Register::Zero)
                    );
                }
            }
            assert_eq!(decode(base ^ (1 << 22)), Some(Err(()))); // N must match sf.
            assert!(decode(base | (1 << 21)).is_none()); // fixed o0
        }
    }

    #[test]
    fn unary_forms_use_exact_fixed_bits_and_zero_register_roles() {
        let forms = [
            (0x5ac01000, Kind::LeadingZeros { width: Width::W32 }),
            (0xdac01000, Kind::LeadingZeros { width: Width::X64 }),
            (0x5ac01400, Kind::LeadingSignBits { width: Width::W32 }),
            (0xdac01400, Kind::LeadingSignBits { width: Width::X64 }),
            (0x5ac00000, Kind::ReverseBits { width: Width::W32 }),
            (0xdac00000, Kind::ReverseBits { width: Width::X64 }),
            (
                0x5ac00800,
                Kind::ReverseBytes {
                    width: Width::W32,
                    group_bytes: 4,
                },
            ),
            (
                0x5ac00400,
                Kind::ReverseBytes {
                    width: Width::W32,
                    group_bytes: 2,
                },
            ),
            (
                0xdac00c00,
                Kind::ReverseBytes {
                    width: Width::X64,
                    group_bytes: 8,
                },
            ),
            (
                0xdac00800,
                Kind::ReverseBytes {
                    width: Width::X64,
                    group_bytes: 4,
                },
            ),
            (
                0xdac00400,
                Kind::ReverseBytes {
                    width: Width::X64,
                    group_bytes: 2,
                },
            ),
        ];
        for (base, kind) in forms {
            for destination in 0..32 {
                for source in 0..32 {
                    let operand = decode(base | (source << 5) | destination).unwrap().unwrap();
                    assert_eq!(operand.kind, kind);
                    assert_eq!(operand.destination, register(destination, false));
                    assert_eq!(operand.left, register(source, false));
                    assert_eq!(operand.right, Register::Zero);
                    assert_eq!(operand.accumulator, Register::Zero);
                }
            }
            for bit in 10..32 {
                if let Some(Ok(neighbor)) = decode(base ^ (1 << bit)) {
                    assert_ne!(neighbor.kind, kind, "{base:08x} bit {bit}");
                }
            }
        }
        // W32 REV with the X64-only opcode and reserved one-source neighbors.
        for word in [0x5ac00c00, 0x5ac01800, 0xdac01800, 0x5ac02000, 0xdac02000] {
            assert!(decode(word).is_none(), "{word:08x}");
        }
    }

    #[test]
    fn division_fixed_bits_width_and_zero_roles_are_exact() {
        for (base, signed) in [(0x1ac00800, false), (0x1ac00c00, true)] {
            for (sf, width) in [(0, Width::W32), (1u32 << 31, Width::X64)] {
                let word = base | sf | (31 << 16) | (31 << 5) | 31;
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.kind, Kind::Divide { signed, width });
                assert_eq!(operand.destination, Register::Zero);
                assert_eq!(operand.left, Register::Zero);
                assert_eq!(operand.right, Register::Zero);
                assert_eq!(operand.accumulator, Register::Zero);
                for bit in [11, 12, 13, 14, 15, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30] {
                    // A neighboring encoding can be a different valid integer
                    // operation (for example UMULH), but never another divide.
                    if let Some(Ok(neighbor)) = decode(word ^ (1 << bit)) {
                        assert!(
                            !matches!(neighbor.kind, Kind::Divide { .. }),
                            "{word:08x} bit {bit}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn opcode_space_and_reserved_neighbors_are_explicit() {
        for sf in 0..2 {
            for opcode in 0..8 {
                for subtract in 0..2 {
                    let word = 0x1b000000 | (sf << 31) | (opcode << 21) | (subtract << 15);
                    let valid = opcode == 0
                        || (sf == 1
                            && (opcode == 1
                                || opcode == 5
                                || (subtract == 0 && (opcode == 2 || opcode == 6))));
                    assert_eq!(decode(word).unwrap().is_ok(), valid, "{word:08x}");
                }
            }
        }
        for bit in 24..31 {
            assert!(decode(0x9b007c00 ^ (1 << bit)).is_none());
        }
    }

    #[test]
    fn every_operand_uses_zero_instead_of_sp() {
        let operand = decode(0x9b000000 | (31 << 16) | (31 << 10) | (31 << 5) | 31)
            .unwrap()
            .unwrap();
        assert_eq!(operand.destination, Register::Zero);
        assert_eq!(operand.left, Register::Zero);
        assert_eq!(operand.right, Register::Zero);
        assert_eq!(operand.accumulator, Register::Zero);
    }

    #[test]
    fn high_product_ignores_all_accumulator_encodings() {
        for signed in [false, true] {
            for accumulator in 0..32 {
                let word = (if signed { 0x9b400000 } else { 0x9bc00000 }) | (accumulator << 10);
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.kind, Kind::High { signed });
                assert_eq!(operand.accumulator, Register::Zero);
            }
        }
    }
}
