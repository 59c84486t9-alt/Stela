//! Apple A64 scalar integer multiply encodings, with ZR in every register role.
//!
//! Semantics and fixed bits follow the pinned Arm 2026-06 MADD/MSUB,
//! SMADDL/SMSUBL, UMADDL/UMSUBL and SMULH/UMULH instruction XML.
use super::{Register, Width, register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
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

/// Match the data-processing (three-source) class. Unsupported/reserved class
/// members return Err, so they cannot accidentally become a nearby multiply.
/// MUL/MNEG and long aliases are represented by an ordinary ZR accumulator.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
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
