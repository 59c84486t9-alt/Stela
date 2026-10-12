//! Decode architectural operand roles, including SP versus the zero register.
use crate::{GuestAddress, Lifter, UnsupportedReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    W32,
    X64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    X(u8),
    Sp,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideMove {
    Zero,
    Keep,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logical {
    And,
    Or,
    Xor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    AddSubRegister {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
        shift: Shift,
        amount: u8,
    },
    LogicalRegister {
        width: Width,
        kind: Logical,
        invert: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
        shift: Shift,
        amount: u8,
    },
    Branch {
        target: GuestAddress,
    },
    BranchCondition {
        target: GuestAddress,
        condition: u8,
    },
    BranchZero {
        target: GuestAddress,
        source: Register,
        width: Width,
        nonzero: bool,
    },
    BranchBit {
        target: GuestAddress,
        source: Register,
        bit: u8,
        nonzero: bool,
    },
    MoveWide {
        width: Width,
        kind: WideMove,
        destination: Register,
        immediate: u16,
        shift: u8,
    },
    AddSub {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        source: Register,
        immediate: u32,
    },
    Nop,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub pc: GuestAddress,
    pub operation: Operation,
}

pub struct Decoder;

fn register(value: u32, sp: bool) -> Register {
    if value == 31 {
        if sp { Register::Sp } else { Register::Zero }
    } else {
        Register::X(value as u8)
    }
}

impl Lifter for Decoder {
    type Instruction = Instruction;
    fn lift(&self, pc: GuestAddress, word: u32) -> Result<Instruction, UnsupportedReason> {
        let unsupported = || UnsupportedReason::Instruction {
            address: pc,
            encoding: word,
        };
        let width = if word >> 31 == 0 {
            Width::W32
        } else {
            Width::X64
        };
        let target = |immediate: u32, bits: u32| {
            let signed = ((i64::from(immediate) << (64 - bits)) >> (64 - bits)) * 4;
            pc.0.checked_add_signed(signed)
                .map(GuestAddress)
                .ok_or_else(unsupported)
        };
        let shift = match (word >> 22) & 3 {
            0 => Shift::Lsl,
            1 => Shift::Lsr,
            2 => Shift::Asr,
            _ => Shift::Ror,
        };
        let amount = ((word >> 10) & 63) as u8;
        let operation = if word == 0xd65f03c0 {
            Operation::Return
        } else if word == 0xd503201f {
            Operation::Nop
        } else if word & 0xfc000000 == 0x14000000 {
            Operation::Branch {
                target: target(word & 0x03ffffff, 26)?,
            }
        } else if word & 0xff000010 == 0x54000000 {
            Operation::BranchCondition {
                target: target((word >> 5) & 0x7ffff, 19)?,
                condition: (word & 15) as u8,
            }
        } else if word & 0x7e000000 == 0x34000000 {
            Operation::BranchZero {
                target: target((word >> 5) & 0x7ffff, 19)?,
                source: register(word & 31, false),
                width,
                nonzero: word & (1 << 24) != 0,
            }
        } else if word & 0x7e000000 == 0x36000000 {
            Operation::BranchBit {
                target: target((word >> 5) & 0x3fff, 14)?,
                source: register(word & 31, false),
                bit: (((word >> 26) & 32) | ((word >> 19) & 31)) as u8,
                nonzero: word & (1 << 24) != 0,
            }
        } else if word & 0x1f200000 == 0x0b000000 {
            if shift == Shift::Ror || (width == Width::W32 && amount >= 32) {
                return Err(unsupported());
            }
            Operation::AddSubRegister {
                width,
                subtract: word & (1 << 30) != 0,
                flags: word & (1 << 29) != 0,
                destination: register(word & 31, false),
                left: register((word >> 5) & 31, false),
                right: register((word >> 16) & 31, false),
                shift,
                amount,
            }
        } else if word & 0x1f000000 == 0x0a000000 {
            if width == Width::W32 && amount >= 32 {
                return Err(unsupported());
            }
            let opcode = (word >> 29) & 3;
            Operation::LogicalRegister {
                width,
                kind: match opcode {
                    0 | 3 => Logical::And,
                    1 => Logical::Or,
                    _ => Logical::Xor,
                },
                invert: word & (1 << 21) != 0,
                flags: opcode == 3,
                destination: register(word & 31, false),
                left: register((word >> 5) & 31, false),
                right: register((word >> 16) & 31, false),
                shift,
                amount,
            }
        } else if word & 0x1f800000 == 0x12800000 {
            let kind = match (word >> 29) & 3 {
                0 => WideMove::Not,
                2 => WideMove::Zero,
                3 => WideMove::Keep,
                _ => return Err(unsupported()),
            };
            let shift = (((word >> 21) & 3) * 16) as u8;
            if width == Width::W32 && shift >= 32 {
                return Err(unsupported());
            }
            Operation::MoveWide {
                width,
                kind,
                destination: register(word & 31, false),
                immediate: ((word >> 5) & 0xffff) as u16,
                shift,
            }
        } else if word & 0x1f800000 == 0x11000000 {
            let flags = word & (1 << 29) != 0;
            let immediate = ((word >> 10) & 0xfff) << if word & (1 << 22) != 0 { 12 } else { 0 };
            Operation::AddSub {
                width,
                subtract: word & (1 << 30) != 0,
                flags,
                destination: register(word & 31, !flags),
                source: register((word >> 5) & 31, true),
                immediate,
            }
        } else {
            return Err(unsupported());
        };
        Ok(Instruction { pc, operation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sp_and_zero_are_decoded_by_instruction_role() {
        let add = Decoder.lift(GuestAddress(0), 0x910003ff).unwrap(); // add sp,sp,#0
        assert!(matches!(
            add.operation,
            Operation::AddSub {
                destination: Register::Sp,
                source: Register::Sp,
                ..
            }
        ));
        let cmp = Decoder.lift(GuestAddress(0), 0xf10003ff).unwrap(); // subs xzr,sp,#0
        assert!(matches!(
            cmp.operation,
            Operation::AddSub {
                destination: Register::Zero,
                source: Register::Sp,
                flags: true,
                ..
            }
        ));
        assert!(Decoder.lift(GuestAddress(0), 0x52c00000).is_err()); // undefined W32 MOVZ shift 32
        assert!(Decoder.lift(GuestAddress(0), 0x91800000).is_err()); // reserved add-immediate bit
        assert!(Decoder.lift(GuestAddress(0), 0x0b008000).is_err()); // W32 shift 32
        assert!(Decoder.lift(GuestAddress(0), 0x0bc00000).is_err()); // reserved arithmetic ROR
        assert!(Decoder.lift(GuestAddress(0), 0x0a008000).is_err()); // W32 logical shift 32
        assert!(Decoder.lift(GuestAddress(0), 0x54000010).is_err()); // BC.cond is a different instruction
        assert!(Decoder.lift(GuestAddress(0), 0x94000000).is_err()); // BL requires call semantics
        assert!(Decoder.lift(GuestAddress(0), 0x17ffffff).is_err()); // PC-relative underflow
    }
}
