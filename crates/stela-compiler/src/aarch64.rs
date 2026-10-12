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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
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
        let operation = if word == 0xd65f03c0 {
            Operation::Return
        } else if word == 0xd503201f {
            Operation::Nop
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
    }
}
