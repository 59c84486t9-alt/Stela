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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryTransfer {
    Store,
    Load { signed: bool, width: Width },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressMode {
    Offset,
    PreIndex,
    PostIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Memory {
        transfer: MemoryTransfer,
        bytes: u8,
        data: Register,
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
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
        } else if word & 0x3f000000 == 0x39000000 || word & 0x3f200000 == 0x38000000 {
            // Scalar integer loads/stores only: VR=0. Reject PRFM, reserved
            // signed sizes, register offsets, atomics and unprivileged forms.
            let size = word >> 30;
            let transfer = match (word >> 22) & 3 {
                0 => MemoryTransfer::Store,
                1 => MemoryTransfer::Load {
                    signed: false,
                    width: if size == 3 { Width::X64 } else { Width::W32 },
                },
                2 if size < 3 => MemoryTransfer::Load {
                    signed: true,
                    width: Width::X64,
                },
                3 if size < 2 => MemoryTransfer::Load {
                    signed: true,
                    width: Width::W32,
                },
                _ => return Err(unsupported()),
            };
            let (displacement, mode) = if word & (1 << 24) != 0 {
                ((((word >> 10) & 0xfff) << size) as i32, AddressMode::Offset)
            } else {
                let immediate = ((word >> 12) & 0x1ff) as i32;
                let mode = match (word >> 10) & 3 {
                    0 => AddressMode::Offset,
                    1 => AddressMode::PostIndex,
                    3 => AddressMode::PreIndex,
                    _ => return Err(unsupported()),
                };
                ((immediate << 23) >> 23, mode)
            };
            let rn = (word >> 5) & 31;
            let rt = word & 31;
            // Writeback overlap has constrained-unpredictable semantics.
            // Reject it rather than choosing one possible architectural result.
            if mode != AddressMode::Offset && rn == rt && rn != 31 {
                return Err(unsupported());
            }
            Operation::Memory {
                transfer,
                bytes: 1 << size,
                data: register(rt, false),
                base: register(rn, true),
                displacement,
                mode,
            }
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
    fn memory_neighbors_and_unpredictable_writeback_fail_closed() {
        for word in [
            0xf9800000, // PRFM: same unsigned-immediate family, no load result
            0xf8800000, // PRFUM
            0xb9c00000, // unallocated signed word -> W32
            0xf9c00000, // unallocated signed doubleword
            0xf8400800, // LDTR: unprivileged access is a different policy
            0xf8000800, // STTR
            0xf8606800, // register-offset LDR
            0x3d400000, // SIMD/FP LDR
            0xf8400c00, // pre-index LDR with base/target overlap
            0xf8400400, // post-index LDR with base/target overlap
            0xf8000c00, // pre-index STR with base/target overlap
            0xf8000400, // post-index STR with base/target overlap
        ] {
            assert!(Decoder.lift(GuestAddress(0), word).is_err(), "{word:#x}");
        }
        // The same register as base and destination is defined without writeback.
        assert!(Decoder.lift(GuestAddress(0), 0xf9400000).is_ok());
        // Rt=31 is ZR, Rn=31 is SP; they do not overlap.
        assert!(Decoder.lift(GuestAddress(0), 0xf8400fff).is_ok());
    }

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
