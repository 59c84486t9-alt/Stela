//! Decode architectural operand roles, including SP versus the zero register.
use crate::{GuestAddress, Lifter, UnsupportedReason};
pub mod bitfield;
pub mod conditional_select;
pub mod crc;
pub mod integer_math;
pub mod pc_relative;
pub mod register_offset;
pub mod simd;

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
pub enum RegisterExtend {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
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
    Simd(simd::Operand),
    Bitfield(bitfield::Operand),
    PcRelative(pc_relative::Operand),
    ConditionalSelect(conditional_select::Operand),
    ConditionalCompare(conditional_select::CompareOperand),
    Crc(crc::Operand),
    IntegerMath(integer_math::Operand),
    MemoryRegisterOffset(register_offset::Operand),
    MemoryPair {
        transfer: MemoryTransfer,
        bytes: u8,
        data: [Register; 2],
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
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
    AddSubCarry {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
    },
    AddSubExtended {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
        extend: RegisterExtend,
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
    LogicalImmediate {
        width: Width,
        kind: Logical,
        flags: bool,
        destination: Register,
        source: Register,
        immediate: u64,
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

/// Decode the logical-immediate subset of Arm's DecodeBitMasks operation.
/// Each element contains a rotated, nonempty run of ones shorter than the
/// element, then repeats to the operand width. High rotation bits are ignored.
fn logical_mask(width: Width, n: u32, rotation: u32, size: u32) -> Option<u64> {
    if width == Width::W32 && n != 0 {
        return None;
    }
    let selector = (n << 6) | ((!size) & 63);
    if selector < 2 {
        return None;
    }
    let element_bits = 1u32 << (31 - selector.leading_zeros());
    let levels = element_bits - 1;
    let ones = (size & levels) + 1;
    if ones == element_bits {
        return None;
    }
    let rotation = rotation & levels;
    // A valid run never fills a 64-bit element, so this shift cannot be 64.
    let run = (1u64 << ones) - 1;
    let rotated = if rotation == 0 {
        run
    } else {
        (run >> rotation) | (run << (element_bits - rotation))
    };
    let element = if element_bits == 64 {
        rotated
    } else {
        rotated & ((1u64 << element_bits) - 1)
    };
    let operand_bits = if width == Width::W32 { 32 } else { 64 };
    let mut mask = 0;
    for position in (0..operand_bits).step_by(element_bits as usize) {
        mask |= element << position;
    }
    Some(mask)
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
        } else if let Some(decoded) = pc_relative::decode(pc, word) {
            Operation::PcRelative(decoded)
        } else if let Some(decoded) = bitfield::decode(word) {
            Operation::Bitfield(decoded)
        } else if let Some(decoded) = conditional_select::decode(word) {
            Operation::ConditionalSelect(decoded)
        } else if let Some(decoded) = conditional_select::decode_compare(word) {
            Operation::ConditionalCompare(decoded)
        } else if let Some(decoded) = crc::decode(word) {
            Operation::Crc(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = integer_math::decode(word) {
            Operation::IntegerMath(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = simd::decode(word) {
            Operation::Simd(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = register_offset::decode(word) {
            Operation::MemoryRegisterOffset(decoded.map_err(|()| unsupported())?)
        } else if word & 0x3e000000 == 0x28000000 {
            // Integer LDP/STP/LDPSW. SIMD, non-temporal pairs, tagged
            // stores and reserved opcodes are not interchangeable with these accesses.
            let opcode = word >> 30;
            let loading = word & (1 << 22) != 0;
            let bytes = match opcode {
                0 => 4,
                1 if loading => 4,
                2 => 8,
                _ => return Err(unsupported()),
            };
            let mode = match (word >> 23) & 3 {
                1 => AddressMode::PostIndex,
                2 => AddressMode::Offset,
                3 => AddressMode::PreIndex,
                _ => return Err(unsupported()),
            };
            let rn = (word >> 5) & 31;
            let rt = word & 31;
            let rt2 = (word >> 10) & 31;
            if (loading && rt == rt2)
                || (mode != AddressMode::Offset && rn != 31 && (rn == rt || rn == rt2))
            {
                return Err(unsupported());
            }
            let immediate = ((word >> 15) & 0x7f) as i32;
            Operation::MemoryPair {
                transfer: if loading {
                    MemoryTransfer::Load {
                        signed: opcode == 1,
                        width: if opcode == 0 { Width::W32 } else { Width::X64 },
                    }
                } else {
                    MemoryTransfer::Store
                },
                bytes,
                data: [register(rt, false), register(rt2, false)],
                base: register(rn, true),
                displacement: ((immediate << 25) >> 25) * i32::from(bytes),
                mode,
            }
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
        } else if word & 0x1fe0fc00 == 0x1a000000 {
            Operation::AddSubCarry {
                width,
                subtract: word & (1 << 30) != 0,
                flags: word & (1 << 29) != 0,
                destination: register(word & 31, false),
                left: register((word >> 5) & 31, false),
                right: register((word >> 16) & 31, false),
            }
        } else if word & 0x1fe00000 == 0x0b200000 {
            let amount = ((word >> 10) & 7) as u8;
            if amount > 4 {
                return Err(unsupported());
            }
            let flags = word & (1 << 29) != 0;
            let extend = match (word >> 13) & 7 {
                0 => RegisterExtend::Uxtb,
                1 => RegisterExtend::Uxth,
                2 => RegisterExtend::Uxtw,
                3 => RegisterExtend::Uxtx,
                4 => RegisterExtend::Sxtb,
                5 => RegisterExtend::Sxth,
                6 => RegisterExtend::Sxtw,
                _ => RegisterExtend::Sxtx,
            };
            Operation::AddSubExtended {
                width,
                subtract: word & (1 << 30) != 0,
                flags,
                destination: register(word & 31, !flags),
                left: register((word >> 5) & 31, true),
                right: register((word >> 16) & 31, false),
                extend,
                amount,
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
        } else if word & 0x1f800000 == 0x12000000 {
            let opcode = (word >> 29) & 3;
            Operation::LogicalImmediate {
                width,
                kind: match opcode {
                    0 | 3 => Logical::And,
                    1 => Logical::Or,
                    _ => Logical::Xor,
                },
                flags: opcode == 3,
                destination: register(word & 31, opcode != 3),
                source: register((word >> 5) & 31, false),
                immediate: logical_mask(
                    width,
                    (word >> 22) & 1,
                    (word >> 16) & 63,
                    (word >> 10) & 63,
                )
                .ok_or_else(unsupported)?,
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
    fn extended_arithmetic_validates_options_shifts_and_sp_zero_roles() {
        let extensions = [
            RegisterExtend::Uxtb,
            RegisterExtend::Uxth,
            RegisterExtend::Uxtw,
            RegisterExtend::Uxtx,
            RegisterExtend::Sxtb,
            RegisterExtend::Sxth,
            RegisterExtend::Sxtw,
            RegisterExtend::Sxtx,
        ];
        for width in [Width::W32, Width::X64] {
            for subtract in [false, true] {
                for flags in [false, true] {
                    for (option, extend) in extensions.into_iter().enumerate() {
                        for amount in 0..8 {
                            let word = (u32::from(width == Width::X64) << 31)
                                | (u32::from(subtract) << 30)
                                | (u32::from(flags) << 29)
                                | 0x0b3f03ff
                                | ((option as u32) << 13)
                                | (amount << 10);
                            let decoded = Decoder.lift(GuestAddress(0), word);
                            if amount > 4 {
                                assert!(decoded.is_err());
                                continue;
                            }
                            assert_eq!(
                                decoded.unwrap().operation,
                                Operation::AddSubExtended {
                                    width,
                                    subtract,
                                    flags,
                                    destination: if flags { Register::Zero } else { Register::Sp },
                                    left: Register::Sp,
                                    right: Register::Zero,
                                    extend,
                                    amount: amount as u8,
                                }
                            );
                            for reserved in [1 << 22, 1 << 23] {
                                assert!(Decoder.lift(GuestAddress(0), word | reserved).is_err());
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn carry_operands_use_zero_and_require_the_exact_instruction_encoding() {
        for width in [Width::W32, Width::X64] {
            for subtract in [false, true] {
                for flags in [false, true] {
                    let word = (u32::from(width == Width::X64) << 31)
                        | (u32::from(subtract) << 30)
                        | (u32::from(flags) << 29)
                        | 0x1a1f03ff;
                    assert_eq!(
                        Decoder.lift(GuestAddress(0), word).unwrap().operation,
                        Operation::AddSubCarry {
                            width,
                            subtract,
                            flags,
                            destination: Register::Zero,
                            left: Register::Zero,
                            right: Register::Zero,
                        }
                    );
                    // Bits 15:10 are fixed, not a shift or ignored field.
                    for reserved in 1..64 {
                        assert!(
                            Decoder
                                .lift(GuestAddress(0), word | (reserved << 10))
                                .is_err()
                        );
                    }
                }
            }
        }
        for word in [
            0xd500401f, // CFINV
            0xba008400, // RMIF
            0x3a00080d, // SETF8
            0x3a00480d, // SETF16
        ] {
            assert!(Decoder.lift(GuestAddress(0), word).is_err(), "{word:#x}");
        }
    }

    #[test]
    fn logical_immediate_masks_match_all_rotated_runs_and_reserved_encodings() {
        for (width, bits) in [(Width::W32, 32), (Width::X64, 64)] {
            let mut expected = std::collections::BTreeMap::new();
            for element_bits in [2, 4, 8, 16, 32, 64] {
                if element_bits > bits {
                    continue;
                }
                for ones in 1..element_bits {
                    for rotation in 0..64 {
                        // Construct the reference bit-by-bit instead of using
                        // the decoder's shift/rotate/replication arithmetic.
                        let mut mask = 0u64;
                        for position in 0..bits {
                            if (position + rotation) % element_bits < ones {
                                mask |= 1 << position;
                            }
                        }
                        let n = u32::from(element_bits == 64);
                        let size = ((-2 * element_bits) | (ones - 1)) as u32 & 63;
                        expected.insert((n, rotation as u32, size), mask);
                    }
                }
            }
            for n in 0..=1 {
                for rotation in 0..64 {
                    for size in 0..64 {
                        let key = (n, rotation, size);
                        assert_eq!(
                            logical_mask(width, n, rotation, size),
                            expected.get(&key).copied(),
                            "{width:?} N={n} immr={rotation} imms={size}"
                        );
                        for opcode in 0..4 {
                            let word = (u32::from(width == Width::X64) << 31)
                                | (opcode << 29)
                                | 0x12000000
                                | (n << 22)
                                | (rotation << 16)
                                | (size << 10);
                            assert_eq!(
                                Decoder.lift(GuestAddress(0), word).is_ok(),
                                expected.contains_key(&key),
                                "word {word:#x}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn logical_immediate_distinguishes_sp_destination_and_zero_source() {
        for (word, destination, flags) in [
            (0x92401fff, Register::Sp, false),  // and sp,xzr,#0xff
            (0x32001fff, Register::Sp, false),  // orr wsp,wzr,#0xff
            (0xd2401fff, Register::Sp, false),  // eor sp,xzr,#0xff
            (0xf2401fff, Register::Zero, true), // tst xzr,#0xff
        ] {
            assert!(matches!(
                Decoder.lift(GuestAddress(0), word).unwrap().operation,
                Operation::LogicalImmediate {
                    destination: actual_destination,
                    source: Register::Zero,
                    flags: actual_flags,
                    immediate: 255,
                    ..
                } if actual_destination == destination && actual_flags == flags
            ));
        }
    }

    #[test]
    fn pair_neighbors_and_unpredictable_operands_are_rejected() {
        for word in [
            0xa8400400, // LDNP x0,x1,[x0] is non-temporal, not LDP
            0xa8000400, // STNP
            0x6d400000, // SIMD LDP d0,d0,[x0] has duplicate V destinations
            0xe9400400, // unallocated integer pair opcode
            0x69000400, // STGP allocation-tag store must not become plain STP
            0xa9400000, // LDP with identical destinations
            0xa9407fff, // LDP xzr,xzr,[sp] still has identical destinations
            0xa8c10400, // LDP post-index overlaps first destination
            0xa9c10420, // LDP pre-index overlaps second destination
            0xa8810400, // STP post-index overlaps first source
            0xa9810420, // STP pre-index overlaps second source
        ] {
            assert!(Decoder.lift(GuestAddress(0), word).is_err(), "{word:#x}");
        }
        assert!(Decoder.lift(GuestAddress(0), 0xa9400400).is_ok()); // offset LDP can overwrite base
        assert!(Decoder.lift(GuestAddress(0), 0xa9000000).is_ok()); // STP same source twice is defined
        assert!(Decoder.lift(GuestAddress(0), 0xa9bf7fff).is_ok()); // STP xzr,xzr,[sp,#-16]!
        assert!(matches!(
            Decoder.lift(GuestAddress(0), 0xad0183e0).unwrap().operation,
            Operation::Simd(simd::Operand::MemoryPair { load: false, .. })
        )); // original Xcode STP q0,q0,[sp,#48]
    }

    #[test]
    fn memory_neighbors_and_unpredictable_writeback_fail_closed() {
        for word in [
            0xf9800000, // PRFM: same unsigned-immediate family, no load result
            0xf8800000, // PRFUM
            0xb9c00000, // unallocated signed word -> W32
            0xf9c00000, // unallocated signed doubleword
            0xf8400800, // LDTR: unprivileged access is a different policy
            0xf8000800, // STTR
            0x3cc00800, // SIMD unprivileged/reserved mode
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
        // SIMD Rt0 is V0, independent of the X0 address/writeback register.
        assert!(matches!(
            Decoder.lift(GuestAddress(0), 0x3c400c00).unwrap().operation,
            Operation::Simd(simd::Operand::Memory { .. })
        ));
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
