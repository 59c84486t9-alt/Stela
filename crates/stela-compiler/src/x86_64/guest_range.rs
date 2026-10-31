//! Which accesses of a system-mode block check their address against the
//! guest's native ranges ([`super::RangeCheck`]).
//!
//! An immediate-offset access moves at most 2^16 bytes from its base, so
//! once one through a base register has been made, the base is within
//! 2^16 of a range. While the base keeps that value or moves from it by
//! immediates (writeback, or ADD and SUB immediate, also into another
//! register), every later immediate-offset access through it is within
//! 2^35 of a range, as a block holds at most 1,024 instructions. With
//! five-level paging that is in a range, or in PML5 entry 1 or 510, which
//! no shadow root maps, where an x86 #PF takes the fault the guest's
//! translation gives; Stela's window, 63 entries from either range, stays
//! out of reach. With four-level paging it is in a range, above 2^47
//! (non-canonical, #GP), in the unmapped guard of at least 2^35 bytes below
//! the upper range (#PF), or across 0 or 2^64, wrapping into a range as
//! Arm's address arithmetic does; never in Stela's window below the guard.
//! Those accesses need no check of their own. Any other write of the
//! register, and any instruction this analysis does not know, forgets it.
use crate::aarch64::{
    Instruction, MemoryTransfer, Operation, Register, Width, atomic, literal, non_temporal,
    ordered, simd,
};
use alloc::vec::Vec;

/// A register's bit in a set of bases: X0-X30 and SP as bit 31.
fn bit(register: Register) -> u32 {
    match register {
        Register::X(index) => 1 << index,
        Register::Sp => 1 << 31,
        Register::Zero => 0,
    }
}

/// For each instruction of a block, whether its access checks the guest
/// range: all but the immediate-offset accesses through a base the block
/// has already made such an access through, unmodified since but by
/// immediates.
pub(crate) fn checks(instructions: &[Instruction]) -> Vec<bool> {
    let mut bases = 0u32;
    instructions
        .iter()
        .map(|instruction| {
            let check =
                immediate_base(&instruction.operation).is_none_or(|base| bases & bit(base) == 0);
            bases = after(&instruction.operation, bases);
            check
        })
        .collect()
}

/// The base of an access whose address is the base plus an immediate.
fn immediate_base(operation: &Operation) -> Option<Register> {
    match operation {
        Operation::Memory { base, .. }
        | Operation::MemoryPair { base, .. }
        | Operation::Simd(
            simd::Operand::Memory { base, .. } | simd::Operand::MemoryPair { base, .. },
        ) => Some(*base),
        Operation::Simd(simd::Operand::StructureMemory(operand)) => Some(operand.base),
        Operation::MemoryUnprivileged(operand) => Some(operand.base),
        Operation::MemoryNonTemporal(operand) => Some(operand.base),
        Operation::Atomic(operand) => Some(operand.base),
        Operation::Ordered(ordered::Operand::Transfer { base, .. }) => Some(*base),
        _ => None,
    }
}

/// The bases known after `operation`, given `bases` before it.
fn after(operation: &Operation, bases: u32) -> u32 {
    let loaded = |transfer: &MemoryTransfer| matches!(transfer, MemoryTransfer::Load { .. });
    match operation {
        Operation::Memory {
            transfer,
            data,
            base,
            ..
        } => {
            let bases = bases | bit(*base);
            if loaded(transfer) {
                bases & !bit(*data)
            } else {
                bases
            }
        }
        Operation::MemoryPair {
            transfer,
            data,
            base,
            ..
        } => {
            let bases = bases | bit(*base);
            if loaded(transfer) {
                bases & !bit(data[0]) & !bit(data[1])
            } else {
                bases
            }
        }
        Operation::MemoryUnprivileged(operand) => {
            let bases = bases | bit(operand.base);
            if loaded(&operand.transfer) {
                bases & !bit(operand.data)
            } else {
                bases
            }
        }
        Operation::MemoryNonTemporal(operand) => {
            let bases = bases | bit(operand.base);
            match operand.data {
                non_temporal::Data::Integer(data) if operand.load => {
                    bases & !bit(data[0]) & !bit(data[1])
                }
                _ => bases,
            }
        }
        // Vector data; the base moves by an immediate if at all.
        Operation::Simd(
            simd::Operand::Memory { base, .. } | simd::Operand::MemoryPair { base, .. },
        ) => bases | bit(*base),
        Operation::Simd(simd::Operand::StructureMemory(operand)) => match operand.post_index {
            simd::structure_memory::PostIndex::Register(_) => bases & !bit(operand.base),
            _ => bases | bit(operand.base),
        },
        Operation::AddSub {
            width,
            destination,
            source,
            ..
        } => {
            if *width == Width::X64 && bases & bit(*source) != 0 {
                bases | bit(*destination)
            } else {
                bases & !bit(*destination)
            }
        }
        Operation::AddSubRegister { destination, .. }
        | Operation::AddSubCarry { destination, .. }
        | Operation::AddSubExtended { destination, .. }
        | Operation::LogicalRegister { destination, .. }
        | Operation::LogicalImmediate { destination, .. }
        | Operation::MoveWide { destination, .. } => bases & !bit(*destination),
        // CAS and CASP return the old value in the compared registers.
        Operation::Atomic(operand) => {
            let bases = bases | bit(operand.base);
            match operand.kind {
                atomic::Kind::CompareExchange { compare, .. } => bases & !bit(compare),
                atomic::Kind::CompareExchangePair { compare, .. } => {
                    bases & !bit(compare[0]) & !bit(compare[1])
                }
                atomic::Kind::ReadModifyWrite { destination, .. } => bases & !bit(destination),
            }
        }
        Operation::Ordered(ordered::Operand::Transfer {
            kind, data, base, ..
        }) => {
            let bases = bases | bit(*base);
            if *kind == ordered::Kind::Release {
                bases
            } else {
                bases & !bit(*data)
            }
        }
        // A register offset proves nothing of its base.
        Operation::MemoryRegisterOffset(operand) => {
            if loaded(&operand.transfer) {
                bases & !bit(operand.data)
            } else {
                bases
            }
        }
        Operation::Literal(operand) => match operand.transfer {
            literal::Transfer::Integer { destination, .. } => bases & !bit(destination),
            literal::Transfer::Simd { .. } => bases,
        },
        Operation::PcRelative(operand) => bases & !bit(operand.destination),
        Operation::ConditionalSelect(operand) => bases & !bit(operand.destination),
        Operation::Bitfield(operand) => bases & !bit(operand.destination),
        Operation::IntegerMath(operand) => bases & !bit(operand.destination),
        Operation::IntegerUnary(operand) => bases & !bit(operand.destination),
        Operation::IntegerMinMax(operand) => bases & !bit(operand.destination),
        Operation::Crc(operand) => bases & !bit(operand.destination),
        // NZCV, barriers and hints only; the block a branch leaves is over.
        Operation::Flags(_)
        | Operation::BranchCondition { .. }
        | Operation::BranchZero { .. }
        | Operation::BranchBit { .. }
        | Operation::Synchronization(_)
        | Operation::Ordered(ordered::Operand::Barrier { .. })
        | Operation::Nop
        | Operation::Prefetch(_) => bases,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, Lifter, aarch64::Decoder};
    use alloc::vec::Vec;

    fn lift(words: &[u32]) -> Vec<Instruction> {
        words
            .iter()
            .enumerate()
            .map(|(index, &word)| {
                Decoder
                    .lift(GuestAddress(0x1000 + 4 * index as u64), word)
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn a_base_is_checked_once_until_it_changes_but_by_immediates() {
        // stp x29, x30, [sp, #-16]!; mov x29, sp; ldr x0, [x29, #8];
        // str x1, [sp, #8]; sub sp, sp, #32; ldp x2, x3, [sp], #16;
        // ldr x4, [x5]; ldr x5, [x5, #8]; ldr x6, [x5]; add w5, w6, #1;
        // ldr x7, [x5]; ldr x8, [x6, x9]; ldr x10, [x6]
        let words = [
            0xa9bf_7bfd,
            0x9100_03fd,
            0xf940_07a0,
            0xf900_07e1,
            0xd100_83ff,
            0xa8c1_0fe2,
            0xf940_00a4,
            0xf940_04a5,
            0xf940_00a6,
            0x1100_04c5,
            0xf940_00a7,
            0xf869_68c8,
            0xf940_00ca,
        ];
        assert_eq!(
            checks(&lift(&words)),
            [
                true,  // the first access through SP
                true,  // a move
                false, // X29 = SP
                false, // SP again
                true,  // SUB SP, SP, #imm
                false, // SP moved by an immediate
                true,  // the first through X5
                false, // X5 again, which the load replaces
                true,  // X5 was loaded
                true,  // an add
                true,  // a W result is no address near a range
                true,  // a register offset is checked at its sum
                true,  // X6 was loaded and has made no access
            ]
        );
    }

    #[test]
    fn unknown_instructions_and_register_post_indexes_forget_bases() {
        // ldr x0, [x1]; fmov x2, d0 (not analyzed); ldr x6, [x1];
        // ld1 {v0.16b}, [x1], x7; ldr x8, [x1]; ld1 {v0.16b}, [x1], #16;
        // ldr x9, [x1]
        let words = [
            0xf940_0020,
            0x9e66_0002,
            0xf940_0026,
            0x4cc7_7020,
            0xf940_0028,
            0x4cdf_7020,
            0xf940_0029,
        ];
        assert_eq!(
            checks(&lift(&words)),
            [true, true, true, false, true, false, false]
        );
    }
}
