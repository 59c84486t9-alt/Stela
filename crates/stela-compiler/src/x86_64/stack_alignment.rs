//! Which accesses of a block check SCTLR_ELx.SA's SP alignment
//! ([`super::STACK_ALIGNMENT_CHECK`]).
//!
//! Once an access through SP has checked it, SP is 16-byte aligned. Moves
//! by multiples of 16 (writeback, ADD and SUB immediate) keep it aligned;
//! any other write of SP, and any instruction this analysis does not know,
//! forgets it. A later access through the aligned SP needs no check of its
//! own: had SP been misaligned, the earlier access would have faulted, and
//! a block's instructions run in order.
use crate::aarch64::{AddressMode, Instruction, Operation, Register, simd};
use alloc::vec::Vec;

/// SCTLR_ELx.SA's alignment of SP.
const STACK_ALIGNMENT_BYTES: i64 = 16;

/// For each instruction of a block, whether an access of it through SP
/// checks SP's alignment: all but those after an access through SP that
/// checked it, with SP aligned since.
pub(crate) fn checks(instructions: &[Instruction]) -> Vec<bool> {
    let mut aligned = false;
    instructions
        .iter()
        .map(|instruction| {
            let check = !aligned;
            aligned = after(&instruction.operation, aligned);
            check
        })
        .collect()
}

/// Whether a move of SP by `bytes` keeps it aligned.
fn keeps_alignment(bytes: i64) -> bool {
    bytes % STACK_ALIGNMENT_BYTES == 0
}

/// Whether an access through `base` with this writeback leaves SP known
/// aligned, given `aligned` before it. An access through SP checks it
/// (`x86_64::memory_address`).
fn access(base: Register, writeback: Option<i64>, aligned: bool) -> bool {
    if base != Register::Sp {
        return aligned;
    }
    writeback.is_none_or(keeps_alignment)
}

/// An immediate writeback's move of the base, if any.
fn writeback(mode: AddressMode, displacement: i32) -> Option<i64> {
    (mode != AddressMode::Offset).then_some(i64::from(displacement))
}

/// Whether SP is known aligned after `operation`, given `aligned` before.
fn after(operation: &Operation, aligned: bool) -> bool {
    match operation {
        Operation::Memory {
            base,
            displacement,
            mode,
            ..
        }
        | Operation::MemoryPair {
            base,
            displacement,
            mode,
            ..
        }
        | Operation::Simd(
            simd::Operand::Memory {
                base,
                displacement,
                mode,
                ..
            }
            | simd::Operand::MemoryPair {
                base,
                displacement,
                mode,
                ..
            },
        ) => access(*base, writeback(*mode, *displacement), aligned),
        Operation::MemoryRegisterOffset(operand) => access(operand.base, None, aligned),
        Operation::Simd(simd::Operand::MemoryRegisterOffset(operand)) => {
            access(operand.base, None, aligned)
        }
        Operation::Simd(simd::Operand::StructureMemory(operand)) => {
            use simd::structure_memory::PostIndex;
            match operand.post_index {
                PostIndex::None => access(operand.base, None, aligned),
                PostIndex::TransferredBytes => access(
                    operand.base,
                    Some(i64::from(operand.transferred_bytes())),
                    aligned,
                ),
                // An access through SP checks it, but X0-X30 move it by any amount.
                PostIndex::Register(_) => aligned && operand.base != Register::Sp,
            }
        }
        Operation::AddSub {
            destination: Register::Sp,
            source,
            immediate,
            ..
        } => aligned && *source == Register::Sp && keeps_alignment(i64::from(*immediate)),
        Operation::AddSubExtended { destination, .. }
        | Operation::LogicalImmediate { destination, .. } => {
            aligned && *destination != Register::Sp
        }
        // Their destinations are never SP, and their accesses never have
        // writeback.
        Operation::AddSub { .. }
        | Operation::AddSubRegister { .. }
        | Operation::AddSubCarry { .. }
        | Operation::LogicalRegister { .. }
        | Operation::MoveWide { .. }
        | Operation::FloatingPoint(_)
        | Operation::FloatingPointRegister(_)
        | Operation::Bitfield(_)
        | Operation::PcRelative(_)
        | Operation::ConditionalSelect(_)
        | Operation::ConditionalCompare(_)
        | Operation::Crc(_)
        | Operation::Flags(_)
        | Operation::IntegerMath(_)
        | Operation::IntegerMinMax(_)
        | Operation::IntegerUnary(_)
        | Operation::Literal(_)
        | Operation::MemoryNonTemporal(_)
        | Operation::MemoryUnprivileged(_)
        | Operation::Atomic(_)
        | Operation::Ordered(_)
        | Operation::Prefetch(_)
        | Operation::Synchronization(_)
        | Operation::BranchCondition { .. }
        | Operation::BranchZero { .. }
        | Operation::BranchBit { .. }
        | Operation::Nop => aligned,
        Operation::Simd(_) => aligned,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, Lifter, aarch64::Decoder};

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
    fn sp_is_checked_once_until_it_moves_by_other_than_sixteens() {
        // ldr x0, [sp, #8]; str q1, [sp, #16]; stp x29, x30, [sp, #-16]!;
        // ldr x2, [sp]; sub sp, sp, #8; ldr x3, [sp]; ldr x4, [sp];
        // add sp, sp, #8; fmul d0, d1, d2; ldr x5, [sp]; mov sp, x6;
        // ldr x7, [sp]; ldr x8, [sp], #8; ldr x9, [sp]
        let words = [
            0xf940_07e0,
            0x3d80_07e1,
            0xa9bf_7bfd,
            0xf940_03e2,
            0xd100_23ff,
            0xf940_03e3,
            0xf940_03e4,
            0x9100_23ff,
            0x1e62_0820,
            0xf940_03e5,
            0x9100_00df,
            0xf940_03e7,
            0xf840_87e8,
            0xf940_03e9,
        ];
        assert_eq!(
            checks(&lift(&words)),
            [
                true,  // the first access through SP
                false, // aligned since
                false, // moved by 16
                false, // still aligned
                false, // SUB SP, SP, #8 itself accesses nothing
                true,  // moved by 8
                false, // checked by the previous one
                false, // ADD SP, SP, #8 itself accesses nothing
                true,  // FMUL accesses nothing
                true,  // the sum of two moves by 8 is not tracked
                false, // MOV SP, X6 itself accesses nothing
                true,  // SP was replaced
                false, // checked, then moved by 8
                true,  // moved by 8
            ]
        );
    }
}
