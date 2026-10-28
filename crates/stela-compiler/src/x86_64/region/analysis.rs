//! Liveness analysis. Every GPR is live at a region exit.
use super::location::GPR_SLOTS;
use super::{BYTE_LOAD_BYTES, DOUBLEWORD_LOAD_BYTES, HALFWORD_LOAD_BYTES, WORD_LOAD_BYTES};
use crate::aarch64::integer_math::Kind as IntegerMath;
use crate::aarch64::{
    AddressMode, Instruction, MemoryTransfer, Operation, Register, Shift, WideMove, Width,
};
use alloc::vec;
use alloc::vec::Vec;

pub const MAX_INSTRUCTIONS: usize = 256;
const PAIR_OFFSET_BITS: u32 = 7;
const PAIR_OFFSET_HALF_RANGE: i32 = 1 << (PAIR_OFFSET_BITS - 1);

pub fn slot(register: Register) -> Option<usize> {
    match register {
        Register::X(index) if index < 31 => Some(usize::from(index)),
        Register::Sp => Some(31),
        _ => None,
    }
}
fn valid(register: Register) -> bool {
    !matches!(register, Register::X(index) if index >= 31)
}
fn bits(width: Width) -> u8 {
    if width == Width::X64 { 64 } else { 32 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effects {
    pub reads: u32,
    pub writes: u32,
}

/// The caller supplies decoder-validated operations. These additional checks
/// refuse malformed private IR too. Flags, memory and all control transfers end
/// the default prefix; the separate clean-load tier adds only its selected unsigned loads.
/// Absence here never means architectural support is absent.
pub fn effects(operation: &Operation) -> Option<Effects> {
    let (reads, destination): (Vec<Register>, Register) = match *operation {
        Operation::Nop => (vec![], Register::Zero),
        Operation::PcRelative(operand) => (vec![], operand.destination),
        Operation::MoveWide {
            width,
            kind,
            destination,
            shift,
            ..
        } if shift < bits(width) && shift % 16 == 0 => (
            if kind == WideMove::Keep {
                vec![destination]
            } else {
                vec![]
            },
            destination,
        ),
        Operation::AddSub {
            flags: false,
            destination,
            source,
            immediate,
            ..
        } if immediate <= 0x00ff_f000 => (vec![source], destination),
        Operation::AddSubRegister {
            width,
            flags: false,
            destination,
            left,
            right,
            shift,
            amount,
            ..
        } if amount < bits(width) && shift != Shift::Ror => (vec![left, right], destination),
        Operation::LogicalRegister {
            width,
            flags: false,
            destination,
            left,
            right,
            amount,
            ..
        } if amount < bits(width) => (vec![left, right], destination),
        Operation::LogicalImmediate {
            flags: false,
            destination,
            source,
            ..
        } => (vec![source], destination),
        Operation::IntegerMath(operand) => {
            let registers = [
                operand.destination,
                operand.left,
                operand.right,
                operand.accumulator,
            ];
            if registers.contains(&Register::Sp) || !registers.into_iter().all(valid) {
                return None;
            }
            match operand.kind {
                IntegerMath::Low { .. } => (
                    vec![operand.left, operand.right, operand.accumulator],
                    operand.destination,
                ),
                IntegerMath::Extract { width, amount }
                    if operand.left == operand.right
                        && amount < bits(width)
                        && !operand.subtract
                        && operand.accumulator == Register::Zero =>
                {
                    (vec![operand.left], operand.destination)
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    if !valid(destination) || !reads.iter().copied().all(valid) {
        return None;
    }
    Some(Effects {
        reads: reads
            .into_iter()
            .filter_map(slot)
            .fold(0, |mask, index| mask | (1 << index)),
        writes: slot(destination).map_or(0, |index| 1 << index),
    })
}

/// Only unsigned W and X pairs and zero-extending byte, halfword and word
/// loads and doubleword loads with an X-register or SP base and no
/// writeback. Every other memory form ends a region.
pub fn clean_load_effects(operation: &Operation) -> Option<Effects> {
    if let Operation::MemoryPair {
        transfer: MemoryTransfer::Load {
            signed: false,
            width,
        },
        bytes,
        data,
        base,
        displacement,
        mode: AddressMode::Offset,
    } = *operation
        && matches!(
            (width, bytes),
            (Width::W32, WORD_LOAD_BYTES) | (Width::X64, DOUBLEWORD_LOAD_BYTES)
        )
        && let Some(base) = slot(base)
        && displacement % i32::from(bytes) == 0
        && (-PAIR_OFFSET_HALF_RANGE..PAIR_OFFSET_HALF_RANGE)
            .contains(&(displacement / i32::from(bytes)))
        && data[0] != data[1]
        && data
            .iter()
            .copied()
            .all(|register| valid(register) && register != Register::Sp)
    {
        return Some(Effects {
            reads: 1 << base,
            writes: data
                .into_iter()
                .filter_map(slot)
                .fold(0, |mask, guest| mask | (1 << guest)),
        });
    }

    if let Operation::Memory {
        transfer: MemoryTransfer::Load {
            signed: false,
            width,
        },
        bytes,
        data,
        base,
        mode: AddressMode::Offset,
        ..
    } = *operation
        && matches!(
            (width, bytes),
            (
                Width::W32,
                BYTE_LOAD_BYTES | HALFWORD_LOAD_BYTES | WORD_LOAD_BYTES
            ) | (Width::X64, DOUBLEWORD_LOAD_BYTES)
        )
        && let Some(base) = slot(base)
        && valid(data)
        && data != Register::Sp
    {
        return Some(Effects {
            reads: 1 << base,
            writes: slot(data).map_or(0, |index| 1 << index),
        });
    }
    effects(operation)
}

/// [`clean_load_effects`], and the stores the shared emitter makes one host
/// store per element, with or without its page-crossing split: byte,
/// halfword, word and doubleword stores with an X-register or SP base, and,
/// under SCTLR_ELx.SA (`stack_alignment`), W and X pairs through SP whose
/// offset is a multiple of the element size, which the checked SP
/// alignment keeps within a page (`memory_store::aligned_immediate`). None
/// writes back.
pub fn clean_access_effects(operation: &Operation, stack_alignment: bool) -> Option<Effects> {
    let aligned_sp = |base: Register, bytes: u8, displacement: i32| {
        base == Register::Sp && stack_alignment && displacement % i32::from(bytes) == 0
    };
    let data_reads = |data: &[Register]| {
        data.iter()
            .filter_map(|&register| slot(register))
            .fold(0, |mask, guest| mask | (1 << guest))
    };
    match *operation {
        Operation::Memory {
            transfer: MemoryTransfer::Store,
            bytes,
            data,
            base,
            mode: AddressMode::Offset,
            ..
        } if matches!(
            bytes,
            BYTE_LOAD_BYTES | HALFWORD_LOAD_BYTES | WORD_LOAD_BYTES | DOUBLEWORD_LOAD_BYTES
        ) && valid(data)
            && data != Register::Sp =>
        {
            Some(Effects {
                reads: (1 << slot(base)?) | data_reads(&[data]),
                writes: 0,
            })
        }
        Operation::MemoryPair {
            transfer: MemoryTransfer::Store,
            bytes,
            data,
            base,
            displacement,
            mode: AddressMode::Offset,
        } if matches!(bytes, WORD_LOAD_BYTES | DOUBLEWORD_LOAD_BYTES)
            && aligned_sp(base, bytes, displacement)
            && (-PAIR_OFFSET_HALF_RANGE..PAIR_OFFSET_HALF_RANGE)
                .contains(&(displacement / i32::from(bytes)))
            && data
                .iter()
                .all(|&register| valid(register) && register != Register::Sp) =>
        {
            Some(Effects {
                reads: (1 << slot(base)?) | data_reads(&data),
                writes: 0,
            })
        }
        _ => clean_load_effects(operation),
    }
}

pub fn prefix_clean_access_effects(
    instructions: &[Instruction],
    stack_alignment: bool,
) -> Vec<Effects> {
    instructions
        .iter()
        .map_while(|instruction| clean_access_effects(&instruction.operation, stack_alignment))
        .collect()
}

/// A future overwrite kills the current value even if a later version is read.
/// A killed value still needs its old value until that overwrite commits, and
/// eviction always writes it back if dirty: asynchronous recovery requires it.
pub fn next_use(effects: &[Effects], after: usize, guest: usize) -> usize {
    debug_assert!(guest < GPR_SLOTS);
    let bit = 1u32 << guest;
    for (index, effect) in effects.iter().enumerate().skip(after) {
        if effect.reads & bit != 0 {
            return index;
        }
        if effect.writes & bit != 0 {
            return usize::MAX;
        }
    }
    usize::MAX
}

pub fn prefix_effects(instructions: &[Instruction]) -> Vec<Effects> {
    instructions
        .iter()
        .map_while(|instruction| effects(&instruction.operation))
        .collect()
}

/// Every direct target and fallthrough after a control transfer starts a new
/// region.
#[cfg(test)]
pub fn leaf_entries(instructions: &[Instruction]) -> alloc::collections::BTreeSet<u64> {
    let mut entries = alloc::collections::BTreeSet::new();
    if let Some(first) = instructions.first() {
        entries.insert(first.pc.0);
    }
    for (index, instruction) in instructions.iter().enumerate() {
        let target = match instruction.operation {
            Operation::Branch { target }
            | Operation::BranchCondition { target, .. }
            | Operation::BranchZero { target, .. }
            | Operation::BranchBit { target, .. } => Some(target),
            _ => None,
        };
        if let Some(target) = target {
            entries.insert(target.0);
        }
        if (target.is_some() || matches!(instruction.operation, Operation::Return))
            && let Some(next) = instructions.get(index + 1)
        {
            entries.insert(next.pc.0);
        }
    }
    entries
}
