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
/// `lea r10d, [rax+disp8]`, which starts every page-crossing store recipe.
const CROSSING_STORE_START: [u8; 3] = [0x44, 0x8d, 0x50];

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

/// Inspect only selected baseline scalar output for a conservative cost gate.
/// This is not an executable decoder, instruction semantic validator or runtime
/// admission mechanism. Any unrecognized form declines region optimization.
/// Only one optional operand-size prefix and one REX prefix are recognized;
/// General selected memory operands are direct RDI frame accesses without SIB/RIP;
/// the clean-load tier additionally recognizes exactly the existing LEA/MOVZX forms.
pub fn selected_output_instruction_count(code: &[u8]) -> Option<usize> {
    selected_output_instruction_ends(code).map(|ends| ends.len())
}

/// Fail-closed boundaries for the same selected output forms, never semantic admission.
pub fn selected_output_instruction_ends(code: &[u8]) -> Option<Vec<usize>> {
    output_instruction_ends(code, false)
}

/// Cost only: flag-bearing pure spans. This cannot change the legacy region gate.
pub(super) fn allocated_output_instruction_count(code: &[u8]) -> Option<usize> {
    output_instruction_ends(code, true).map(|ends| ends.len())
}

fn output_instruction_ends(code: &[u8], extended: bool) -> Option<Vec<usize>> {
    const OPERAND_SIZE: u8 = 0x66;
    const REX_FIRST: u8 = 0x40;
    const REX_LAST: u8 = 0x4f;
    const REX_W: u8 = 8;
    const REX_B: u8 = 1;
    const MOV_REG_IMMEDIATE_FIRST: u8 = 0xb8;
    const MOV_REG_IMMEDIATE_LAST: u8 = 0xbf;
    const MOV_RM_IMMEDIATE: u8 = 0xc7;
    const MOV_LOAD: u8 = 0x8b;
    const MOV_STORE: u8 = 0x89;
    const ADD: u8 = 0x01;
    const SUB: u8 = 0x29;
    const AND: u8 = 0x21;
    const OR: u8 = 0x09;
    const XOR: u8 = 0x31;
    const IMMEDIATE_GROUP: u8 = 0x81;
    const SHORT_IMMEDIATE_GROUP: u8 = 0x83;
    const IMUL_IMMEDIATE: u8 = 0x69;
    const PUSH_FIRST: u8 = 0x50;
    const POP_LAST: u8 = 0x5f;
    const NEAR_JUMP: u8 = 0xe9;
    const SHORT_JUMP: u8 = 0xeb;
    const ACCUMULATOR_IMMEDIATES: [u8; 6] = [0x05, 0x2d, 0x25, 0x35, 0x3d, 0xa9];
    const CONDITION_MOVE_FIRST: u8 = 0x40;
    const CONDITION_MOVE_LAST: u8 = 0x4f;
    const CONDITION_JUMP_FIRST: u8 = 0x80;
    const CONDITION_JUMP_LAST: u8 = 0x8f;
    const CONDITION_SET_FIRST: u8 = 0x90;
    const CONDITION_SET_LAST: u8 = 0x9f;
    const TEST: u8 = 0x85;
    const TEST_BYTE: u8 = 0x84;
    const INC_DEC_GROUP: u8 = 0xff;
    const SHIFT_IMMEDIATE_GROUP: u8 = 0xc1;
    const UNARY_GROUP: u8 = 0xf7;
    const NOP: u8 = 0x90;
    const FRAME_RM: u8 = 7;
    const REX_X64_LOW_REGISTERS: u8 = 0x48;
    const LEA: u8 = 0x8d;
    const LEA_RAX_RAX_DISP8: u8 = 0x40;
    const LEA_RAX_RAX_DISP32: u8 = 0x80;
    const LEA_RDX_RAX_DISP8: u8 = 0x50;
    const LEA_RDX_RAX_DISP32: u8 = 0x90;
    const LEA_RDX_RDX_DISP8: u8 = 0x52;
    const TWO_BYTE_OPCODE: u8 = 0x0f;
    const MOVZX_BYTE: u8 = 0xb6;
    const MOVZX_WORD: u8 = 0xb7;
    const IMUL: u8 = 0xaf;
    const SHRD_IMMEDIATE: u8 = 0xac;
    const ECX_FROM_RAX_MEMORY: u8 = 0x08;
    const REX_R8_WORD: u8 = 0x44;
    const REX_R8_DOUBLEWORD: u8 = 0x4c;
    const R8D_FROM_RAX_DISP8: u8 = 0x40;
    const MOV_BYTE_STORE: u8 = 0x88;

    let mut cursor = 0usize;
    let mut ends = vec![];
    while cursor < code.len() {
        // The exact system-mode guest range check of an access address.
        if let Some((bytes, check_ends)) = super::super::RangeCheck::at(&code[cursor..]) {
            ends.extend(check_ends.iter().map(|end| cursor + end));
            cursor += bytes;
            continue;
        }
        // The exact SCTLR_ELx.SA check of an SP base.
        if code[cursor..].starts_with(&super::super::STACK_ALIGNMENT_CHECK) {
            ends.extend(super::super::STACK_ALIGNMENT_CHECK_ENDS.map(|end| cursor + end));
            cursor += super::super::STACK_ALIGNMENT_CHECK.len();
            continue;
        }
        // The exact page-crossing H/W/X store of RCX to [RAX], whose branches
        // stay inside it.
        if code[cursor..].starts_with(&CROSSING_STORE_START)
            && let Some((recipe, recipe_ends)) =
                [HALFWORD_LOAD_BYTES, WORD_LOAD_BYTES, DOUBLEWORD_LOAD_BYTES]
                    .into_iter()
                    .filter_map(super::super::memory_store::crossing_store)
                    .find(|(recipe, _)| code[cursor..].starts_with(recipe))
        {
            ends.extend(recipe_ends.iter().map(|end| cursor + end));
            cursor += recipe.len();
            continue;
        }
        let word = code.get(cursor).copied() == Some(OPERAND_SIZE);
        cursor += usize::from(word);
        let rex = code
            .get(cursor)
            .copied()
            .filter(|byte| (REX_FIRST..=REX_LAST).contains(byte));
        cursor += usize::from(rex.is_some());
        let opcode = *code.get(cursor)?;
        cursor += 1;
        if extended
            && !word
            && (PUSH_FIRST..=POP_LAST).contains(&opcode)
            && rex.is_none_or(|rex| rex == (REX_FIRST | REX_B))
        {
            // Borrowed native ABI registers; no memory addressing operand.
        } else if extended && !word && rex.is_none() && matches!(opcode, NEAR_JUMP | SHORT_JUMP) {
            cursor += if opcode == NEAR_JUMP { 4 } else { 1 };
        } else if extended && !word && ACCUMULATOR_IMMEDIATES.contains(&opcode) {
            cursor += 4;
        } else if (MOV_REG_IMMEDIATE_FIRST..=MOV_REG_IMMEDIATE_LAST).contains(&opcode) {
            cursor += if rex.is_some_and(|rex| rex & REX_W != 0) {
                8
            } else if word {
                2
            } else {
                4
            };
        } else if opcode == LEA
            && !word
            && (rex == Some(REX_X64_LOW_REGISTERS) || (extended && rex.is_none()))
        {
            let modrm = *code.get(cursor)?;
            // The shared address additions ([`super::super::address_add`]).
            let low = rex == Some(REX_X64_LOW_REGISTERS);
            if low && matches!(modrm, LEA_RAX_RAX_DISP32 | LEA_RDX_RAX_DISP32) {
                cursor += 5;
            } else if low && matches!(modrm, LEA_RAX_RAX_DISP8 | LEA_RDX_RAX_DISP8) {
                cursor += 2;
            } else if extended && modrm == LEA_RDX_RDX_DISP8 {
                // Flag-neutral selector adjustment.
                cursor += 2;
            } else if extended
                && rex.is_none()
                && code.get(cursor - 1..cursor + 2)? == super::super::CAPTURE_COMBINE
            {
                // The NZCV capture's combining step.
                cursor += 2;
            } else {
                return None;
            }
        } else if opcode == TWO_BYTE_OPCODE && !word {
            let second = *code.get(cursor)?;
            if matches!(second, MOVZX_BYTE | MOVZX_WORD) && rex.is_none() {
                // Exact existing LDRB/LDRH data access MOVZX ECX,[RAX].
                if code.get(cursor + 1).copied() != Some(ECX_FROM_RAX_MEMORY) {
                    return None;
                }
                cursor += 2;
            } else if extended
                && (CONDITION_JUMP_FIRST..=CONDITION_JUMP_LAST).contains(&second)
                && rex.is_none()
            {
                cursor += 5;
            } else if extended
                && ((CONDITION_MOVE_FIRST..=CONDITION_MOVE_LAST).contains(&second)
                    || (CONDITION_SET_FIRST..=CONDITION_SET_LAST).contains(&second))
            {
                if *code.get(cursor + 1)? >> 6 != 3 {
                    return None;
                }
                cursor += 2;
            } else if matches!(second, IMUL | SHRD_IMMEDIATE) {
                // Selected low multiply and baseline equal-source EXTR recipes.
                // Memory forms are deliberately outside this cost inspector.
                if *code.get(cursor + 1)? >> 6 != 3 {
                    return None;
                }
                cursor += 2 + usize::from(second == SHRD_IMMEDIATE);
            } else {
                return None;
            }
        } else if opcode == MOV_LOAD
            && !word
            && rex.is_none_or(|rex| rex == REX_X64_LOW_REGISTERS)
            && code.get(cursor).copied() == Some(ECX_FROM_RAX_MEMORY)
        {
            // Exact selected W load into ECX or X load into RCX.
            cursor += 1;
        } else if opcode == MOV_LOAD
            && !word
            && matches!(
                (rex, code.get(cursor..cursor + 2)),
                (
                    Some(REX_R8_WORD),
                    Some([R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES])
                ) | (
                    Some(REX_R8_DOUBLEWORD),
                    Some([R8D_FROM_RAX_DISP8, DOUBLEWORD_LOAD_BYTES])
                )
            )
        {
            // Exact second unsigned W or X pair load into R8.
            cursor += 2;
        } else if opcode == MOV_BYTE_STORE
            && !word
            && rex.is_none()
            && code.get(cursor).copied() == Some(ECX_FROM_RAX_MEMORY)
        {
            // Exact selected STRB store of CL to [RAX].
            cursor += 1;
        } else if opcode == MOV_STORE
            && code.get(cursor).copied() == Some(ECX_FROM_RAX_MEMORY)
            && match rex {
                None => true,
                Some(rex) => !word && rex == REX_X64_LOW_REGISTERS,
            }
        {
            // Exact selected H/W/X store of RCX to [RAX].
            cursor += 1;
        } else if opcode == MOV_STORE
            && !word
            && matches!(
                (rex, code.get(cursor..cursor + 2)),
                (
                    Some(REX_R8_WORD),
                    Some([R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES])
                ) | (
                    Some(REX_R8_DOUBLEWORD),
                    Some([R8D_FROM_RAX_DISP8, DOUBLEWORD_LOAD_BYTES])
                )
            )
        {
            // Exact second W or X pair store of R8.
            cursor += 2;
        } else if opcode == NOP && !word && rex.is_none() {
            // Exact single-byte NOP only.
        } else {
            let recognized = matches!(
                opcode,
                MOV_RM_IMMEDIATE
                    | MOV_LOAD
                    | MOV_STORE
                    | ADD
                    | SUB
                    | AND
                    | OR
                    | XOR
                    | IMMEDIATE_GROUP
                    | SHORT_IMMEDIATE_GROUP
                    | IMUL_IMMEDIATE
                    | TEST
                    | TEST_BYTE
                    | INC_DEC_GROUP
                    | SHIFT_IMMEDIATE_GROUP
                    | UNARY_GROUP
            );
            if !recognized
                || (!extended
                    && matches!(
                        opcode,
                        SHORT_IMMEDIATE_GROUP | IMUL_IMMEDIATE | TEST | TEST_BYTE | INC_DEC_GROUP
                    ))
                || (word && !matches!(opcode, MOV_RM_IMMEDIATE | MOV_LOAD | MOV_STORE))
            {
                return None;
            }
            let modrm = *code.get(cursor)?;
            cursor += 1;
            let mode = modrm >> 6;
            let extension = (modrm >> 3) & 7;
            let rm = modrm & 7;
            if mode != 3 {
                if matches!(opcode, IMUL_IMMEDIATE | TEST | TEST_BYTE | INC_DEC_GROUP) {
                    return None;
                }
                if rm != FRAME_RM || rex.is_some_and(|rex| rex & REX_B != 0) {
                    return None;
                }
                cursor += match mode {
                    0 => 0,
                    1 => 1,
                    2 => 4,
                    _ => return None,
                };
            }
            match opcode {
                MOV_RM_IMMEDIATE if extension == 0 => {
                    cursor += if word && !rex.is_some_and(|rex| rex & REX_W != 0) {
                        2
                    } else {
                        4
                    }
                }
                MOV_RM_IMMEDIATE => return None,
                IMMEDIATE_GROUP
                    if matches!(extension, 0 | 5)
                        || (extended && matches!(extension, 4 | 6 | 7)) =>
                {
                    cursor += 4
                }
                SHORT_IMMEDIATE_GROUP
                    if matches!(extension, 0 | 5)
                        || (extended && matches!(extension, 4 | 6 | 7)) =>
                {
                    cursor += 1
                }
                IMMEDIATE_GROUP | SHORT_IMMEDIATE_GROUP => return None,
                IMUL_IMMEDIATE => cursor += 4,
                INC_DEC_GROUP if extension == 0 => {}
                INC_DEC_GROUP => return None,
                SHIFT_IMMEDIATE_GROUP if matches!(extension, 1 | 4 | 5 | 7) => cursor += 1,
                SHIFT_IMMEDIATE_GROUP => return None,
                UNARY_GROUP if extension == 2 || (extension == 3 && mode == 3) => {}
                UNARY_GROUP => return None,
                _ => {}
            }
        }
        if cursor > code.len() {
            return None;
        }
        ends.push(cursor);
    }
    Some(ends)
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
