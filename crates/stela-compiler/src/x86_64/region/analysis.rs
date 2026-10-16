//! Bounded architectural liveness. Every final GPR is live at the exit.
use super::recovery::GPR_SLOTS;
use super::{BYTE_LOAD_BYTES, WORD_LOAD_BYTES};
use crate::aarch64::integer_math::Kind as IntegerMath;
use crate::aarch64::{
    AddressMode, Instruction, MemoryTransfer, Operation, Register, Shift, WideMove, Width,
};

pub const MAX_INSTRUCTIONS: usize = 256;
const PAIR_OFFSET_BITS: u32 = 7;
const PAIR_OFFSET_HALF_RANGE: i32 = 1 << (PAIR_OFFSET_BITS - 1);
#[cfg(test)]
pub const ALL_GPRS: u32 = u32::MAX;

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

/// Only existing ordinary unsigned byte/word loads with an X-register base.
/// All other memory addressing/transfer forms remain canonical boundaries.
pub fn clean_load_effects(operation: &Operation) -> Option<Effects> {
    if let Operation::MemoryPair {
        transfer:
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
        bytes: WORD_LOAD_BYTES,
        data,
        base: Register::X(base),
        displacement,
        mode: AddressMode::Offset,
    } = *operation
        && base < 31
        && displacement % i32::from(WORD_LOAD_BYTES) == 0
        && (-PAIR_OFFSET_HALF_RANGE..PAIR_OFFSET_HALF_RANGE)
            .contains(&(displacement / i32::from(WORD_LOAD_BYTES)))
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
        transfer:
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
        bytes: BYTE_LOAD_BYTES | WORD_LOAD_BYTES,
        data,
        base: Register::X(base),
        mode: AddressMode::Offset,
        ..
    } = *operation
        && base < 31
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

pub fn prefix_clean_load_effects(instructions: &[Instruction]) -> Vec<Effects> {
    instructions
        .iter()
        .map_while(|instruction| clean_load_effects(&instruction.operation))
        .collect()
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Liveness {
    pub live_before: Vec<u32>,
    pub live_exit: u32,
}

#[cfg(test)]
impl Liveness {
    pub fn compute(effects: &[Effects]) -> Self {
        let mut live = ALL_GPRS;
        let mut live_before = vec![0; effects.len()];
        for (index, effect) in effects.iter().enumerate().rev() {
            live = (live & !effect.writes) | effect.reads;
            live_before[index] = live;
        }
        Self {
            live_before,
            live_exit: ALL_GPRS,
        }
    }
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
    const PUSH_FLAGS: u8 = 0x9c;
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
    const LEA_RDX_RAX_DISP32: u8 = 0x90;
    const LEA_RDX_RDX_DISP8: u8 = 0x52;
    const TWO_BYTE_OPCODE: u8 = 0x0f;
    const MOVZX_BYTE: u8 = 0xb6;
    const IMUL: u8 = 0xaf;
    const SHRD_IMMEDIATE: u8 = 0xac;
    const ECX_FROM_RAX_MEMORY: u8 = 0x08;
    const REX_R8_WORD: u8 = 0x44;
    const R8D_FROM_RAX_DISP8: u8 = 0x40;

    let mut cursor = 0usize;
    let mut ends = vec![];
    while cursor < code.len() {
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
        } else if extended && !word && rex.is_none() && opcode == PUSH_FLAGS {
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
            if modrm == LEA_RDX_RAX_DISP32 && rex == Some(REX_X64_LOW_REGISTERS) {
                cursor += 5;
            } else if extended && modrm == LEA_RDX_RDX_DISP8 {
                // Flag-neutral selector adjustment.
                cursor += 2;
            } else {
                return None;
            }
        } else if opcode == TWO_BYTE_OPCODE && !word {
            let second = *code.get(cursor)?;
            if second == MOVZX_BYTE && rex.is_none() {
                // Exact existing LDRB data access MOVZX ECX,byte [RAX].
                if code.get(cursor..cursor + 2)? != [MOVZX_BYTE, ECX_FROM_RAX_MEMORY] {
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
            && rex.is_none()
            && code.get(cursor).copied() == Some(ECX_FROM_RAX_MEMORY)
        {
            // Exact selected unsigned W load into ECX.
            cursor += 1;
        } else if opcode == MOV_LOAD
            && !word
            && rex == Some(REX_R8_WORD)
            && code.get(cursor..cursor + 2)? == [R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES]
        {
            // Exact second unsigned W pair load into R8D.
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

/// Every direct target and control-transfer fallthrough is a fresh region entry.
/// Guest instructions and branch fixups remain original typed operations.
#[cfg(test)]
pub fn leaf_entries(instructions: &[Instruction]) -> std::collections::BTreeSet<u64> {
    let mut entries = std::collections::BTreeSet::new();
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
