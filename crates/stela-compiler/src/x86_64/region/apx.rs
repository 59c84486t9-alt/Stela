//! APX register-only spans with all 31 guest integer registers resident.
//! Frame and invocation pointers live on the private stack. Guest memory,
//! helpers and flag producers end the span before any guest effect is emitted.
//! This private candidate is test-only until all asynchronous entry, settlement,
//! IRQ and context boundaries preserve the complete host integer register bank.
use super::{AllocationStats, MAX_INSTRUCTIONS, OptimizedRegion, RegionError};
use crate::aarch64::{Instruction, Logical, Operation, Register, Shift, WideMove, Width};
use crate::x86_64::asm::apx::AluOperands;
use crate::x86_64::asm::{Alu, Asm, Code, Gpr, Mem, ShiftOp, Size, Unary};
use alloc::vec::Vec;

const FRAME: i32 = 0;
const CONTEXT: i32 = 8;
const TEMPORARY: i32 = 16;
const STACK_BYTES: usize = 32;
// Conservatively preserve R30/R31 as well as SysV's legacy callee-saved bank.
const SAVED: [Gpr; 8] = [
    Gpr::Rbx,
    Gpr::Rbp,
    Gpr::R12,
    Gpr::R13,
    Gpr::R14,
    Gpr::R15,
    Gpr::R30,
    Gpr::R31,
];

fn resident(guest: u8) -> Gpr {
    assert!(guest < 31);
    Gpr::from_encoding(if guest < 4 { guest } else { guest + 1 })
}
fn register(register: Register) -> bool {
    matches!(register, Register::X(0..=30) | Register::Zero)
}
fn width_size(width: Width) -> Size {
    Size::of(width == Width::X64)
}
fn valid(operation: &Operation) -> bool {
    match *operation {
        Operation::Nop => true,
        Operation::PcRelative(operand) => register(operand.destination),
        Operation::MoveWide {
            width,
            destination,
            shift,
            ..
        } => register(destination) && shift % 16 == 0 && shift < width_size(width).bits() as u8,
        Operation::AddSub {
            flags: false,
            destination,
            source,
            immediate,
            ..
        } => register(destination) && register(source) && immediate <= 0x00ff_f000,
        Operation::AddSubRegister {
            width,
            flags: false,
            destination,
            left,
            right,
            shift,
            amount,
            ..
        } => {
            register(destination)
                && register(left)
                && register(right)
                && shift != Shift::Ror
                && amount < width_size(width).bits() as u8
        }
        Operation::LogicalRegister {
            width,
            flags: false,
            destination,
            left,
            right,
            amount,
            ..
        } => {
            register(destination)
                && register(left)
                && register(right)
                && amount < width_size(width).bits() as u8
        }
        Operation::LogicalImmediate {
            flags: false,
            destination,
            source,
            ..
        } => register(destination) && register(source),
        _ => false,
    }
}
fn stack(offset: i32) -> Mem {
    Mem::base(Gpr::Rsp, offset)
}
fn value(register: Register) -> Option<Gpr> {
    match register {
        Register::X(guest) => Some(resident(guest)),
        Register::Zero => None,
        Register::Sp => unreachable!("SP ends APX register-only spans"),
    }
}
fn load(a: &mut Asm, size: Size, destination: Gpr, source: Register) {
    if let Some(source) = value(source) {
        a.mov(size, destination, source);
    } else {
        a.mov_imm32(destination, 0);
    }
}
fn immediate(a: &mut Asm, size: Size, destination: Gpr, bits: u64) {
    if size == Size::Dword {
        a.mov_imm32(destination, bits as u32);
    } else {
        a.mov_imm64(destination, bits);
    }
}
fn temporary(a: &mut Asm, excluded: &[Gpr], emit: impl FnOnce(&mut Asm, Gpr)) {
    let borrowed = (0..31)
        .map(resident)
        .find(|register| !excluded.contains(register))
        .unwrap();
    a.mov_store(Size::Qword, stack(TEMPORARY), borrowed);
    emit(a, borrowed);
    a.mov_load(Size::Qword, borrowed, stack(TEMPORARY));
}
fn logical(kind: Logical) -> Alu {
    match kind {
        Logical::And => Alu::And,
        Logical::Or => Alu::Or,
        Logical::Xor => Alu::Xor,
    }
}
fn apply_immediate(a: &mut Asm, op: Alu, size: Size, destination: Gpr, bits: u64) {
    let bits = if size == Size::Dword {
        bits & 0xffff_ffff
    } else {
        bits
    };
    if size == Size::Dword || (bits as i64) == (bits as i32 as i64) {
        a.alu_imm(op, size, destination, bits as i32);
    } else {
        temporary(a, &[destination], |a, borrowed| {
            immediate(a, size, borrowed, bits);
            a.alu(op, size, destination, borrowed);
        });
    }
}
struct Binary {
    size: Size,
    op: Alu,
    destination: Gpr,
    left: Register,
    right: Register,
    shift: Shift,
    amount: u8,
    invert: bool,
    ndd: bool,
}
fn binary(a: &mut Asm, operation: Binary) {
    let Binary {
        size,
        op,
        destination,
        left,
        right,
        shift,
        amount,
        invert,
        ndd,
    } = operation;
    if ndd
        && amount == 0
        && !invert
        && let (Some(left), Some(right)) = (value(left), value(right))
    {
        a.apx_alu(AluOperands {
            operation: op,
            size,
            destination,
            left,
            right,
            preserve_flags: true,
        });
        return;
    }
    let direct = value(right);
    if amount == 0 && !invert && direct != Some(destination) {
        load(a, size, destination, left);
        if let Some(right) = direct {
            a.alu(op, size, destination, right);
        } else {
            a.alu_imm(op, size, destination, 0);
        }
        return;
    }
    let excluded = [Some(destination), value(left), direct];
    let excluded: Vec<_> = excluded.into_iter().flatten().collect();
    temporary(a, &excluded, |a, borrowed| {
        load(a, size, borrowed, right);
        if amount != 0 {
            let shift = match shift {
                Shift::Lsl => ShiftOp::Shl,
                Shift::Lsr => ShiftOp::Shr,
                Shift::Asr => ShiftOp::Sar,
                Shift::Ror => ShiftOp::Ror,
            };
            a.shift_imm(shift, size, borrowed, amount);
        }
        if invert {
            a.unary(Unary::Not, size, borrowed);
        }
        load(a, size, destination, left);
        a.alu(op, size, destination, borrowed);
    });
}
fn instruction(a: &mut Asm, operation: &Operation, ndd: bool) {
    match *operation {
        Operation::Nop => a.nop(),
        Operation::PcRelative(operand) => {
            if let Some(destination) = value(operand.destination) {
                a.mov_imm64(destination, operand.address);
            }
        }
        Operation::MoveWide {
            width,
            kind,
            destination,
            immediate: bits,
            shift,
        } => {
            if let Some(destination) = value(destination) {
                let size = width_size(width);
                let bits = u64::from(bits) << shift;
                match kind {
                    WideMove::Zero => immediate(a, size, destination, bits),
                    WideMove::Not => immediate(a, size, destination, !bits),
                    WideMove::Keep => {
                        apply_immediate(a, Alu::And, size, destination, !(0xffff_u64 << shift));
                        apply_immediate(a, Alu::Or, size, destination, bits);
                    }
                }
            }
        }
        Operation::AddSub {
            width,
            subtract,
            destination,
            source,
            immediate,
            ..
        } => {
            if let Some(destination) = value(destination) {
                let size = width_size(width);
                load(a, size, destination, source);
                a.alu_imm(
                    if subtract { Alu::Sub } else { Alu::Add },
                    size,
                    destination,
                    immediate as i32,
                );
            }
        }
        Operation::LogicalImmediate {
            width,
            kind,
            destination,
            source,
            immediate,
            ..
        } => {
            if let Some(destination) = value(destination) {
                let size = width_size(width);
                load(a, size, destination, source);
                apply_immediate(a, logical(kind), size, destination, immediate);
            }
        }
        Operation::AddSubRegister {
            width,
            subtract,
            destination,
            left,
            right,
            shift,
            amount,
            ..
        } => {
            if let Some(destination) = value(destination) {
                binary(
                    a,
                    Binary {
                        size: width_size(width),
                        op: if subtract { Alu::Sub } else { Alu::Add },
                        destination,
                        left,
                        right,
                        shift,
                        amount,
                        invert: false,
                        ndd,
                    },
                );
            }
        }
        Operation::LogicalRegister {
            width,
            kind,
            invert,
            destination,
            left,
            right,
            shift,
            amount,
            ..
        } => {
            if let Some(destination) = value(destination) {
                binary(
                    a,
                    Binary {
                        size: width_size(width),
                        op: logical(kind),
                        destination,
                        left,
                        right,
                        shift,
                        amount,
                        invert,
                        ndd,
                    },
                );
            }
        }
        _ => unreachable!("APX admission selected a register-only operation"),
    }
}

fn prefix_plan(
    instructions: &[Instruction],
    target: crate::TargetCpu,
) -> Result<Option<(usize, bool)>, RegionError> {
    prefix_plan_with(instructions, target, valid)
}

fn prefix_plan_with(
    instructions: &[Instruction],
    target: crate::TargetCpu,
    accepted: impl Fn(&Operation) -> bool,
) -> Result<Option<(usize, bool)>, RegionError> {
    if !target.supports(crate::TargetCpu::Apx) || target.data_independent_timing() {
        return Ok(None);
    }
    let ndd = target.supports(crate::TargetCpu::Apx.with_apx_ndd());
    if instructions.len() > MAX_INSTRUCTIONS {
        return Err(RegionError::TooLong);
    }
    let Some(entry) = instructions.first().map(|instruction| instruction.pc) else {
        return Ok(None);
    };
    if entry.0 & 3 != 0 {
        return Err(RegionError::Misaligned);
    }
    let count = instructions
        .iter()
        .take_while(|instruction| accepted(&instruction.operation))
        .count();
    if count < 2 {
        return Ok(None);
    }
    for (index, instruction) in instructions.iter().take(count + 1).enumerate() {
        let expected = entry
            .0
            .checked_add(index as u64 * 4)
            .ok_or(RegionError::AddressOverflow)?;
        if instruction.pc.0 != expected {
            return Err(RegionError::NonContiguous);
        }
    }
    entry
        .0
        .checked_add(count as u64 * 4)
        .ok_or(RegionError::AddressOverflow)?;
    Ok(Some((count, ndd)))
}

pub(in crate::x86_64) fn prefix(
    instructions: &[Instruction],
    target: crate::TargetCpu,
) -> Result<Option<OptimizedRegion>, RegionError> {
    let Some((count, ndd)) = prefix_plan(instructions, target)? else {
        return Ok(None);
    };
    let mut code = Code::new();
    let mut a = code.asm();
    for saved in SAVED {
        a.push(saved);
    }
    a.reserve_stack(STACK_BYTES);
    a.mov_store(Size::Qword, stack(FRAME), Gpr::Rdi);
    a.mov_store(Size::Qword, stack(CONTEXT), Gpr::Rsi);
    for guest in (0..31).filter(|guest| resident(*guest) != Gpr::Rdi) {
        a.mov_load(
            Size::Qword,
            resident(guest),
            Mem::base(Gpr::Rdi, i32::from(guest) * 8),
        );
    }
    a.mov_load(Size::Qword, Gpr::Rdi, Mem::base(Gpr::Rdi, 6 * 8));
    let mut source_map = Vec::with_capacity(count);
    for input in instructions.iter().take(count) {
        source_map.push((input.pc, a.len()));
        instruction(&mut a, &input.operation, ndd);
    }
    a.mov_store(Size::Qword, stack(TEMPORARY), Gpr::Rax);
    a.mov_load(Size::Qword, Gpr::Rax, stack(FRAME));
    for guest in 1..31 {
        a.mov_store(
            Size::Qword,
            Mem::base(Gpr::Rax, i32::from(guest) * 8),
            resident(guest),
        );
    }
    a.mov_load(Size::Qword, Gpr::Rdx, stack(TEMPORARY));
    a.mov_store(Size::Qword, Mem::base(Gpr::Rax, 0), Gpr::Rdx);
    a.mov(Size::Qword, Gpr::Rdi, Gpr::Rax);
    a.mov_load(Size::Qword, Gpr::Rsi, stack(CONTEXT));
    a.release_stack(STACK_BYTES);
    for saved in SAVED.into_iter().rev() {
        a.pop(saved);
    }
    let native_instructions = code.instructions();
    Ok(Some(OptimizedRegion {
        code,
        consumed_instructions: count,
        source_map,
        fault_recovery: Vec::new(),
        stats: AllocationStats {
            state_loads: 31,
            exit_stores: 31,
            peak_resident: 31,
            native_instructions,
            callee_saves: SAVED.len(),
            callee_restores: SAVED.len(),
            ..AllocationStats::default()
        },
    }))
}

#[cfg(test)]
mod tests;
