//! Block control transfers: every branch returns to the dispatcher.
use alloc::vec;
use alloc::vec::Vec;
pub(crate) mod checked_memory;
pub(crate) mod el1_m0;
pub(crate) use super::region::ResidentLoopPlan;

use crate::{
    GuestAddress, NativeBlock,
    aarch64::{Instruction, Operation, Register, Width},
    block::{ExitKind, Terminator},
};

fn exit_kind(code: &mut Vec<u8>, kind: ExitKind) {
    code.push(0xba); // mov edx,kind: zero-extends to the ABI's u64
    code.extend((kind as u32).to_le_bytes());
    code.push(0xc3);
}

pub(super) fn direct_exit(code: &mut Vec<u8>, target: GuestAddress, kind: ExitKind) {
    super::immediate(code, target.0);
    exit_kind(code, kind);
}

fn conditional_exit(
    code: &mut Vec<u8>,
    opcode: Option<u8>,
    target: GuestAddress,
    fallthrough: GuestAddress,
) {
    if let Some(opcode) = opcode {
        code.extend([0x0f, opcode]);
        let fixup = code.len();
        code.extend([0; 4]);
        direct_exit(code, fallthrough, ExitKind::Fallthrough);
        // The taken branch skips the complete fallthrough exit. Both paths
        // leave saved NZCV untouched regardless of host predicate evaluation.
        let relative = (code.len() - fixup - 4) as i32;
        code[fixup..fixup + 4].copy_from_slice(&relative.to_le_bytes());
    }
    direct_exit(code, target, ExitKind::Direct);
}

#[cfg(test)]
fn emit(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
) -> NativeBlock {
    emit_for_target(
        instructions,
        terminal,
        fallthrough,
        crate::TargetCpu::Baseline,
    )
}

pub(crate) fn emit_ordinary_for_target(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
) -> NativeBlock {
    emit_selected(instructions, terminal, fallthrough, target, true)
}

/// Every artifact in this profile accepts the same invocation-local budget ABI.
pub(crate) fn emit_resident_fallback_for_target(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
) -> NativeBlock {
    let base = instructions
        .first()
        .map(|instruction| instruction.pc)
        .or_else(|| terminal.map(|(pc, _)| *pc))
        .unwrap_or(fallthrough);
    let native = emit_ordinary_for_target(instructions, terminal, fallthrough, target);
    super::region::prefix_with_budget(native, base)
}

pub(crate) fn emit_for_target(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
) -> NativeBlock {
    emit_selected(instructions, terminal, fallthrough, target, false)
}

fn emit_selected(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
    optimize_regions: bool,
) -> NativeBlock {
    let mut block = NativeBlock {
        x86_64_code: vec![],
        source_map: vec![],
    };
    let code = &mut block.x86_64_code;
    let mut fixups = vec![];
    let mut cursor = 0;
    while cursor < instructions.len() {
        // Build the new candidate privately. Rejection leaves both cursor and
        // output untouched, so the legacy clean-load chunk partition is exact.
        if optimize_regions
            && let Ok(Some(region)) = super::region::emit_allocated_prefix(&instructions[cursor..])
        {
            let count = region.consumed_instructions;
            let mut baseline = vec![];
            let mut candidate_fixups = vec![];
            for instruction in &instructions[cursor..cursor + count] {
                super::emit_instruction(&mut baseline, instruction, &mut candidate_fixups, target);
            }
            if candidate_fixups.is_empty() && super::region::admits_allocated(&region, &baseline) {
                let offset = code.len();
                block
                    .source_map
                    .extend(region.source_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.extend(region.code);
                cursor += count;
                continue;
            }
        }
        if optimize_regions
            && let Ok(region) = super::region::emit_clean_load_prefix(&instructions[cursor..])
            && region.consumed_instructions != 0
        {
            let count = region.consumed_instructions;
            let mut baseline_code = vec![];
            let mut baseline_map = vec![];
            let mut baseline_fixups = vec![];
            for instruction in &instructions[cursor..cursor + count] {
                baseline_map.push((instruction.pc, baseline_code.len()));
                super::emit_instruction(
                    &mut baseline_code,
                    instruction,
                    &mut baseline_fixups,
                    target,
                );
            }
            debug_assert!(baseline_fixups.is_empty());
            let offset = code.len();
            if super::region::admits_ordinary(&region, &baseline_code) {
                block
                    .source_map
                    .extend(region.source_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.extend(region.code);
            } else {
                // Reject the complete eligible chunk. Rescanning its suffix
                // could bypass the measured cost gate with a different shape.
                block
                    .source_map
                    .extend(baseline_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.extend(baseline_code);
            }
            // Each region wrote back the full register frame, so what follows
            // sees the ordinary direct-RAM ABI.
            cursor += count;
            continue;
        }
        let instruction = &instructions[cursor];
        block.source_map.push((instruction.pc, code.len()));
        if let Operation::FloatingPoint(operand) = &instruction.operation {
            super::simd::emit_numerical(code, operand, instruction.pc, target);
        } else {
            super::emit_instruction(code, instruction, &mut fixups, target);
        }
        cursor += 1;
    }
    debug_assert!(
        fixups.is_empty(),
        "ordinary instruction prefix cannot branch"
    );
    emit_terminal(code, &mut block.source_map, terminal, fallthrough, target);
    block
}
fn emit_terminal(
    code: &mut Vec<u8>,
    source_map: &mut Vec<(GuestAddress, usize)>,
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
) {
    if let Some((pc, terminal)) = terminal {
        source_map.push((*pc, code.len()));
        match terminal {
            Terminator::FloatingPoint(operand) => {
                super::simd::emit_numerical(code, operand, *pc, target);
            }
            Terminator::Clock(request) => {
                // MRS results and ISB come from the runtime clock service.
                direct_exit(code, request.instruction_pc, ExitKind::Clock);
            }
            Terminator::ThreadRegister(request) => {
                direct_exit(code, request.instruction_pc, ExitKind::ThreadRegister);
            }
            Terminator::PointerAuthentication(request) => {
                // Return to the checked runtime helper with unchanged guest
                // state at this instruction. Never embed keys/helper pointers.
                direct_exit(
                    code,
                    request.instruction_pc,
                    ExitKind::PointerAuthentication,
                );
            }
            Terminator::System(request) => {
                direct_exit(code, request.instruction_pc, ExitKind::System);
            }
            Terminator::Trap(trap) => {
                // SVC and BRK stop at the trapping instruction; the runtime
                // handles the trap.
                direct_exit(code, trap.instruction_pc, ExitKind::Trap);
            }
            Terminator::DirectCall(target) => {
                super::immediate(code, fallthrough.0);
                super::store(code, Register::X(30));
                direct_exit(code, *target, ExitKind::Call);
            }
            Terminator::Register { source, kind } => {
                super::load(code, *source);
                if *kind == ExitKind::Call {
                    // Capture BLR X30's target before LR is overwritten.
                    code.extend([0x48, 0x89, 0xc1]); // mov rcx,rax
                    super::immediate(code, fallthrough.0);
                    super::store(code, Register::X(30));
                    code.extend([0x48, 0x89, 0xc8]); // mov rax,rcx
                }
                exit_kind(code, *kind);
            }
            Terminator::Branch(operation) => match *operation {
                Operation::Branch { target } => direct_exit(code, target, ExitKind::Direct),
                Operation::BranchCondition { target, condition } => {
                    let opcode = super::condition(code, condition);
                    conditional_exit(code, opcode, target, fallthrough);
                }
                Operation::BranchZero {
                    target,
                    source,
                    width,
                    nonzero,
                } => {
                    super::load(code, source);
                    if width == Width::X64 {
                        code.push(0x48);
                    }
                    code.extend([0x85, 0xc0]); // test (e/r)ax,(e/r)ax
                    conditional_exit(
                        code,
                        Some(if nonzero { 0x85 } else { 0x84 }),
                        target,
                        fallthrough,
                    );
                }
                Operation::BranchBit {
                    target,
                    source,
                    bit,
                    nonzero,
                } => {
                    super::load(code, source);
                    code.extend([0x48, 0x0f, 0xba, 0xe0, bit]); // bt rax,bit
                    conditional_exit(
                        code,
                        Some(if nonzero { 0x82 } else { 0x83 }),
                        target,
                        fallthrough,
                    );
                }
                _ => unreachable!("block decoder restricts branch terminators"),
            },
        }
    } else {
        direct_exit(code, fallthrough, ExitKind::Fallthrough);
    }
}

#[cfg(test)]
mod tests;
