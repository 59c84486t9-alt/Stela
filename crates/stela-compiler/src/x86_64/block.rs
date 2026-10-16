//! Guest control transfers return to the native dispatcher with canonical state.
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
            // Every admitted region settled the complete canonical frame.
            // Memory, numerical helpers, baseline fallback and terminal exits
            // therefore observe the same ordinary direct-RAM ABI as before.
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
                // MRS results and ISB synchronization belong to the explicit
                // runtime clock service, not a host counter or placeholder.
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
                // The original instruction remains the stop PC for both SVC
                // and BRK. Exception-return metadata stays with the decoder;
                // neither host syscalls nor architectural exception entry run.
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
                    // Capture BLR X30's original target before overwriting LR.
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
mod tests {

    use super::*;
    use crate::block::{SynchronousTrap, TrapKind};
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn clock_exit_requests_runtime_service_without_counter_or_guest_writes() {
        use crate::block::{ClockInstruction, ClockOperation};
        for operation in [
            ClockOperation::InstructionSynchronization,
            ClockOperation::ReadVirtualCounter { destination: 0 },
            ClockOperation::ReadVirtualCounter { destination: 31 },
        ] {
            let pc = GuestAddress(0x123456789000);
            let request = ClockInstruction {
                operation,
                instruction_pc: pc,
                next_pc: GuestAddress(pc.0 + 4),
            };
            let native = emit(
                &[],
                Some(&(pc, Terminator::Clock(request))),
                request.next_pc,
            );
            let mut expected = vec![0x48, 0xb8];
            expected.extend(pc.0.to_le_bytes());
            expected.extend([0xba, 7, 0, 0, 0, 0xc3]);
            // No RDTSC, host helper address, guessed counter, destination write
            // or placeholder ISB: only the checked runtime service may complete.
            assert_eq!(native.x86_64_code, expected);
            assert_eq!(native.source_map, [(pc, 0)]);
        }
    }

    #[test]
    fn pac_helper_exit_has_no_guest_writes_or_embedded_service_address() {
        use crate::block::{PointerAuthentication, decode_pointer_authentication};
        let fixed_words = [
            0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df, 0xd503231f, 0xd503233f, 0xd503235f,
            0xd503237f, 0xd503239f, 0xd50323bf, 0xd50323df, 0xd50323ff, 0xd50320ff, 0xd65f0bff,
            0xd65f0fff, 0xdac143f1, 0xdac147f1,
        ];
        let integer_words = (0..8).flat_map(|op| {
            [
                0xdac10000 | (op << 10) | (16 << 5) | 17,
                0xdac123e0 | (op << 10) | 17,
            ]
        });
        let words: Vec<_> = fixed_words.into_iter().chain(integer_words).collect();
        assert_eq!(words.len(), 33);
        for word in words {
            let operation = decode_pointer_authentication(GuestAddress(0x1000), word)
                .unwrap()
                .unwrap()
                .operation;
            let pc = GuestAddress(0x123456789000);
            let request = PointerAuthentication {
                operation,
                instruction_pc: pc,
                next_pc: GuestAddress(pc.0 + 4),
            };
            let native = emit(
                &[],
                Some(&(pc, Terminator::PointerAuthentication(request))),
                request.next_pc,
            );
            let mut expected = vec![0x48, 0xb8];
            expected.extend(pc.0.to_le_bytes());
            expected.extend([0xba, 6, 0, 0, 0, 0xc3]);
            // Only the SysV return registers RAX/RDX are touched, including for
            // RETAB: the runtime must keep signed LR while authenticating target.
            assert_eq!(native.x86_64_code, expected);
            assert_eq!(native.source_map, [(pc, 0)]);
        }
    }

    #[test]
    fn ordinary_native_prefix_is_preserved_before_pac_boundary() {
        use crate::{
            Lifter,
            aarch64::Decoder,
            block::{PointerAuthentication, PointerAuthenticationOperation},
        };
        let base = GuestAddress(0x4000);
        let instruction = Decoder.lift(base, 0xd2800020).unwrap();
        let pc = GuestAddress(base.0 + 4);
        let ordinary = emit(core::slice::from_ref(&instruction), None, pc);
        let request = PointerAuthentication {
            operation: PointerAuthenticationOperation::SignIbSp,
            instruction_pc: pc,
            next_pc: GuestAddress(pc.0 + 4),
        };
        let native = emit(
            &[instruction],
            Some(&(pc, Terminator::PointerAuthentication(request))),
            request.next_pc,
        );
        assert_eq!(
            &native.x86_64_code[..ordinary.x86_64_code.len() - 16],
            &ordinary.x86_64_code[..ordinary.x86_64_code.len() - 16]
        );
        assert_eq!(native.source_map.len(), 2);
        assert_eq!(native.source_map[1].0, pc);
        assert_eq!(
            &native.x86_64_code[native.x86_64_code.len() - 6..],
            &[0xba, 6, 0, 0, 0, 0xc3]
        );
    }

    #[test]
    fn trap_exit_uses_instruction_pc_and_only_native_return_scratch_registers() {
        for kind in [TrapKind::SupervisorCall, TrapKind::SoftwareBreakpoint] {
            let pc = GuestAddress(0x123456789000);
            let trap = SynchronousTrap {
                kind,
                immediate: 0x80,
                instruction_pc: pc,
                exception_return_pc: if kind == TrapKind::SupervisorCall {
                    GuestAddress(pc.0 + 4)
                } else {
                    pc
                },
            };
            let native = emit(
                &[],
                Some(&(pc, Terminator::Trap(trap))),
                GuestAddress(pc.0 + 4),
            );
            let mut expected = vec![0x48, 0xb8]; // movabs rax,instruction_pc
            expected.extend(pc.0.to_le_bytes());
            expected.extend([0xba, 5, 0, 0, 0, 0xc3]); // mov edx,Trap; ret
            assert_eq!(native.x86_64_code, expected);
            assert_eq!(native.source_map, [(pc, 0)]);
        }
    }
}
