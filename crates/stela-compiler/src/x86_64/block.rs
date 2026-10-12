//! Guest control transfers return to the native dispatcher with canonical state.
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

fn direct_exit(code: &mut Vec<u8>, target: GuestAddress, kind: ExitKind) {
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

pub(crate) fn emit(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
) -> NativeBlock {
    let mut block = NativeBlock {
        x86_64_code: vec![],
        source_map: vec![],
    };
    let code = &mut block.x86_64_code;
    let mut fixups = vec![];
    for instruction in instructions {
        block.source_map.push((instruction.pc, code.len()));
        super::emit_instruction(code, instruction, &mut fixups);
    }
    debug_assert!(
        fixups.is_empty(),
        "ordinary instruction prefix cannot branch"
    );
    if let Some((pc, terminal)) = terminal {
        block.source_map.push((*pc, code.len()));
        match terminal {
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
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{SynchronousTrap, TrapKind};

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
