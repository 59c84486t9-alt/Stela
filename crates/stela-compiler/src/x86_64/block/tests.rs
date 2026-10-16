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
