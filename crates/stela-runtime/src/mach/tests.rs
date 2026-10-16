use super::*;
use stela_compiler::{GuestAddress, GuestState, block::TrapKind};
#[test]
fn borrowed_register_completion_preserves_the_pc_owner() {
    let trap = SynchronousTrap {
        kind: TrapKind::SupervisorCall,
        immediate: 0x80,
        instruction_pc: GuestAddress(0x1000),
        exception_return_pc: GuestAddress(0x1004),
    };
    for flags in 0..16 {
        for value in [0, i32::MAX, i32::MIN, -1] {
            let mut state = ThreadState {
                pc: trap.instruction_pc,
                registers: GuestState {
                    nzcv: flags << 28,
                    ..GuestState::default()
                },
            };
            state.registers.x[SYSCALL_SELECTOR_REGISTER] = 0xfeed_face_ffff_ffe4;
            let mut borrowed = state.registers.clone();
            let pending = PendingCall::from_registers(state.pc, &borrowed, &trap, 0).unwrap();
            let legacy = PendingCall::from_trap(&state, &trap, 0).unwrap();
            assert_eq!(pending.request(), legacy.request());
            let continuation = pending.complete_registers(&mut borrowed, value).unwrap();
            assert_eq!(state.pc, trap.instruction_pc);
            legacy.complete(&mut state, value).unwrap();
            assert_eq!(continuation, state.pc);
            assert_eq!(borrowed, state.registers);
        }
    }
    let mut registers = GuestState::default();
    registers.x[SYSCALL_SELECTOR_REGISTER] = (-28i64) as u64;
    let pending = PendingCall::from_registers(trap.instruction_pc, &registers, &trap, 0).unwrap();
    registers.x[1] = 1;
    let before = registers.clone();
    assert!(pending.complete_registers(&mut registers, 7).is_err());
    assert_eq!(registers, before);
}
#[test]
fn mach_capture_and_completion_preserve_carry_and_other_state() {
    let trap = SynchronousTrap {
        kind: TrapKind::SupervisorCall,
        immediate: 0x80,
        instruction_pc: GuestAddress(0x1000),
        exception_return_pc: GuestAddress(0x1004),
    };
    for flags in 0..16 {
        for value in [0, 1, i32::MAX, i32::MIN, -1] {
            let mut state = ThreadState {
                pc: trap.instruction_pc,
                registers: GuestState {
                    x: std::array::from_fn(|i| 0xdeadc0de12340000 + i as u64),
                    nzcv: flags << 28,
                    v: [[123, 456]; 32],
                    fpcr: 17,
                    fpsr: 29,
                    ..GuestState::default()
                },
            };
            state.registers.x[16] = 0xfeedfaceffffffe4; // signed32 selector -28
            let pending = PendingCall::from_trap(&state, &trap, 9).unwrap();
            assert_eq!(
                pending.request(),
                &Request {
                    number: 28,
                    arguments: state.registers.x[..9].to_vec()
                }
            );
            let mut expected = state.clone();
            expected.pc = trap.exception_return_pc;
            expected.registers.x[0] = value as i64 as u64;
            pending.complete(&mut state, value).unwrap();
            assert_eq!(state.pc, expected.pc);
            assert_eq!(state.registers, expected.registers);
            let pending = PendingCall::from_trap(
                &ThreadState {
                    pc: trap.instruction_pc,
                    ..state.clone()
                },
                &trap,
                0,
            )
            .unwrap();
            let before = state.clone();
            assert!(pending.complete(&mut state, 0).is_err());
            assert_eq!(state.pc, before.pc);
            assert_eq!(state.registers, before.registers);
        }
    }
    for selector in [
        0,
        28,
        0x80000000,
        (-3i32) as u32 as u64,
        (-4i32) as u32 as u64,
    ] {
        let mut state = ThreadState {
            pc: trap.instruction_pc,
            registers: GuestState::default(),
        };
        state.registers.x[16] = selector;
        assert!(PendingCall::from_trap(&state, &trap, 0).is_err());
    }
}
