use super::*;
use crate::process::MAX_PROCESS_ID;
use stela_compiler::{GuestAddress, GuestState, block::TrapKind};

const TEST_PC: u64 = 0x1000;
const SVC_IMMEDIATE: u16 = 0x80;
const CARRY: u32 = 0x20000000;
const NZCV_SHIFT: u32 = 28;
const NZCV_COMBINATIONS: u32 = 16;

fn trap() -> SynchronousTrap {
    SynchronousTrap {
        kind: TrapKind::SupervisorCall,
        immediate: SVC_IMMEDIATE,
        instruction_pc: GuestAddress(TEST_PC),
        exception_return_pc: GuestAddress(TEST_PC + 4),
    }
}

fn state(indirect: bool, flags: u32) -> ThreadState {
    let mut registers = GuestState {
        x: std::array::from_fn(|index| 0xdeadc0de12340000 + index as u64),
        sp: 0xfeed0000,
        nzcv: flags << NZCV_SHIFT,
        reserved: 0xa5a5,
        v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
        fpcr: 17,
        fpsr: 29,
    };
    registers.x[super::super::SYSCALL_SELECTOR_REGISTER] = if indirect {
        0
    } else {
        u64::from(SYSCALL_NUMBER)
    };
    if indirect {
        registers.x[0] = u64::from(SYSCALL_NUMBER);
    }
    ThreadState {
        registers,
        pc: trap().instruction_pc,
    }
}

#[test]
fn direct_and_indirect_queries_preserve_complete_state_for_all_flags() {
    for pid in [1, MAX_PROCESS_ID] {
        let process = Context::new(1, pid).unwrap();
        for indirect in [false, true] {
            for flags in 0..NZCV_COMBINATIONS {
                let mut state = state(indirect, flags);
                let mut expected = state.clone();
                expected.pc = trap().exception_return_pc;
                expected.registers.x[0] = u64::from(pid);
                expected.registers.x[1] = 0;
                expected.registers.nzcv &= !CARRY;
                assert!(handles(&state, &trap()));
                let event = service(&mut state, &trap(), &process);
                assert!(event.declined.is_none());
                assert!(event.request.unwrap().arguments().is_empty());
                assert_eq!(
                    event.completion,
                    Some(BsdCompletion::Success { values: [pid, 0] })
                );
                assert_eq!(state.pc, expected.pc);
                assert_eq!(state.registers, expected.registers);
            }
        }
    }
}

#[test]
fn other_calls_and_invalid_traps_preserve_the_pending_state() {
    let process = Context::new(1, 1).unwrap();
    for number in [SYSCALL_NUMBER - 1, SYSCALL_NUMBER + 1] {
        let mut state = state(false, 15);
        state.registers.x[super::super::SYSCALL_SELECTOR_REGISTER] = u64::from(number);
        let before = state.clone();
        assert!(!handles(&state, &trap()));
        let event = service(&mut state, &trap(), &process);
        assert!(event.completion.is_none() && event.declined.is_some());
        assert_eq!(state.pc, before.pc);
        assert_eq!(state.registers, before.registers);
    }
    for mutation in 0..4 {
        let mut state = state(false, 15);
        let before = state.clone();
        let mut bad = trap();
        match mutation {
            0 => bad.immediate += 1,
            1 => bad.instruction_pc.0 += 4,
            2 => bad.exception_return_pc.0 += 4,
            _ => bad.kind = TrapKind::SoftwareBreakpoint,
        }
        let event = service(&mut state, &bad, &process);
        assert!(event.completion.is_none() && event.declined.is_some());
        assert_eq!(state.pc, before.pc);
        assert_eq!(state.registers, before.registers);
    }
}
