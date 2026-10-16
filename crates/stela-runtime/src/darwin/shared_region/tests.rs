use super::*;
use stela_compiler::{GuestAddress, GuestState, block::TrapKind};

const NZCV_SHIFT: u32 = 28;
const NZCV_COMBINATIONS: u32 = 16;
const CARRY: u32 = 1 << 29;
const SVC_IMMEDIATE: u16 = 0x80;
const INSTRUCTION_BYTES: u64 = 4;
const TEST_PC: u64 = 0x1000;

fn trap() -> SynchronousTrap {
    SynchronousTrap {
        kind: TrapKind::SupervisorCall,
        immediate: SVC_IMMEDIATE,
        instruction_pc: GuestAddress(TEST_PC),
        exception_return_pc: GuestAddress(TEST_PC + INSTRUCTION_BYTES),
    }
}

fn state(indirect: bool, address: u64, flags: u32) -> ThreadState {
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
    registers.x[usize::from(indirect)] = address;
    ThreadState {
        registers,
        pc: trap().instruction_pc,
    }
}

#[test]
fn absence_returns_einval_without_dereferencing_any_destination() {
    for indirect in [false, true] {
        for flags in 0..NZCV_COMBINATIONS {
            // NULL is not a successful detach when the task has no region.
            // These invalid numeric destinations must never be accessed.
            for address in [0, 1, 0x1234, u64::MAX - 1, u64::from(u32::MAX)] {
                let mut state = state(indirect, address, flags);
                let mut expected = state.clone();
                expected.registers.x[0] = u64::from(DARWIN_EINVAL);
                expected.registers.x[1] = 0;
                expected.registers.nzcv |= CARRY;
                expected.pc = trap().exception_return_pc;
                assert!(handles(&state, &trap()));
                let event = service_absent(&mut state, &trap());
                assert_eq!(event.request.unwrap().arguments(), [address]);
                assert_eq!(
                    event.completion,
                    Some(BsdCompletion::Error {
                        errno: DARWIN_EINVAL
                    })
                );
                assert!(event.declined.is_none());
                assert_eq!(state.pc, expected.pc);
                assert_eq!(state.registers, expected.registers);
            }
        }
    }
}

#[test]
fn map_with_linking_command_remains_pending() {
    for indirect in [false, true] {
        for flags in 0..NZCV_COMBINATIONS {
            let mut state = state(indirect, DYLD_VM_END_MWL, flags);
            let before = state.clone();
            let event = service_absent(&mut state, &trap());
            assert_eq!(event.request.unwrap().arguments(), [DYLD_VM_END_MWL]);
            assert!(event.completion.is_none());
            assert!(event.declined.unwrap().contains("map_with_linking"));
            assert_eq!(state.pc, before.pc);
            assert_eq!(state.registers, before.registers);
        }
    }
}

#[test]
fn other_services_and_invalid_traps_preserve_state() {
    for number in [1, SYSCALL_NUMBER - 1, SYSCALL_NUMBER + 1] {
        let mut state = state(false, 1, 0);
        state.registers.x[super::super::SYSCALL_SELECTOR_REGISTER] = u64::from(number);
        let before = state.clone();
        assert!(!handles(&state, &trap()));
        let event = service_absent(&mut state, &trap());
        assert!(event.completion.is_none() && event.declined.is_some());
        assert_eq!(state.pc, before.pc);
        assert_eq!(state.registers, before.registers);
    }
    let mut state = state(false, 1, 0);
    let before = state.clone();
    let mut invalid = trap();
    invalid.exception_return_pc.0 += INSTRUCTION_BYTES;
    let event = service_absent(&mut state, &invalid);
    assert!(event.request.is_none());
    assert!(event.completion.is_none() && event.declined.is_some());
    assert_eq!(state.pc, before.pc);
    assert_eq!(state.registers, before.registers);
}
