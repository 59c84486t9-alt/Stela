use super::*;
use crate::darwin::SYSCALL_SELECTOR_REGISTER;
use stela_compiler::{GuestAddress, GuestState, block::TrapKind};

const NZCV_SHIFT: u32 = 28;
const NZCV_COMBINATIONS: u32 = 16;
const CARRY: u32 = 0x20000000;
const SVC_IMMEDIATE: u16 = 0x80;

fn trap() -> SynchronousTrap {
    SynchronousTrap {
        kind: TrapKind::SupervisorCall,
        immediate: SVC_IMMEDIATE,
        instruction_pc: GuestAddress(0x1000),
        exception_return_pc: GuestAddress(0x1004),
    }
}

fn state(indirect: bool, namespace: u64, flags: u32) -> ThreadState {
    let mut registers = GuestState {
        x: std::array::from_fn(|index| 0xdeadc0de12340000 + index as u64),
        sp: 0xfeed0000,
        nzcv: flags << NZCV_SHIFT,
        reserved: 0xa5a5,
        v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
        fpcr: 17,
        fpsr: 29,
    };
    registers.x[SYSCALL_SELECTOR_REGISTER] = if indirect {
        0
    } else {
        u64::from(SYSCALL_NUMBER)
    };
    registers.x[usize::from(indirect)] = namespace;
    if indirect {
        registers.x[0] = u64::from(SYSCALL_NUMBER);
    }
    ThreadState {
        registers,
        pc: trap().instruction_pc,
    }
}

fn assert_state(actual: &ThreadState, expected: &ThreadState) {
    assert_eq!(actual.pc, expected.pc);
    assert_eq!(actual.registers, expected.registers);
}

#[test]
fn direct_and_indirect_calls_preserve_complete_state_except_bsd_error_result() {
    for indirect in [false, true] {
        for flags in 0..NZCV_COMBINATIONS {
            for namespace in [0, 1, u64::from(u32::MAX)] {
                let mut state = state(indirect, namespace, flags);
                assert!(handles(&state, &trap()));
                let errno = if namespace == 0 {
                    DARWIN_ENOTSUP
                } else {
                    DARWIN_EINVAL
                };
                let mut expected = state.clone();
                expected.pc = trap().exception_return_pc;
                expected.registers.x[0] = u64::from(errno);
                expected.registers.x[1] = 0;
                expected.registers.nzcv |= CARRY;
                let event = service(&mut state, &trap());
                let request = event.request.unwrap();
                assert_eq!(request.number, SYSCALL_NUMBER);
                assert_eq!(request.indirect, indirect);
                assert_eq!(request.prototype(), PROTOTYPE);
                assert_eq!(request.arguments(), &[namespace]);
                assert_eq!(event.completion, Some(BsdCompletion::Error { errno }));
                assert!(event.declined.is_none());
                assert_state(&state, &expected);
            }
        }
    }
}

#[test]
fn namespace_uses_only_low_uint32_and_selectors_keep_common_bsd_rules() {
    for indirect in [false, true] {
        for upper in [0, 1, 0xfeedface, u32::MAX] {
            for namespace in [0, 1, u32::MAX] {
                let argument = (u64::from(upper) << 32) | u64::from(namespace);
                let mut state = state(indirect, argument, 0);
                // Direct X16 truncates to u16 after signed32 dispatch;
                // indirect X0 supplies the low u16 syscall number.
                let selector_register = if indirect {
                    0
                } else {
                    SYSCALL_SELECTOR_REGISTER
                };
                state.registers.x[selector_register] |= u64::from(upper) << 32;
                assert!(handles(&state, &trap()));
                let event = service(&mut state, &trap());
                let errno = if namespace == 0 {
                    DARWIN_ENOTSUP
                } else {
                    DARWIN_EINVAL
                };
                assert_eq!(event.completion, Some(BsdCompletion::Error { errno }));
                assert_eq!(event.request.unwrap().arguments(), &[argument]);
                assert_eq!(state.registers.x[0], u64::from(errno));
            }
        }
    }
}

#[test]
fn unknown_services_preserve_state_and_report_explicit_decline() {
    for indirect in [false, true] {
        for number in [1, SYSCALL_NUMBER - 1, SYSCALL_NUMBER + 1, u16::MAX] {
            let mut state = state(indirect, 0, 0);
            state.registers.x[if indirect {
                0
            } else {
                SYSCALL_SELECTOR_REGISTER
            }] = u64::from(number);
            let before = state.clone();
            assert!(!handles(&state, &trap()));
            let event = service(&mut state, &trap());
            assert_eq!(event.request.unwrap().number, number);
            assert!(event.completion.is_none());
            assert!(event.declined.is_some());
            assert_state(&state, &before);
        }
    }
}

#[test]
fn invalid_traps_and_stale_pc_preserve_state() {
    let mutations: [fn(&mut SynchronousTrap); 6] = [
        |trap| trap.kind = TrapKind::SoftwareBreakpoint,
        |trap| trap.immediate ^= 1,
        |trap| trap.instruction_pc.0 += 4,
        |trap| trap.instruction_pc.0 += 1,
        |trap| trap.exception_return_pc.0 -= 4,
        |trap| trap.exception_return_pc.0 += 4,
    ];
    for mutate in mutations {
        let mut state = state(false, 0, 0);
        let before = state.clone();
        let mut trap = trap();
        mutate(&mut trap);
        assert!(!handles(&state, &trap));
        let event = service(&mut state, &trap);
        assert!(event.request.is_none());
        assert!(event.completion.is_none());
        assert!(event.declined.is_some());
        assert_state(&state, &before);
    }
    let mut state = state(false, 0, 0);
    state.registers.nzcv |= 1;
    let before = state.clone();
    assert!(!handles(&state, &trap()));
    let event = service(&mut state, &trap());
    assert!(event.completion.is_none());
    assert!(event.declined.is_some());
    assert_state(&state, &before);
}
