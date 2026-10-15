//! Current-process identity through the common Darwin BSD-call boundary.
//!
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
//! bsd/kern/kern_prot.c getpid, syscalls.master and ARM systemcalls.c. This
//! service reads the current thread's shared guest process owner, never host PID.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
};
use crate::{blocks::ThreadState, process::Context};
use anyhow::{Result, ensure};
use stela_compiler::block::SynchronousTrap;

pub const SYSCALL_NUMBER: u16 = 20;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 0,
    return_type: BsdReturnType::Int,
};

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// The runtime binds this immutable process owner through the current thread
/// before dispatch. A different call or incoherent pending trap has no effects.
pub fn service(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    process: &Context,
) -> BsdServiceEvent {
    let mut event = BsdServiceEvent {
        trap: *trap,
        request: None,
        completion: None,
        declined: None,
    };
    let result = (|| -> Result<BsdCompletion> {
        let pending = PendingBsdCall::from_trap(state, trap, PROTOTYPE)?;
        let request = *pending.request();
        event.request = Some(request);
        ensure!(
            request.number == SYSCALL_NUMBER,
            "BSD service {} is not implemented by the process identity profile",
            request.number
        );
        // ARM entry zeros both retval slots; getpid writes only the first.
        let completion = BsdCompletion::Success {
            values: [process.pid(), 0],
        };
        pending.complete(state, completion)?;
        Ok(completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

#[cfg(test)]
mod tests {
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
}
