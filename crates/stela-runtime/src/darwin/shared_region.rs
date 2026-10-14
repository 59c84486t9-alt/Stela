//! The absent-task-region branch of Darwin's shared-region query.
//!
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
//! bsd/vm/vm_unix.c and osfmk/mach/dyld_pager.h. This profile does not claim
//! the private macOS 27 kernel contract or model an existing shared region.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
};
use crate::blocks::ThreadState;
use anyhow::{Result, ensure};
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-arm64-absent-shared-region-v1";
pub const SYSCALL_NUMBER: u16 = 294;

/// The LP64 DYLD_VM_END_MWL command precedes the task-region lookup in XNU.
const DYLD_VM_END_MWL: u64 = u64::MAX;
const DARWIN_EINVAL: u32 = 22;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 1,
    return_type: BsdReturnType::Int,
};

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// Service BSD294 for a process that owns no guest shared-region attachment.
///
/// The caller must establish that absence from its actual process ownership;
/// host shared-cache mappings cannot satisfy this ARM guest condition. XNU
/// returns EINVAL before accessing the destination, including a NULL pointer.
/// There is consequently no guest-memory read, copyout or mapping transition.
/// The map-with-linking command requires process policy state and remains
/// pending. Existing empty/mapped regions require a separate reviewed profile.
pub fn service_absent(state: &mut ThreadState, trap: &SynchronousTrap) -> BsdServiceEvent {
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
            "BSD service {} is not implemented by the absent shared-region profile",
            request.number
        );
        let [address] = request.arguments() else {
            unreachable!("the validated shared-region prototype contains one argument")
        };
        ensure!(
            *address != DYLD_VM_END_MWL,
            "disabling map_with_linking requires owned process policy state"
        );
        let completion = BsdCompletion::Error {
            errno: DARWIN_EINVAL,
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
}
