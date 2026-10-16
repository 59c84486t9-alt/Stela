//! The ARM64 platform call (`SVC #0x80` with W16 = 0x80000000, XNU
//! `osfmk/arm/machdep_call.c`): get and set the TSD base exposed through
//! TPIDRRO_EL0. X3 holds the subcode. The setter keeps saved X0 and NZCV; the
//! getter writes only X0. Unsupported subcodes are errors.

use crate::{
    blocks::ThreadState,
    darwin::{SYSCALL_SELECTOR_REGISTER, validate_trap_parts},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use stela_compiler::{GuestAddress, GuestState, block::SynchronousTrap};

pub const PLATFORM_CALL_SELECTOR: i32 = i32::MIN;
pub const SET_THREAD_SPECIFIC_DATA: u32 = 2;
pub const GET_THREAD_SPECIFIC_DATA: u32 = 3;

const ARGUMENT_REGISTER: usize = 0;
const SUBCODE_REGISTER: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    SetThreadSpecificData { address: u64 },
    GetThreadSpecificData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Completion {
    SetThreadSpecificData,
    GetThreadSpecificData { address: u64 },
}

/// Immutable request and stopped-state snapshot; no thread service has run yet.
#[derive(Debug)]
pub struct PendingCall {
    request: Request,
    issued: ThreadState,
    trap: SynchronousTrap,
}

impl PendingCall {
    pub fn from_trap(state: &ThreadState, trap: &SynchronousTrap) -> Result<Self> {
        Self::from_registers(state.pc, &state.registers, trap)
    }

    pub(crate) fn from_registers(
        pc: GuestAddress,
        registers: &GuestState,
        trap: &SynchronousTrap,
    ) -> Result<Self> {
        validate_trap_parts(pc, registers, trap)?;
        let selector = registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32;
        ensure!(
            selector == PLATFORM_CALL_SELECTOR,
            "selector is not an ARM Darwin platform call"
        );
        let subcode = registers.x[SUBCODE_REGISTER] as u32;
        let request = match subcode {
            SET_THREAD_SPECIFIC_DATA => Request::SetThreadSpecificData {
                address: registers.x[ARGUMENT_REGISTER],
            },
            GET_THREAD_SPECIFIC_DATA => Request::GetThreadSpecificData,
            _ => anyhow::bail!("ARM Darwin platform subcode {subcode} is unsupported"),
        };
        Ok(Self {
            request,
            issued: ThreadState {
                pc,
                registers: registers.clone(),
            },
            trap: *trap,
        })
    }

    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Apply a thread-service result. Declined services leave the call pending;
    /// an invalid reply or changed state never modifies the saved state.
    pub fn complete(self, state: &mut ThreadState, completion: Completion) -> Result<()> {
        ensure!(
            state.pc == self.issued.pc,
            "pending ARM Darwin platform PC changed"
        );
        state.pc = self.complete_registers(&mut state.registers, completion)?;
        Ok(())
    }

    pub(crate) fn complete_registers(
        self,
        registers: &mut GuestState,
        completion: Completion,
    ) -> Result<GuestAddress> {
        ensure!(
            *registers == self.issued.registers,
            "pending ARM Darwin platform state changed"
        );
        match (self.request, completion) {
            (Request::SetThreadSpecificData { .. }, Completion::SetThreadSpecificData) => {}
            (Request::GetThreadSpecificData, Completion::GetThreadSpecificData { address }) => {
                registers.x[ARGUMENT_REGISTER] = address
            }
            _ => anyhow::bail!("ARM Darwin platform completion does not match its request"),
        }
        Ok(self.trap.exception_return_pc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::{GuestAddress, GuestState, block::TrapKind};

    const NZCV_SHIFT: u32 = 28;
    const NZCV_COMBINATIONS: u32 = 16;
    const SVC_IMMEDIATE: u16 = 0x80;

    fn trap() -> SynchronousTrap {
        SynchronousTrap {
            kind: TrapKind::SupervisorCall,
            immediate: SVC_IMMEDIATE,
            instruction_pc: GuestAddress(0x1000),
            exception_return_pc: GuestAddress(0x1004),
        }
    }

    fn state(subcode: u32, flags: u32) -> ThreadState {
        let mut registers = GuestState {
            x: std::array::from_fn(|index| 0xdeadc0de12340000 + index as u64),
            sp: 0xfeed0000,
            nzcv: flags << NZCV_SHIFT,
            reserved: 0xa5a5,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 17,
            fpsr: 29,
        };
        registers.x[SYSCALL_SELECTOR_REGISTER] = PLATFORM_CALL_SELECTOR as u32 as u64;
        registers.x[SUBCODE_REGISTER] = u64::from(subcode);
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
    fn borrowed_platform_completion_preserves_pc_authority_and_validates_before_write() {
        let input = state(SET_THREAD_SPECIFIC_DATA, 15);
        let mut bank = input.registers.clone();
        let actual_pc = input.pc;
        let pending = PendingCall::from_registers(actual_pc, &bank, &trap()).unwrap();
        assert_eq!(
            pending
                .complete_registers(&mut bank, Completion::SetThreadSpecificData)
                .unwrap(),
            trap().exception_return_pc
        );
        assert_eq!(bank, input.registers);
        assert_eq!(actual_pc, trap().instruction_pc);
        let pending = PendingCall::from_registers(actual_pc, &bank, &trap()).unwrap();
        assert!(
            pending
                .complete_registers(
                    &mut bank,
                    Completion::GetThreadSpecificData { address: u64::MAX }
                )
                .is_err()
        );
        assert_eq!(bank, input.registers);
    }

    #[test]
    fn set_completion_preserves_all_saved_registers_and_flags() {
        for flags in 0..NZCV_COMBINATIONS {
            for address in [0, 1, 0x123456789abcdef0, u64::MAX] {
                let mut state = state(SET_THREAD_SPECIFIC_DATA, flags);
                state.registers.x[ARGUMENT_REGISTER] = address;
                let pending = PendingCall::from_trap(&state, &trap()).unwrap();
                assert_eq!(
                    pending.request(),
                    &Request::SetThreadSpecificData { address }
                );
                let mut expected = state.clone();
                expected.pc = trap().exception_return_pc;
                pending
                    .complete(&mut state, Completion::SetThreadSpecificData)
                    .unwrap();
                assert_state(&state, &expected);
            }
        }
    }

    #[test]
    fn get_completion_changes_only_x0_and_pc() {
        for flags in 0..NZCV_COMBINATIONS {
            for address in [0, 1, 0x123456789abcdef0, u64::MAX] {
                let mut state = state(GET_THREAD_SPECIFIC_DATA, flags);
                let pending = PendingCall::from_trap(&state, &trap()).unwrap();
                assert_eq!(pending.request(), &Request::GetThreadSpecificData);
                let mut expected = state.clone();
                expected.pc = trap().exception_return_pc;
                expected.registers.x[ARGUMENT_REGISTER] = address;
                pending
                    .complete(&mut state, Completion::GetThreadSpecificData { address })
                    .unwrap();
                assert_state(&state, &expected);
            }
        }
    }

    #[test]
    fn dispatch_uses_only_low_32_bits_of_selector_and_subcode() {
        for upper in [0, 1, 0xfeedface, u32::MAX] {
            for subcode in [SET_THREAD_SPECIFIC_DATA, GET_THREAD_SPECIFIC_DATA] {
                let mut state = state(subcode, 0);
                state.registers.x[SYSCALL_SELECTOR_REGISTER] |= u64::from(upper) << 32;
                state.registers.x[SUBCODE_REGISTER] |= u64::from(upper) << 32;
                let before = state.clone();
                let pending = PendingCall::from_trap(&state, &trap()).unwrap();
                let expected = if subcode == SET_THREAD_SPECIFIC_DATA {
                    Request::SetThreadSpecificData {
                        address: state.registers.x[ARGUMENT_REGISTER],
                    }
                } else {
                    Request::GetThreadSpecificData
                };
                assert_eq!(pending.request(), &expected);
                assert_state(&state, &before);
            }
        }
    }

    #[test]
    fn unsupported_selectors_and_subcodes_preserve_state() {
        for selector in [0, 1, i32::MAX, -1, PLATFORM_CALL_SELECTOR + 1] {
            let mut state = state(SET_THREAD_SPECIFIC_DATA, 0);
            state.registers.x[SYSCALL_SELECTOR_REGISTER] = selector as u32 as u64;
            let before = state.clone();
            assert!(PendingCall::from_trap(&state, &trap()).is_err());
            assert_state(&state, &before);
        }
        for subcode in [0, 1, 4, u32::MAX] {
            let state = state(subcode, 0);
            let before = state.clone();
            assert!(PendingCall::from_trap(&state, &trap()).is_err());
            assert_state(&state, &before);
        }
    }

    #[test]
    fn mismatched_completions_preserve_state() {
        for (subcode, completion) in [
            (
                SET_THREAD_SPECIFIC_DATA,
                Completion::GetThreadSpecificData { address: 123 },
            ),
            (GET_THREAD_SPECIFIC_DATA, Completion::SetThreadSpecificData),
        ] {
            let mut state = state(subcode, 0);
            let pending = PendingCall::from_trap(&state, &trap()).unwrap();
            let before = state.clone();
            assert!(pending.complete(&mut state, completion).is_err());
            assert_state(&state, &before);
        }
    }

    #[test]
    fn changed_state_is_rejected_before_completion_writes() {
        let mutations: [fn(&mut ThreadState); 9] = [
            |state| state.pc.0 += 4,
            |state| state.registers.x[ARGUMENT_REGISTER] ^= 1,
            |state| state.registers.x[30] ^= 1,
            |state| state.registers.sp ^= 1,
            |state| state.registers.nzcv ^= 1 << NZCV_SHIFT,
            |state| state.registers.reserved ^= 1,
            |state| state.registers.v[31][1] ^= 1,
            |state| state.registers.fpcr ^= 1,
            |state| state.registers.fpsr ^= 1,
        ];
        for mutate in mutations {
            let mut state = state(GET_THREAD_SPECIFIC_DATA, 0);
            let pending = PendingCall::from_trap(&state, &trap()).unwrap();
            mutate(&mut state);
            let before = state.clone();
            assert!(
                pending
                    .complete(
                        &mut state,
                        Completion::GetThreadSpecificData { address: 123 }
                    )
                    .is_err()
            );
            assert_state(&state, &before);
        }
    }

    #[test]
    fn incoherent_or_non_svc_traps_preserve_state() {
        let mutations: [fn(&mut SynchronousTrap); 6] = [
            |trap| trap.kind = TrapKind::SoftwareBreakpoint,
            |trap| trap.immediate ^= 1,
            |trap| trap.instruction_pc.0 += 4,
            |trap| trap.instruction_pc.0 += 1,
            |trap| trap.exception_return_pc.0 -= 4,
            |trap| trap.exception_return_pc.0 += 4,
        ];
        for mutate in mutations {
            let state = state(SET_THREAD_SPECIFIC_DATA, 0);
            let before = state.clone();
            let mut trap = trap();
            mutate(&mut trap);
            assert!(PendingCall::from_trap(&state, &trap).is_err());
            assert_state(&state, &before);
        }
        let mut state = state(SET_THREAD_SPECIFIC_DATA, 0);
        state.registers.nzcv |= 1;
        let before = state.clone();
        assert!(PendingCall::from_trap(&state, &trap()).is_err());
        assert_state(&state, &before);
    }

    #[test]
    fn requests_and_completions_serialize_with_typed_snake_case_kinds() {
        assert_eq!(
            serde_json::to_value(Request::SetThreadSpecificData { address: 123 }).unwrap(),
            serde_json::json!({"kind": "set_thread_specific_data", "address": 123})
        );
        assert_eq!(
            serde_json::to_value(Request::GetThreadSpecificData).unwrap(),
            serde_json::json!({"kind": "get_thread_specific_data"})
        );
        assert_eq!(
            serde_json::to_value(Completion::SetThreadSpecificData).unwrap(),
            serde_json::json!({"kind": "set_thread_specific_data"})
        );
        assert_eq!(
            serde_json::to_value(Completion::GetThreadSpecificData { address: 123 }).unwrap(),
            serde_json::json!({"kind": "get_thread_specific_data", "address": 123})
        );
    }
}
