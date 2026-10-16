//! ARM64 Mach trap ABI and opt-in host-owned bootstrap port rights.
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
//! osfmk/arm64/bsd_arm64.c and osfmk/kern/syscall_sw.c. This is not an IPC bridge.
use crate::{
    blocks::ThreadState,
    darwin::{SYSCALL_SELECTOR_REGISTER, validate_trap_parts},
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
use anyhow::{Result, ensure};
use serde::Serialize;
use stela_compiler::block::SynchronousTrap;

pub const HOST_PORT_PROFILE: &str = "darwin-host-owned-mach-ports-v1";
pub const REPLY_PORT_TRAP: u32 = 26;
pub const THREAD_SELF_TRAP: u32 = 27;
pub const TASK_SELF_TRAP: u32 = 28;
pub const HOST_SELF_TRAP: u32 = 29;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Request {
    pub number: u32,
    pub arguments: Vec<u64>,
}

/// Capture a stopped call without touching memory or invoking a backend.
pub struct PendingCall {
    request: Request,
    issued: ThreadState,
    trap: SynchronousTrap,
}
impl PendingCall {
    pub fn from_trap(
        state: &ThreadState,
        trap: &SynchronousTrap,
        argument_count: usize,
    ) -> Result<Self> {
        Self::from_registers(state.pc, &state.registers, trap, argument_count)
    }

    /// Capture immutable ABI evidence; actual PC remains with its consumer.
    pub(crate) fn from_registers(
        pc: stela_compiler::GuestAddress,
        registers: &stela_compiler::GuestState,
        trap: &SynchronousTrap,
        argument_count: usize,
    ) -> Result<Self> {
        validate_trap_parts(pc, registers, trap)?;
        let selector = registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32;
        ensure!(
            selector < 0 && selector != i32::MIN && selector != -3 && selector != -4,
            "selector is not an ordinary Mach trap"
        );
        ensure!(
            argument_count <= 9,
            "Mach LP64 prototype exceeds nine register arguments"
        );
        Ok(Self {
            request: Request {
                number: selector.unsigned_abs(),
                arguments: registers.x[..argument_count].to_vec(),
            },
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
    pub fn complete(self, state: &mut ThreadState, value: i32) -> Result<()> {
        ensure!(
            state.pc == self.issued.pc && state.registers == self.issued.registers,
            "pending Mach state changed"
        );
        state.pc = self.complete_registers(&mut state.registers, value)?;
        Ok(())
    }

    /// Commit only the actual register bank; caller retires the returned PC.
    pub(crate) fn complete_registers(
        self,
        registers: &mut stela_compiler::GuestState,
        value: i32,
    ) -> Result<stela_compiler::GuestAddress> {
        ensure!(
            *registers == self.issued.registers,
            "pending Mach registers changed"
        );
        // Unlike BSD returns, Mach completion does not normalize carry or X1.
        registers.x[0] = value as i64 as u64;
        Ok(self.trap.exception_return_pc)
    }
}

pub mod ports;
pub(crate) use ports::host::current_thread_identifier;
pub use ports::{HostPorts, PortKind, PortRight};

#[derive(Debug, Serialize)]
pub struct Event {
    pub trap: SynchronousTrap,
    pub request: Option<Request>,
    pub result: Option<i32>,
    pub declined: Option<String>,
}
pub fn service(state: &mut ThreadState, trap: &SynchronousTrap, ports: &mut HostPorts) -> Event {
    let mut event = Event {
        trap: *trap,
        request: None,
        result: None,
        declined: None,
    };
    let result = (|| -> Result<i32> {
        let pending = PendingCall::from_trap(state, trap, 0)?;
        event.request = Some(pending.request().clone());
        let value = ports.request(pending.request())?;
        pending.complete(state, value)?;
        Ok(value)
    })();
    match result {
        Ok(value) => event.result = Some(value),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

#[cfg(test)]
mod tests {
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
        let pending =
            PendingCall::from_registers(trap.instruction_pc, &registers, &trap, 0).unwrap();
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
}
