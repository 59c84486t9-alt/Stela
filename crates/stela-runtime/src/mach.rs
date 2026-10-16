//! The ARM64 Mach trap ABI and host-backed bootstrap port rights
//! (XNU `osfmk/arm64/bsd_arm64.c`, `osfmk/kern/syscall_sw.c`).
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
mod tests;
