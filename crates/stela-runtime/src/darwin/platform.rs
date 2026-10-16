//! Pure ARM64 Darwin platform-call ABI for a stopped SVC #0x80.
//!
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
//! osfmk/arm64/sleh.c, osfmk/arm64/machine_routines.c (platform_syscall),
//! osfmk/arm/machdep_call.c and osfmk/arm64/machine_machdep.h.
//! X16 selects this boundary through its signed low 32 bits; X3 supplies the
//! unsigned 32-bit subcode. The setter ignores its internal kernel return value
//! and preserves saved X0 and NZCV. The getter writes only saved X0.
//!
//! An external thread service owns TSD storage and address sanitization. Darwin
//! exposes that base through TPIDRRO_EL0, distinct from TPIDR_EL0. This adapter
//! performs no memory access, host call, system-register update or EL transition.
//! Unsupported subcodes remain explicit even where the pinned kernel ignores
//! them. These public sources do not establish the private macOS 27 contract.

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

    /// Apply one actual thread-service result. A declined service must leave the
    /// call pending. Invalid replies and changed state never mutate saved state.
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
mod tests;
