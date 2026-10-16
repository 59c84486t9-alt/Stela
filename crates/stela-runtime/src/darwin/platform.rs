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
mod tests;
