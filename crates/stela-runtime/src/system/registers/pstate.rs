//! PSTATE register and immediate writes. The caller sets PC afterwards, so a
//! later interrupt observes the completed instruction.

pub mod immediate;

use crate::system::{
    access::{Request, Resolution, StateWrite},
    pstate::{self, Context, DAIF_MASK, NZCV_MASK, PstateField, SP_SELECT_MASK, Snapshot},
    state::{PSTATE_IL_MASK, StackBank, StateError, SystemState},
};
use stela_compiler::GuestState;

const ZERO_REGISTER: u8 = 31;

/// An unapplied effect. Optional effects must reach their owner, never a plain
/// bit store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Nzcv { value: u32 },
    SpEl0 { value: u64 },
    SpSelect { bank: StackBank },
    Daif { mask: u64, value: u64 },
    Backend(pstate::BackendRequest),
    UnownedRead(Request),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    IllegalExecutionState,
    InvalidNzcv,
    InvalidDaifMask,
    InvalidDaifValue,
    State(StateError),
    BackendRequired,
}

/// Resolve against the flags, PSTATE and the inactive stack pointers. TLS reads
/// stay unsupported here and TLS writes stay StateWrite for the typed owner.
/// NotHandled is a family miss, not proof of UNDEFINED.
pub fn resolve(
    request: Request,
    context: &Context,
    system: &SystemState,
    registers: &GuestState,
) -> Resolution<Effect> {
    if context.profile.current_el != system.current_el() {
        return Resolution::Unsupported("PSTATE access context differs from current EL");
    }
    if system.pstate(registers) & PSTATE_IL_MASK != 0 {
        return Resolution::Unsupported("illegal execution state requires its exception owner");
    }
    if request.rt > ZERO_REGISTER {
        return Resolution::Unsupported("system register operand exceeds five bits");
    }
    let snapshot = Snapshot {
        pstate: Some(system.pstate(registers)),
        thread_id_el0: None,
        thread_id_read_only_el0: None,
        thread_id_el1: None,
        stack_pointer_el0: system.read_sp_el0().ok(),
    };
    match pstate::resolve(request, context, &snapshot) {
        Resolution::Read(_) if requires_read_owner(request, context, system) => {
            Resolution::BackendRequired(Effect::UnownedRead(request))
        }
        Resolution::Read(value) => Resolution::Read(value),
        Resolution::Write(StateWrite {
            encoding: pstate::NZCV,
            value,
        }) => Resolution::BackendRequired(Effect::Nzcv {
            value: value as u32,
        }),
        Resolution::Write(StateWrite {
            encoding: pstate::SP_EL0,
            value,
        }) => Resolution::BackendRequired(Effect::SpEl0 { value }),
        Resolution::Write(write) => Resolution::Write(write),
        Resolution::BackendRequired(pstate::BackendRequest::Pstate {
            field: PstateField::Daif,
            mask,
            value,
        }) => Resolution::BackendRequired(Effect::Daif { mask, value }),
        Resolution::BackendRequired(pstate::BackendRequest::Pstate {
            field: PstateField::SpSelect,
            mask: SP_SELECT_MASK,
            value,
        }) => Resolution::BackendRequired(Effect::SpSelect {
            bank: if value & SP_SELECT_MASK == 0 {
                StackBank::El0
            } else {
                StackBank::El1
            },
        }),
        Resolution::BackendRequired(operation) => {
            Resolution::BackendRequired(Effect::Backend(operation))
        }
        Resolution::NotHandled => Resolution::NotHandled,
        Resolution::Unallocated => Resolution::Unallocated,
        Resolution::Undefined => Resolution::Undefined,
        Resolution::Trap(trap) => Resolution::Trap(trap),
        Resolution::Unsupported(reason) => Resolution::Unsupported(reason),
    }
}

fn requires_read_owner(request: Request, context: &Context, system: &SystemState) -> bool {
    match request.encoding {
        pstate::PAN | pstate::UAO | pstate::DIT | pstate::SSBS => true,
        pstate::TCO => match context.features.mte {
            pstate::MteFeature::One {
                register_raz_wi: true,
                ..
            } => false,
            pstate::MteFeature::TwoOrLater => system.mte().is_none(),
            _ => true,
        },
        _ => false,
    }
}

/// Apply only an already authorized direct effect, with no external callbacks.
/// Every rejection occurs before mutation. DAIF updates never touch GuestState
/// flags, active SP, monitor/event state, or asynchronous interrupt delivery.
/// Success is instruction state completion; the runtime must commit nextPC
/// before a later boundary owner can arbitrate pending asynchronous exceptions.
pub fn commit(
    effect: Effect,
    system: &mut SystemState,
    registers: &mut GuestState,
) -> Result<(), CommitError> {
    if system.pstate(registers) & PSTATE_IL_MASK != 0 {
        return Err(CommitError::IllegalExecutionState);
    }
    match effect {
        Effect::Nzcv { value } => {
            if u64::from(value) & !NZCV_MASK != 0 {
                return Err(CommitError::InvalidNzcv);
            }
            registers.nzcv = value;
            Ok(())
        }
        Effect::SpEl0 { value } => system.write_sp_el0(value).map_err(CommitError::State),
        Effect::SpSelect { bank } => system
            .set_spsel(registers, bank)
            .map_err(CommitError::State),
        Effect::Daif { mask, value } => {
            if mask & !DAIF_MASK != 0 {
                return Err(CommitError::InvalidDaifMask);
            }
            if value & !mask != 0 {
                return Err(CommitError::InvalidDaifValue);
            }
            let updated = (system.pstate(registers) & !mask) | value;
            system.write_daif(updated);
            Ok(())
        }
        Effect::Backend(_) | Effect::UnownedRead(_) => Err(CommitError::BackendRequired),
    }
}

#[cfg(test)]
mod tests;
