//! Source-bound immediate completion through the shared PSTATE effect owner.
//!
//! The caller holds the actual immutable registered source and current controls.
//! An unavailable asynchronous boundary owner prevents DAIF mutation; this module
//! never guesses a pending IRQ or reports a passive field write as completion.

use super::{CommitError, Effect};
use crate::system::{
    access::{Request, Resolution},
    pstate::Context,
    state::SystemState,
};
use stela_compiler::{
    GuestAddress, GuestState,
    block::system::{SystemInstruction, SystemOperation},
};

pub(crate) mod el1_daif;

const ZERO_REGISTER: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    WrongSource,
    NotImmediate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Source(SourceError),
    Commit(CommitError),
}

/// Uncompleted decisions carry their original request for exact trap syndromes
/// and actual backend dispatch. They have applied no instruction effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    Complete {
        next_pc: GuestAddress,
    },
    Uncompleted {
        request: Request,
        decision: Resolution<Effect>,
    },
}

/// Recheck the canonical typed descriptor against actual original bytes before
/// using its immediate. CRm is the operand; no GPR or XZR value is sampled.
pub fn request(
    instruction: SystemInstruction,
    source_pc: GuestAddress,
    source_word: u32,
) -> Result<Request, SourceError> {
    if !instruction.matches_source(source_pc, source_word) {
        return Err(SourceError::WrongSource);
    }
    let SystemOperation::PstateImmediate(encoding) = instruction.operation else {
        return Err(SourceError::NotImmediate);
    };
    Ok(Request::write(encoding, ZERO_REGISTER, 0))
}

/// Complete only effects for which the actual state owner suffices. Source
/// Undefined/Trap/NotHandled and optional backend decisions remain unapplied.
/// DAIF requires the real postcommit asynchronous boundary owner, which is not
/// supplied by a PSTATE snapshot or the current pure interrupt-access planner.
/// Parent runtime must dispatch that requirement before permitting mutation.
pub fn complete(
    instruction: SystemInstruction,
    source_pc: GuestAddress,
    source_word: u32,
    context: &Context,
    system: &mut SystemState,
    registers: &mut GuestState,
) -> Result<Completion, Error> {
    let request = request(instruction, source_pc, source_word).map_err(Error::Source)?;
    let decision = super::resolve(request, context, system, registers);
    match decision {
        Resolution::BackendRequired(effect @ Effect::SpSelect { .. }) => {
            super::commit(effect, system, registers).map_err(Error::Commit)?;
            Ok(Completion::Complete {
                next_pc: instruction.next_pc,
            })
        }
        decision => Ok(Completion::Uncompleted { request, decision }),
    }
}

#[cfg(test)]
#[path = "immediate/tests.rs"]
mod tests;
