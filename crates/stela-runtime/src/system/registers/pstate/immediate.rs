//! MSR (immediate) to PSTATE fields.

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

/// A pending decision, keeping its request for trap syndromes and backend
/// dispatch; nothing has been applied.
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

/// Re-check the descriptor against the source bytes before using its immediate.
/// CRm is the operand; no GPR is read.
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

/// Complete the effects the state owner can apply alone. Undefined, Trap,
/// NotHandled and backend decisions stay unapplied. DAIF needs the asynchronous
/// boundary owner after commit, which a PSTATE snapshot does not provide, so
/// the runtime must dispatch it before allowing the change.
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
mod tests;
