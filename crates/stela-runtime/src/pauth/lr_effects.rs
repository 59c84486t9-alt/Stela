//! Evaluating FEAT_PAuth_LR instructions into effects for the retiring owner
//! to validate and commit.

use super::{
    AuthenticationError,
    conditional::Operands,
    lr_context::{self, AuthenticationKind, InstructionKey},
    lr_instruction::{Action, Instruction, Key, Staged},
    lr_service::{self, BorrowedLinkRegisterService, KeySelection, PacmControlValue},
};
use crate::system::state::Pacm;
use stela_compiler::{GuestAddress, block::PointerAuthenticationOperation};

const ZERO_REGISTER: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    Register { destination: u8, value: u64 },
    Return { target: GuestAddress },
    Pacm(Pacm),
    Discard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Evaluation {
    Candidate(Effect),
    AuthenticationFault { code: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Service(lr_service::Error),
    Crypto(lr_context::Error),
    InvalidDestination,
}

/// No guest state changes, including on missing resources or authentication
/// failure. Explicit LR forms always use both staged modifiers; PACM does not
/// change that selection. Selected-key bypass precedes any key lookup.
pub(crate) fn evaluate(
    instruction: Instruction,
    service: &BorrowedLinkRegisterService<'_>,
) -> Result<Evaluation, Error> {
    let staged = service.stage(instruction).map_err(Error::Service)?;
    let Staged::Pointer(operands) = staged else {
        let value = match service.pacm_control_value().map_err(Error::Service)? {
            PacmControlValue::Zero => Pacm::Zero,
            PacmControlValue::One => Pacm::One,
        };
        return Ok(Evaluation::Candidate(Effect::Pacm(value)));
    };
    evaluate_pointer(
        Operands {
            key: operands.key,
            action: operands.action,
            pointer: operands.pointer,
            first: operands.modifier1,
            second: Some(operands.modifier2),
            destination: operands.destination,
        },
        service,
    )
}

/// Legacy SP/1716/RET forms select modifiers from actual borrowed PACM.
/// None leaves other forms with their existing single-modifier service.
/// XZR discards only a successful result, after key/resource/fault checks.
pub(crate) fn evaluate_conditional(
    operation: PointerAuthenticationOperation,
    service: &BorrowedLinkRegisterService<'_>,
) -> Result<Option<Evaluation>, Error> {
    service
        .stage_conditional(operation)
        .map_err(Error::Service)?
        .map(|operands| evaluate_pointer(operands, service))
        .transpose()
}

fn evaluate_pointer(
    operands: Operands,
    service: &BorrowedLinkRegisterService<'_>,
) -> Result<Evaluation, Error> {
    let key = match operands.key {
        Key::Ia => InstructionKey::A,
        Key::Ib => InstructionKey::B,
    };
    let value = match service.key_selection(key) {
        KeySelection::Bypass => operands.pointer,
        KeySelection::UseKey => {
            let crypto = service.crypto().map_err(Error::Service)?;
            if operands.action == Action::Sign {
                match operands.second {
                    Some(second) => crypto.sign(key, operands.pointer, operands.first, second),
                    None => crypto.sign_single(key, operands.pointer, operands.first),
                }
                .map_err(Error::Crypto)?
            } else {
                let kind = if operands.action == Action::Return {
                    AuthenticationKind::Return
                } else {
                    AuthenticationKind::Standalone
                };
                let authenticated = match operands.second {
                    Some(second) => {
                        crypto.authenticate(key, operands.pointer, operands.first, second, kind)
                    }
                    None => crypto.authenticate_single(key, operands.pointer, operands.first, kind),
                };
                match authenticated {
                    Ok(result) => result.pointer,
                    Err(lr_context::Error::Authentication(AuthenticationError::Failure {
                        code,
                    })) => {
                        return Ok(Evaluation::AuthenticationFault { code });
                    }
                    Err(error) => return Err(Error::Crypto(error)),
                }
            }
        }
    };
    let effect = if operands.action == Action::Return {
        Effect::Return {
            target: GuestAddress(value),
        }
    } else {
        match operands.destination {
            Some(ZERO_REGISTER) => Effect::Discard,
            Some(destination) if destination < ZERO_REGISTER => {
                Effect::Register { destination, value }
            }
            _ => return Err(Error::InvalidDestination),
        }
    };
    Ok(Evaluation::Candidate(effect))
}
