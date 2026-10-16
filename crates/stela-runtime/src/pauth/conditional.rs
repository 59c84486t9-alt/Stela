//! Operands of the IA/IB instructions whose behavior depends on PSTATE.PACM.

use super::lr_instruction::{Action, Key, StageError};
use crate::system::state::Pacm;
use stela_compiler::block::{
    PointerAuthenticationKey, PointerAuthenticationModifier,
    PointerAuthenticationOperation as Operation,
};

const INSTRUCTION_BYTES: u64 = 4;
const LINK_REGISTER: u8 = 30;
const ZERO_REGISTER: u8 = 31;
const HINT_POINTER_REGISTER: u8 = 17;
const FIRST_HINT_MODIFIER: usize = 16;
const SECOND_HINT_MODIFIER: usize = 15;
const SP_AUTH_MODIFIER: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Operands {
    pub key: Key,
    pub action: Action,
    pub pointer: u64,
    pub first: u64,
    pub second: Option<u64>,
    pub destination: Option<u8>,
}

/// None means this operation is not conditional on PACM. Data keys and ordinary
/// register modifiers keep their existing path. Some snapshots every operand,
/// including OLD X16/X15, before the canonical consumer can write any register.
pub(crate) fn stage(
    operation: Operation,
    pc: u64,
    x: &[u64; 31],
    sp: u64,
    pacm: Pacm,
) -> Result<Option<Operands>, StageError> {
    if !pc.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(StageError::UnalignedPc);
    }
    let (key, action, destination, first, second) = match operation {
        Operation::Sign1716 { key } => (
            key,
            Action::Sign,
            Some(HINT_POINTER_REGISTER),
            x[FIRST_HINT_MODIFIER],
            x[SECOND_HINT_MODIFIER],
        ),
        Operation::Authenticate1716 { key } => (
            key,
            Action::Authenticate,
            Some(HINT_POINTER_REGISTER),
            x[FIRST_HINT_MODIFIER],
            x[SECOND_HINT_MODIFIER],
        ),
        Operation::SignIbSp => (
            PointerAuthenticationKey::Ib,
            Action::Sign,
            Some(LINK_REGISTER),
            sp,
            pc,
        ),
        Operation::AuthenticateIbSp => (
            PointerAuthenticationKey::Ib,
            Action::Authenticate,
            Some(LINK_REGISTER),
            sp,
            x[SP_AUTH_MODIFIER],
        ),
        Operation::Sign {
            key,
            destination,
            modifier: PointerAuthenticationModifier::StackPointer,
        } if !key_is_data(key) => (key, Action::Sign, Some(destination), sp, pc),
        Operation::Authenticate {
            key,
            destination,
            modifier: PointerAuthenticationModifier::StackPointer,
        } if !key_is_data(key) => (
            key,
            Action::Authenticate,
            Some(destination),
            sp,
            x[SP_AUTH_MODIFIER],
        ),
        Operation::ReturnIaSp => (
            PointerAuthenticationKey::Ia,
            Action::Return,
            None,
            sp,
            x[SP_AUTH_MODIFIER],
        ),
        Operation::ReturnIbSp => (
            PointerAuthenticationKey::Ib,
            Action::Return,
            None,
            sp,
            x[SP_AUTH_MODIFIER],
        ),
        _ => return Ok(None),
    };
    let key = match key {
        PointerAuthenticationKey::Ia => Key::Ia,
        PointerAuthenticationKey::Ib => Key::Ib,
        _ => return Err(StageError::InvalidOperands),
    };
    let pointer_register = destination.unwrap_or(LINK_REGISTER);
    let pointer = match pointer_register {
        ZERO_REGISTER => 0,
        register if register < ZERO_REGISTER => x[usize::from(register)],
        _ => return Err(StageError::InvalidOperands),
    };
    Ok(Some(Operands {
        key,
        action,
        pointer,
        first,
        second: if pacm == Pacm::One {
            Some(second)
        } else {
            None
        },
        destination,
    }))
}

const fn key_is_data(key: PointerAuthenticationKey) -> bool {
    matches!(
        key,
        PointerAuthenticationKey::Da | PointerAuthenticationKey::Db
    )
}
