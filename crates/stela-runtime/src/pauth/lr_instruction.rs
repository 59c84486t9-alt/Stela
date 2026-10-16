//! Operands and effects of the FEAT_PAuth_LR instructions.

#[cfg(test)]
use stela_compiler::block::pauth_lr::decode;
pub(crate) use stela_compiler::block::pauth_lr::{Instruction, Key};

const REGISTER_MASK: u32 = 31;
const INSTRUCTION_BYTES: u64 = 4;
const LINK_REGISTER: usize = 30;
const POINTER_REGISTER: usize = 17;
const FIRST_MODIFIER: usize = 16;
const SECOND_MODIFIER: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Sign,
    Authenticate,
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operands {
    pub key: Key,
    pub action: Action,
    pub pointer: u64,
    pub modifier1: u64,
    pub modifier2: u64,
    pub destination: Option<u8>,
    pub implicit_bti: bool,
    pub instruction_pc: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staged {
    Pointer(Operands),
    Pacm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageError {
    InvalidOperands,
    UnalignedPc,
}

/// A snapshot of the instruction's operands, all from the same pre-state. The
/// executing owner authorizes and applies the effects.
pub fn stage(
    instruction: Instruction,
    pc: u64,
    x: &[u64; 31],
    sp: u64,
) -> Result<Staged, StageError> {
    if !instruction.valid() {
        return Err(StageError::InvalidOperands);
    }
    if !pc.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(StageError::UnalignedPc);
    }
    let mut operands = Operands {
        key: Key::Ia,
        action: Action::Authenticate,
        pointer: x[LINK_REGISTER],
        modifier1: sp,
        modifier2: pc,
        destination: Some(LINK_REGISTER as u8),
        implicit_bti: false,
        instruction_pc: pc,
    };
    match instruction {
        Instruction::Pacm => return Ok(Staged::Pacm),
        Instruction::Sign171615(key) | Instruction::Authenticate171615(key) => {
            operands.key = key;
            operands.pointer = x[POINTER_REGISTER];
            operands.modifier1 = x[FIRST_MODIFIER];
            operands.modifier2 = x[SECOND_MODIFIER];
            operands.destination = Some(POINTER_REGISTER as u8);
            if matches!(instruction, Instruction::Sign171615(_)) {
                operands.action = Action::Sign;
            }
        }
        Instruction::AuthenticateSpRegister { key, register } => {
            operands.key = key;
            operands.modifier2 = if register == REGISTER_MASK as u8 {
                0
            } else {
                x[usize::from(register)]
            };
        }
        Instruction::AuthenticateSpPc { key, offset } => {
            operands.key = key;
            operands.modifier2 = pc.wrapping_sub(u64::from(offset));
        }
        Instruction::SignSpPc { key, implicit_bti } => {
            operands.key = key;
            operands.action = Action::Sign;
            operands.implicit_bti = implicit_bti;
        }
        Instruction::ReturnSpRegister { key, register } => {
            operands.key = key;
            operands.action = Action::Return;
            operands.modifier2 = x[usize::from(register)];
            operands.destination = None;
        }
        Instruction::ReturnSpPc { key, offset } => {
            operands.key = key;
            operands.action = Action::Return;
            operands.modifier2 = pc.wrapping_sub(u64::from(offset));
            operands.destination = None;
        }
    }
    Ok(Staged::Pointer(operands))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum FeatureEffect {
    Execute,
    NoEffect,
    Undefined,
}

/// PACM alone is a HINT NOP when FEAT_PAuth_LR is absent.
#[cfg(test)]
pub const fn feature_effect(instruction: Instruction, present: bool) -> FeatureEffect {
    if present {
        FeatureEffect::Execute
    } else if matches!(instruction, Instruction::Pacm) {
        FeatureEffect::NoEffect
    } else {
        FeatureEffect::Undefined
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum PacmEffect {
    NoEffect,
    Set(bool),
}

/// Pure state effect after the system owner resolves IsPACMEnabled from the
/// selected current EL/SCTLR2/HCRX controls. No state ownership is conferred.
#[cfg(test)]
pub const fn pacm_effect(feature_present: bool, enabled: bool) -> PacmEffect {
    if feature_present {
        PacmEffect::Set(enabled)
    } else {
        PacmEffect::NoEffect
    }
}

#[cfg(test)]
mod tests;
