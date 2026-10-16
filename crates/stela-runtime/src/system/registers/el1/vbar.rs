//! VBAR_EL1 writes.
use super::{BackendRequest, Context, Effect, Register, resolve};
use crate::system::{
    access::{Request, Resolution},
    state::SystemState,
};
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::system::registers::Direction,
    block::system::{SystemInstruction, SystemOperation},
};

const ZERO_REGISTER: u8 = 31;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceError {
    WrongSource,
    NotRegister,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Read { destination: u8 },
    Write,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StagedEl1Vbar {
    instruction: SystemInstruction,
    kind: Kind,
    value: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Preparation {
    Staged(StagedEl1Vbar),
    Uncompleted {
        request: Request,
        decision: Resolution<BackendRequest>,
    },
}

/// Re-validate the source before reading its register operand. EL1 access
/// priority, alignment and NV/FGT behavior come from the shared resolver. Any
/// other register is a family miss.
pub(crate) fn prepare(
    instruction: SystemInstruction,
    source_pc: GuestAddress,
    source_word: u32,
    context: &Context,
    system: &SystemState,
    registers: &GuestState,
) -> Result<Preparation, SourceError> {
    if !instruction.matches_source(source_pc, source_word) {
        return Err(SourceError::WrongSource);
    }
    let SystemOperation::Register(access) = instruction.operation else {
        return Err(SourceError::NotRegister);
    };
    let request = match access.direction() {
        Direction::Read => Request::read(access.encoding(), access.rt()),
        Direction::Write => Request::write(
            access.encoding(),
            access.rt(),
            if access.rt() == ZERO_REGISTER {
                0
            } else {
                registers.x[usize::from(access.rt())]
            },
        ),
    };
    if access.encoding() != Register::Vbar.encoding() {
        return Ok(Preparation::Uncompleted {
            request,
            decision: Resolution::NotHandled,
        });
    }
    let decision = resolve(request, context, system);
    let selected = match decision {
        Resolution::Read(value) => StagedEl1Vbar {
            instruction,
            kind: Kind::Read {
                destination: access.rt(),
            },
            value,
        },
        Resolution::BackendRequired(BackendRequest::State(Effect::Vbar(value))) => StagedEl1Vbar {
            instruction,
            kind: Kind::Write,
            value,
        },
        decision => return Ok(Preparation::Uncompleted { request, decision }),
    };
    Ok(Preparation::Staged(selected))
}
impl StagedEl1Vbar {
    pub(crate) const fn instruction(&self) -> SystemInstruction {
        self.instruction
    }
    pub(crate) const fn kind(&self) -> Kind {
        self.kind
    }
    pub(crate) const fn destination(&self) -> Option<u8> {
        match self.kind {
            Kind::Read { destination } => Some(destination),
            Kind::Write => None,
        }
    }
    pub(crate) const fn value(&self) -> u64 {
        self.value
    }
    /// The token binds the instruction, kind, destination, value, state,
    /// context, source and attempt before retirement starts. Applying it cannot
    /// fail and does not store PC.
    pub(crate) fn apply(
        self,
        mut loan: crate::blocks::retirement::checked::el1_system::El1SystemEffectLoan<'_>,
    ) -> GuestAddress {
        match self.kind {
            Kind::Write => loan.write_vbar_authorized(self.value),
            Kind::Read { destination } => loan.write_register_authorized(destination, self.value),
        }
        self.instruction.next_pc
    }
}

#[cfg(test)]
mod tests;
