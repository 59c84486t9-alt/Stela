//! EL0/EL1 system-register access decisions over the exception registers.
pub(crate) mod vbar;

use crate::system::{
    access::{
        AccessKind, Encoding, ExceptionLevel, Profile, Request, Resolution, SecurityState, Trap,
    },
    state::{El1Registers, PSTATE_IL_MASK, SystemState},
};

const ZERO_REGISTER: u8 = 31;
const SYSTEM_REGISTER_OP0: u8 = 0b11;
const EL1_REGISTER_OP1: u8 = 0b000;
const NVX_MASK: u8 = 0b111;
const NV_TRAP: u8 = 0b011;
const NV_MEMORY: u8 = 0b111;
const NV_LOW_MASK: u8 = 0b011;
const VECTOR_ALIGNMENT_MASK: u64 = (1 << 11) - 1;
const ELR_NVMEM: u16 = 0x230;
const SPSR_NVMEM: u16 = 0x160;
const ESR_NVMEM: u16 = 0x138;
const FAR_NVMEM: u16 = 0x220;
const VBAR_NVMEM: u16 = 0x250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Elr,
    Spsr,
    Esr,
    Far,
    Vbar,
}
impl Register {
    pub const ALL: [Self; 5] = [Self::Elr, Self::Spsr, Self::Esr, Self::Far, Self::Vbar];
    pub const fn encoding(self) -> Encoding {
        let (crn, crm, op2) = match self {
            Self::Elr => (4, 0, 1),
            Self::Spsr => (4, 0, 0),
            Self::Esr => (5, 2, 0),
            Self::Far => (6, 0, 0),
            Self::Vbar => (12, 0, 0),
        };
        Encoding::new(SYSTEM_REGISTER_OP0, EL1_REGISTER_OP1, crn, crm, op2)
    }
    pub fn decode(encoding: Encoding) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|register| register.encoding() == encoding)
    }
    const fn nested_offset(self) -> u16 {
        match self {
            Self::Elr => ELR_NVMEM,
            Self::Spsr => SPSR_NVMEM,
            Self::Esr => ESR_NVMEM,
            Self::Far => FAR_NVMEM,
            Self::Vbar => VBAR_NVMEM,
        }
    }
    fn value(self, bank: &El1Registers) -> u64 {
        match self {
            Self::Elr => bank.elr(),
            Self::Spsr => bank.spsr(),
            Self::Esr => bank.esr(),
            Self::Far => bank.far(),
            Self::Vbar => bank.vbar(),
        }
    }
}

/// Selected effective FGT bits; this snapshot stores no architectural values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FineGrainedTraps {
    pub esr: bool,
    pub far: bool,
    pub vbar: bool,
}
impl FineGrainedTraps {
    const fn selected(self, register: Register) -> bool {
        match register {
            Register::Esr => self.esr,
            Register::Far => self.far,
            Register::Vbar => self.vbar,
            Register::Elr | Register::Spsr => false,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Controls {
    pub effective_nvx: u8,
    pub hcr_trvm: bool,
    pub hcr_tvm: bool,
    pub scr_fgt_enabled: bool,
    pub read_traps: FineGrainedTraps,
    pub write_traps: FineGrainedTraps,
    pub current_exlock_enabled: bool,
    pub halted: bool,
    pub pstate_exlock: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub aa64: bool,
    pub gcs: bool,
    pub fine_grained_traps: bool,
    /// Missing controls decline only once the source's EL1 path needs them.
    pub controls: Option<Controls>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Elr(u64),
    Far(u64),
    Vbar(u64),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRequest {
    State(Effect),
    ControlsRequired(Request),
    ExlockException(Request),
    NestedMemory {
        offset: u16,
        request: Request,
    },
    /// SPSR/ESR have feature/EC-dependent reserved and writable fields. This
    /// source-reviewed access leaf does not invent a universal write mask.
    RegisterFields {
        register: Register,
        request: Request,
    },
}

pub fn resolve(
    request: Request,
    context: &Context,
    state: &SystemState,
) -> Resolution<BackendRequest> {
    let Some(register) = Register::decode(request.encoding) else {
        return Resolution::NotHandled;
    };
    if state.pstate_misc() & PSTATE_IL_MASK != 0 {
        return Resolution::Unsupported("illegal execution state requires its exception owner");
    }
    if request.rt > ZERO_REGISTER {
        return Resolution::Unsupported("EL1 register Rt exceeds five bits");
    }
    if context.profile.current_el != state.current_el() {
        return Resolution::Unsupported("EL1 register context differs from actual PSTATE.EL");
    }
    if !context.aa64 || context.profile.current_el == ExceptionLevel::El0 {
        return Resolution::Undefined;
    }
    if context.profile.current_el != ExceptionLevel::El1
        || context.profile.security != SecurityState::NonSecure
    {
        return Resolution::Unsupported("EL1 register bank requires NonSecure EL1 ownership");
    }
    let Some(controls) = context.controls else {
        return Resolution::BackendRequired(BackendRequest::ControlsRequired(request));
    };
    if controls.effective_nvx > NVX_MASK
        || (!context.profile.el2_enabled && controls.effective_nvx != 0)
    {
        return Resolution::Unsupported("effective nested controls differ from EL2 availability");
    }
    let write = matches!(request.kind, AccessKind::Write { .. });
    if write
        && matches!(register, Register::Elr | Register::Spsr)
        && context.gcs
        && controls.current_exlock_enabled
        && !controls.halted
        && controls.pstate_exlock
        && controls.effective_nvx & NV_LOW_MASK != NV_LOW_MASK
    {
        return Resolution::BackendRequired(BackendRequest::ExlockException(request));
    }
    if matches!(register, Register::Elr | Register::Spsr | Register::Vbar)
        && controls.effective_nvx == NV_TRAP
    {
        return Resolution::Trap(Trap::system_access(ExceptionLevel::El2));
    }
    if matches!(register, Register::Esr | Register::Far)
        && context.profile.el2_enabled
        && if write {
            controls.hcr_tvm
        } else {
            controls.hcr_trvm
        }
    {
        return Resolution::Trap(Trap::system_access(ExceptionLevel::El2));
    }
    let fgt_enabled = context.profile.el2_enabled
        && context.fine_grained_traps
        && (!context.profile.el3_present || controls.scr_fgt_enabled);
    let trap_bits = if write {
        controls.write_traps
    } else {
        controls.read_traps
    };
    if fgt_enabled && trap_bits.selected(register) {
        return Resolution::Trap(Trap::system_access(ExceptionLevel::El2));
    }
    if controls.effective_nvx == NV_MEMORY {
        return Resolution::BackendRequired(BackendRequest::NestedMemory {
            offset: register.nested_offset(),
            request,
        });
    }
    if matches!(register, Register::Spsr | Register::Esr) {
        return Resolution::BackendRequired(BackendRequest::RegisterFields { register, request });
    }
    match request.write_value() {
        None => {
            let value = register.value(state.el1_registers());
            Resolution::Read(if register == Register::Vbar {
                value & !VECTOR_ALIGNMENT_MASK
            } else {
                value
            })
        }
        Some(value) => {
            let effect = match register {
                Register::Elr => Effect::Elr(value),
                Register::Far => Effect::Far(value),
                Register::Vbar if value & VECTOR_ALIGNMENT_MASK == 0 => Effect::Vbar(value),
                _ => {
                    return Resolution::BackendRequired(BackendRequest::RegisterFields {
                        register,
                        request,
                    });
                }
            };
            Resolution::BackendRequired(BackendRequest::State(effect))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    IllegalExecutionState,
    WrongExceptionLevel,
    UnalignedVectorBase,
}
/// Commit an authorized direct effect to the existing sole bank. The caller
/// retains source/control authorization through this synchronous exclusive loan.
pub fn commit(effect: Effect, state: &mut SystemState) -> Result<(), CommitError> {
    if state.pstate_misc() & PSTATE_IL_MASK != 0 {
        return Err(CommitError::IllegalExecutionState);
    }
    if state.current_el() != ExceptionLevel::El1 {
        return Err(CommitError::WrongExceptionLevel);
    }
    if let Effect::Vbar(value) = effect
        && value & VECTOR_ALIGNMENT_MASK != 0
    {
        return Err(CommitError::UnalignedVectorBase);
    }
    let bank = state.el1_registers_mut();
    match effect {
        Effect::Elr(value) => bank.set_elr(value),
        Effect::Far(value) => bank.set_far(value),
        Effect::Vbar(value) => bank.set_vbar(value),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
