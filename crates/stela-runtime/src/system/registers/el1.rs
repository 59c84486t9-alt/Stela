//! Exact EL0/EL1 access decisions over SystemState's sole exception-register owner.
//! Feature/access checks precede readbacks or unapplied typed writes. Optional
//! field policies, EXLOCK delivery and nested memory never become a shadow bank.
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
mod tests {
    use super::*;
    use crate::system::state::{PSTATE_EL0T, PSTATE_EL1H};
    fn state(mode: u64) -> SystemState {
        SystemState::new(mode, 0x1000, El1Registers::new(1, 2, 3, 4, 0x8000)).unwrap()
    }
    fn context(el: ExceptionLevel) -> Context {
        let traps = FineGrainedTraps {
            esr: false,
            far: false,
            vbar: false,
        };
        Context {
            profile: Profile {
                current_el: el,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            aa64: true,
            gcs: false,
            fine_grained_traps: false,
            controls: Some(Controls {
                effective_nvx: 0,
                hcr_trvm: false,
                hcr_tvm: false,
                scr_fgt_enabled: false,
                read_traps: traps,
                write_traps: traps,
                current_exlock_enabled: false,
                halted: false,
                pstate_exlock: false,
            }),
        }
    }
    #[test]
    fn source_el0_undefined_precedes_unavailable_controls_even_for_xzr() {
        let state = state(PSTATE_EL0T);
        let mut context = context(ExceptionLevel::El0);
        context.controls = None;
        for register in Register::ALL {
            for request in [
                Request::read(register.encoding(), ZERO_REGISTER),
                Request::write(register.encoding(), ZERO_REGISTER, u64::MAX),
            ] {
                assert_eq!(resolve(request, &context, &state), Resolution::Undefined);
            }
        }
    }
    #[test]
    fn illegal_execution_state_precedes_access_and_blocks_every_direct_effect() {
        let mut state = state(PSTATE_EL1H | PSTATE_IL_MASK);
        let before = state.clone();
        let mut context = context(ExceptionLevel::El0);
        context.controls = None;
        for register in Register::ALL {
            for request in [
                Request::read(register.encoding(), ZERO_REGISTER),
                Request::write(register.encoding(), ZERO_REGISTER, u64::MAX),
            ] {
                assert_eq!(
                    resolve(request, &context, &state),
                    Resolution::Unsupported("illegal execution state requires its exception owner")
                );
                assert_eq!(state, before);
            }
        }
        for effect in [Effect::Elr(5), Effect::Far(6), Effect::Vbar(0x9000)] {
            assert_eq!(
                commit(effect, &mut state),
                Err(CommitError::IllegalExecutionState)
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn direct_effects_update_only_the_existing_named_register() {
        for (register, value) in [
            (Register::Elr, u64::MAX),
            (Register::Far, 0x5678),
            (Register::Vbar, 0x9000),
        ] {
            let mut state = state(PSTATE_EL1H);
            let before = state.clone();
            let request = Request::write(register.encoding(), 2, value);
            let Resolution::BackendRequired(BackendRequest::State(effect)) =
                resolve(request, &context(ExceptionLevel::El1), &state)
            else {
                panic!("direct effect");
            };
            commit(effect, &mut state).unwrap();
            assert_eq!(register.value(state.el1_registers()), value);
            for other in Register::ALL {
                if other != register {
                    assert_eq!(
                        other.value(state.el1_registers()),
                        other.value(before.el1_registers())
                    );
                }
            }
        }
    }
    #[test]
    fn exlock_precedes_elr_nested_memory_and_traps_in_source_order() {
        let state = state(PSTATE_EL1H);
        let mut context = context(ExceptionLevel::El1);
        context.profile.el2_enabled = true;
        context.gcs = true;
        let controls = context.controls.as_mut().unwrap();
        controls.current_exlock_enabled = true;
        controls.pstate_exlock = true;
        let request = Request::write(Register::Elr.encoding(), 0, 1);
        assert_eq!(
            resolve(request, &context, &state),
            Resolution::BackendRequired(BackendRequest::ExlockException(request))
        );
        context.controls.as_mut().unwrap().effective_nvx = NV_TRAP;
        assert_eq!(
            resolve(request, &context, &state),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
        );
        context.controls.as_mut().unwrap().effective_nvx = NV_MEMORY;
        assert_eq!(
            resolve(request, &context, &state),
            Resolution::BackendRequired(BackendRequest::NestedMemory {
                offset: ELR_NVMEM,
                request
            })
        );
    }
    #[test]
    fn field_and_forged_effect_requirements_never_silently_mask_writes() {
        let mut state = state(PSTATE_EL1H);
        let before = state.clone();
        for register in [Register::Spsr, Register::Esr] {
            let request = Request::write(register.encoding(), 0, u64::MAX);
            assert_eq!(
                resolve(request, &context(ExceptionLevel::El1), &state),
                Resolution::BackendRequired(BackendRequest::RegisterFields { register, request })
            );
        }
        assert_eq!(
            commit(Effect::Vbar(1), &mut state),
            Err(CommitError::UnalignedVectorBase)
        );
        assert_eq!(state, before);
    }
}

#[cfg(test)]
mod ordering_tests {
    use super::*;
    use crate::system::state::PSTATE_EL1H;

    fn inputs() -> (SystemState, Context) {
        let state =
            SystemState::new(PSTATE_EL1H, 0, El1Registers::new(1, 2, 3, 4, 0x8123)).unwrap();
        let no_traps = FineGrainedTraps {
            esr: false,
            far: false,
            vbar: false,
        };
        let context = Context {
            profile: Profile {
                current_el: ExceptionLevel::El1,
                security: SecurityState::NonSecure,
                el2_enabled: true,
                el3_present: true,
            },
            aa64: true,
            gcs: false,
            fine_grained_traps: true,
            controls: Some(Controls {
                effective_nvx: NV_MEMORY,
                hcr_trvm: false,
                hcr_tvm: false,
                scr_fgt_enabled: true,
                read_traps: no_traps,
                write_traps: no_traps,
                current_exlock_enabled: false,
                halted: false,
                pstate_exlock: false,
            }),
        };
        (state, context)
    }

    #[test]
    fn vm_and_direction_specific_fgt_traps_precede_nested_redirection() {
        let (state, mut context) = inputs();
        let read = Request::read(Register::Esr.encoding(), ZERO_REGISTER);
        let write = Request::write(Register::Esr.encoding(), ZERO_REGISTER, u64::MAX);
        context.controls.as_mut().unwrap().hcr_trvm = true;
        assert_eq!(
            resolve(read, &context, &state),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
        );
        assert_eq!(
            resolve(write, &context, &state),
            Resolution::BackendRequired(BackendRequest::NestedMemory {
                offset: ESR_NVMEM,
                request: write
            })
        );
        context.controls.as_mut().unwrap().hcr_trvm = false;
        context.controls.as_mut().unwrap().read_traps.esr = true;
        assert_eq!(
            resolve(read, &context, &state),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
        );
        context.controls.as_mut().unwrap().scr_fgt_enabled = false;
        assert_eq!(
            resolve(read, &context, &state),
            Resolution::BackendRequired(BackendRequest::NestedMemory {
                offset: ESR_NVMEM,
                request: read
            })
        );
    }

    #[test]
    fn vector_read_res0_does_not_authorize_masking_an_unknown_write_policy() {
        let (state, mut context) = inputs();
        context.controls.as_mut().unwrap().effective_nvx = 0;
        assert_eq!(
            resolve(
                Request::read(Register::Vbar.encoding(), 2),
                &context,
                &state
            ),
            Resolution::Read(0x8000)
        );
        let write = Request::write(Register::Vbar.encoding(), 2, 0x8123);
        assert_eq!(
            resolve(write, &context, &state),
            Resolution::BackendRequired(BackendRequest::RegisterFields {
                register: Register::Vbar,
                request: write
            })
        );
    }

    #[test]
    fn missing_controls_and_profile_mismatch_cannot_return_bank_values() {
        let (state, mut context) = inputs();
        let request = Request::read(Register::Far.encoding(), 0);
        context.controls = None;
        assert_eq!(
            resolve(request, &context, &state),
            Resolution::BackendRequired(BackendRequest::ControlsRequired(request))
        );
        context.profile.current_el = ExceptionLevel::El0;
        assert!(matches!(
            resolve(request, &context, &state),
            Resolution::Unsupported(_)
        ));
    }
}
