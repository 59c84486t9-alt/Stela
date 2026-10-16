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
mod tests {
    use super::*;
    use crate::system::{
        access::{ExceptionLevel, Profile, SecurityState},
        state::{El1Registers, PSTATE_EL1H, PSTATE_IL_MASK},
    };
    const SOURCE_PC: GuestAddress = GuestAddress(0x1000);
    const MSR_VBAR_X10: u32 = 0xd518_c00a;
    const MRS_VBAR_X11: u32 = 0xd538_c00b;
    const MSR_ELR_X10: u32 = 0xd518_402a;
    const DESTINATION_MASK: u32 = 0x1f;
    const VECTOR_BASE: u64 = 0x8000;
    fn state() -> SystemState {
        SystemState::new(
            PSTATE_EL1H,
            0x1234,
            El1Registers::new(1, 2, 3, 4, VECTOR_BASE),
        )
        .unwrap()
    }
    fn context() -> Context {
        let traps = super::super::FineGrainedTraps {
            esr: false,
            far: false,
            vbar: false,
        };
        Context {
            profile: Profile {
                current_el: ExceptionLevel::El1,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            aa64: true,
            gcs: false,
            fine_grained_traps: false,
            controls: Some(super::super::Controls {
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
    fn instruction(word: u32) -> SystemInstruction {
        stela_compiler::block::system::decode_system_instruction(SOURCE_PC, word)
            .unwrap()
            .unwrap()
    }
    fn staged(word: u32, system: &SystemState, registers: &GuestState) -> StagedEl1Vbar {
        let Preparation::Staged(stage) = prepare(
            instruction(word),
            SOURCE_PC,
            word,
            &context(),
            system,
            registers,
        )
        .unwrap() else {
            panic!("expected direct VBAR stage")
        };
        stage
    }
    #[test]
    fn aligned_write_and_read_stage_exact_values_without_mutating_owned_banks() {
        let system = state();
        let mut registers = GuestState::default();
        registers.x[10] = 0x10000;
        let before = (system.clone(), registers.clone());
        let write = staged(MSR_VBAR_X10, &system, &registers);
        assert_eq!(write.instruction(), instruction(MSR_VBAR_X10));
        assert_eq!(write.kind(), Kind::Write);
        assert_eq!(write.destination(), None);
        assert_eq!(write.value(), registers.x[10]);
        let read = staged(MRS_VBAR_X11, &system, &registers);
        assert_eq!(read.kind(), Kind::Read { destination: 11 });
        assert_eq!(read.destination(), Some(11));
        assert_eq!(read.value(), VECTOR_BASE);
        assert_eq!((system, registers), before);
    }
    #[test]
    fn zero_register_is_architectural_discard_or_zero_operand_never_active_sp() {
        let system = state();
        let registers = GuestState {
            sp: 0x12345,
            ..GuestState::default()
        };
        let read = (MRS_VBAR_X11 & !DESTINATION_MASK) | u32::from(ZERO_REGISTER);
        assert_eq!(
            staged(read, &system, &registers).destination(),
            Some(ZERO_REGISTER)
        );
        let write = (MSR_VBAR_X10 & !DESTINATION_MASK) | u32::from(ZERO_REGISTER);
        assert_eq!(staged(write, &system, &registers).value(), 0);
    }
    #[test]
    fn missing_context_unaligned_write_il_and_other_register_remain_uncompleted() {
        let system = state();
        let mut registers = GuestState::default();
        registers.x[10] = VECTOR_BASE | 1;
        assert!(matches!(
            prepare(
                instruction(MSR_VBAR_X10),
                SOURCE_PC,
                MSR_VBAR_X10,
                &context(),
                &system,
                &registers
            ),
            Ok(Preparation::Uncompleted {
                decision: Resolution::BackendRequired(BackendRequest::RegisterFields { .. }),
                ..
            })
        ));
        let mut missing = context();
        missing.controls = None;
        assert!(matches!(
            prepare(
                instruction(MRS_VBAR_X11),
                SOURCE_PC,
                MRS_VBAR_X11,
                &missing,
                &system,
                &registers
            ),
            Ok(Preparation::Uncompleted {
                decision: Resolution::BackendRequired(BackendRequest::ControlsRequired(_)),
                ..
            })
        ));
        let illegal = SystemState::new(
            PSTATE_EL1H | PSTATE_IL_MASK,
            0,
            El1Registers::new(0, 0, 0, 0, 0),
        )
        .unwrap();
        assert!(matches!(
            prepare(
                instruction(MRS_VBAR_X11),
                SOURCE_PC,
                MRS_VBAR_X11,
                &context(),
                &illegal,
                &registers
            ),
            Ok(Preparation::Uncompleted {
                decision: Resolution::Unsupported(_),
                ..
            })
        ));
        assert!(matches!(
            prepare(
                instruction(MSR_ELR_X10),
                SOURCE_PC,
                MSR_ELR_X10,
                &context(),
                &system,
                &registers
            ),
            Ok(Preparation::Uncompleted {
                decision: Resolution::NotHandled,
                ..
            })
        ));
        assert_eq!(
            prepare(
                instruction(MRS_VBAR_X11),
                SOURCE_PC,
                MSR_VBAR_X10,
                &context(),
                &system,
                &registers
            ),
            Err(SourceError::WrongSource)
        );
    }
}
