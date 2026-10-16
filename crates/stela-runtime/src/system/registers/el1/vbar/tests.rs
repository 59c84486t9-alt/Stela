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
