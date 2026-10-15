use super::*;
use crate::memory::tags::{AllocationTag, TagGenerationState, TagRandomization};
use crate::system::debug::DebugControls;
use crate::system::profile::{ScalableEntryAbsence, SystemEntryFeatures};
use crate::system::pstate::MteFeature;
use crate::system::state::{
    El1Registers, MteState, PSTATE_EL0T, PSTATE_IL_MASK, PSTATE_SS_MASK, StackBank,
};

const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const MDSCR_SOFTWARE_STEP: u64 = 1;
const MDSCR_KERNEL_DEBUG_ENABLE: u64 = 1 << 13;
const MDSCR_MONITOR_DEBUG_ENABLE: u64 = 1 << 15;
const SP0: u64 = 0x1000;
const SP1: u64 = 0x2000;
const SOURCE_PC: u64 = 0x4000;
const FLAGS: u32 = 0xa000_0000;

fn features() -> EntryProfile {
    EntryProfile::base(
        SystemEntryFeatures::declared_absent(),
        ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
    )
    .unwrap()
}

fn entry() -> EntryControls {
    EntryControls {
        tcr_el1: 0,
        mdscr_el1: 0,
        debug: DebugControls {
            halted: false,
            ignore_traps_in_debug: false,
            halting_allowed: false,
            edscr_tda: false,
            os_locked: false,
            breakpoint_count: 0,
            watchpoint_count: 0,
            raw_bank: 0,
            effective_bank: 0,
        },
    }
}

fn controls() -> FixedEl1Controls {
    FixedEl1Controls::new(
        features(),
        crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
        0,
        entry(),
    )
    .unwrap()
}

fn state(mode: u64) -> (SystemState, GuestState) {
    let sp1_active = mode & PSTATE_MODE_MASK == PSTATE_EL1H;
    (
        SystemState::new(
            mode,
            if sp1_active { SP0 } else { SP1 },
            El1Registers::new(SOURCE_PC, PSTATE_EL1H, 0, 0, 0),
        )
        .unwrap(),
        GuestState {
            sp: if sp1_active { SP1 } else { SP0 },
            nzcv: FLAGS,
            ..GuestState::default()
        },
    )
}

fn request(effects: RequiredEffects) -> ServiceRequest {
    ServiceRequest {
        effects,
        profile: own_el1_profile(),
        source_el: ExceptionLevel::El1,
        source_pstate: PSTATE_EL1H | u64::from(FLAGS),
        source_pc: SOURCE_PC,
        controls: entry(),
    }
}

#[test]
fn constructor_checks_actual_mmu_tbi_debug_controls() {
    assert_eq!(
        FixedEl1Controls::new(
            features(),
            crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
            SCTLR_MMU_ENABLE,
            entry()
        )
        .unwrap_err(),
        FixedControlsError::MmuEnabled
    );
    for tbi in [TCR_TBI0, TCR_TBI1, TCR_TBI0 | TCR_TBI1] {
        let entry = EntryControls {
            tcr_el1: tbi,
            ..entry()
        };
        assert!(matches!(
            FixedEl1Controls::new(
                features(),
                crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                0,
                entry
            ),
            Err(FixedControlsError::EntryControls(_))
        ));
    }
    for debug in [
        MDSCR_SOFTWARE_STEP,
        MDSCR_KERNEL_DEBUG_ENABLE,
        MDSCR_MONITOR_DEBUG_ENABLE,
    ] {
        let entry = EntryControls {
            mdscr_el1: debug,
            ..entry()
        };
        assert!(matches!(
            FixedEl1Controls::new(
                features(),
                crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                0,
                entry
            ),
            Err(FixedControlsError::EntryControls(_))
        ));
    }
    for halted in [false, true] {
        for halting_allowed in [false, true] {
            let mut entry = entry();
            entry.debug.halted = halted;
            entry.debug.halting_allowed = halting_allowed;
            let result = FixedEl1Controls::new(
                features(),
                crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                0,
                entry,
            );
            assert_eq!(result.is_ok(), !halted && !halting_allowed);
        }
    }
}

#[test]
fn getters_preserve_declared_controls_without_mutable_access() {
    let sctlr = !SCTLR_MMU_ENABLE;
    let owner = FixedEl1Controls::new(
        features(),
        crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
        sctlr,
        entry(),
    )
    .unwrap();
    assert_eq!(owner.sctlr_el1(), sctlr);
    assert_eq!(owner.entry_controls(), entry());
    assert_eq!(owner.entry_profile(), features());
}

#[test]
fn snapshots_read_actual_state_without_copying_its_authority() {
    let owner = controls();
    for mode in [PSTATE_EL1T, PSTATE_EL1H] {
        let (mut system, mut registers) = state(mode | DAIF_MASK);
        let before = (system.clone(), registers.clone());
        let snapshot = owner.entry_snapshot(&system, &registers).unwrap();
        assert_eq!(snapshot.profile, own_el1_profile());
        assert_eq!(snapshot.features, features());
        assert_eq!(snapshot.controls, entry());
        assert_eq!((system.clone(), registers.clone()), before);
        registers.nzcv = u32::MAX;
        system.set_spsel(&mut registers, StackBank::El0).unwrap();
        assert!(owner.entry_snapshot(&system, &registers).is_ok());
        assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
        assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
        assert_eq!(
            system.pstate(&registers),
            PSTATE_EL1T | DAIF_MASK | NZCV_MASK
        );
    }
}

#[test]
fn snapshots_reject_el0_step_il_and_optional_state() {
    let owner = controls();
    for mode in [
        PSTATE_EL0T,
        PSTATE_EL1H | PSTATE_SS_MASK,
        PSTATE_EL1T | PSTATE_IL_MASK,
    ] {
        let (system, registers) = state(mode);
        assert!(owner.entry_snapshot(&system, &registers).is_err());
    }
    let system = SystemState::new_with_mte(
        PSTATE_EL1H,
        SP0,
        El1Registers::new(0, 0, 0, 0, 0),
        MteFeature::TwoOrLater,
        MteState::new(
            0,
            TagRandomization::ArchitecturalLfsr,
            TagGenerationState {
                seed: 0,
                tag: AllocationTag::new(0).unwrap(),
            },
        ),
    )
    .unwrap();
    assert!(matches!(
        owner.entry_snapshot(&system, &GuestState::default()),
        Err(FixedControlsError::MteState)
    ));
}

#[test]
fn source_pstate_rejects_every_out_of_scope_bit_and_mode() {
    for mode in 0..=PSTATE_MODE_MASK {
        assert_eq!(
            check_source_pstate(mode).is_ok(),
            [PSTATE_EL1T, PSTATE_EL1H].contains(&mode)
        );
    }
    for bit in 0..u64::BITS {
        let value = 1u64 << bit;
        if value & SOURCE_PSTATE_MASK == 0 {
            assert_eq!(
                check_source_pstate(PSTATE_EL1H | value),
                Err(FixedControlsError::UnsupportedPstate(value))
            );
        }
    }
}

#[test]
fn exception_requests_require_exact_profile_level_controls_and_non_irq_effects() {
    let owner = controls();
    for effect in [
        RequiredEffects::Entry { irq: false },
        RequiredEffects::Return,
    ] {
        assert_eq!(owner.check_exception_request(&request(effect)), Ok(()));
    }
    let base = request(RequiredEffects::Return);
    for profile in [
        Profile {
            current_el: ExceptionLevel::El0,
            ..base.profile
        },
        Profile {
            security: SecurityState::Secure,
            ..base.profile
        },
        Profile {
            el2_enabled: true,
            ..base.profile
        },
        Profile {
            el3_present: true,
            ..base.profile
        },
    ] {
        assert_eq!(
            owner.check_exception_request(&ServiceRequest { profile, ..base }),
            Err(FixedControlsError::ProfileMismatch)
        );
    }
    assert_eq!(
        owner.check_exception_request(&ServiceRequest {
            source_el: ExceptionLevel::El0,
            ..base
        }),
        Err(FixedControlsError::SourceLevelMismatch)
    );
    let different = EntryControls {
        tcr_el1: 1,
        ..entry()
    };
    assert_eq!(
        owner.check_exception_request(&ServiceRequest {
            controls: different,
            ..base
        }),
        Err(FixedControlsError::ControlsMismatch)
    );
    assert_eq!(
        owner.check_exception_request(&request(RequiredEffects::Entry { irq: true })),
        Err(FixedControlsError::InterruptEntry)
    );
    for source_pstate in [
        PSTATE_EL0T,
        PSTATE_EL1H | PSTATE_SS_MASK,
        PSTATE_EL1T | PSTATE_IL_MASK,
    ] {
        assert!(
            owner
                .check_exception_request(&ServiceRequest {
                    source_pstate,
                    ..base
                })
                .is_err()
        );
    }
}

#[test]
fn return_scope_checks_saved_mode_before_any_mutation() {
    let owner = controls();
    for current_mode in [PSTATE_EL1T, PSTATE_EL1H] {
        let (mut system, registers) = state(current_mode);
        for saved_mode in 0..=PSTATE_MODE_MASK {
            system
                .el1_registers_mut()
                .set_spsr(saved_mode | NZCV_MASK | DAIF_MASK | PSTATE_IL_MASK);
            let before = system.clone();
            assert_eq!(
                owner.validate_return(&system).is_ok(),
                [PSTATE_EL1T, PSTATE_EL1H].contains(&saved_mode)
            );
            assert_eq!(system, before);
            assert_eq!(registers.nzcv, FLAGS);
        }
    }
    let (system, _) = state(PSTATE_EL0T);
    assert_eq!(
        owner.validate_return(&system),
        Err(FixedControlsError::SourceLevelMismatch)
    );
}

#[test]
fn tbi_off_branch_preserves_all_bits_and_rejects_other_levels() {
    let owner = controls();
    for target in [0, 1, SOURCE_PC, u64::MAX, 1 << 63] {
        assert_eq!(
            owner.branch_address(target, ExceptionLevel::El1),
            Ok(target)
        );
        for level in [
            ExceptionLevel::El0,
            ExceptionLevel::El2,
            ExceptionLevel::El3,
        ] {
            assert_eq!(
                owner.branch_address(target, level),
                Err(FixedControlsError::UnsupportedDestination(level))
            );
        }
    }
}
