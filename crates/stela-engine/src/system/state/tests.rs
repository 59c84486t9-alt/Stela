use super::*;
use crate::memory::tags::AllocationTag;

mod pacm {
    use super::*;

    const FLAGS: u32 = 0xa000_0000;
    const INITIAL_SP: u64 = 0x2000;
    const INACTIVE_SP: u64 = 0x3000;
    const BTYPE_MASK: u64 = 3 << 10;

    fn el1() -> El1Registers {
        El1Registers::new(1, 2, 3, 4, 5)
    }

    #[test]
    fn absent_storage_refuses_pacm_and_updates_without_mutation() {
        assert!(SystemState::new(PSTATE_PACM_MASK, INACTIVE_SP, el1()).is_err());
        let mut state = SystemState::new(PSTATE_EL1H, INACTIVE_SP, el1()).unwrap();
        let before = state.clone();
        assert_eq!(
            state.set_pacm(Pacm::One),
            Err(StateError::UnsupportedPacmProfile)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn explicit_initial_pacm_has_no_inferred_reset_or_btype() {
        for initial in [0, PSTATE_PACM_MASK] {
            let state = SystemState::new_with_pacm(
                PSTATE_EL1H | initial,
                INACTIVE_SP,
                el1(),
                PacmStateFeature::Full,
            )
            .unwrap();
            assert_eq!(state.pstate_misc(), PSTATE_EL1H | initial);
            assert_eq!(state.pacm().bit(), initial != 0);
        }
        assert!(
            SystemState::new_with_pacm(
                PSTATE_EL1H | BTYPE_MASK,
                INACTIVE_SP,
                el1(),
                PacmStateFeature::Full,
            )
            .is_err()
        );
    }

    #[test]
    fn pacm_updates_preserve_original_pstate_flags_stacks_and_registers() {
        let mut state = SystemState::new_with_pacm(
            PSTATE_EL1H | DAIF_MASK,
            INACTIVE_SP,
            el1(),
            PacmStateFeature::Full,
        )
        .unwrap();
        let registers = GuestState {
            nzcv: FLAGS,
            sp: INITIAL_SP,
            ..GuestState::default()
        };
        let original_registers = registers.clone();
        for value in [Pacm::One, Pacm::Zero] {
            state.set_pacm(value).unwrap();
            assert_eq!(
                state.pstate(&registers),
                PSTATE_EL1H | DAIF_MASK | u64::from(FLAGS) | value.pstate_bits()
            );
            assert_eq!(state.stack_pointer(StackBank::El0, &registers), INACTIVE_SP);
            assert_eq!(registers, original_registers);
            assert_eq!(state.el1_registers(), &el1());
        }
    }

    #[test]
    fn state_transition_stores_authorized_value_without_resolving_controls() {
        let mut state = SystemState::new_with_pacm(
            PSTATE_EL1H | PSTATE_PACM_MASK,
            INACTIVE_SP,
            el1(),
            PacmStateFeature::Full,
        )
        .unwrap();
        let mut registers = GuestState {
            nzcv: FLAGS,
            sp: INITIAL_SP,
            ..GuestState::default()
        };
        state
            .transition_pstate(
                &mut registers,
                PSTATE_EL0T | PSTATE_PACM_MASK | u64::from(FLAGS),
            )
            .unwrap();
        assert_eq!(state.pacm(), Pacm::One);
        assert_eq!(registers.sp, INACTIVE_SP);
        state
            .transition_pstate(&mut registers, PSTATE_EL1H | u64::from(FLAGS))
            .unwrap();
        assert_eq!(state.pacm(), Pacm::Zero);
        assert_eq!(registers.sp, INITIAL_SP);
    }

    #[test]
    fn invalid_transition_preserves_full_original_state() {
        let mut state = SystemState::new_with_pacm(
            PSTATE_EL1H | PSTATE_PACM_MASK,
            INACTIVE_SP,
            el1(),
            PacmStateFeature::Full,
        )
        .unwrap();
        let mut registers = GuestState {
            nzcv: FLAGS,
            sp: INITIAL_SP,
            ..GuestState::default()
        };
        let before_state = state.clone();
        let before_registers = registers.clone();
        assert!(
            state
                .transition_pstate(&mut registers, PSTATE_EL0T | BTYPE_MASK)
                .is_err()
        );
        assert_eq!(state, before_state);
        assert_eq!(registers, before_registers);
    }
}

const SP0: u64 = 0x1000;
const SP1: u64 = 0x2000;
const FLAGS: u32 = 0xa000_0000;

fn el1() -> El1Registers {
    El1Registers::new(1, 2, 3, 4, 5)
}
fn state(mode: u64) -> (SystemState, GuestState) {
    let sp1_active = mode == PSTATE_EL1H;
    let registers = GuestState {
        sp: if sp1_active { SP1 } else { SP0 },
        nzcv: FLAGS,
        ..GuestState::default()
    };
    (
        SystemState::new(mode, if sp1_active { SP0 } else { SP1 }, el1()).unwrap(),
        registers,
    )
}

#[test]
fn all_supported_modes_derive_el_and_stack() {
    for mode in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
        let (system, registers) = state(mode);
        assert_eq!(
            system.current_el(),
            if mode == PSTATE_EL0T {
                ExceptionLevel::El0
            } else {
                ExceptionLevel::El1
            }
        );
        assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
        assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
        assert_eq!(system.pstate(&registers), mode | u64::from(FLAGS));
    }
}

#[test]
fn unsupported_bits_and_modes_are_rejected() {
    assert_eq!(
        SystemState::new(NZCV_MASK, 0, el1()),
        Err(StateError::FlagsInMiscPstate)
    );
    for mode in 0..=PSTATE_MODE_MASK {
        assert_eq!(
            SystemState::new(mode, 0, el1()).is_ok(),
            [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H].contains(&mode)
        );
    }
    for bit in 0..u64::BITS {
        let value = 1u64 << bit;
        if value & (BASE_MISC_MASK | NZCV_MASK) == 0 {
            assert_eq!(
                SystemState::new(PSTATE_EL1H | value, 0, el1()),
                Err(StateError::UnsupportedPstateBits(value))
            );
        }
    }
}

#[test]
fn failed_transitions_preserve_complete_state() {
    for psr in [PSTATE_EL1H | TCO_MASK, PSTATE_MODE_MASK, 1 << 63] {
        let (mut system, mut registers) = state(PSTATE_EL0T);
        let before = (system.clone(), registers.clone());
        assert!(system.transition_pstate(&mut registers, psr).is_err());
        assert_eq!((system, registers), before);
    }
}

#[test]
fn transitions_exchange_only_distinct_banks() {
    for from in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
        for to in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
            let (mut system, mut registers) = state(from);
            let original = registers.clone();
            system
                .transition_pstate(&mut registers, to | u64::from(FLAGS))
                .unwrap();
            assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
            assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
            let mut expected = original;
            expected.sp = if to == PSTATE_EL1H { SP1 } else { SP0 };
            assert_eq!(registers, expected);
        }
    }
}

#[test]
fn flags_have_only_guest_state_authority() {
    let (mut system, mut registers) = state(PSTATE_EL1T);
    registers.nzcv = u32::MAX;
    assert_eq!(system.pstate(&registers), PSTATE_EL1T | NZCV_MASK);
    system.set_spsel(&mut registers, StackBank::El1).unwrap();
    assert_eq!(registers.nzcv, u32::MAX);
    system
        .transition_pstate(&mut registers, PSTATE_EL0T | u64::from(FLAGS))
        .unwrap();
    assert_eq!(registers.nzcv, FLAGS);
}

#[test]
fn sp_el0_access_rejects_active_bank() {
    for mode in [PSTATE_EL0T, PSTATE_EL1T] {
        let (mut system, _) = state(mode);
        let before = system.clone();
        assert_eq!(system.read_sp_el0(), Err(StateError::ActiveSpEl0));
        assert_eq!(system.write_sp_el0(7), Err(StateError::ActiveSpEl0));
        assert_eq!(system, before);
    }
    let (mut system, registers) = state(PSTATE_EL1H);
    system.write_sp_el0(7).unwrap();
    assert_eq!(system.read_sp_el0(), Ok(7));
    assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
}

#[test]
fn spsel_denies_el0_and_preserves_other_state() {
    for bank in [StackBank::El0, StackBank::El1] {
        let (mut system, mut registers) = state(PSTATE_EL0T);
        let before = (system.clone(), registers.clone());
        assert_eq!(
            system.set_spsel(&mut registers, bank),
            Err(StateError::El0StackSelection)
        );
        assert_eq!((system, registers), before);
    }
    let (mut system, mut registers) = state(PSTATE_EL1T);
    for bank in [StackBank::El1, StackBank::El0, StackBank::El0] {
        system.set_spsel(&mut registers, bank).unwrap();
        assert_eq!(system.active_stack_bank(), bank);
        assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
        assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
        assert_eq!(registers.nzcv, FLAGS);
    }
}

#[test]
fn el1_registers_have_named_accessors() {
    let (mut system, _) = state(PSTATE_EL1H);
    let bank = system.el1_registers_mut();
    bank.set_elr(11);
    bank.set_spsr(12);
    bank.set_esr(13);
    bank.set_far(14);
    bank.set_vbar(15);
    let bank = system.el1_registers();
    assert_eq!(
        (bank.elr(), bank.spsr(), bank.esr(), bank.far(), bank.vbar()),
        (11, 12, 13, 14, 15)
    );
}

fn mte() -> MteState {
    MteState::new(
        0x1234,
        TagRandomization::ArchitecturalLfsr,
        TagGenerationState {
            seed: 0x5678,
            tag: AllocationTag::new(9).unwrap(),
        },
    )
}

#[test]
fn mte_profile_is_explicit_and_tco_has_one_owner() {
    for feature in [
        MteFeature::Absent,
        MteFeature::One {
            register_raz_wi: false,
            immediate_ignored: false,
        },
    ] {
        assert_eq!(
            SystemState::new_with_mte(PSTATE_EL1H, SP0, el1(), feature, mte()),
            Err(StateError::UnsupportedMteProfile)
        );
    }
    let mut system = SystemState::new_with_mte(
        PSTATE_EL1H | TCO_MASK,
        SP0,
        el1(),
        MteFeature::TwoOrLater,
        mte(),
    )
    .unwrap();
    let mut registers = GuestState {
        sp: SP1,
        ..GuestState::default()
    };
    assert!(system.tag_check_override());
    system
        .transition_pstate(&mut registers, PSTATE_EL0T | u64::from(FLAGS))
        .unwrap();
    assert!(!system.tag_check_override());
    system
        .transition_pstate(&mut registers, PSTATE_EL1H | TCO_MASK)
        .unwrap();
    assert!(system.tag_check_override());
    assert_eq!(system.mte(), Some(&mte()));
}

#[test]
fn allocation_permission_is_a_snapshot_not_persistent_gcr_state() {
    let mut state = mte();
    for enabled in [true, false, true] {
        let controls = state.generation_controls(enabled);
        assert_eq!(controls.allocation_access_enabled, enabled);
        assert_eq!(controls.excluded_tags, 0x1234);
        assert_eq!(controls.randomization, TagRandomization::ArchitecturalLfsr);
    }
    state.set_excluded_tags(7);
    state.set_randomization(TagRandomization::External);
    state.generation_mut().seed = 11;
    assert_eq!(state.excluded_tags(), 7);
    assert_eq!(state.randomization(), TagRandomization::External);
    assert_eq!(state.generation().seed, 11);
}
