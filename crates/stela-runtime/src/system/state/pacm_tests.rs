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
