use super::*;
use crate::system::state::{El1Registers, PSTATE_PACM_MASK, Pacm};

const CONTINUATION: GuestAddress = GuestAddress(0x1004);
const DESTINATION: u8 = 17;
const RESULT: u64 = 0x1234;

fn system(feature: PacmStateFeature) -> SystemState {
    SystemState::new_with_pacm(0, 0x2000, El1Registers::new(1, 2, 3, 4, 5), feature).unwrap()
}
fn prepared(effect: Effect) -> PreparedEffect {
    PreparedEffect {
        effect,
        continuation: CONTINUATION,
        authenticated: None,
    }
}

#[test]
fn missing_pacm_storage_refuses_before_register_effect() {
    let state = system(PacmStateFeature::Absent);
    assert!(
        prepared(Effect::Register {
            destination: DESTINATION,
            value: RESULT
        })
        .validate(&state)
        .is_err()
    );
}

#[test]
fn invalid_destination_refuses_before_commit() {
    let state = system(PacmStateFeature::Full);
    assert!(
        prepared(Effect::Register {
            destination: ZERO_REGISTER,
            value: RESULT
        })
        .validate(&state)
        .is_err()
    );
}

#[test]
fn register_effect_preserves_system_flags_and_other_registers() {
    let mut state = system(PacmStateFeature::Full);
    let original_system = state.clone();
    let mut registers = GuestState {
        nzcv: 0xa000_0000,
        sp: 0x3000,
        ..GuestState::default()
    };
    let mut expected = registers.clone();
    expected.x[usize::from(DESTINATION)] = RESULT;
    let effect = prepared(Effect::Register {
        destination: DESTINATION,
        value: RESULT,
    });
    effect.validate(&state).unwrap();
    effect.commit(&mut registers, &mut state).unwrap();
    assert_eq!(registers, expected);
    assert_eq!(state, original_system);
}

#[test]
fn pacm_effect_changes_only_actual_system_pacm() {
    let mut state = system(PacmStateFeature::Full);
    let mut registers = GuestState::default();
    let original = registers.clone();
    let effect = prepared(Effect::Pacm(Pacm::One));
    effect.validate(&state).unwrap();
    effect.commit(&mut registers, &mut state).unwrap();
    assert_eq!(state.pstate_misc(), PSTATE_PACM_MASK);
    assert_eq!(registers, original);
    let expected = SystemState::new_with_pacm(
        PSTATE_PACM_MASK,
        0x2000,
        El1Registers::new(1, 2, 3, 4, 5),
        PacmStateFeature::Full,
    )
    .unwrap();
    assert_eq!(state, expected);
    assert_eq!(state.el1_registers(), &El1Registers::new(1, 2, 3, 4, 5));
}

#[test]
fn return_and_discard_candidates_do_not_write_original_banks() {
    for candidate in [
        Effect::Return {
            target: CONTINUATION,
        },
        Effect::Discard,
    ] {
        let mut state = system(PacmStateFeature::Full);
        let original_system = state.clone();
        let mut registers = GuestState::default();
        let original = registers.clone();
        let effect = prepared(candidate);
        effect.validate(&state).unwrap();
        assert_eq!(effect.continuation(), CONTINUATION);
        effect.commit(&mut registers, &mut state).unwrap();
        assert_eq!(registers, original);
        assert_eq!(state, original_system);
    }
}
