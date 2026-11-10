//! FPCR trap enables: an instruction traps only when it raises an enabled
//! exception (`execute`).
use super::*;

const FADD_S0_S1_S2: u32 = 0x1e22_2820;
const FDIV_D0_D1_D2: u32 = 0x1e62_1820;
const ONE: u64 = 0x3ff0_0000_0000_0000;
const DOUBLE_MAX: u64 = 0x7fef_ffff_ffff_ffff;
const FADD_D0_D1_D2: u32 = 0x1e62_2820;

fn operation(word: u32) -> FloatingPointOperation {
    FloatingPointOperation::decode(word).unwrap().unwrap()
}

fn enables(exceptions: u32) -> u32 {
    exceptions << FPCR_EXCEPTION_ENABLE_SHIFT
}

#[test]
fn enabled_traps_leave_an_exact_instruction_unchanged() {
    let mut state = initial_state();
    state.v[1] = [0x3f80_0000, 0];
    state.v[2] = [0x4000_0000, 0];
    state.fpcr |= enables(EXCEPTIONS);
    let mut expected = state.clone();
    expected.v[0] = [0x4040_0000, 0];
    assert_eq!(execute(&mut state, &operation(FADD_S0_S1_S2)), Ok(()));
    assert_eq!(state, expected);
}

#[test]
fn an_enabled_exception_traps_without_writing_its_destination() {
    let mut state = initial_state();
    state.v[1] = [ONE, 0];
    state.v[2] = [0, 0];
    state.fpcr |= enables(DIVIDE_BY_ZERO);
    let expected = state.clone();
    assert_eq!(
        execute(&mut state, &operation(FDIV_D0_D1_D2)),
        Err(Trapped {
            exceptions: DIVIDE_BY_ZERO
        })
    );
    assert_eq!(state, expected);
}

#[test]
fn an_exception_whose_enable_is_clear_accumulates_beside_other_enables() {
    let mut state = initial_state();
    state.v[1] = [ONE, 0];
    state.v[2] = [0, 0];
    state.fpcr |= enables(INVALID | OVERFLOW | INEXACT);
    let mut expected = state.clone();
    expected.v[0] = [0x7ff0_0000_0000_0000, 0];
    expected.fpsr |= DIVIDE_BY_ZERO;
    assert_eq!(execute(&mut state, &operation(FDIV_D0_D1_D2)), Ok(()));
    assert_eq!(state, expected);
}

#[test]
fn a_trap_sets_only_the_raised_exceptions_whose_enables_are_clear() {
    let mut state = initial_state();
    state.v[1] = [DOUBLE_MAX, 0];
    state.v[2] = [DOUBLE_MAX, 0];
    state.fpsr = 0;
    state.fpcr |= enables(OVERFLOW);
    let mut expected = state.clone();
    expected.fpsr = INEXACT;
    assert_eq!(
        execute(&mut state, &operation(FADD_D0_D1_D2)),
        Err(Trapped {
            exceptions: OVERFLOW
        })
    );
    assert_eq!(state, expected);
}

#[test]
fn clear_enables_keep_the_untrapped_completion() {
    let mut state = initial_state();
    state.v[1] = [ONE, 0];
    state.v[2] = [0, 0];
    let mut expected = state.clone();
    assert_eq!(complete(&mut expected, &operation(FDIV_D0_D1_D2)), Ok(()));
    assert_eq!(execute(&mut state, &operation(FDIV_D0_D1_D2)), Ok(()));
    assert_eq!(state, expected);
}
