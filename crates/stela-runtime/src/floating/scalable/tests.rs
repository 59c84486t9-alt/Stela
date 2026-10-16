use super::*;
use stela_compiler::aarch64::floating::FPCR_EXCEPTION_ENABLE_MASK;

mod sme_vector;

#[test]
fn controls_preserve_raw_storage_and_select_actual_feature_availability() {
    let state = GuestState {
        fpcr: u32::MAX,
        ..GuestState::default()
    };
    let ordinary = NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
    assert_eq!(
        ordinary.fpcr,
        state.fpcr & !FPCR_EXCEPTION_ENABLE_MASK & !FPCR_EBF
    );
    let enabled =
        NumericalControls::new(state.fpcr, true, NumericalFeatures::new(true, true, true));
    assert_eq!(enabled.fpcr, state.fpcr);
    assert!(enabled.features.rpres());
    assert_eq!(state.fpcr, u32::MAX);
}
