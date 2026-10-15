//! One transactional numerical completion boundary for scalable SVE/SME state.
mod arithmetic;
mod bfloat16;
mod comparison;
mod conversion;
mod dot;
mod rounding;
mod sme_matrix;
mod sme_vector;

use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_EBF, UnsupportedControl, features::NumericalFeatures},
        sve::floating::{Operation, control::effective_fpcr},
    },
    block::scalable::{AdmittedScalableNumericalInstruction, ScalableNumericalOperation},
};

use crate::scalable::ScalableState;

#[derive(Debug)]
pub enum CompletionError {
    State(anyhow::Error),
    UnsupportedControl(UnsupportedControl),
}

impl std::fmt::Display for CompletionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(error) => std::fmt::Display::fmt(error, formatter),
            Self::UnsupportedControl(control) => write!(
                formatter,
                "numerical exception enables are unsupported: {:#x}",
                control.enabled_exceptions
            ),
        }
    }
}

impl std::error::Error for CompletionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(error) => Some(error.as_ref()),
            Self::UnsupportedControl(_) => None,
        }
    }
}

impl From<anyhow::Error> for CompletionError {
    fn from(error: anyhow::Error) -> Self {
        Self::State(error)
    }
}

impl From<UnsupportedControl> for CompletionError {
    fn from(error: UnsupportedControl) -> Self {
        Self::UnsupportedControl(error)
    }
}

/// Immutable instruction controls derived once from the bound CPU profile.
/// Imported raw FPCR storage is never rewritten during numerical completion.
#[derive(Debug, Clone, Copy)]
pub(super) struct NumericalControls {
    pub fpcr: u32,
    pub features: NumericalFeatures,
}

impl NumericalControls {
    pub(super) fn new(raw_fpcr: u32, streaming: bool, features: NumericalFeatures) -> Self {
        let mut fpcr = effective_fpcr(raw_fpcr, streaming, features.full_a64());
        if !features.ebf16() {
            fpcr &= !FPCR_EBF;
        }
        Self { fpcr, features }
    }
}

/// Complete an instruction admitted by the immutable streaming profile after
/// the caller recovers its registered original source. The current owned state
/// must still match that profile. Each family snapshots affected sources and
/// stages its complete architectural outputs before committing.
pub(crate) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    instruction: &AdmittedScalableNumericalInstruction,
) -> Result<(), CompletionError> {
    let profile = instruction.profile();
    if scalable.vector_length() != profile.vector_length() || scalable.mode() != profile.mode() {
        return Err(anyhow::anyhow!("scalable numerical state/profile mismatch").into());
    }
    let controls = NumericalControls::new(
        state.fpcr,
        scalable.mode().streaming(),
        instruction.numerical_features(),
    );
    match instruction.operation() {
        ScalableNumericalOperation::Sve(operation) => match operation {
            Operation::Arithmetic(operand) => {
                arithmetic::complete(state, scalable, operand, controls)
            }
            Operation::Rounding(operand) => rounding::complete(state, scalable, operand, controls),
            Operation::Dot(operand) => dot::complete(state, scalable, operand, controls),
            Operation::Bfloat16(operand) => bfloat16::complete(state, scalable, operand, controls),
            Operation::Comparison(operand) => {
                comparison::complete(state, scalable, operand, controls)
            }
            Operation::Conversion(operand) => {
                conversion::complete(state, scalable, operand, controls)
            }
        },
        ScalableNumericalOperation::SmeVector(operand) => {
            sme_vector::complete(state, scalable, operand, controls)
        }
        ScalableNumericalOperation::SmeMatrix(operand) => {
            sme_matrix::complete(state, scalable, operand, controls)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::floating::FPCR_EXCEPTION_ENABLE_MASK;

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
}

#[cfg(test)]
mod sme_vector_tests;
