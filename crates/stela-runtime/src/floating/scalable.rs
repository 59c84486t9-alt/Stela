//! Software completion of SVE and SME floating-point instructions.
mod arithmetic;
mod bfloat16;
mod comparison;
mod conversion;
mod dot;
mod faminmax;
mod fp8;
mod fp8_conversion_fixed;
mod rounding;
mod sme_extrema_scale;
mod sme_fp8_conversion;
mod sme_fp8_matrix;
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

impl core::fmt::Display for CompletionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::State(error) => core::fmt::Display::fmt(error, formatter),
            Self::UnsupportedControl(control) => write!(
                formatter,
                "numerical exception enables are unsupported: {:#x}",
                control.enabled_exceptions
            ),
        }
    }
}

impl core::error::Error for CompletionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
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
        scalable.mode().streaming()
            && !matches!(
                instruction.operation(),
                ScalableNumericalOperation::FixedFp8Conversion(_)
            ),
        instruction.numerical_features(),
    );
    match instruction.operation() {
        ScalableNumericalOperation::FixedFp8Conversion(operand) => {
            fp8_conversion_fixed::complete(state, scalable, operand, controls)
        }
        ScalableNumericalOperation::SmeFp8Conversion(operand) => {
            sme_fp8_conversion::complete(state, scalable, operand, controls)
        }
        ScalableNumericalOperation::SmeFp8Matrix(operand) => {
            sme_fp8_matrix::complete(state, scalable, operand, controls)
        }
        ScalableNumericalOperation::Sve(operation) => match operation {
            Operation::Arithmetic(operand) => {
                arithmetic::complete(state, scalable, operand, controls)
            }
            Operation::Rounding(operand) => rounding::complete(state, scalable, operand, controls),
            Operation::Dot(operand) => dot::complete(state, scalable, operand, controls),
            Operation::Bfloat16(operand) => bfloat16::complete(state, scalable, operand, controls),
            Operation::FaMinMax(operand) => faminmax::complete(state, scalable, operand, controls),
            Operation::Fp8(operand) => fp8::complete(state, scalable, operand, controls),
            Operation::Comparison(operand) => {
                comparison::complete(state, scalable, operand, controls)
            }
            Operation::Conversion(operand) => {
                conversion::complete(state, scalable, operand, controls)
            }
        },
        ScalableNumericalOperation::SmeExtremaScale(operand) => {
            sme_extrema_scale::complete(state, scalable, operand, controls)
        }
        ScalableNumericalOperation::SmeVector(operand) => {
            sme_vector::complete(state, scalable, operand, controls)
        }
        ScalableNumericalOperation::SmeMatrix(operand) => {
            sme_matrix::complete(state, scalable, operand, controls)
        }
    }
}

#[cfg(test)]
mod tests;
