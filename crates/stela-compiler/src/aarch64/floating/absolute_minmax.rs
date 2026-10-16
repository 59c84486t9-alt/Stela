//! FAMIN/FAMAX lane results. Callers handle lane selection and FPSR.
use super::{
    Control, FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_FZ16, Format, Outcome, UnsupportedControl, nan,
    unpack,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsoluteMinMaxOperation {
    Minimum,
    Maximum,
}

/// Evaluate FPAbsMin/FPAbsMax without host floating-point effects.
/// These operations ignore AH and input/output flushing. Numeric results have
/// their sign cleared; NaN propagation retains the original operand signs.
pub fn evaluate(
    format: Format,
    operation: AbsoluteMinMaxOperation,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr & !(FPCR_AH | FPCR_FIZ | FPCR_FZ | FPCR_FZ16))?;
    let mut exceptions = 0;
    // Classification is invariant under sign clearing. Keep the original bits
    // through NaN processing, which explicitly consumes signed source operands.
    let left = unpack(format, left, control, &mut exceptions);
    let right = unpack(format, right, control, &mut exceptions);
    if let Some(bits) = nan(format, left, right, control, &mut exceptions) {
        return Ok(Outcome { bits, exceptions });
    }
    let magnitude_mask = format.sign_mask() - 1;
    let left = left.bits & magnitude_mask;
    let right = right.bits & magnitude_mask;
    // Positive IEEE encodings are ordered as unsigned integers, including
    // subnormals, zero and infinity. Selection is exact and cannot raise IDC.
    let bits = match operation {
        AbsoluteMinMaxOperation::Minimum => left.min(right),
        AbsoluteMinMaxOperation::Maximum => left.max(right),
    };
    Ok(Outcome { bits, exceptions })
}

#[cfg(test)]
mod tests;
