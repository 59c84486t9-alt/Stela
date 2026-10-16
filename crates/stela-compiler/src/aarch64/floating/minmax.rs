//! Exact same-format min/max outcomes; callers own shape, merging and reduction order.
use super::{
    Class, Control, Format, INEXACT, INVALID, Outcome, UNDERFLOW, UnsupportedControl,
    compare_operands, nan, process_denormals, unpack,
};
use core::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinMaxOperation {
    Minimum,
    Maximum,
    MinimumNumber,
    MaximumNumber,
}

impl MinMaxOperation {
    const fn minimum(self) -> bool {
        matches!(self, Self::Minimum | Self::MinimumNumber)
    }

    const fn number(self) -> bool {
        matches!(self, Self::MinimumNumber | Self::MaximumNumber)
    }
}

/// Evaluate one lane with fresh exception bits and no host floating-point effects.
/// Number variants restrict alternative min/max behavior while retaining AH's
/// ordinary NaN priority, output flushing and post-operation denormal checks.
pub fn evaluate(
    format: Format,
    operation: MinMaxOperation,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let mut left = unpack(format, left, control, &mut exceptions);
    let mut right = unpack(format, right, control, &mut exceptions);
    let alternative_minmax = control.alternative() && !operation.number();

    if alternative_minmax {
        if left.class == Class::Zero
            && right.class == Class::Zero
            && left.negative != right.negative
        {
            return Ok(Outcome {
                bits: right.bits,
                exceptions,
            });
        }
        if left.class.nan() || right.class.nan() {
            // AH selects the raw second operand, including signaling NaNs.
            // Unpack has already converted a flushed second input to signed zero.
            return Ok(Outcome {
                bits: right.bits,
                exceptions: exceptions | INVALID,
            });
        }
    }

    if operation.number() && !(control.alternative() && left.class.nan() && right.class.nan()) {
        // Replace a lone quiet NaN before the ordinary NaN-priority rules.
        // Under AH=0 this also replaces a quiet NaN paired with signaling NaN.
        let replacement = format.infinity(!operation.minimum());
        if left.class == Class::QuietNaN && right.class != Class::QuietNaN {
            left = unpack(format, replacement, control, &mut exceptions);
        } else if left.class != Class::QuietNaN && right.class == Class::QuietNaN {
            right = unpack(format, replacement, control, &mut exceptions);
        }
    }
    if let Some(bits) = nan(format, left, right, control, &mut exceptions) {
        return Ok(Outcome { bits, exceptions });
    }

    let preferred = if operation.minimum() {
        Ordering::Less
    } else {
        Ordering::Greater
    };
    let selected = if compare_operands(left, right) == preferred {
        left
    } else {
        right
    };
    let bits = if selected.class == Class::Zero {
        // Standard min/max zero signs also apply to number variants under AH.
        let sign = if operation.minimum() {
            left.bits | right.bits
        } else {
            left.bits & right.bits
        };
        sign & format.sign_mask()
    } else if selected.class == Class::Denormal
        && control.alternative()
        && operation.number()
        && control.flush_output(format)
    {
        // Plain AH min/max clears output FZ/FZ16; number variants do not.
        // The selected exact denormal is flushed after unconstrained rounding.
        exceptions |= UNDERFLOW | INEXACT;
        selected.bits & format.sign_mask()
    } else {
        // Selected finite values and infinities are already exact in this format.
        selected.bits
    };
    process_denormals(format, control, left, right, &mut exceptions);
    Ok(Outcome { bits, exceptions })
}

#[cfg(test)]
mod tests;
