//! FRINT* rounding to integral values, including the bounded FRINT32/64 forms.
use super::{
    Class, Control, FPCR_DN, Format, INEXACT, INVALID, Outcome, UnsupportedControl, unpack,
};
use rustc_apfloat::{
    Float, Round, Status,
    ieee::{Double, Half, Single},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingOperation {
    NearestEven,
    NearestAway,
    TowardPositive,
    TowardNegative,
    TowardZero,
    Current,
    CurrentExact,
    Signed32Zero,
    Signed32Current,
    Signed64Zero,
    Signed64Current,
}

impl RoundingOperation {
    fn round(self, control: Control) -> Round {
        match self {
            Self::NearestEven => Round::NearestTiesToEven,
            Self::NearestAway => Round::NearestTiesToAway,
            Self::TowardPositive => Round::TowardPositive,
            Self::TowardNegative => Round::TowardNegative,
            Self::TowardZero | Self::Signed32Zero | Self::Signed64Zero => Round::TowardZero,
            Self::Current | Self::CurrentExact | Self::Signed32Current | Self::Signed64Current => {
                control.round()
            }
        }
    }

    pub(crate) const fn signed_width(self) -> Option<u32> {
        match self {
            Self::Signed32Zero | Self::Signed32Current => Some(u32::BITS),
            Self::Signed64Zero | Self::Signed64Current => Some(u64::BITS),
            _ => None,
        }
    }

    pub(crate) const fn exact(self) -> bool {
        matches!(self, Self::CurrentExact) || self.signed_width().is_some()
    }
}

fn signed_limit<F: Float>(width: u32) -> F {
    F::from_u128(1).value.scalbn(width as i32 - 1)
}

fn indefinite(format: Format, width: u32) -> u64 {
    match format {
        Format::Single => (-signed_limit::<Single>(width)).to_bits() as u64,
        Format::Double => (-signed_limit::<Double>(width)).to_bits() as u64,
        Format::Half => unreachable!("bounded integral rounding has no half form"),
    }
}

fn finite<F: Float>(operation: RoundingOperation, control: Control, bits: u64) -> Outcome {
    let source = F::from_bits(u128::from(bits));
    // Same-format integral rounding is exact after the integer is selected.
    // The integer-only library preserves source sign for zero and leaves large
    // already integral values unchanged, without host FP or double rounding.
    let result = source.round_to_integral(operation.round(control));
    debug_assert!(!result.status.intersects(
        Status::INVALID_OP | Status::DIV_BY_ZERO | Status::OVERFLOW | Status::UNDERFLOW
    ));
    if let Some(width) = operation.signed_width() {
        let limit = signed_limit::<F>(width);
        // The positive maximum (limit-1) may not be representable in F. Using
        // the exact power-of-two boundary tests the rounded integer directly.
        if result.value >= limit || result.value < -limit {
            return Outcome {
                bits: (-limit).to_bits() as u64,
                exceptions: INVALID,
            };
        }
    }
    Outcome {
        bits: result.value.to_bits() as u64,
        exceptions: if operation.exact() && result.status.contains(Status::INEXACT) {
            INEXACT
        } else {
            0
        },
    }
}

/// Evaluate one FRINT lane with fresh status only. AHP is ignored, FZ16 is
/// observed, and AH suppresses IDC without any post-operation denormal check.
/// Scalar merging, active lanes and sticky status belong to the caller.
pub fn evaluate(
    format: Format,
    operation: RoundingOperation,
    fpcr: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    assert!(
        format != Format::Half || operation.signed_width().is_none(),
        "decoded bounded integral rounding requires S/D"
    );
    let mut exceptions = 0;
    // Shared unpack raises IDC only for AH0 S/D input flushing. FPRoundInt/N
    // suppress AH1 input-denormal exceptions and never process denormals later.
    let operand = unpack(format, bits, control, &mut exceptions);
    let result = if let Some(width) = operation.signed_width()
        && (operand.class.nan() || operand.class == Class::Infinity)
    {
        // Bounded forms replace every NaN and infinity with signed minimum,
        // independent of NaN payload, signaling, DN and the source sign.
        Outcome {
            bits: indefinite(format, width),
            exceptions: INVALID,
        }
    } else if operand.class.nan() {
        Outcome {
            bits: if control.0 & FPCR_DN != 0 {
                control.default_nan(format)
            } else {
                operand.bits | format.quiet_bit()
            },
            exceptions: if operand.class == Class::SignalingNaN {
                INVALID
            } else {
                0
            },
        }
    } else if matches!(operand.class, Class::Zero | Class::Infinity) {
        Outcome {
            bits: operand.bits,
            exceptions: 0,
        }
    } else {
        match format {
            Format::Half => finite::<Half>(operation, control, operand.bits),
            Format::Single => finite::<Single>(operation, control, operand.bits),
            Format::Double => finite::<Double>(operation, control, operand.bits),
        }
    };
    Ok(Outcome {
        bits: result.bits,
        exceptions: exceptions | result.exceptions,
    })
}

#[cfg(test)]
mod tests;
