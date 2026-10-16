//! BF16 conversion and Single fused arithmetic in the standard BF16 profile.
pub mod arithmetic;
mod dot;
pub mod extended_dot;

pub use dot::dot_add;

use super::{
    Class, Control, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_MASK,
    FPCR_ROUNDING_SHIFT, Format, INEXACT, INVALID, OVERFLOW, Operand, Outcome, UNDERFLOW,
    UnsupportedControl,
    fused::{self, FusedOperation},
    unpack,
};
use rustc_apfloat::Round;

pub const BFLOAT16_BITS: u32 = 16;
pub const BFLOAT16_FRACTION_BITS: u32 = 7;
pub const BFLOAT16_TO_SINGLE_SHIFT: u32 = Format::Single.bits() - BFLOAT16_BITS;

const BFLOAT16_EXPONENT_BITS: u32 = BFLOAT16_BITS - BFLOAT16_FRACTION_BITS - 1;
const BFLOAT16_SIGN_MASK: u32 = 1 << (BFLOAT16_BITS - 1);
const BFLOAT16_INFINITY: u32 = ((1 << BFLOAT16_EXPONENT_BITS) - 1) << BFLOAT16_FRACTION_BITS;
const RETAINED_LOW_BIT: u32 = 1;
const DISCARDED_MASK: u32 = (1 << BFLOAT16_TO_SINGLE_SHIFT) - 1;
const DISCARDED_MIDPOINT: u32 = 1 << (BFLOAT16_TO_SINGLE_SHIFT - 1);

/// BF16 shares Single's exponent and high fraction fields, including NaNs.
pub const fn widen(bits: u16) -> u32 {
    (bits as u32) << BFLOAT16_TO_SINGLE_SHIFT
}

/// BFNeg preserves NaN sign under AH and raises no status.
pub fn negate(fpcr: u32, bits: u16) -> u16 {
    (super::negate(Format::Single, u64::from(widen(bits)), Control(fpcr))
        >> BFLOAT16_TO_SINGLE_SHIFT) as u16
}

fn effective_control(fpcr: u32) -> Result<Control, UnsupportedControl> {
    let control = Control(fpcr);
    if control.alternative() {
        // FPConvertBF and BFMulAddH suppress exceptions under AH. Retain AH/DN
        // while forcing input/output flush and nearest-even independently.
        Ok(Control(
            (fpcr | FPCR_FIZ | FPCR_FZ)
                & !(FPCR_EXCEPTION_ENABLE_MASK | FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT),
        ))
    } else {
        Control::checked(fpcr)
    }
}

fn round_finite(source: Operand, control: Control) -> Outcome {
    let sign = (source.bits >> BFLOAT16_TO_SINGLE_SHIFT) as u32 & BFLOAT16_SIGN_MASK;
    let magnitude = (source.bits & !Format::Single.sign_mask()) as u32;
    let retained = magnitude >> BFLOAT16_TO_SINGLE_SHIFT;
    let discarded = magnitude & DISCARDED_MASK;
    let inexact = discarded != 0;
    let increment = match control.round() {
        Round::NearestTiesToEven => {
            discarded > DISCARDED_MIDPOINT
                || discarded == DISCARDED_MIDPOINT && retained & RETAINED_LOW_BIT != 0
        }
        Round::TowardPositive => inexact && !source.negative,
        Round::TowardNegative => inexact && source.negative,
        Round::TowardZero => false,
        _ => unreachable!("two-bit FPCR rounding field"),
    };
    let rounded = retained + u32::from(increment);
    let mut exceptions = if inexact { INEXACT } else { 0 };
    // BF16 and Single have the same minimum normal exponent. Unflushed tiny
    // sources are Single subnormals; AH0 detects tininess before rounding,
    // including a rounded BF16 minimum normal. Exact subnormals raise no flag.
    if source.class == Class::Denormal && inexact {
        exceptions |= UNDERFLOW;
    }
    if rounded == BFLOAT16_INFINITY {
        exceptions |= OVERFLOW | INEXACT;
    }
    Outcome {
        bits: u64::from(sign | rounded),
        exceptions,
    }
}

/// Convert original Single bits to BF16 with one target rounding. No late IDC
/// processing applies; AH0 FZ may already flush the Single input with IDC.
pub fn convert(fpcr: u32, bits: u32) -> Result<Outcome, UnsupportedControl> {
    let control = effective_control(fpcr)?;
    let mut exceptions = 0;
    let source = unpack(Format::Single, u64::from(bits), control, &mut exceptions);
    let mut result = if source.class.nan() {
        if source.class == Class::SignalingNaN {
            exceptions |= INVALID;
        }
        let quiet = if control.0 & FPCR_DN != 0 {
            control.default_nan(Format::Single)
        } else {
            source.bits | Format::Single.quiet_bit()
        };
        Outcome {
            bits: quiet >> BFLOAT16_TO_SINGLE_SHIFT,
            exceptions: 0,
        }
    } else if matches!(source.class, Class::Zero | Class::Infinity) {
        Outcome {
            bits: source.bits >> BFLOAT16_TO_SINGLE_SHIFT,
            exceptions: 0,
        }
    } else {
        // Any source small enough for BF16 output flush is a Single subnormal
        // and was already flushed during unpack when the policy enables FZ.
        round_finite(source, control)
    };
    result.exceptions = if control.alternative() {
        0
    } else {
        result.exceptions | exceptions
    };
    Ok(result)
}

/// BFMLAL widens both BF16 operands exactly and reuses Single FPMulAdd. The
/// absent EBF16 feature cannot select a different algorithm through raw FPCR.
pub fn multiply_add(
    fpcr: u32,
    addend: u32,
    left: u16,
    right: u16,
) -> Result<Outcome, UnsupportedControl> {
    let control = effective_control(fpcr)?;
    let mut result = fused::evaluate(
        Format::Single,
        FusedOperation::Add,
        control.0,
        u64::from(addend),
        u64::from(widen(left)),
        u64::from(widen(right)),
    )?;
    if control.alternative() {
        result.exceptions = 0;
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
