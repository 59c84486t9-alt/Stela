//! Half multiplicands and a Single accumulator with one architectural rounding.
use super::{
    Class, Control, FPCR_DN, Format, INPUT_DENORMAL, INVALID, Operand, Outcome, UnsupportedControl,
    fused, negate, unpack,
};
use rustc_apfloat::{
    Float, FloatConvert, Status, StatusAnd,
    ieee::{Half, Single},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideningOperation {
    Add,
    Subtract,
}

const HALF_TO_SINGLE_FRACTION_SHIFT: u32 =
    Format::Single.fraction_bits() - Format::Half.fraction_bits();
const HALF_TO_SINGLE_SIGN_SHIFT: u32 = Format::Single.bits() - Format::Half.bits();

fn nan(
    addend: Operand,
    left: Operand,
    right: Operand,
    control: Control,
    exceptions: &mut u32,
) -> Option<u64> {
    // Keep each original class and width until FPProcessNaNs3H selects it.
    let operands = [
        (Format::Single, addend),
        (Format::Half, left),
        (Format::Half, right),
    ];
    let signaling = operands
        .iter()
        .any(|(_, operand)| operand.class == Class::SignalingNaN);
    let (format, selected) = if control.alternative()
        && operands
            .iter()
            .filter(|(_, operand)| operand.class.nan())
            .count()
            >= 2
    {
        if left.class.nan() {
            (Format::Half, left)
        } else {
            (Format::Half, right)
        }
    } else {
        operands
            .iter()
            .find(|(_, operand)| operand.class == Class::SignalingNaN)
            .or_else(|| {
                operands
                    .iter()
                    .find(|(_, operand)| operand.class == Class::QuietNaN)
            })
            .copied()?
    };
    if signaling {
        *exceptions |= INVALID;
    }
    Some(if control.0 & FPCR_DN != 0 {
        // Converting the default Half NaN gives the default Single NaN too.
        control.default_nan(Format::Single)
    } else if format == Format::Half {
        let sign = (selected.bits & format.sign_mask()) << HALF_TO_SINGLE_SIGN_SHIFT;
        let payload = (selected.bits & (format.quiet_bit() - 1)) << HALF_TO_SINGLE_FRACTION_SHIFT;
        sign | Format::Single.infinity(false) | Format::Single.quiet_bit() | payload
    } else {
        selected.bits | format.quiet_bit()
    })
}

fn widen_half(bits: u64) -> u64 {
    let source = Half::from_bits(u128::from(bits));
    debug_assert!(source.is_finite());
    let mut loses_info = false;
    let converted: StatusAnd<Single> = source.convert(&mut loses_info);
    debug_assert!(!loses_info && converted.status == Status::OK);
    converted.value.to_bits() as u64
}

/// Evaluate one FMLAL/FMLSL lane. Original Half NaNs are classified before any
/// widening; lane selection, source snapshots and sticky status belong to callers.
pub fn evaluate(
    operation: WideningOperation,
    fpcr: u32,
    addend: u32,
    left: u16,
    right: u16,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let left = if operation == WideningOperation::Subtract {
        negate(Format::Half, u64::from(left), control)
    } else {
        u64::from(left)
    };
    let mut exceptions = 0;
    let addend = unpack(Format::Single, u64::from(addend), control, &mut exceptions);
    let left = unpack(Format::Half, left, control, &mut exceptions);
    let right = unpack(Format::Half, u64::from(right), control, &mut exceptions);
    let invalid_product = left.class == Class::Infinity && right.class == Class::Zero
        || left.class == Class::Zero && right.class == Class::Infinity;
    if let Some(mut bits) = nan(addend, left, right, control, &mut exceptions) {
        if !control.alternative() && addend.class == Class::QuietNaN && invalid_product {
            bits = control.default_nan(Format::Single);
            exceptions |= INVALID;
        }
        return Ok(Outcome { bits, exceptions });
    }
    let product_negative = left.negative ^ right.negative;
    let product_infinite = left.class == Class::Infinity || right.class == Class::Infinity;
    if invalid_product
        || addend.class == Class::Infinity
            && product_infinite
            && addend.negative != product_negative
    {
        return Ok(Outcome {
            bits: control.default_nan(Format::Single),
            exceptions: exceptions | INVALID,
        });
    }
    let mut result = if addend.class == Class::Infinity || product_infinite {
        Outcome {
            bits: Format::Single.infinity(if addend.class == Class::Infinity {
                addend.negative
            } else {
                product_negative
            }),
            exceptions: 0,
        }
    } else if addend.class == Class::Zero
        && (left.class == Class::Zero || right.class == Class::Zero)
        && addend.negative == product_negative
    {
        Outcome {
            bits: if addend.negative {
                Format::Single.sign_mask()
            } else {
                0
            },
            exceptions: 0,
        }
    } else {
        // Every finite Half widens exactly. Its product needs at most 22
        // significand bits and is zero or normal Single, so no prior rounding occurs.
        fused::finite::<Single>(
            Format::Single,
            addend.bits,
            widen_half(left.bits),
            widen_half(right.bits),
            control,
        )
    };
    // FPMulAddH processes only the Single accumulator after non-invalid work.
    // Half denormals never generate IDC, and NaN/invalid branches skip this.
    if control.alternative() && addend.class == Class::Denormal {
        exceptions |= INPUT_DENORMAL;
    }
    result.exceptions |= exceptions;
    Ok(result)
}

#[cfg(test)]
mod tests;
