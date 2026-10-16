//! Integer exponent extraction and exact power-of-two scaling for SVE lanes.
use super::{
    Class, Control, Format, INVALID, Outcome, UnsupportedControl, nan, precision,
    process_denormals, unpack, widen,
};
use rustc_apfloat::{
    Float,
    ieee::{Double, Half, Single},
};

/// Extract the signed integer exponent, with integer extrema for special inputs.
/// The caller owns active-lane selection, effective FPCR and sticky status.
pub fn logb(format: Format, fpcr: u32, bits: u64) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    let minimum_integer = format.sign_mask();
    let result = match operand.class {
        Class::Zero | Class::QuietNaN | Class::SignalingNaN => {
            exceptions |= INVALID;
            return Ok(Outcome {
                bits: minimum_integer,
                exceptions,
            });
        }
        Class::Infinity => {
            return Ok(Outcome {
                bits: minimum_integer - 1,
                exceptions,
            });
        }
        Class::Normal => {
            let exponent = (operand.bits & format.exponent_mask()) >> format.fraction_bits();
            exponent as i64 - i64::from(format.exponent_bias())
        }
        Class::Denormal => {
            let fraction = operand.bits & format.fraction_mask();
            i64::from(fraction.ilog2()) + 1
                - i64::from(format.exponent_bias())
                - i64::from(format.fraction_bits())
        }
    };
    process_denormals(format, control, operand, operand, &mut exceptions);
    let lane_mask = format.sign_mask() | (format.sign_mask() - 1);
    Ok(Outcome {
        bits: result as u64 & lane_mask,
        exceptions,
    })
}

/// Scale a floating lane by a signed integer lane with one architectural rounding.
/// Clamp the exponent adjustment before widening and avoid intermediate H/S/D
/// powers of two, whose underflow or overflow would change the result and status.
pub fn scale(
    format: Format,
    fpcr: u32,
    bits: u64,
    scale_bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    // Repeating the same unpacked operand applies the shared unary NaN behavior
    // without introducing another classification or changing NaN priority.
    if let Some(bits) = nan(format, operand, operand, control, &mut exceptions) {
        return Ok(Outcome { bits, exceptions });
    }
    match operand.class {
        Class::Zero | Class::Infinity => {
            return Ok(Outcome {
                bits: operand.bits,
                exceptions,
            });
        }
        Class::Normal | Class::Denormal => {}
        Class::QuietNaN | Class::SignalingNaN => unreachable!("NaNs handled before finite scaling"),
    }
    let sign_extension_shift = u64::BITS - format.bits();
    let signed_scale = ((scale_bits << sign_extension_shift) as i64) >> sign_extension_shift;
    let exponent = ((bits & format.exponent_mask()) >> format.fraction_bits()) as i64;
    let fraction_precision = i64::from(format.fraction_bits()) + 1;
    let maximum_exponent_field = (format.exponent_mask() >> format.fraction_bits()) as i64;
    let minimum_scale = -fraction_precision - exponent;
    let maximum_scale = maximum_exponent_field + fraction_precision - exponent;
    let clamped_scale = signed_scale.clamp(minimum_scale, maximum_scale) as i32;
    let value = match format {
        Format::Half => widen(Half::from_bits(u128::from(operand.bits))),
        Format::Single => widen(Single::from_bits(u128::from(operand.bits))),
        Format::Double => widen(Double::from_bits(u128::from(operand.bits))),
    };
    // FPClampScale bounds every H/S/D result well inside Quad's exponent range;
    // widening and exponent adjustment therefore retain the exact significand.
    let scaled = value.scalbn(clamped_scale);
    debug_assert!(scaled.is_finite() && !scaled.is_zero());
    debug_assert!(scaled.scalbn(-clamped_scale).bitwise_eq(value));
    let mut result = precision::round_ieee(scaled, format, control, control.round(), true, false);
    process_denormals(format, control, operand, operand, &mut exceptions);
    result.exceptions |= exceptions;
    Ok(result)
}

#[cfg(test)]
mod tests;
