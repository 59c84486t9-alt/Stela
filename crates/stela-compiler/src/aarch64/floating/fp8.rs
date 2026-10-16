//! Exact OFP8 conversions and fused dot arithmetic, independent of host FP state.
//! Callers own feature/access admission, effective controls and transactional commit.
use super::{
    Class, Control, FPCR_AHP, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_FZ16, Format,
    INEXACT, INVALID, OVERFLOW, Outcome, UNDERFLOW, UnsupportedControl, precision::round_ieee,
    unpack as unpack_ieee, widen,
};
use rustc_apfloat::{
    Float, Round, Status,
    ieee::{Half, Quad, Single},
};

pub const FPMR_F8S1_SHIFT: u32 = 0;
pub const FPMR_F8S2_SHIFT: u32 = 3;
pub const FPMR_F8D_SHIFT: u32 = 6;
pub const FPMR_OSM: u64 = 1 << 14;
pub const FPMR_OSC: u64 = 1 << 15;
pub const FPMR_LSCALE_SHIFT: u32 = 16;
pub const FPMR_NSCALE_SHIFT: u32 = 24;
pub const FPMR_LSCALE2_SHIFT: u32 = 32;
const F8_SELECTOR_MASK: u64 = 7;
const LSCALE_MASK: u64 = 127;
const LSCALE2_MASK: u64 = 63;
const HALF_SCALE_MASK: u64 = 15;
const FP8_SIGN: u8 = 128;
// Every finite FP8 value is an integer multiple of its smallest subnormal.
const FP8_UNIT_POWER: i32 = -16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionFormat {
    Half,
    BFloat16,
    Single,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FP8Format {
    E5M2,
    E4M3,
    Unsupported,
}

impl FP8Format {
    pub const fn decode(selector: u64) -> Self {
        match selector & F8_SELECTOR_MASK {
            0 => Self::E5M2,
            1 => Self::E4M3,
            _ => Self::Unsupported,
        }
    }
    pub const fn source(fpmr: u64, source2: bool) -> Self {
        Self::decode(
            fpmr >> if source2 {
                FPMR_F8S2_SHIFT
            } else {
                FPMR_F8S1_SHIFT
            },
        )
    }
    const fn fraction_bits(self) -> u32 {
        match self {
            Self::E4M3 => 3,
            _ => 2,
        }
    }
    const fn minimum_exponent(self) -> i32 {
        match self {
            Self::E4M3 => -6,
            _ => -14,
        }
    }
    const fn maximum(self) -> u8 {
        match self {
            Self::E4M3 => 126,
            _ => 123,
        }
    }
    const fn infinity(self) -> u8 {
        match self {
            Self::E4M3 => 127,
            _ => 124,
        }
    }
    const fn default_nan(self) -> u8 {
        match self {
            Self::E4M3 => 127,
            _ => 126,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FP8Class {
    Zero,
    Finite,
    Infinity,
    QuietNaN,
    SignalingNaN,
}

#[derive(Debug, Clone, Copy)]
pub struct FP8Operand {
    pub class: FP8Class,
    pub negative: bool,
    pub value: Quad,
}

/// Every finite FP8 value is represented exactly. Unsupported selectors behave
/// as signaling NaNs for every bit pattern, including encoded zeros.
pub fn unpack(format: FP8Format, bits: u8) -> FP8Operand {
    let negative = bits & FP8_SIGN != 0;
    let fraction_bits = format.fraction_bits();
    let fraction = u32::from(bits) & ((1 << fraction_bits) - 1);
    let exponent = u32::from(bits & !FP8_SIGN) >> fraction_bits;
    let maximum_exponent = (1 << (7 - fraction_bits)) - 1;
    let class = if format == FP8Format::Unsupported {
        FP8Class::SignalingNaN
    } else if exponent == 0 && fraction == 0 {
        FP8Class::Zero
    } else if exponent == maximum_exponent {
        match format {
            FP8Format::E4M3 if fraction == 7 => FP8Class::SignalingNaN,
            FP8Format::E5M2 if fraction == 0 => FP8Class::Infinity,
            FP8Format::E5M2 if fraction == 1 => FP8Class::SignalingNaN,
            FP8Format::E5M2 => FP8Class::QuietNaN,
            _ => FP8Class::Finite,
        }
    } else {
        FP8Class::Finite
    };
    let mut value = if class == FP8Class::Finite {
        let significand = fraction + if exponent == 0 { 0 } else { 1 << fraction_bits };
        let power = format.minimum_exponent() + exponent.max(1) as i32 - 1 - fraction_bits as i32;
        Quad::from_u128(u128::from(significand)).value.scalbn(power)
    } else {
        Quad::ZERO
    };
    if negative {
        value = -value;
    }
    FP8Operand {
        class,
        negative,
        value,
    }
}

#[derive(Debug, Clone, Copy)]
struct IntegerOperand {
    pub class: FP8Class,
    pub negative: bool,
    pub value: i64,
}

// Integer widening avoids constructing a Quad operand. The public Quad
// unpacker and fused-dot baseline remain unchanged in this selected projection.
fn unpack_integer(format: FP8Format, bits: u8) -> IntegerOperand {
    let negative = bits & FP8_SIGN != 0;
    let fraction_bits = format.fraction_bits();
    let fraction = u32::from(bits) & ((1 << fraction_bits) - 1);
    let exponent = u32::from(bits & !FP8_SIGN) >> fraction_bits;
    let maximum_exponent = (1 << (7 - fraction_bits)) - 1;
    let class = if format == FP8Format::Unsupported {
        FP8Class::SignalingNaN
    } else if exponent == 0 && fraction == 0 {
        FP8Class::Zero
    } else if exponent == maximum_exponent {
        match format {
            FP8Format::E4M3 if fraction == 7 => FP8Class::SignalingNaN,
            FP8Format::E5M2 if fraction == 0 => FP8Class::Infinity,
            FP8Format::E5M2 if fraction == 1 => FP8Class::SignalingNaN,
            FP8Format::E5M2 => FP8Class::QuietNaN,
            _ => FP8Class::Finite,
        }
    } else {
        FP8Class::Finite
    };
    let mut value = if class == FP8Class::Finite {
        let significand = fraction + if exponent == 0 { 0 } else { 1 << fraction_bits };
        let power = format.minimum_exponent() + exponent.max(1) as i32 - 1 - fraction_bits as i32;
        i64::from(significand) << (power - FP8_UNIT_POWER)
    } else {
        0
    };
    if negative {
        value = -value;
    }
    IntegerOperand {
        class,
        negative,
        value,
    }
}

fn conversion_control(fpcr: u32, clear_ahp: bool) -> Result<Control, UnsupportedControl> {
    Control::checked(
        fpcr & !(FPCR_FIZ | FPCR_FZ | FPCR_FZ16 | if clear_ahp { FPCR_AHP } else { 0 }),
    )
}

fn long_scale(fpmr: u64, source2: bool, half: bool) -> i32 {
    let raw = if source2 {
        (fpmr >> FPMR_LSCALE2_SHIFT) & LSCALE2_MASK
    } else {
        (fpmr >> FPMR_LSCALE_SHIFT) & LSCALE_MASK
    };
    (raw & if half { HALF_SCALE_MASK } else { LSCALE_MASK }) as i32
}

/// FP8ConvertFP/FP8ConvertBF: fixed RNE; FIZ/FZ/FZ16/AHP ignored.
pub fn from_fp8(
    destination: ConversionFormat,
    source2: bool,
    fpcr: u32,
    fpmr: u64,
    bits: u8,
) -> Result<Outcome, UnsupportedControl> {
    let control = conversion_control(fpcr, true)?;
    let operand = unpack_integer(FP8Format::source(fpmr, source2), bits);
    let format = if destination == ConversionFormat::Half {
        Format::Half
    } else {
        Format::Single
    };
    let narrow = |bits| {
        if destination == ConversionFormat::BFloat16 {
            bits >> 16
        } else {
            bits
        }
    };
    let sign = if operand.negative {
        format.sign_mask()
    } else {
        0
    };
    let result = match operand.class {
        FP8Class::QuietNaN | FP8Class::SignalingNaN => Outcome {
            bits: narrow(control.default_nan(format)),
            exceptions: if operand.class == FP8Class::SignalingNaN {
                INVALID
            } else {
                0
            },
        },
        FP8Class::Infinity => Outcome {
            bits: narrow(format.infinity(operand.negative)),
            exceptions: 0,
        },
        FP8Class::Zero => Outcome {
            bits: narrow(sign),
            exceptions: 0,
        },
        FP8Class::Finite => {
            let scale = long_scale(fpmr, source2, destination == ConversionFormat::Half);
            // ASL LSCALE[:6] is a six-bit width slice, not bits[6:0].
            let scale = if destination != ConversionFormat::Half {
                scale & LSCALE2_MASK as i32
            } else {
                scale
            };
            let fraction = if destination == ConversionFormat::BFloat16 {
                super::bfloat16::BFLOAT16_FRACTION_BITS as i32
            } else {
                format.fraction_bits() as i32
            };
            let bias = format.exponent_bias() as i32;
            let minimum = 1 - bias;
            let significand = operand.value.unsigned_abs();
            let power = FP8_UNIT_POWER - scale;
            let leading = (u64::BITS - 1 - significand.leading_zeros()) as i32 + power;
            let (retained, inexact) = quantize(significand, power, leading.max(minimum) - fraction);
            let exponent = if leading >= minimum {
                leading + bias
            } else {
                i32::from(retained >= 1 << fraction)
            };
            let bits = ((exponent as u64) << fraction) | (retained & ((1 << fraction) - 1));
            let sign_shift = if destination == ConversionFormat::BFloat16 {
                super::bfloat16::BFLOAT16_BITS - 1
            } else {
                format.bits() - 1
            };
            // At most four significant input bits are widened to at least
            // eight. Every normal and BF16 result is exact. Half can discard
            // bits only on its subnormal lattice; those sparse values cannot
            // round up to minimum normal, so both AH tininess rules agree.
            Outcome {
                bits: bits | (u64::from(operand.negative) << sign_shift),
                exceptions: if inexact { INEXACT | UNDERFLOW } else { 0 },
            }
        }
    };
    Ok(result)
}

/// Round nonnegative integer * 2^power to integer multiples of 2^quantum.
/// Returns the rounded integer and whether any original bits were discarded.
fn quantize(significand: u64, power: i32, quantum: i32) -> (u64, bool) {
    let shift = quantum - power;
    if shift <= 0 {
        return (significand << (-shift) as u32, false);
    }
    if shift >= u64::BITS as i32 {
        return (0, significand != 0);
    }
    let shift = shift as u32;
    let retained = significand >> shift;
    let discarded = significand & ((1 << shift) - 1);
    let midpoint = 1 << (shift - 1);
    (
        retained + u64::from(discarded > midpoint || discarded == midpoint && retained & 1 != 0),
        discarded != 0,
    )
}

fn finite_to_fp8(
    format: FP8Format,
    control: Control,
    fpmr: u64,
    negative: bool,
    significand: u64,
    power: i32,
) -> Outcome {
    let leading = (u64::BITS - 1 - significand.leading_zeros()) as i32 + power;
    let fraction = format.fraction_bits() as i32;
    let minimum = format.minimum_exponent();
    let quantum = leading.max(minimum) - fraction;
    let (mut retained, inexact) = quantize(significand, power, quantum);
    let mut exponent = (leading - minimum + 1).max(0);
    if retained == 1 << (fraction + 1) {
        retained >>= 1;
        exponent += 1;
    }
    if exponent == 0 && retained >= 1 << fraction {
        exponent = 1;
    }
    let magnitude = ((exponent as u64) << fraction) | (retained & ((1 << fraction) - 1));
    let overflow = magnitude > u64::from(format.maximum());
    let mut exceptions = if inexact { INEXACT } else { 0 };
    if inexact {
        let tiny = if control.alternative() {
            let (unconstrained, _) = quantize(significand, power, leading - fraction);
            leading + i32::from(unconstrained == 1 << (fraction + 1)) < minimum
        } else {
            leading < minimum
        };
        if tiny {
            exceptions |= UNDERFLOW;
        }
    }
    let magnitude = if overflow {
        exceptions |= OVERFLOW | INEXACT;
        if fpmr & FPMR_OSC != 0 {
            format.maximum()
        } else {
            format.infinity()
        }
    } else {
        magnitude as u8
    };
    Outcome {
        bits: u64::from(magnitude | if negative { FP8_SIGN } else { 0 }),
        exceptions,
    }
}

/// FPConvertFP8/BFConvertFP8: FPUnpack ignores AHP; fixed RNE and no flush.
pub fn to_fp8(
    source: ConversionFormat,
    fpcr: u32,
    fpmr: u64,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = conversion_control(fpcr, true)?;
    let format = FP8Format::decode(fpmr >> FPMR_F8D_SHIFT);
    if format == FP8Format::Unsupported {
        return Ok(Outcome {
            bits: 255,
            exceptions: INVALID,
        });
    }
    let (ieee, bits) = match source {
        ConversionFormat::Half => (Format::Half, bits),
        ConversionFormat::BFloat16 => (Format::Single, bits << 16),
        ConversionFormat::Single => (Format::Single, bits),
    };
    let mut ignored = 0;
    let operand = unpack_ieee(ieee, bits, control, &mut ignored);
    let sign = if operand.negative { FP8_SIGN } else { 0 };
    Ok(match operand.class {
        Class::QuietNaN | Class::SignalingNaN => Outcome {
            bits: u64::from(
                format.default_nan() | if control.alternative() { FP8_SIGN } else { 0 },
            ),
            exceptions: if operand.class == Class::SignalingNaN {
                INVALID
            } else {
                0
            },
        },
        Class::Infinity => Outcome {
            bits: u64::from(
                sign | if fpmr & FPMR_OSC != 0 {
                    format.maximum()
                } else {
                    format.infinity()
                },
            ),
            exceptions: 0,
        },
        Class::Zero => Outcome {
            bits: u64::from(sign),
            exceptions: 0,
        },
        Class::Normal | Class::Denormal => {
            let exponent = ((bits & ieee.exponent_mask()) >> ieee.fraction_bits()) as i32;
            let significand = bits & ieee.fraction_mask()
                | if exponent != 0 {
                    1 << ieee.fraction_bits()
                } else {
                    0
                };
            let raw_scale = (fpmr >> FPMR_NSCALE_SHIFT) as u8;
            let scale = if source == ConversionFormat::Half {
                ((raw_scale << 3) as i8 >> 3) as i32
            } else {
                raw_scale as i8 as i32
            };
            let power =
                exponent.max(1) - ieee.exponent_bias() as i32 - ieee.fraction_bits() as i32 + scale;
            finite_to_fp8(format, control, fpmr, operand.negative, significand, power)
        }
    })
}

/// FP8DotAddFP/FP8MulAddFP: one fused RNE and no exception side effects.
/// A product group has 1, 2, 4 or 8 terms; callers select the architectural group.
pub fn dot_add(
    format: Format,
    fpcr: u32,
    fpmr: u64,
    addend: u64,
    left: &[u8],
    right: &[u8],
) -> u64 {
    assert!(matches!(format, Format::Half | Format::Single));
    assert!(matches!(left.len(), 1 | 2 | 4 | 8) && left.len() == right.len());
    let control =
        Control(fpcr & !(FPCR_FIZ | FPCR_FZ | FPCR_FZ16 | FPCR_AHP | FPCR_EXCEPTION_ENABLE_MASK));
    let mut ignored = 0;
    let accumulator = unpack_ieee(format, addend, control, &mut ignored);
    let pairs = left.iter().zip(right).map(|(&left, &right)| {
        (
            unpack(FP8Format::source(fpmr, false), left),
            unpack(FP8Format::source(fpmr, true), right),
        )
    });
    let mut positive_infinity = accumulator.class == Class::Infinity && !accumulator.negative;
    let mut negative_infinity = accumulator.class == Class::Infinity && accumulator.negative;
    let mut same_zero = accumulator.class == Class::Zero;
    let mut invalid = accumulator.class.nan();
    let mut sum = Quad::ZERO;
    for (left, right) in pairs {
        let nan = |operand: FP8Operand| {
            matches!(operand.class, FP8Class::QuietNaN | FP8Class::SignalingNaN)
        };
        invalid |= nan(left) || nan(right);
        let infinite = left.class == FP8Class::Infinity || right.class == FP8Class::Infinity;
        let zero = left.class == FP8Class::Zero || right.class == FP8Class::Zero;
        let negative = left.negative ^ right.negative;
        invalid |= infinite && zero;
        positive_infinity |= infinite && !negative;
        negative_infinity |= infinite && negative;
        same_zero &= zero && accumulator.negative == negative;
        // Finite FP8 products and all eight-term sums span fewer than 70 bits,
        // so binary128 contains this unscaled dot exactly, including cancellation.
        let product = left.value.mul_r(right.value, Round::NearestTiesToEven);
        debug_assert_eq!(product.status, Status::OK);
        let next = sum.add_r(product.value, Round::NearestTiesToEven);
        debug_assert_eq!(next.status, Status::OK);
        sum = next.value;
    }
    if invalid || positive_infinity && negative_infinity {
        return control.default_nan(format);
    }
    if positive_infinity || negative_infinity {
        return format.infinity(negative_infinity);
    }
    if same_zero {
        return if accumulator.negative {
            format.sign_mask()
        } else {
            0
        };
    }
    let addend = match format {
        Format::Half => widen(Half::from_bits(u128::from(addend))),
        Format::Single => widen(Single::from_bits(u128::from(addend))),
        Format::Double => unreachable!(),
    };
    let sum = sum.scalbn(-long_scale(fpmr, false, format == Format::Half));
    let fused = addend.add_r(sum, Round::TowardZero);
    if fused.value.is_zero() {
        return 0;
    }
    // One potentially inexact addition follows the exact dot. Jam truncation
    // into an odd low bit before narrowing; 113 bits exceed the target's 24/11
    // by more than two, preserving every target midpoint and exponent boundary.
    let exact_surrogate =
        Quad::from_bits(fused.value.to_bits() | u128::from(fused.status.contains(Status::INEXACT)));
    let result = round_ieee(
        exact_surrogate,
        format,
        Control(control.0 & !FPCR_AHP),
        Round::NearestTiesToEven,
        false,
        false,
    );
    if fpmr & FPMR_OSM != 0 && result.exceptions & OVERFLOW != 0 {
        (result.bits & format.sign_mask()) | (format.exponent_mask() - 1)
    } else {
        result.bits
    }
}

#[cfg(test)]
mod tests;
