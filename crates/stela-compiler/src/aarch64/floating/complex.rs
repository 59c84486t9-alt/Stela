//! Complex pair arithmetic with architectural source rotation and operand order.
use super::{
    BinaryOperation, Control, Format, Outcome, UnsupportedControl, evaluate,
    fused::{self, FusedOperation},
    negate,
};

pub const COMPONENTS: usize = 2;
pub const REAL: usize = 0;
pub const IMAGINARY: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    Degrees0,
    Degrees90,
    Degrees180,
    Degrees270,
}

impl Rotation {
    pub const fn left_component(self) -> usize {
        match self {
            Self::Degrees0 | Self::Degrees180 => REAL,
            Self::Degrees90 | Self::Degrees270 => IMAGINARY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairOutcome {
    pub bits: [u64; COMPONENTS],
    pub exceptions: u32,
}

fn rotate_right(
    format: Format,
    rotation: Rotation,
    control: Control,
    right: [u64; COMPONENTS],
) -> [u64; COMPONENTS] {
    // FPNeg transforms original M, including its AH-sensitive NaN sign. It
    // cannot be replaced by subtraction or by negating the other multiplier.
    match rotation {
        Rotation::Degrees0 => right,
        Rotation::Degrees90 => [negate(format, right[IMAGINARY], control), right[REAL]],
        Rotation::Degrees180 => [
            negate(format, right[REAL], control),
            negate(format, right[IMAGINARY], control),
        ],
        Rotation::Degrees270 => [right[IMAGINARY], negate(format, right[REAL], control)],
    }
}

fn pair(real: Outcome, imaginary: Outcome) -> PairOutcome {
    PairOutcome {
        bits: [real.bits, imaginary.bits],
        exceptions: real.exceptions | imaginary.exceptions,
    }
}

/// Evaluate one FCADD pair. Decoded instructions admit only 90/270 degrees.
///
/// # Panics
/// Panics if rotation is 0 or 180 degrees, outside FCADD's allocated forms.
pub fn add_pair(
    format: Format,
    rotation: Rotation,
    fpcr: u32,
    left: [u64; COMPONENTS],
    right: [u64; COMPONENTS],
) -> Result<PairOutcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    assert!(
        matches!(rotation, Rotation::Degrees90 | Rotation::Degrees270),
        "FCADD requires 90 or 270 degrees"
    );
    let right = rotate_right(format, rotation, control, right);
    let real = evaluate(format, BinaryOperation::Add, fpcr, left[REAL], right[REAL])?;
    let imaginary = evaluate(
        format,
        BinaryOperation::Add,
        fpcr,
        left[IMAGINARY],
        right[IMAGINARY],
    )?;
    Ok(pair(real, imaginary))
}

/// Evaluate one partial FCMLA pair with independent fused component rounding.
/// The unselected N component is never unpacked or numerically evaluated.
pub fn multiply_add_pair(
    format: Format,
    rotation: Rotation,
    fpcr: u32,
    addend: [u64; COMPONENTS],
    left: [u64; COMPONENTS],
    right: [u64; COMPONENTS],
) -> Result<PairOutcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let right = rotate_right(format, rotation, control, right);
    let left = left[rotation.left_component()];
    let real = fused::evaluate(
        format,
        FusedOperation::Add,
        fpcr,
        addend[REAL],
        left,
        right[REAL],
    )?;
    let imaginary = fused::evaluate(
        format,
        FusedOperation::Add,
        fpcr,
        addend[IMAGINARY],
        left,
        right[IMAGINARY],
    )?;
    Ok(pair(real, imaginary))
}

#[cfg(test)]
mod tests;
