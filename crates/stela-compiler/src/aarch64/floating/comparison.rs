//! Exact Arm FP ordering and predicate lanes without host FP effects.
use core::cmp::Ordering;

use super::{
    Class, Control, Format, INVALID, Outcome, UnsupportedControl, compare_operands,
    process_denormals, unpack,
};
use crate::aarch64::flags::{NZCV_C, NZCV_N, NZCV_V, NZCV_Z};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Predicate {
    Equal,
    GreaterEqual,
    Greater,
    LessEqual,
    Less,
    AbsoluteGreaterEqual,
    AbsoluteGreater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagsOutcome {
    pub nzcv: u32,
    pub exceptions: u32,
}

fn compare(
    format: Format,
    signal_all_nans: bool,
    absolute: bool,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<(Option<Ordering>, u32), UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let mut left = unpack(format, left, control, &mut exceptions);
    let mut right = unpack(format, right, control, &mut exceptions);
    if left.class.nan() || right.class.nan() {
        if signal_all_nans
            || left.class == Class::SignalingNaN
            || right.class == Class::SignalingNaN
        {
            exceptions |= INVALID;
        }
        // AH0 input flushing has already contributed IDC. The NaN branch
        // suppresses post-comparison AH1 denormal processing.
        return Ok((None, exceptions));
    }
    if absolute {
        // Arm FPAbs preserves NaN signs under AH1, without raising status.
        // NaNs have already returned, so clearing both remaining signs is
        // equivalent and preserves the unpacked denormal classes for IDC.
        left.bits &= !format.sign_mask();
        right.bits &= !format.sign_mask();
        left.negative = false;
        right.negative = false;
    }
    let ordering = compare_operands(left, right);
    process_denormals(format, control, left, right, &mut exceptions);
    Ok((Some(ordering), exceptions))
}

/// FCMP/E comparison outcome. Conditional instructions call this only when
/// their condition holds; false conditions bypass numerical enable checks.
pub fn flags(
    format: Format,
    signal_all_nans: bool,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<FlagsOutcome, UnsupportedControl> {
    let (ordering, exceptions) = compare(format, signal_all_nans, false, fpcr, left, right)?;
    let nzcv = match ordering {
        None => NZCV_C | NZCV_V,
        Some(Ordering::Less) => NZCV_N,
        Some(Ordering::Equal) => NZCV_Z | NZCV_C,
        Some(Ordering::Greater) => NZCV_C,
    };
    Ok(FlagsOutcome { nzcv, exceptions })
}

/// One scalar or vector predicate lane. EQ signals only SNaNs; all ordered
/// inequalities signal any NaN. Destination merging and sticky FPSR are caller duties.
pub fn predicate(
    format: Format,
    operation: Predicate,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let absolute = matches!(
        operation,
        Predicate::AbsoluteGreaterEqual | Predicate::AbsoluteGreater
    );
    let (ordering, exceptions) = compare(
        format,
        operation != Predicate::Equal,
        absolute,
        fpcr,
        left,
        right,
    )?;
    let passed = match operation {
        Predicate::Equal => ordering == Some(Ordering::Equal),
        Predicate::GreaterEqual | Predicate::AbsoluteGreaterEqual => {
            matches!(ordering, Some(Ordering::Greater | Ordering::Equal))
        }
        Predicate::Greater | Predicate::AbsoluteGreater => ordering == Some(Ordering::Greater),
        Predicate::LessEqual => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
        Predicate::Less => ordering == Some(Ordering::Less),
    };
    Ok(Outcome {
        bits: if passed {
            u64::MAX >> (u64::BITS - format.bits())
        } else {
            0
        },
        exceptions,
    })
}

#[cfg(test)]
mod tests;
