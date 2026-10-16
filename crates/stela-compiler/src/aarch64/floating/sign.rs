//! Raw floating sign transforms, independent of numerical exceptions.
use super::{Control, Format};

/// FPAbs preserves every NaN bit under AH; otherwise it clears only the sign.
pub fn absolute(format: Format, fpcr: u32, bits: u64) -> u64 {
    let nan = bits & format.exponent_mask() == format.exponent_mask()
        && bits & format.fraction_mask() != 0;
    if Control(fpcr).alternative() && nan {
        bits
    } else {
        bits & !format.sign_mask()
    }
}

/// FPNeg uses the shared arithmetic core's AH-sensitive pre-operation transform.
pub fn negate(format: Format, fpcr: u32, bits: u64) -> u64 {
    super::negate(format, bits, Control(fpcr))
}

#[cfg(test)]
mod tests;
