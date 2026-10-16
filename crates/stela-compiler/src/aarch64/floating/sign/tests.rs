use super::*;
use crate::aarch64::floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK};

#[test]
fn ah_preserves_both_nan_classes_and_plain_sign_changes_do_not_quiet() {
    for format in [Format::Half, Format::Single, Format::Double] {
        let sign = format.sign_mask();
        for payload in [1, format.quiet_bit() | 1] {
            let nan = sign | format.exponent_mask() | payload;
            assert_eq!(absolute(format, FPCR_AH, nan), nan);
            assert_eq!(negate(format, FPCR_AH, nan), nan);
            assert_eq!(absolute(format, 0, nan), nan ^ sign);
            assert_eq!(negate(format, 0, nan), nan ^ sign);
        }
    }
}

#[test]
fn retained_exception_enables_do_not_block_sign_operations() {
    for format in [Format::Half, Format::Single, Format::Double] {
        let sign = format.sign_mask();
        for value in [
            0,
            sign,
            format.exponent_mask(),
            sign | format.exponent_mask(),
        ] {
            assert_eq!(
                absolute(format, FPCR_EXCEPTION_ENABLE_MASK, value),
                value & !sign
            );
            assert_eq!(
                negate(format, FPCR_EXCEPTION_ENABLE_MASK, value),
                value ^ sign
            );
        }
    }
}
