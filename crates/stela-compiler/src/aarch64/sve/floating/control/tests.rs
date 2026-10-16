use super::*;
use crate::aarch64::floating::{EXCEPTIONS, FPCR_EXCEPTION_ENABLE_SHIFT};

#[test]
fn ordinary_streaming_suppresses_only_exception_enables() {
    // Include reserved imported storage: effective controls may clear only
    // the specified enable field, rather than normalizing raw FPCR.
    const OTHER_CONTROLS: u32 = !FPCR_EXCEPTION_ENABLE_MASK;
    for exception_subset in 0..=EXCEPTIONS {
        if exception_subset & !EXCEPTIONS != 0 {
            continue;
        }
        let fpcr = OTHER_CONTROLS | (exception_subset << FPCR_EXCEPTION_ENABLE_SHIFT);
        assert_eq!(effective_fpcr(fpcr, true, false), OTHER_CONTROLS);
        assert_eq!(effective_fpcr(fpcr, true, true), fpcr);
        assert_eq!(effective_fpcr(fpcr, false, false), fpcr);
        assert_eq!(effective_fpcr(fpcr, false, true), fpcr);
    }
}

#[test]
fn precision_conversion_ignores_ahp_in_every_mode() {
    const IMPORTED_FPCR: u32 = u32::MAX;
    for streaming in [false, true] {
        for full_a64 in [false, true] {
            assert_eq!(
                conversion_fpcr(IMPORTED_FPCR, streaming, full_a64),
                effective_fpcr(IMPORTED_FPCR, streaming, full_a64) & !FPCR_AHP
            );
        }
    }
}
