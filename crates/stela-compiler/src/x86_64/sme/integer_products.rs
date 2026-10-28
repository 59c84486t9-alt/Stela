//! Integer product kernels shared by the SME families.
use crate::x86_64::asm::Code;
use crate::{TargetCpu, x86_64::isa::SimdOpcode as Host};

pub(crate) const PRODUCT_LEFT: u8 = 0;
pub(crate) const PRODUCT_RIGHT: u8 = 1;
pub(crate) const PRODUCT_TEMPORARY: u8 = 3;
pub(crate) const PRODUCT_HIGH: u8 = 4;

/// Multiply eight same-sign 16-bit pairs into eight full 32-bit products.
///
/// Inputs are XMM0/1; XMM0 receives products0..3 and XMM4 products4..7.
/// XMM3 is scratch. All other XMM/GPR registers, memory and FP state survive.
/// Widen each resulting product before any 64-bit sum; PMADDWD overflow cannot
/// be repaired by sign-extending its already truncated pair result.
pub(crate) fn word_products(code: &mut Code, signed: bool, target: TargetCpu) {
    Host::MoveAligned.register(code, PRODUCT_TEMPORARY, PRODUCT_LEFT, target);
    Host::MultiplyLowWord.register(code, PRODUCT_LEFT, PRODUCT_RIGHT, target);
    (if signed {
        Host::MultiplyHighSignedWord
    } else {
        Host::MultiplyHighUnsignedWord
    })
    .register(code, PRODUCT_TEMPORARY, PRODUCT_RIGHT, target);
    Host::MoveAligned.register(code, PRODUCT_HIGH, PRODUCT_LEFT, target);
    Host::UnpackLowWord.register(code, PRODUCT_LEFT, PRODUCT_TEMPORARY, target);
    Host::UnpackHighWord.register(code, PRODUCT_HIGH, PRODUCT_TEMPORARY, target);
}
