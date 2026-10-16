//! Clearing upper Z bytes after AdvSIMD writes to V registers.

use super::{ADDRESS_RDX, Host, storage_pointer, upper_offset, vector_memory, xmm};
use crate::{
    TargetCpu,
    aarch64::scalable::{VectorLength, is_z_register},
    context::SCALABLE_Z_UPPER_OFFSET,
};
use alloc::vec::Vec;

/// Apply an accepted legacy V write's upper-Z clearing effect. The caller owns
/// instruction legality and which destination(s) require this effect. Clobbers
/// the selected zero XMM and RDX; preserves the canonical low128 V register.
pub(crate) fn clear_z_upper(
    code: &mut Vec<u8>,
    register: u8,
    zero: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    assert!(is_z_register(register));
    xmm(zero);
    if length.chunks() == 1 {
        return;
    }
    storage_pointer(code, SCALABLE_Z_UPPER_OFFSET);
    Host::Xor.register(code, zero, zero, target);
    for chunk in 1..length.chunks() {
        vector_memory(
            code,
            Host::StoreUnaligned,
            zero,
            ADDRESS_RDX,
            upper_offset(register, chunk, length),
            target,
        );
    }
}

#[cfg(test)]
mod tests;
