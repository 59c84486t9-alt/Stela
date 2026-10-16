//! ADR and ADRP, computed from the guest PC.
use super::{Register, register};
use crate::GuestAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: Register,
    pub address: u64,
}

pub fn decode(pc: GuestAddress, word: u32) -> Option<Operand> {
    // Arm ADR_only_pcreladdr / ADRP_only_pcreladdr: op is bit 31;
    // immlo is bits 30:29, immhi is bits 23:5, bits 28:24 are 10000.
    if word & 0x1f000000 != 0x10000000 {
        return None;
    }
    let immediate = ((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3);
    let signed = (i64::from(immediate) << 43) >> 43;
    let address = if word >> 31 == 0 {
        pc.0.wrapping_add_signed(signed)
    } else {
        // ADRP's architectural granule is always 4 KiB, including on Apple
        // platforms whose virtual memory mappings use 16 KiB pages.
        (pc.0 & !0xfff).wrapping_add_signed(signed * 4096)
    };
    Some(Operand {
        destination: register(word & 31, false),
        address,
    })
}

#[cfg(test)]
mod tests;
