//! Memory attributes of a translation (Arm ARM D8.6): the MAIR byte a
//! descriptor selects and its shareability, and the defaults with stage 1
//! disabled.

use super::MemoryType;

/// Device-nGnRnE: data accesses with the MMU off.
pub const DEVICE_NGNRNE: u8 = 0x00;
/// Normal Inner/Outer Write-Through, Read-Allocate: instruction fetch with the
/// MMU off and SCTLR.I set.
pub const NORMAL_WRITE_THROUGH: u8 = 0xaa;
/// Normal Inner/Outer Non-cacheable: instruction fetch with SCTLR.I clear.
pub const NORMAL_NON_CACHEABLE: u8 = 0x44;
/// SH encoding of Outer Shareable.
pub const OUTER_SHAREABLE: u8 = 0b10;

const SCTLR_I: u64 = 1 << 12;
const ATTRIBUTE_INDEX_SHIFT: u64 = 2;
const SHAREABILITY_SHIFT: u64 = 8;

/// The MAIR attribute byte, memory type and shareability of a descriptor.
pub fn of_descriptor(mair: u64, descriptor: u64) -> (u8, MemoryType, u8) {
    let index = (descriptor >> ATTRIBUTE_INDEX_SHIFT) & 7;
    let attribute = (mair >> (index * 8)) as u8;
    let memory = memory_type(attribute);
    let shareability = (descriptor >> SHAREABILITY_SHIFT) as u8 & 3;
    (
        attribute,
        memory,
        effective_shareability(attribute, shareability),
    )
}

pub fn memory_type(attribute: u8) -> MemoryType {
    if attribute & 0xf0 == 0 {
        MemoryType::Device
    } else {
        MemoryType::Normal
    }
}

/// Device memory and Normal memory that is Non-cacheable at both levels are
/// Outer Shareable whatever SH says.
pub fn effective_shareability(attribute: u8, shareability: u8) -> u8 {
    if memory_type(attribute) == MemoryType::Device || attribute == NORMAL_NON_CACHEABLE {
        OUTER_SHAREABLE
    } else {
        shareability
    }
}

/// Attributes with stage 1 disabled: data is Device-nGnRnE, and instruction
/// fetch is Normal, Write-Through cacheable when SCTLR.I is set; both Outer
/// Shareable.
pub fn disabled(sctlr: u64, execute: bool) -> (u8, MemoryType) {
    let attribute = match (execute, sctlr & SCTLR_I != 0) {
        (false, _) => DEVICE_NGNRNE,
        (true, true) => NORMAL_WRITE_THROUGH,
        (true, false) => NORMAL_NON_CACHEABLE,
    };
    (attribute, memory_type(attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mair_selects_the_byte_and_shareability_follows_the_type() {
        // Index 0 Device-nGnRE, 1 Normal write-back, 2 Normal Non-cacheable.
        let mair = 0x44_ff_04;
        let inner_shareable = 0b11 << 8;
        assert_eq!(
            of_descriptor(mair, 1 << 2 | inner_shareable),
            (0xff, MemoryType::Normal, 0b11)
        );
        assert_eq!(
            of_descriptor(mair, inner_shareable),
            (0x04, MemoryType::Device, OUTER_SHAREABLE)
        );
        assert_eq!(
            of_descriptor(mair, 2 << 2),
            (0x44, MemoryType::Normal, OUTER_SHAREABLE)
        );
        assert_eq!(disabled(0, false), (DEVICE_NGNRNE, MemoryType::Device));
        assert_eq!(
            disabled(SCTLR_I, true),
            (NORMAL_WRITE_THROUGH, MemoryType::Normal)
        );
        assert_eq!(
            disabled(0, true),
            (NORMAL_NON_CACHEABLE, MemoryType::Normal)
        );
    }
}
