//! Alignment faults (pseudocode AArch64.UnalignedAccessFaults,
//! AArch64.S1HasAlignmentFaultDueToMemType and
//! AArch64.S2HasAlignmentFaultDueToMemType) for the profile, which has
//! FEAT_LSE2.
//!
//! IMPLEMENTATION DEFINED and CONSTRAINED UNPREDICTABLE choices:
//! - the single-copy-atomic granule ("Aligned quantity for atomic access")
//!   is 16 bytes, the smallest FEAT_LSE2 allows;
//! - Device memory does not support unaligned accesses;
//! - an unaligned exclusive, atomic or ordered access to Normal memory that
//!   is not Write-Back shareable with the data cache enabled does not fault
//!   (Unpredictable_LSE2_ALIGNMENT_FAULT: Arm's `ConstrainUnpredictable`
//!   choice), as native code makes it.

use super::Alignment;

/// SCTLR_ELx.A: alignment checking for every data access.
pub const SCTLR_A: u64 = 1 << 1;
/// SCTLR_ELx.nAA: LDAPR, LDAR, STLR and their unscaled forms do not fault
/// when unaligned within 16 bytes.
pub const SCTLR_NAA: u64 = 1 << 6;
/// SCTLR_ELx.C: the stage-1 data cache is enabled.
pub const SCTLR_C: u64 = 1 << 2;

const ATOMIC_GRANULE: u64 = 16;
const ORDERED_GRANULE: u64 = 16;

/// What kind of data access is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Plain,
    /// Load-, store-exclusive and their pairs.
    Exclusive,
    /// LSE atomics, CAS and CASP.
    Atomic,
    /// Load-acquire (RCsc or RCpc) and store-release.
    Ordered,
    /// DC ZVA.
    Zero,
}

/// One data access: its kind, its size in bytes and whether it is a pair,
/// whose halves are each checked for alignment unless it is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub kind: Kind,
    pub bytes: u64,
    pub pair: bool,
}

impl Shape {
    /// The access is naturally aligned (pseudocode `aligned` in Mem).
    pub fn aligned(self, address: u64) -> bool {
        let unit = if self.pair && self.kind != Kind::Exclusive {
            self.bytes / 2
        } else {
            self.bytes
        };
        address.is_multiple_of(unit.max(1))
    }
}

/// The `aligned` value computed by Arm Mem and kept by each MemSingle.
/// It describes the original access, not a fresh instruction at a split address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryCheck {
    aligned: bool,
    zero: bool,
}
impl MemoryCheck {
    pub fn new(shape: Shape, address: u64) -> Self {
        Self {
            aligned: shape.aligned(address),
            zero: shape.kind == Kind::Zero,
        }
    }
    /// Mem's 32-byte ASIMD pair at an eight-byte-aligned address explicitly
    /// becomes four aligned eight-byte accesses (FEAT_LS64WB is disabled).
    pub fn aligned() -> Self {
        Self {
            aligned: true,
            zero: false,
        }
    }
    pub fn faults(self, memory: Alignment) -> bool {
        memory.device && (self.zero || !self.aligned)
    }
}

/// Whether `bytes` at `address` stay inside one naturally aligned
/// `quantity` (pseudocode AllInAlignedQuantity).
fn within(address: u64, bytes: u64, quantity: u64) -> bool {
    address / quantity == address.wrapping_add(bytes.saturating_sub(1)) / quantity
}

/// The check made before translation (pseudocode
/// AArch64.UnalignedAccessFaults), with `sctlr` the SCTLR_ELx of the
/// regime the access is made in.
pub fn before_translation(sctlr: u64, address: u64, shape: Shape) -> bool {
    if shape.aligned(address) {
        return false;
    }
    if sctlr & SCTLR_A != 0 {
        return true;
    }
    match shape.kind {
        Kind::Exclusive | Kind::Atomic => !within(address, shape.bytes, ATOMIC_GRANULE),
        Kind::Ordered if sctlr & SCTLR_NAA != 0 => false,
        Kind::Ordered if shape.pair => {
            let half = shape.bytes / 2;
            !within(address, half, ORDERED_GRANULE)
                || !within(address.wrapping_add(half), half, ORDERED_GRANULE)
        }
        Kind::Ordered => !within(address, shape.bytes, ORDERED_GRANULE),
        Kind::Plain | Kind::Zero => false,
    }
}

/// The check made after translation, from the memory type at each stage,
/// summarized by `memory` (pseudocode AArch64.S1HasAlignmentFaultDueToMemType and
/// AArch64.S2HasAlignmentFaultDueToMemType).
pub fn after_translation(memory: Alignment, address: u64, shape: Shape) -> bool {
    memory.device && (shape.kind == Kind::Zero || !shape.aligned(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(kind: Kind, bytes: u64) -> Shape {
        Shape {
            kind,
            bytes,
            pair: false,
        }
    }

    fn translation(device: bool) -> Alignment {
        Alignment { device }
    }

    #[test]
    fn sctlr_a_lse2_granules_and_naa_decide_before_translation() {
        super::super::test_translation_chip();
        let plain = shape(Kind::Plain, 8);
        assert!(!before_translation(0, 0x1004, plain));
        assert!(before_translation(SCTLR_A, 0x1004, plain));
        assert!(!before_translation(SCTLR_A, 0x1008, plain));
        // Exclusives and atomics may be unaligned inside 16 bytes (FEAT_LSE2).
        let atomic = shape(Kind::Atomic, 8);
        assert!(!before_translation(0, 0x1004, atomic));
        assert!(before_translation(0, 0x100c, atomic));
        assert!(before_translation(0, 0x100c, shape(Kind::Exclusive, 8)));
        // Ordered accesses fault across 16 bytes unless nAA is set.
        let ordered = shape(Kind::Ordered, 4);
        assert!(!before_translation(0, 0x1002, ordered));
        assert!(before_translation(0, 0x100e, ordered));
        assert!(!before_translation(SCTLR_NAA, 0x100e, ordered));
        // An ordered pair checks each half; an exclusive pair is one unit.
        let pair = Shape {
            kind: Kind::Ordered,
            bytes: 8,
            pair: true,
        };
        assert!(!before_translation(0, 0x1002, pair));
        assert!(before_translation(0, 0x100e, pair));
        let exclusive_pair = Shape {
            kind: Kind::Exclusive,
            bytes: 16,
            pair: true,
        };
        assert!(!exclusive_pair.aligned(0x1008) && exclusive_pair.aligned(0x1010));
        assert!(!before_translation(0, 0x1000, shape(Kind::Zero, 64)));
    }

    #[test]
    fn device_memory_alone_decides_after_translation() {
        super::super::test_translation_chip();
        let device = translation(true);
        let normal = translation(false);
        assert!(after_translation(device, 0x1004, shape(Kind::Plain, 8)));
        assert!(!after_translation(device, 0x1008, shape(Kind::Plain, 8)));
        assert!(!after_translation(normal, 0x1004, shape(Kind::Plain, 8)));
        // DC ZVA to Device memory always faults.
        assert!(after_translation(device, 0x1000, shape(Kind::Zero, 64)));
        assert!(!after_translation(normal, 0x1000, shape(Kind::Zero, 64)));
        // An unaligned atomic to Normal memory of any cacheability completes;
        // to Device memory it faults.
        assert!(!after_translation(normal, 0x1004, shape(Kind::Atomic, 8)));
        assert!(after_translation(device, 0x1004, shape(Kind::Atomic, 8)));
    }
}
