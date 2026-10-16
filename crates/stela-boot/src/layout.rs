//! Where the system-mode engine lives once the guest owns the x86 address
//! space: five-level (LA57) paging gives PML5 entry 0 to the guest's TTBR0
//! range and entry 511 to its TTBR1 range, and Stela takes entry 64.
//! `docs/design/system.md#host-placement` explains the choice.

/// PML5 entry 64: bits 56:48 = 0x40. Every guest root shares this entry.
pub const WINDOW: u64 = 0x0040_0000_0000_0000;
pub const WINDOW_INDEX: usize = 64;
/// The engine's copy of this image.
pub const IMAGE: u64 = WINDOW;
/// The engine heap.
pub const HEAP: u64 = WINDOW + 0x1_0000_0000;
/// The engine stack; the page below it stays unmapped as a guard.
pub const STACK: u64 = WINDOW + 0x2_0000_0000;
/// Native code, executable and not writable here; written through the physmap.
pub const CODE: u64 = WINDOW + 0x3_0000_0000;
/// Every host physical page Stela uses, RW+NX, at this offset.
pub const PHYSMAP: u64 = WINDOW + (1 << 47);

/// The window address of host physical address `physical`.
pub const fn physical(physical: u64) -> u64 {
    PHYSMAP + physical
}
