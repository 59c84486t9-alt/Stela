//! Where the system-mode engine lives once the guest owns the x86 address
//! space, for the host's placement (`docs/design/system.md#host-placement`).
//! Under LA57, PML5 entry 0 holds the guest's TTBR0 range, entry 511 its
//! TTBR1 range, and Stela's window is entry 64. On a four-level host the
//! window starts at the upper half's bottom, PML4 entry 256, and fills the
//! slices below the guard slice under the guest's native upper range.
//!
//! The loader sets the placement before it builds any table, and the engine
//! sets it again from the handoff first thing: its image is a copy taken
//! before the loader ran.
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use stela_engine::machine::mmu::placement::Placement;
use stela_engine::machine::mmu::placement::SLICE;
use stela_engine::machine::mmu::placement::UPPER_HALF;

/// PML5 entry 64: bits 56:48 = 0x40.
const FIVE_LEVEL_WINDOW: u64 = 0x0040_0000_0000_0000;
const FIVE_LEVEL_WINDOW_INDEX: usize = 64;
/// The physmap's offset in the window: past the window's other parts, and
/// under LA57 half the root entry, on a four-level host 1 TiB, half the
/// first slice.
const FIVE_LEVEL_PHYSMAP: u64 = 1 << 47;
pub const FOUR_LEVEL_PHYSMAP: u64 = 1 << 40;
/// Bytes a four-level root entry maps: 512 GiB.
const PML4_ENTRY: u64 = 1 << 39;

/// The engine's copy of this image, at the window's start.
const IMAGE: u64 = 0;
/// The engine stack; the page below it stays unmapped as a guard.
const STACK: u64 = 0x2_0000_0000;
/// Native code, executable and not writable here; written through the
/// physmap.
const CODE: u64 = 0x3_0000_0000;
/// The translation helper's two-page bounce slot.
const BOUNCE: u64 = 0x4_0000_0000;
// 0x5/0x6 windows belong to MMIO and scoped RAM-publication diagnostics.
const INVOCATION_STACKS: u64 = 0x7_0000_0000;
const TASK_STACKS: u64 = 0x8_0000_0000;

/// The four-level slices below `U`, or zero under LA57.
static SLICES: AtomicU8 = AtomicU8::new(0);
static WINDOW: AtomicU64 = AtomicU64::new(FIVE_LEVEL_WINDOW);
static PHYSMAP: AtomicU64 = AtomicU64::new(FIVE_LEVEL_WINDOW + FIVE_LEVEL_PHYSMAP);

/// Place the window for `placement`; once per phase, before any table.
pub fn set(placement: Placement) {
    let (slices, window, physmap) = match placement {
        Placement::FiveLevel => (0, FIVE_LEVEL_WINDOW, FIVE_LEVEL_PHYSMAP),
        Placement::FourLevel { slices } => (slices, UPPER_HALF, FOUR_LEVEL_PHYSMAP),
    };
    SLICES.store(slices, Ordering::Relaxed);
    WINDOW.store(window, Ordering::Relaxed);
    PHYSMAP.store(window + physmap, Ordering::Relaxed);
}

pub fn placement() -> Placement {
    match SLICES.load(Ordering::Relaxed) {
        0 => Placement::FiveLevel,
        slices => Placement::FourLevel { slices },
    }
}

/// The placement whose physmap reaches host physical address `top`: LA57
/// when the CPU has it, else the fewest four-level slices.
pub fn choose(la57: bool, top: u64) -> Option<Placement> {
    match la57 {
        true => (top <= FIVE_LEVEL_PHYSMAP).then_some(Placement::FiveLevel),
        false => Placement::four_level_for(FOUR_LEVEL_PHYSMAP + top),
    }
}

/// The level of a root's entries: 4 for a PML5, 3 for a PML4.
pub fn top_level() -> u32 {
    match placement() {
        Placement::FiveLevel => 4,
        Placement::FourLevel { .. } => 3,
    }
}

/// The root entries the window takes, which every root shares.
pub fn window_entries() -> (usize, usize) {
    match placement() {
        Placement::FiveLevel => (FIVE_LEVEL_WINDOW_INDEX, FIVE_LEVEL_WINDOW_INDEX),
        Placement::FourLevel { slices } => {
            let first = 256;
            let entries = (u64::from(slices) - 1) * (SLICE / PML4_ENTRY);
            (first, first + entries as usize - 1)
        }
    }
}

pub fn window() -> u64 {
    WINDOW.load(Ordering::Relaxed)
}

pub fn image() -> u64 {
    window() + IMAGE
}

pub fn stack() -> u64 {
    window() + STACK
}

pub fn invocation_stacks() -> u64 {
    window() + INVOCATION_STACKS
}
pub fn task_stacks() -> u64 {
    window() + TASK_STACKS
}

pub fn code() -> u64 {
    window() + CODE
}

pub fn bounce() -> u64 {
    window() + BOUNCE
}

/// The window address of host physical address `physical`.
pub fn physical(physical: u64) -> u64 {
    PHYSMAP.load(Ordering::Relaxed) + physical
}
