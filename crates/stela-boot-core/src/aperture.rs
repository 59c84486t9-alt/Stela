//! The rules the native MMIO aperture's owned mappings rely on: the processor
//! controls that make its uncached leaves uncached on Intel and AMD alike,
//! which host processors and roots may use it, how a retired translation
//! leaves every processor's TLB, and where a PCI BAR sits in the CPU's
//! physical space. Pure functions over observed register values and firmware
//! descriptions, and the shootdown's generation bookkeeping.
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

const CR0_WRITE_PROTECT: u64 = 1 << 16;
const CR4_LA57: u64 = 1 << 12;
const CR4_PCIDE: u64 = 1 << 17;
const EFER_NXE: u64 = 1 << 11;
/// The IA32_PAT memory type encodings (Intel SDM Vol. 3A 12.12.2, AMD APM
/// Vol. 2 7.8.1 give the same table).
const WRITE_BACK: u8 = 6;
const UNCACHED: u8 = 0;
/// The PAT entry a PTE with PWT and PCD set and PAT clear selects: the
/// aperture's leaves.
pub const LEAF_PAT_INDEX: u32 = 3;

/// One host processor's controls, read in the host's root.
#[derive(Clone, Copy, Debug)]
pub struct Controls {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub pat: u64,
    /// The paging levels the loader built the window for, 4 or 5.
    pub levels: u32,
}

/// Why the controls cannot carry the aperture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// PAT entry 0 is not write-back, so the page tables' own
    /// write-back aliases are not.
    TablesNotWriteBack,
    /// The leaves' PAT entry is not uncached.
    LeavesNotUncached,
    /// Supervisor writes ignore read-only leaves without CR0.WP.
    WriteProtectOff,
    /// CR3 carries cache controls for the root without PCIDs.
    RootCacheControls,
    /// CR4.LA57 does not match the window's paging levels.
    PagingLevels,
    /// The leaves set NX, reserved without EFER.NXE.
    NoExecuteOff,
}

/// How a retired aperture translation leaves this processor's TLB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flush {
    /// INVLPG each page: without PCIDs it covers every root.
    Pages,
    /// Toggle CR4.PGE, which drops every PCID's entries (Intel SDM Vol. 3A
    /// 4.10.4.1, AMD APM Vol. 2 5.5.3): the loader root has a PCID of its own
    /// while the engine runs.
    AllContexts,
}

/// Check the controls the aperture needs and choose its TLB flush.
pub fn qualify(controls: &Controls) -> Result<Flush, Refusal> {
    let pat = |index: u32| (controls.pat >> (8 * index)) as u8;
    if pat(0) != WRITE_BACK {
        return Err(Refusal::TablesNotWriteBack);
    }
    if pat(LEAF_PAT_INDEX) != UNCACHED {
        return Err(Refusal::LeavesNotUncached);
    }
    if controls.cr0 & CR0_WRITE_PROTECT == 0 {
        return Err(Refusal::WriteProtectOff);
    }
    let tagged = controls.cr4 & CR4_PCIDE != 0;
    if !tagged && controls.cr3 & 0xfff != 0 {
        return Err(Refusal::RootCacheControls);
    }
    if (controls.cr4 & CR4_LA57 != 0) != (controls.levels == 5) {
        return Err(Refusal::PagingLevels);
    }
    if controls.efer & EFER_NXE == 0 {
        return Err(Refusal::NoExecuteOff);
    }
    Ok(if tagged {
        Flush::AllContexts
    } else {
        Flush::Pages
    })
}

/// Whether a root whose top-level entry for the aperture is `current`
/// reaches the aperture's leaves, given the loader root's `loader` entry:
/// every root copies the loader's window entries, so equal present entries
/// lead to the same tables.
pub fn shares_aperture(current: u64, loader: u64) -> bool {
    current & 1 != 0 && current == loader
}

/// The most processors that may share the aperture, MADT's 8-bit APIC IDs
/// and x2APIC's beyond them alike: the boot's processor cap.
pub const MAX_PROCESSORS: usize = 256;

/// Which other host processors may hold aperture translations, and how far
/// each has flushed. Until one [`join`]s, only the boot processor runs and a
/// retirement's local flush is complete. After that a retirement
/// [`request`]s a generation, interrupts every [`sharer`], and waits until
/// each has [`acknowledge`]d it: a processor acknowledges a generation once
/// it has flushed every aperture translation older than the request.
/// Installation needs no remote flush, since processors do not cache
/// not-present entries, and the permission's lock orders installations and
/// retirements.
///
/// [`join`]: Self::join
/// [`request`]: Self::request
/// [`sharer`]: Self::sharers
/// [`acknowledge`]: Self::acknowledge
#[derive(Debug)]
pub struct Processors {
    joined: AtomicUsize,
    requested: AtomicU64,
    apic: [AtomicU32; MAX_PROCESSORS],
    acknowledged: [AtomicU64; MAX_PROCESSORS],
}

impl Default for Processors {
    fn default() -> Self {
        Self::new()
    }
}

impl Processors {
    pub const fn new() -> Self {
        Self {
            joined: AtomicUsize::new(0),
            requested: AtomicU64::new(0),
            apic: [const { AtomicU32::new(0) }; MAX_PROCESSORS],
            acknowledged: [const { AtomicU64::new(0) }; MAX_PROCESSORS],
        }
    }

    /// The processor with `apic` ID starts and may translate through the
    /// aperture from now on; its slot, or `None` when every slot is taken.
    /// Joins are made by the boot processor, before each one starts.
    pub fn join(&self, apic: u32) -> Option<usize> {
        let slot = self.joined.load(Ordering::Relaxed);
        if slot == MAX_PROCESSORS {
            return None;
        }
        self.apic[slot].store(apic, Ordering::Relaxed);
        self.acknowledged[slot].store(self.requested.load(Ordering::Acquire), Ordering::Relaxed);
        self.joined.store(slot + 1, Ordering::Release);
        Some(slot)
    }

    /// Whether only the boot processor may hold aperture translations.
    pub fn alone(&self) -> bool {
        self.joined.load(Ordering::Acquire) == 0
    }

    /// The slot of the processor with `apic` ID.
    pub fn slot(&self, apic: u32) -> Option<usize> {
        (0..self.joined.load(Ordering::Acquire))
            .find(|&slot| self.apic[slot].load(Ordering::Relaxed) == apic)
    }

    /// Each joined processor's slot and APIC ID.
    pub fn sharers(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        (0..self.joined.load(Ordering::Acquire))
            .map(|slot| (slot, self.apic[slot].load(Ordering::Relaxed)))
    }

    /// Publish a flush request after the retired entries are cleared; the
    /// generation each sharer must acknowledge. Interrupts are sent after
    /// this store, so a processor woken by one sees the request.
    pub fn request(&self) -> u64 {
        self.requested.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// The latest requested generation.
    pub fn requested(&self) -> u64 {
        self.requested.load(Ordering::Acquire)
    }

    /// Slot `slot`'s processor flushed every translation older than
    /// `generation`'s request.
    pub fn acknowledge(&self, slot: usize, generation: u64) {
        if let Some(acknowledged) = self.acknowledged.get(slot) {
            acknowledged.fetch_max(generation, Ordering::Release);
        }
    }

    /// The generation slot `slot`'s processor last acknowledged.
    pub fn acknowledged(&self, slot: usize) -> u64 {
        self.acknowledged
            .get(slot)
            .map_or(0, |acknowledged| acknowledged.load(Ordering::Acquire))
    }

    /// Whether every sharer but `except` (the retiring processor's slot)
    /// acknowledged `generation`.
    pub fn flushed(&self, generation: u64, except: Option<usize>) -> bool {
        self.sharers()
            .all(|(slot, _)| Some(slot) == except || self.acknowledged(slot) >= generation)
    }
}

/// A root bridge's memory window as firmware describes it: bus addresses
/// `minimum..=maximum`, which the CPU reaches at `translation` above them.
#[derive(Clone, Copy, Debug)]
pub struct BusWindow {
    pub segment: u32,
    pub minimum: u64,
    pub maximum: u64,
    pub translation: u64,
}

/// The CPU physical address of a memory BAR at bus address `address` for
/// `bytes` on `segment`, when one root bridge window holds all of it.
pub fn bar_physical(
    windows: impl IntoIterator<Item = BusWindow>,
    segment: u32,
    address: u64,
    bytes: u64,
) -> Option<u64> {
    let last = address.checked_add(bytes.checked_sub(1)?)?;
    windows
        .into_iter()
        .find(|window| {
            window.segment == segment && window.minimum <= address && last <= window.maximum
        })
        .and_then(|window| address.checked_add(window.translation))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAT_DEFAULT: u64 = 0x0007_0406_0007_0406;

    fn controls() -> Controls {
        Controls {
            cr0: 0x8001_0033,
            cr3: 0x1000,
            cr4: 0x20,
            efer: 0xd01,
            pat: PAT_DEFAULT,
            levels: 4,
        }
    }

    #[test]
    fn the_power_on_pat_carries_the_aperture_on_either_vendor() {
        assert_eq!(qualify(&controls()), Ok(Flush::Pages));
        let five = Controls {
            cr4: 0x20 | CR4_LA57,
            levels: 5,
            ..controls()
        };
        assert_eq!(qualify(&five), Ok(Flush::Pages));
    }

    #[test]
    fn pcids_flush_every_context_and_allow_tagged_roots() {
        let tagged = Controls {
            cr3: 0x1001,
            cr4: 0x20 | CR4_PCIDE,
            ..controls()
        };
        assert_eq!(qualify(&tagged), Ok(Flush::AllContexts));
        let untagged = Controls {
            cr3: 0x1018,
            ..controls()
        };
        assert_eq!(qualify(&untagged), Err(Refusal::RootCacheControls));
    }

    #[test]
    fn controls_the_leaves_depend_on_refuse() {
        for (changed, refusal) in [
            (
                Controls {
                    pat: PAT_DEFAULT & !0xff | 1,
                    ..controls()
                },
                Refusal::TablesNotWriteBack,
            ),
            (
                Controls {
                    pat: PAT_DEFAULT | 7 << 24,
                    ..controls()
                },
                Refusal::LeavesNotUncached,
            ),
            (
                Controls {
                    cr0: 0x8000_0033,
                    ..controls()
                },
                Refusal::WriteProtectOff,
            ),
            (
                Controls {
                    levels: 5,
                    ..controls()
                },
                Refusal::PagingLevels,
            ),
            (
                Controls {
                    efer: 0x501,
                    ..controls()
                },
                Refusal::NoExecuteOff,
            ),
        ] {
            assert_eq!(qualify(&changed), Err(refusal));
        }
    }

    #[test]
    fn only_the_loader_roots_present_entry_reaches_the_aperture() {
        assert!(shares_aperture(0x5003, 0x5003));
        assert!(!shares_aperture(0x5003, 0x6003));
        assert!(!shares_aperture(0, 0));
    }

    #[test]
    fn a_retirement_waits_for_every_sharer_but_the_retiring_one() {
        let processors = Processors::new();
        assert!(processors.alone());
        assert!(processors.flushed(processors.request(), None));
        let a = processors.join(4).unwrap();
        let b = processors.join(9).unwrap();
        assert!(!processors.alone());
        assert_eq!(processors.slot(9), Some(b));
        assert_eq!(processors.slot(5), None);
        // A processor that joins has seen every earlier request.
        assert!(processors.flushed(processors.requested(), None));
        let generation = processors.request();
        assert!(!processors.flushed(generation, Some(b)));
        processors.acknowledge(a, generation);
        assert!(processors.flushed(generation, Some(b)));
        assert!(!processors.flushed(generation, None));
        processors.acknowledge(b, generation);
        processors.acknowledge(b, generation - 1);
        assert_eq!(processors.acknowledged(b), generation);
        assert!(processors.flushed(generation, None));
        assert_eq!(
            processors.sharers().collect::<alloc::vec::Vec<_>>(),
            [(a, 4), (b, 9)]
        );
    }

    #[test]
    fn joins_stop_at_the_processor_cap() {
        let processors = Processors::new();
        for apic in 0..MAX_PROCESSORS as u32 {
            assert!(processors.join(apic).is_some());
        }
        assert_eq!(processors.join(1000), None);
    }

    #[test]
    fn bars_map_through_the_window_that_holds_them() {
        let windows = [
            BusWindow {
                segment: 0,
                minimum: 0x8000_0000,
                maximum: 0x8fff_ffff,
                translation: 0,
            },
            BusWindow {
                segment: 1,
                minimum: 0x8000_0000,
                maximum: 0x8fff_ffff,
                translation: 0x10_0000_0000,
            },
        ];
        assert_eq!(
            bar_physical(windows, 0, 0x8000_4000, 0x4000),
            Some(0x8000_4000)
        );
        assert_eq!(
            bar_physical(windows, 1, 0x8000_4000, 0x4000),
            Some(0x10_8000_4000)
        );
        assert_eq!(bar_physical(windows, 0, 0x8fff_f000, 0x2000), None);
        assert_eq!(bar_physical(windows, 2, 0x8000_0000, 0x1000), None);
        assert_eq!(bar_physical(windows, 0, 0x8000_0000, 0), None);
    }
}
