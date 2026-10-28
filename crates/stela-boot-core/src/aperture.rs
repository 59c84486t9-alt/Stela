//! The rules the native MMIO aperture's owned mappings rely on: the processor
//! controls that make its uncached leaves uncached on Intel and AMD alike,
//! which host processors and roots may use it, how a retired translation
//! leaves the TLB, and where a PCI BAR sits in the CPU's physical space.
//! Pure functions over observed register values and firmware descriptions.
use core::sync::atomic::{AtomicBool, Ordering};

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

/// Which processors may hold aperture translations. Until [`share`] only the
/// boot processor runs, so a retirement's local flush is complete; after it
/// the other host processors may hold the translations, and with no
/// cross-processor shootdown a retirement refuses and the mapping stays.
/// Installation needs no remote flush, since processors do not cache
/// not-present entries, and the authority's lock orders installations.
///
/// [`share`]: Self::share
#[derive(Debug, Default)]
pub struct Processors {
    shared: AtomicBool,
}

impl Processors {
    pub const fn new() -> Self {
        Self {
            shared: AtomicBool::new(false),
        }
    }

    /// The other host processors start: from now on they may translate
    /// through the aperture.
    pub fn share(&self) {
        self.shared.store(true, Ordering::Release);
    }

    /// Whether a retired translation can be flushed from every processor
    /// that may hold it.
    pub fn may_retire(&self) -> bool {
        !self.shared.load(Ordering::Acquire)
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
    fn retirement_refuses_once_other_processors_may_translate() {
        let processors = Processors::new();
        assert!(processors.may_retire());
        processors.share();
        assert!(!processors.may_retire());
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
