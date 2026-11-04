//! Software TLBs for translated accesses and device translations.
//!
//! The translated variant
//! (`docs/design/system.md#host-placement`): blocks that access guest
//! addresses outside the host's native ranges ([`super::placement`]) call a
//! host helper for each such access, which looks the page up here and
//! returns where the host reaches it. A miss, or a write to a page filled
//! read-only, leaves to the engine, which translates the access through
//! [`super`]'s walker, delivers its fault or fills the entry, and runs the
//! access again. The host clears the TLB whenever it drops shadow
//! translations: TLB maintenance, regime and control changes.
//!
//! Entries hold the host address of each guest page, so the helper needs
//! no walk: an access within one page, or across two pages the host holds
//! contiguously, runs there; across discontiguous pages the helper maps
//! both into its bounce slot, so the returned address is always valid for
//! the whole access and writes reach the guest's own frames.
//!
//! A separate cache records successful translations outside RAM. Its hits
//! avoid another walk, while the engine still performs each device access.

use super::{Requester, Translation, attributes};

/// The page an entry maps.
pub const PAGE: u64 = 1 << 12;
/// The entries, direct-mapped by virtual page number.
pub const ENTRIES: usize = 256;
/// The views (shadow roots: EL0, privileged, privileged with PAN, ...) an
/// entry's tag distinguishes.
pub const VIEWS: u8 = 8;

/// One page's translation for one view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Entry {
    /// The page's virtual address with the view in its low bits; valid
    /// while `host` is nonzero.
    tag: u64,
    /// The host address of the page.
    host: u64,
    writable: bool,
}

/// Where an access runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// At this host address, valid for the whole access.
    Direct(u64),
    /// Across two pages at these discontiguous host addresses: the helper
    /// maps them into its bounce slot and runs the access at the first
    /// page's offset there.
    Split { first: u64, second: u64 },
    /// The page holding `address` has no entry that permits the access:
    /// the engine translates it.
    Miss { address: u64 },
}

/// The software TLB.
#[derive(Debug, Clone)]
pub struct Tlb {
    entries: [Entry; ENTRIES],
    devices: DevicePages,
}

impl Default for Tlb {
    fn default() -> Self {
        Self {
            entries: [Entry::default(); ENTRIES],
            devices: DevicePages::default(),
        }
    }
}

const fn slot(page: u64) -> usize {
    ((page / PAGE) as usize) % ENTRIES
}

const fn tag(page: u64, view: u8) -> u64 {
    page | view as u64
}

impl Tlb {
    /// The host address of the page holding `address` for `view`, if an
    /// entry permits the access.
    fn page(&self, address: u64, write: bool, view: u8) -> Option<u64> {
        let page = address & !(PAGE - 1);
        let entry = &self.entries[slot(page)];
        (entry.host != 0 && entry.tag == tag(page, view) && (entry.writable || !write))
            .then_some(entry.host)
    }

    /// Where the `bytes`-byte access at `address` runs for `view`.
    pub fn lookup(&self, address: u64, bytes: u64, write: bool, view: u8) -> Lookup {
        let offset = address & (PAGE - 1);
        let Some(first) = self.page(address, write, view) else {
            return Lookup::Miss { address };
        };
        if offset + bytes <= PAGE {
            return Lookup::Direct(first + offset);
        }
        let next = (address | (PAGE - 1)).wrapping_add(1);
        match self.page(next, write, view) {
            None => Lookup::Miss { address: next },
            Some(second) if second == first + PAGE => Lookup::Direct(first + offset),
            Some(second) => Lookup::Split { first, second },
        }
    }

    /// Record that `view` reaches the page holding `address` at the host's
    /// `host` page, for writes too when `writable`.
    pub fn fill(&mut self, address: u64, host: u64, writable: bool, view: u8) {
        debug_assert!(host != 0 && host.is_multiple_of(PAGE) && view < VIEWS);
        let page = address & !(PAGE - 1);
        self.entries[slot(page)] = Entry {
            tag: tag(page, view),
            host,
            writable,
        };
    }

    /// Forget every entry.
    pub fn clear(&mut self) {
        self.entries = [Entry::default(); ENTRIES];
        self.clear_devices();
    }

    /// Drop device translations without changing cached RAM translations.
    pub fn clear_devices(&mut self) {
        self.devices.valid = 0;
    }

    /// A positive device translation, for a requester and access it permits.
    /// Every access still runs through the engine's device path.
    pub fn device_physical(&self, address: u64, requester: Requester, write: bool) -> Option<u64> {
        let (slot, tag) = device_tag(address, requester);
        if self.devices.valid & (1 << slot) == 0 {
            return None;
        }
        let (recorded, physical) = self.devices.entries[slot];
        let access = if write { DEVICE_WRITE } else { DEVICE_READ };
        (recorded == tag && physical & access != 0)
            .then_some((physical & !(PAGE - 1)) | (address & (PAGE - 1)))
    }

    /// Record a translated page outside RAM.
    /// The caller still checks watchpoints. Leave Tagged memory to the walk.
    pub fn record_device(&mut self, address: u64, requester: Requester, translation: Translation) {
        if translation.attributes == attributes::TAGGED {
            return;
        }
        debug_assert_eq!(translation.physical % PAGE, address % PAGE);
        let (slot, tag) = device_tag(address, requester);
        let rights = u64::from(translation.readable) | (u64::from(translation.writable) << 1);
        let physical = (translation.physical & !(PAGE - 1)) | rights;
        self.devices.entries[slot] = (tag, physical);
        self.devices.valid |= 1 << slot;
    }
}

const DEVICE_ENTRIES: usize = 64;
const DEVICE_READ: u64 = 1;
const DEVICE_WRITE: u64 = 2;

#[derive(Debug, Clone)]
struct DevicePages {
    /// Full virtual tag, physical page with data permissions in its low bits.
    entries: [(u64, u64); DEVICE_ENTRIES],
    valid: u64,
}

impl Default for DevicePages {
    fn default() -> Self {
        Self {
            entries: [(0, 0); DEVICE_ENTRIES],
            valid: 0,
        }
    }
}

fn device_tag(address: u64, requester: Requester) -> (usize, u64) {
    let page = address / PAGE;
    let requester = u64::from(requester.el)
        | (u64::from(requester.pan) << 8)
        | (u64::from(requester.unprivileged) << 9)
        | (u64::from(requester.guarded) << 10);
    // Registers in separate apertures can start at the same page offset.
    let slot = ((page ^ (page >> 6) ^ requester ^ (requester >> 6)) as usize) % DEVICE_ENTRIES;
    let tag = (address & !(PAGE - 1)) | requester;
    (slot, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VA: u64 = 0xffff_8000_1234_5000;
    const HOST: u64 = 0x7000_0000;
    const KERNEL: Requester = Requester {
        el: 1,
        pan: false,
        unprivileged: false,
        guarded: false,
    };

    fn device(physical: u64, readable: bool, writable: bool) -> Translation {
        Translation {
            physical,
            memory: super::super::MemoryType::Device,
            attributes: 0x04,
            shareability: 0b10,
            readable,
            writable,
            executable: false,
            pan_sensitive: false,
            guarded: false,
            global: true,
            asid: 0,
            size: PAGE,
            alignment: super::super::Alignment { device: true },
        }
    }

    #[test]
    fn device_page_hits_require_matching_requester_and_access_permissions() {
        let mut tlb = Tlb::default();
        tlb.record_device(VA + 4, KERNEL, device(4, true, false));
        assert_eq!(tlb.device_physical(VA + 12, KERNEL, false), Some(12));
        assert_eq!(tlb.device_physical(VA + 12, KERNEL, true), None);
        for requester in [
            Requester { el: 2, ..KERNEL },
            Requester {
                pan: true,
                ..KERNEL
            },
            Requester {
                unprivileged: true,
                ..KERNEL
            },
            Requester {
                guarded: true,
                ..KERNEL
            },
        ] {
            assert_eq!(tlb.device_physical(VA, requester, false), None);
        }
        let with_pan = Requester {
            pan: true,
            ..KERNEL
        };
        tlb.record_device(VA, with_pan, device(HOST, true, true));
        assert_eq!(tlb.device_physical(VA, with_pan, true), Some(HOST));
        assert_eq!(tlb.device_physical(VA, KERNEL, false), Some(0));
        tlb.record_device(VA, KERNEL, device(HOST, false, true));
        assert_eq!(tlb.device_physical(VA + 12, KERNEL, true), Some(HOST + 12));
        assert_eq!(tlb.device_physical(VA + 12, KERNEL, false), None);
        assert_eq!(tlb.lookup(VA, 1, true, 1), Lookup::Miss { address: VA });
        tlb.clear();
        assert_eq!(tlb.device_physical(VA, KERNEL, true), None);
    }

    #[test]
    fn clearing_devices_preserves_ram_entries() {
        let mut tlb = Tlb::default();
        let ram = VA + PAGE;
        tlb.fill(ram, HOST, true, 1);
        tlb.record_device(VA, KERNEL, device(HOST + PAGE, true, true));
        tlb.clear_devices();
        assert_eq!(tlb.device_physical(VA, KERNEL, false), None);
        assert_eq!(tlb.lookup(ram, 1, true, 1), Lookup::Direct(HOST));
    }

    #[test]
    fn device_cache_refuses_tagged_memory_and_requires_the_full_virtual_page() {
        let mut tlb = Tlb::default();
        let tagged = Translation {
            attributes: attributes::TAGGED,
            ..device(HOST, true, true)
        };
        tlb.record_device(VA, KERNEL, tagged);
        assert_eq!(tlb.device_physical(VA, KERNEL, false), None);

        let alias = VA ^ (PAGE << 12);
        tlb.record_device(VA, KERNEL, device(HOST, true, true));
        tlb.record_device(alias, KERNEL, device(HOST + PAGE, true, true));
        assert_eq!(tlb.device_physical(VA, KERNEL, false), None);
        assert_eq!(tlb.device_physical(alias, KERNEL, false), Some(HOST + PAGE));
    }

    #[test]
    fn an_access_within_a_filled_page_runs_at_its_host_address() {
        let mut tlb = Tlb::default();
        assert_eq!(
            tlb.lookup(VA + 8, 8, false, 1),
            Lookup::Miss { address: VA + 8 }
        );
        tlb.fill(VA + 0x10, HOST, false, 1);
        assert_eq!(tlb.lookup(VA + 8, 8, false, 1), Lookup::Direct(HOST + 8));
        // Another view, and a write to a read-only page, miss.
        assert_eq!(
            tlb.lookup(VA + 8, 8, false, 0),
            Lookup::Miss { address: VA + 8 }
        );
        assert_eq!(
            tlb.lookup(VA + 8, 8, true, 1),
            Lookup::Miss { address: VA + 8 }
        );
        tlb.fill(VA, HOST, true, 1);
        assert_eq!(tlb.lookup(VA + 8, 8, true, 1), Lookup::Direct(HOST + 8));
        // A page sharing the slot replaces it.
        let alias = VA + PAGE * ENTRIES as u64;
        tlb.fill(alias, HOST + PAGE, true, 1);
        assert_eq!(tlb.lookup(VA, 1, false, 1), Lookup::Miss { address: VA });
        tlb.clear();
        assert_eq!(
            tlb.lookup(alias, 1, false, 1),
            Lookup::Miss { address: alias }
        );
    }

    #[test]
    fn an_access_across_two_pages_needs_both_and_splits_when_the_host_does() {
        let mut tlb = Tlb::default();
        let last = VA + PAGE - 4;
        tlb.fill(VA, HOST, true, 0);
        assert_eq!(
            tlb.lookup(last, 8, false, 0),
            Lookup::Miss { address: VA + PAGE }
        );
        tlb.fill(VA + PAGE, HOST + PAGE, true, 0);
        assert_eq!(
            tlb.lookup(last, 8, true, 0),
            Lookup::Direct(HOST + PAGE - 4)
        );
        tlb.fill(VA + PAGE, HOST + 5 * PAGE, false, 0);
        assert_eq!(
            tlb.lookup(last, 8, false, 0),
            Lookup::Split {
                first: HOST,
                second: HOST + 5 * PAGE
            }
        );
        // The second page is read-only.
        assert_eq!(
            tlb.lookup(last, 8, true, 0),
            Lookup::Miss { address: VA + PAGE }
        );
        // The top page wraps to page 0, as ARM's address arithmetic does.
        tlb.fill(u64::MAX, HOST, true, 0);
        assert_eq!(
            tlb.lookup(u64::MAX - 1, 4, false, 0),
            Lookup::Miss { address: 0 }
        );
    }
}
