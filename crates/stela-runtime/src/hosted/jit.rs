//! MAP_JIT regions and their per-thread write protection, as XNU and
//! libpthread present them to an arm64 process on Apple silicon.
//!
//! A `MAP_JIT` mapping is one VM entry (`used_for_jit`) whose pages, while
//! their VM protection is RWX, the SPTM pmap types `XNU_USER_JIT`: SPRR
//! permission index 5 (AP 0b01, UXN clear, PXN set). SPRR_PERM_EL0, which
//! the kernel saves and restores per thread, gives index 5 either `r-x` or
//! `rw-` at EL0, so each thread sees a JIT page as executable or as
//! writable, never both. libpthread's `pthread_jit_write_protect_np`
//! writes the register from the commpage (`_COMM_PAGE_APRR_SUPPORT` 3 at
//! 0x10c, the write-enable value at 0x110, the write-disable value at
//! 0x118) and reads it back. Every 26A434 Mac kernelcache's
//! `commpage_populate` stores 3 and the values below, and
//! `machine_thread_create` starts every thread at the write-disable value.
//! A MAP_JIT page whose VM protection is not RWX is an ordinary page
//! (`XNU_USER_DEBUG`), outside the per-thread view.
//!
//! The hosted process runs one thread's guest code at a time (the
//! execution lock), so the host protection of the RWX JIT pages follows
//! the view of the thread that holds it: read/write while that thread's
//! view is writable, read-only otherwise, so its writes fault as the
//! arm64 kernel's permission fault does. Guest code never executes from
//! host pages, and the engine's fetch translation does not yet take the
//! view's execute half: a thread whose view is writable still executes JIT
//! code ([`Jit::executable`] names the pages where it would fault).
use crate::hosted::darwin::EINVAL;
use crate::hosted::memory::{self, Protection};
use anyhow::Result;
use std::collections::BTreeMap;

/// `_COMM_PAGE_APRR_SUPPORT`: the JIT toggle is SPRR_PERM_EL0.
pub const APRR_SUPPORT_SPRR: u8 = 3;
/// SPRR_PERM_EL0 with JIT pages `rw-` (`_COMM_PAGE_APRR_WRITE_ENABLE`).
pub const WRITE_ENABLED: u64 = 0x2010_0020_3030_0000;
/// SPRR_PERM_EL0 with JIT pages `r-x` (`_COMM_PAGE_APRR_WRITE_DISABLE`), a
/// new thread's.
pub const WRITE_DISABLED: u64 = 0x2010_0020_3010_0000;
/// The SPRR permission index of `XNU_USER_JIT` pages.
const JIT_INDEX: u32 = 5;
/// The EL0 half of a permission index's SPRR_PERM nibble, and its `rw-`.
const EL_FIELD: u64 = 3;
const EL_READ_WRITE: u64 = 3;

/// `<sys/mman.h>` flags `mmap` checks against MAP_JIT.
const MAP_SHARED: u64 = 0x0001;
const MAP_FIXED: u64 = 0x0010;
pub const MAP_JIT: u64 = 0x0800;
const MAP_ANON: u64 = 0x1000;
const MAP_RESILIENT_CODESIGN: u64 = 0x2000;
const MAP_RESILIENT_MEDIA: u64 = 0x4000;
const MAP_TPRO: u64 = 0x8_0000;

/// Whether SPRR_PERM_EL0 `permissions` gives JIT pages `rw-`.
pub fn writable(permissions: u64) -> bool {
    (permissions >> (4 * JIT_INDEX)) & EL_FIELD == EL_READ_WRITE
}

/// Whether EL0 may write SPRR_PERM_EL0 `permissions`: the kernel locks the
/// register except the EL0 half of the JIT index (the per-thread unlock
/// field it writes with SPRR_PERM_EL0), so a value may differ from a
/// thread's start value there alone.
pub fn user_writable(permissions: u64) -> bool {
    (permissions ^ WRITE_DISABLED) & !(EL_FIELD << (4 * JIT_INDEX)) == 0
}

/// The host protection of a JIT page of VM protection `protection` in the
/// view `writable`.
fn view_protection(writable: bool, protection: Protection) -> Protection {
    match protection {
        Protection::ALL if writable => Protection::READ_WRITE,
        Protection::ALL => Protection::READ,
        other => other,
    }
}

/// One JIT range: its end and VM protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    end: u64,
    protection: Protection,
}

/// The process's JIT ranges and the view their host protection follows.
#[derive(Debug)]
pub struct Jit {
    ranges: BTreeMap<u64, Range>,
    /// The view of the thread holding the execution lock.
    writable: bool,
    /// AMFI lets the process map JIT memory (`mac_proc_check_map_anon`).
    allowed: bool,
    /// `com.apple.security.cs.single-jit` (`vm_map_single_jit`).
    single: bool,
    /// The map ever had a JIT entry (`jit_entry_exists`, never cleared).
    created: bool,
}

impl Jit {
    pub fn new(allowed: bool, single: bool) -> Self {
        Self {
            ranges: BTreeMap::new(),
            writable: false,
            allowed,
            single,
            created: false,
        }
    }

    /// `mmap`'s MAP_JIT checks (`kern_mman.c`, `vm_map_enter`), all
    /// EINVAL: shared, file-backed, resilient or TPRO mappings; a fixed
    /// placement, which arm64 allows only in 4 KiB maps; a process AMFI
    /// denies JIT (EINVAL from the MAC hook); a second JIT entry in a
    /// single-JIT map (`KERN_INVALID_ARGUMENT`).
    pub fn check_map(&self, flags: u64) -> Result<(), u64> {
        let invalid =
            flags & (MAP_SHARED | MAP_RESILIENT_CODESIGN | MAP_RESILIENT_MEDIA | MAP_TPRO) != 0
                || flags & MAP_ANON == 0
                || flags & MAP_FIXED != 0
                || !self.allowed
                || (self.single && self.created);
        if invalid { Err(EINVAL) } else { Ok(()) }
    }

    /// The host protection a JIT page of VM protection `protection` takes
    /// in the current view.
    pub fn host_protection(&self, protection: Protection) -> Protection {
        view_protection(self.writable, protection)
    }

    /// A new JIT entry `[start, start + bytes)` of VM protection
    /// `protection`, mapped with [`Self::host_protection`].
    pub fn insert(&mut self, start: u64, bytes: u64, protection: Protection) {
        self.forget(start, bytes);
        self.ranges.insert(
            start,
            Range {
                end: start + bytes,
                protection,
            },
        );
        self.created = true;
    }

    /// Split the range holding `at` there.
    fn split(&mut self, at: u64) {
        let Some((&start, &range)) = self.ranges.range(..at).next_back() else {
            return;
        };
        if range.end > at {
            self.ranges.insert(start, Range { end: at, ..range });
            self.ranges.insert(at, range);
        }
    }

    /// The JIT pages of `[start, start + bytes)` stop being JIT pages: an
    /// unmapping or a mapping over them.
    pub fn forget(&mut self, start: u64, bytes: u64) {
        let end = start.saturating_add(bytes);
        self.split(start);
        self.split(end);
        let inside: Vec<u64> = self.ranges.range(start..end).map(|(&at, _)| at).collect();
        for at in inside {
            self.ranges.remove(&at);
        }
    }

    /// Change the VM protection of the JIT pages of `[start, start +
    /// bytes)` with `change` (a protection change; the SPTM pmap has no
    /// policy against one): the changed JIT parts with the host
    /// protection they take now, to apply after the host change.
    pub fn protect(
        &mut self,
        start: u64,
        bytes: u64,
        change: impl Fn(Protection) -> Protection,
    ) -> Vec<(u64, u64, Protection)> {
        let end = start.saturating_add(bytes);
        self.split(start);
        self.split(end);
        let writable = self.writable;
        self.ranges
            .range_mut(start..end)
            .map(|(&at, range)| {
                range.protection = change(range.protection);
                (
                    at,
                    range.end - at,
                    view_protection(writable, range.protection),
                )
            })
            .collect()
    }

    /// The JIT part holding `address`: its start, end and VM protection,
    /// which region reports give in place of the host's current one.
    pub fn at(&self, address: u64) -> Option<(u64, u64, Protection)> {
        let (&start, range) = self.ranges.range(..=address).next_back()?;
        (address < range.end).then_some((start, range.end, range.protection))
    }

    /// The arm64 map entry a region report for `address` names when the
    /// host reports its region `[start, end)`: the host coalesces an
    /// anonymous mapping with an adjacent one of equal attributes, and XNU
    /// never coalesces a JIT entry (`used_for_jit`). The entry's start,
    /// end and, for a JIT part, VM protection; `None` when no JIT range
    /// meets the host region.
    pub fn entry(
        &self,
        address: u64,
        start: u64,
        end: u64,
    ) -> Option<(u64, u64, Option<Protection>)> {
        let (_, last) = self.ranges.range(..end).next_back()?;
        if last.end <= start {
            return None;
        }
        let at = address.max(start);
        if let Some((low, high, protection)) = self.at(at) {
            return Some((low.max(start), high.min(end), Some(protection)));
        }
        let low = self
            .ranges
            .range(..at)
            .next_back()
            .map_or(start, |(_, range)| range.end.max(start));
        let high = self
            .ranges
            .range(at..)
            .next()
            .map_or(end, |(&next, _)| next.min(end));
        Some((low, high, None))
    }

    /// Whether the thread holding the execution lock may execute at
    /// `address`: anywhere but an RWX JIT page while its view is writable.
    pub fn executable(&self, address: u64) -> bool {
        !self.writable
            || self
                .at(address)
                .is_none_or(|(_, _, p)| p != Protection::ALL)
    }

    /// The RWX JIT ranges, whose compiled code a thread drops when its view
    /// turns writable.
    pub fn switched(&self) -> Vec<(u64, u64)> {
        self.ranges
            .iter()
            .filter(|(_, range)| range.protection == Protection::ALL)
            .map(|(&start, range)| (start, range.end - start))
            .collect()
    }

    /// Make the host protection of the RWX JIT pages the view `writable`:
    /// the view of the thread taking the execution lock, or of the holder
    /// that just wrote SPRR_PERM_EL0.
    pub fn set_view(&mut self, writable: bool) -> Result<()> {
        if self.writable == writable {
            return Ok(());
        }
        self.writable = writable;
        let host = self.host_protection(Protection::ALL);
        for (start, bytes) in self.switched() {
            memory::protect(start, bytes, host)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: u64 = 0x0002;

    #[test]
    fn the_commpage_values_toggle_the_jit_index_alone() {
        assert!(writable(WRITE_ENABLED));
        assert!(!writable(WRITE_DISABLED));
        assert!(user_writable(WRITE_ENABLED) && user_writable(WRITE_DISABLED));
        assert!(!user_writable(WRITE_DISABLED | 3 << 36));
        assert_eq!(WRITE_ENABLED ^ WRITE_DISABLED, 2 << (4 * JIT_INDEX));
    }

    #[test]
    fn mmap_refuses_what_xnu_refuses_for_map_jit() {
        let jit = Jit::new(true, false);
        let anonymous = MAP_JIT | MAP_ANON | PRIVATE;
        assert_eq!(jit.check_map(anonymous), Ok(()));
        for flag in [MAP_SHARED, MAP_FIXED, MAP_RESILIENT_MEDIA, MAP_TPRO] {
            assert_eq!(jit.check_map(anonymous | flag), Err(EINVAL), "{flag:#x}");
        }
        assert_eq!(jit.check_map(MAP_JIT | PRIVATE), Err(EINVAL));
        assert_eq!(Jit::new(false, false).check_map(anonymous), Err(EINVAL));
        let mut single = Jit::new(true, true);
        assert_eq!(single.check_map(anonymous), Ok(()));
        single.insert(0x10_0000, 0x4000, Protection::ALL);
        single.forget(0x10_0000, 0x4000);
        assert_eq!(single.check_map(anonymous), Err(EINVAL));
    }

    #[test]
    fn ranges_split_on_unmapping_and_protection_changes() {
        let mut jit = Jit::new(true, false);
        jit.insert(0x10_0000, 0x10000, Protection::ALL);
        jit.forget(0x10_4000, 0x4000);
        assert_eq!(
            jit.at(0x10_0000),
            Some((0x10_0000, 0x10_4000, Protection::ALL))
        );
        assert_eq!(jit.at(0x10_4000), None);
        assert_eq!(
            jit.at(0x10_8000),
            Some((0x10_8000, 0x11_0000, Protection::ALL))
        );
        let changed = jit.protect(0x10_c000, 0x8000, |_| Protection::READ_EXECUTE);
        assert_eq!(changed, [(0x10_c000, 0x4000, Protection::READ_EXECUTE)]);
        assert_eq!(jit.switched(), [(0x10_0000, 0x4000), (0x10_8000, 0x4000)]);
        let changed = jit.protect(0x10_c000, 0x4000, |_| Protection::ALL);
        assert_eq!(changed, [(0x10_c000, 0x4000, Protection::READ)]);
    }

    #[test]
    fn region_reports_name_the_jit_entry_inside_a_coalesced_host_region() {
        let mut jit = Jit::new(true, false);
        jit.insert(0x10_8000, 0x4000, Protection::ALL);
        jit.insert(0x11_0000, 0x4000, Protection::READ);
        assert_eq!(jit.entry(0x10_0000, 0x10_0000, 0x10_8000), None);
        assert_eq!(
            jit.entry(0x10_8000, 0x10_0000, 0x10_c000),
            Some((0x10_8000, 0x10_c000, Some(Protection::ALL)))
        );
        assert_eq!(
            jit.entry(0x10_2000, 0x10_0000, 0x11_8000),
            Some((0x10_0000, 0x10_8000, None))
        );
        assert_eq!(
            jit.entry(0x10_c000, 0x10_0000, 0x11_8000),
            Some((0x10_c000, 0x11_0000, None))
        );
        assert_eq!(
            jit.entry(0x0f_0000, 0x11_0000, 0x11_8000),
            Some((0x11_0000, 0x11_4000, Some(Protection::READ)))
        );
        assert_eq!(
            jit.entry(0x11_4000, 0x10_0000, 0x11_8000),
            Some((0x11_4000, 0x11_8000, None))
        );
    }

    #[test]
    fn the_view_decides_host_protection_and_execution() {
        let mut jit = Jit::new(true, false);
        jit.insert(0x10_0000, 0x4000, Protection::ALL);
        jit.insert(0x20_0000, 0x4000, Protection::READ_WRITE);
        assert_eq!(jit.host_protection(Protection::ALL), Protection::READ);
        assert!(jit.executable(0x10_0000));
        jit.writable = true;
        assert_eq!(jit.host_protection(Protection::ALL), Protection::READ_WRITE);
        assert_eq!(
            jit.host_protection(Protection::READ_WRITE),
            Protection::READ_WRITE
        );
        assert!(!jit.executable(0x10_0000));
        assert!(jit.executable(0x20_0000) && jit.executable(0x30_0000));
    }
}
