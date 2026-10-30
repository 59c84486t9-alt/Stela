//! Bounded metadata owned by one Host's executable arena. A live Arc's
//! allocation identity permits reuse of immutable code; equal bytes, a hash,
//! a source PC or a recycled payload pointer do not. This stores no guest state,
//! frame, worker permission or permission grant. Callers revalidate those anew.
use super::NativeCode;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

/// Independent finite metadata envelope for this Host's installed native addresses.
pub const MAX_ENTRIES: usize = 64;
const NO_HINT: u8 = u8::MAX;
const _: () = assert!(MAX_ENTRIES < NO_HINT as usize);
/// Separate Arc<Vec> allocation: the Vec value plus strong/weak counters.
/// Payload capacity is separately charged to the compiler artifact.
/// Allocator headers are excluded, as in that existing accounting policy.
pub const ARC_VEC_METADATA_BYTES: usize =
    core::mem::size_of::<Vec<u8>>() + 2 * core::mem::size_of::<usize>();

struct Entry {
    owner: Weak<Vec<u8>>,
    code: NativeCode,
}
/// Must remain inside the Host that owns all recorded native addresses. Never
/// copy/move its entries to a replacement Host or a different physical worker.
/// Before any patch/discard/reclaim, clear it while no native run is active.
pub struct InstalledCodeCache {
    entries: [Option<Entry>; MAX_ENTRIES],
    /// Allocation-address bits select a hint, never permission to reuse code.
    /// Ring replacement may leave a stale index; lookup rechecks its owner.
    hints: [u8; MAX_ENTRIES],
    next: usize,
}
impl Default for InstalledCodeCache {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            hints: [NO_HINT; MAX_ENTRIES],
            next: 0,
        }
    }
}
impl InstalledCodeCache {
    /// Conservative whole metadata bound, including every separate weak-held
    /// Arc<Vec> allocation after the final strong owner drops its code payload.
    pub const MAX_METADATA_BYTES: usize =
        core::mem::size_of::<Self>() + MAX_ENTRIES * ARC_VEC_METADATA_BYTES;

    pub fn lookup(&mut self, owner: &Arc<Vec<u8>>) -> Option<NativeCode> {
        let identity = Arc::as_ptr(owner);
        let hint = Self::hint_slot(owner);
        if let Some(Some(entry)) = self.entries.get(usize::from(self.hints[hint]))
            && entry.owner.as_ptr() == identity
        {
            // The same Weak and borrowed strong Arc prove identity
            // and lifetime as in the scan below. A hint alone proves neither.
            return Some(entry.code);
        }
        for (index, slot) in self.entries.iter_mut().enumerate() {
            let Some(entry) = slot else {
                continue;
            };
            // These pointers name the Arc-allocated Vec object, never its
            // reusable payload buffer or installed native code. The Weak pins
            // that allocation identity even after its strong owner expires.
            // Avoid strong-count RMWs for every live nonmatching cache entry.
            if entry.owner.as_ptr() != identity {
                if entry.owner.strong_count() == 0 {
                    *slot = None;
                }
                continue;
            }
            // The kept Weak pins this exact allocation against ABA and
            // the caller's borrowed strong Arc keeps it alive for the whole
            // lookup. Equality above names the Arc-allocated Vec, not its
            // replaceable payload buffer. An upgrade/drop adds no permission
            // and would perform two needless strong-count atomic RMWs.
            self.hints[hint] = index as u8;
            return Some(entry.code);
        }
        None
    }
    fn hint_slot(owner: &Arc<Vec<u8>>) -> usize {
        let address = Arc::as_ptr(owner).addr();
        // Mix alignment and page-offset bits without reading code bytes or
        // treating an address/hash as artifact identity. Collisions just scan.
        ((address >> 3) ^ (address >> 12)) % MAX_ENTRIES
    }
    /// Record only after the Host successfully installed all bytes.
    /// Failed/partial installation must never create an entry. Weak<Vec> keeps
    /// only the small Arc/Vec metadata after artifact eviction, not its payload.
    pub fn record(&mut self, owner: &Arc<Vec<u8>>, code: NativeCode) {
        // Preserve the scan's first-entry choice even when the same owner is
        // recorded again across ring wrap. Other stale hints recheck identity.
        self.hints[Self::hint_slot(owner)] = NO_HINT;
        self.entries[self.next] = Some(Entry {
            owner: Arc::downgrade(owner),
            code,
        });
        self.next = (self.next + 1) % MAX_ENTRIES;
    }
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            *entry = None;
        }
        self.hints.fill(NO_HINT);
        self.next = 0;
    }
    pub fn entries(&self) -> usize {
        self.entries.iter().flatten().count()
    }
    /// Conservative accounting also charges shared live Arc metadata here;
    /// joint artifact/Host totals may therefore overcount, never undercount it.
    pub fn retained_metadata_bytes(&self) -> usize {
        core::mem::size_of::<Self>() + self.entries() * ARC_VEC_METADATA_BYTES
    }
}

#[cfg(test)]
mod tests;
