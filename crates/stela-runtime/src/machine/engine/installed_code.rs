//! Bounded metadata owned by one actual Host's executable arena. A live Arc's
//! allocation identity permits reuse of immutable code; equal bytes, a hash,
//! a source PC or a recycled payload pointer do not. This stores no guest state,
//! frame, worker authority or permission grant. Callers revalidate those anew.
use super::NativeCode;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

/// Independent finite metadata envelope for this Host's installed native addresses.
pub const MAX_ENTRIES: usize = 64;
/// Separate Arc<Vec> allocation: the Vec value plus strong/weak counters.
/// Payload capacity is separately charged to the retained compiler artifact.
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
    next: usize,
    #[cfg(test)]
    upgrade_attempts: usize,
}
impl Default for InstalledCodeCache {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            next: 0,
            #[cfg(test)]
            upgrade_attempts: 0,
        }
    }
}
impl InstalledCodeCache {
    /// Conservative whole metadata bound, including every separate weak-held
    /// Arc<Vec> allocation after the final strong owner drops its code payload.
    pub const MAX_METADATA_BYTES: usize =
        core::mem::size_of::<Self>() + MAX_ENTRIES * ARC_VEC_METADATA_BYTES;

    pub fn lookup(&mut self, owner: &Arc<Vec<u8>>) -> Option<NativeCode> {
        for slot in &mut self.entries {
            let Some(entry) = slot else {
                continue;
            };
            // These pointers name the Arc-allocated Vec object, never its
            // reusable payload buffer or installed native code. The Weak pins
            // that allocation identity even after its strong owner expires.
            // Avoid strong-count RMWs for every live nonmatching cache entry.
            if entry.owner.as_ptr() != Arc::as_ptr(owner) {
                if entry.owner.strong_count() == 0 {
                    *slot = None;
                }
                continue;
            }
            #[cfg(test)]
            {
                self.upgrade_attempts += 1;
            }
            let Some(actual) = entry.owner.upgrade() else {
                *slot = None;
                continue;
            };
            if Arc::ptr_eq(&actual, owner) {
                return Some(entry.code);
            }
        }
        None
    }
    /// Record only after the actual Host successfully installed all bytes.
    /// Failed/partial installation must never create an entry. Weak<Vec> keeps
    /// only the small Arc/Vec metadata after artifact eviction, not its payload.
    pub fn record(&mut self, owner: &Arc<Vec<u8>>, code: NativeCode) {
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
mod tests {
    use super::*;
    use crate::machine::InstallError;
    use alloc::vec;

    // An actual isolated byte arena. No native execution/privilege is claimed.
    struct Arena {
        bytes: Vec<u8>,
        cache: InstalledCodeCache,
        installs: usize,
        copies: usize,
        fail: bool,
    }
    impl Arena {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                cache: InstalledCodeCache::default(),
                installs: 0,
                copies: 0,
                fail: false,
            }
        }
        fn immutable(&mut self, owner: &Arc<Vec<u8>>) -> Result<NativeCode, InstallError> {
            if let Some(code) = self.cache.lookup(owner) {
                return Ok(code);
            }
            self.installs += 1;
            if self.fail {
                return Err(InstallError::Full);
            }
            let code = NativeCode(self.bytes.len());
            self.bytes.extend_from_slice(owner);
            self.copies += owner.len();
            self.cache.record(owner, code);
            Ok(code)
        }
        fn patch(&mut self, code: NativeCode, value: u8) {
            self.cache.clear();
            self.bytes[code.0] = value;
        }
        fn discard(&mut self) {
            self.cache.clear();
            self.bytes.clear();
        }
        fn reclaim(&mut self) {
            self.discard();
        }
    }
    #[test]
    fn warm_live_owner_reuses_actual_installed_bytes_without_another_copy() {
        let code = Arc::new(vec![1, 2, 3, 4]);
        let mut arena = Arena::new();
        let cold = arena.immutable(&code).unwrap();
        for _ in 0..32 {
            assert_eq!(arena.immutable(&code).unwrap().0, cold.0);
        }
        assert_eq!((arena.installs, arena.copies, arena.bytes.len()), (1, 4, 4));
        let equal = Arc::new(vec![1, 2, 3, 4]);
        assert_ne!(arena.immutable(&equal).unwrap().0, cold.0);
        assert_eq!((arena.installs, arena.copies), (2, 8));
    }
    #[test]
    fn last_slot_warm_hit_upgrades_only_its_matching_allocation() {
        let mut cache = InstalledCodeCache::default();
        let owners: Vec<_> = (0..MAX_ENTRIES)
            .map(|_| Arc::new(vec![1, 2, 3, 4]))
            .collect();
        for (index, owner) in owners.iter().enumerate() {
            cache.record(owner, NativeCode(index));
        }
        for attempt in 1..=32 {
            assert_eq!(
                cache.lookup(owners.last().unwrap()),
                Some(NativeCode(MAX_ENTRIES - 1))
            );
            assert_eq!(cache.upgrade_attempts, attempt);
        }
        let equal_payload = Arc::new(vec![1, 2, 3, 4]);
        assert!(cache.lookup(&equal_payload).is_none());
        assert_eq!(cache.upgrade_attempts, 32);
        drop(owners);
        assert!(cache.lookup(&equal_payload).is_none());
        assert_eq!(cache.entries(), 0);
        assert_eq!(cache.upgrade_attempts, 32);
    }
    #[test]
    fn expired_owner_reused_payload_and_make_mut_never_authorize_old_code() {
        let original = Arc::new(vec![1, 2, 3]);
        let payload = original.as_ptr();
        let mut cache = InstalledCodeCache::default();
        cache.record(&original, NativeCode(40));
        // The exact payload pointer is reused under a different Arc allocation.
        let value = Arc::try_unwrap(original).unwrap();
        let mut replacement = Arc::new(value);
        assert_eq!(replacement.as_ptr(), payload);
        assert!(cache.lookup(&replacement).is_none());
        assert_eq!(cache.entries(), 0);
        cache.record(&replacement, NativeCode(80));
        assert!(Arc::get_mut(&mut replacement).is_none());
        Arc::make_mut(&mut replacement)[0] = 9;
        assert!(cache.lookup(&replacement).is_none());
        assert_eq!(cache.entries(), 0);
    }
    #[test]
    fn arena_mutation_failure_and_host_replacement_require_a_fresh_install() {
        let code = Arc::new(vec![7, 8]);
        let mut first = Arena::new();
        first.fail = true;
        assert!(matches!(first.immutable(&code), Err(InstallError::Full)));
        assert_eq!(first.cache.entries(), 0);
        first.discard();
        first.fail = false;
        let installed = first.immutable(&code).unwrap();
        first.patch(installed, 0);
        assert_eq!(first.cache.entries(), 0);
        let fresh = first.immutable(&code).unwrap();
        assert_eq!(first.bytes[fresh.0], 7);
        first.reclaim();
        assert_eq!(first.cache.entries(), 0);
        first.immutable(&code).unwrap();
        let mut other_worker = Arena::new();
        assert!(other_worker.cache.lookup(&code).is_none());
        other_worker.immutable(&code).unwrap();
        assert_eq!(other_worker.installs, 1);
        let mut replacement = Arena::new();
        assert!(replacement.cache.lookup(&code).is_none());
        replacement.immutable(&code).unwrap();
        assert_eq!(replacement.installs, 1);
    }
    #[test]
    fn entry_and_expired_weak_metadata_stay_inside_the_finite_bound() {
        let mut cache = InstalledCodeCache::default();
        let mut owners = Vec::new();
        for i in 0..MAX_ENTRIES * 3 {
            let owner = Arc::new(vec![i as u8; 128]);
            cache.record(&owner, NativeCode(i));
            owners.push(owner);
            assert!(cache.entries() <= MAX_ENTRIES);
            assert!(cache.retained_metadata_bytes() <= InstalledCodeCache::MAX_METADATA_BYTES);
        }
        assert!(cache.lookup(&owners[0]).is_none());
        let final_owner = owners.last().unwrap().clone();
        assert_eq!(cache.lookup(&final_owner).unwrap().0, MAX_ENTRIES * 3 - 1);
        drop(owners);
        drop(final_owner);
        assert_eq!(cache.entries(), MAX_ENTRIES);
        assert_eq!(
            cache.retained_metadata_bytes(),
            InstalledCodeCache::MAX_METADATA_BYTES
        );
        assert!(cache.lookup(&Arc::new(vec![0])).is_none());
        assert_eq!(cache.entries(), 0);
        assert_eq!(
            cache.retained_metadata_bytes(),
            core::mem::size_of::<InstalledCodeCache>()
        );
    }
}
