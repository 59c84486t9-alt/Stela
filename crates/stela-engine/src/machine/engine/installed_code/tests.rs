use super::*;
use crate::machine::InstallError;
use alloc::vec;

// An isolated byte arena. No native execution/privilege is claimed.
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
fn warm_live_owner_reuses_installed_bytes_without_another_copy() {
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
fn last_slot_warm_hit_uses_only_the_live_allocation() {
    let mut cache = InstalledCodeCache::default();
    let owners: Vec<_> = (0..MAX_ENTRIES)
        .map(|_| Arc::new(vec![1, 2, 3, 4]))
        .collect();
    for (index, owner) in owners.iter().enumerate() {
        cache.record(owner, NativeCode(index));
    }
    for _ in 0..32 {
        assert_eq!(
            cache.lookup(owners.last().unwrap()),
            Some(NativeCode(MAX_ENTRIES - 1))
        );
        assert_eq!(Arc::strong_count(owners.last().unwrap()), 1);
    }
    let equal_payload = Arc::new(vec![1, 2, 3, 4]);
    assert!(cache.lookup(&equal_payload).is_none());
    drop(owners);
    assert!(cache.lookup(&equal_payload).is_none());
    assert_eq!(cache.entries(), 0);
}
#[test]
fn colliding_hints_and_stale_indices_never_select_another_owner() {
    // More live allocations than hint slots guarantees a real collision,
    // independently of the allocator's placement and alignment choices.
    let owners: Vec<_> = (0..=MAX_ENTRIES)
        .map(|_| Arc::new(vec![1, 2, 3, 4]))
        .collect();
    let (first, second) = owners
        .iter()
        .enumerate()
        .find_map(|(index, first)| {
            owners[index + 1..]
                .iter()
                .find(|second| {
                    InstalledCodeCache::hint_slot(first) == InstalledCodeCache::hint_slot(second)
                })
                .map(|second| (first, second))
        })
        .expect("a collision among more owners than slots");
    let mut cache = InstalledCodeCache::default();
    cache.record(first, NativeCode(10));
    cache.record(second, NativeCode(20));
    for _ in 0..32 {
        assert_eq!(cache.lookup(first), Some(NativeCode(10)));
        assert_eq!(cache.lookup(second), Some(NativeCode(20)));
    }
    // A hint may also name an empty slot, an out-of-range slot, or an
    // installed entry whose bytes happen to equal the requested owner's.
    let hint = InstalledCodeCache::hint_slot(first);
    for index in [2, NO_HINT, 1] {
        cache.hints[hint] = index;
        assert_eq!(cache.lookup(first), Some(NativeCode(10)));
    }
    assert_eq!(Arc::strong_count(first), 1);
    assert_eq!(Arc::strong_count(second), 1);
    cache.clear();
    assert!(cache.hints.iter().all(|&hint| hint == NO_HINT));
    assert!(cache.lookup(first).is_none());
}
#[test]
fn recording_across_ring_wrap_preserves_first_entry_and_expiration() {
    let owners: Vec<_> = (0..MAX_ENTRIES)
        .map(|_| Arc::new(vec![1, 2, 3, 4]))
        .collect();
    let mut cache = InstalledCodeCache::default();
    for (index, owner) in owners.iter().enumerate() {
        cache.record(owner, NativeCode(index));
    }
    let last = owners.last().unwrap();
    assert_eq!(cache.lookup(last), Some(NativeCode(MAX_ENTRIES - 1)));
    // The replacement at slot zero now precedes the owner's old entry.
    cache.record(last, NativeCode(MAX_ENTRIES));
    assert_eq!(cache.lookup(last), Some(NativeCode(MAX_ENTRIES)));
    assert!(cache.lookup(&owners[0]).is_none());
    drop(owners);
    assert!(cache.lookup(&Arc::new(vec![1, 2, 3, 4])).is_none());
    assert_eq!(cache.entries(), 0);
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
#[cfg(feature = "std")]
#[test]
fn caller_strong_owner_survives_concurrent_external_release() {
    let owner = Arc::new(vec![1, 2, 3]);
    let external = Arc::clone(&owner);
    let mut cache = InstalledCodeCache::default();
    cache.record(&owner, NativeCode(40));
    let release = std::thread::spawn(move || drop(external));
    for _ in 0..128 {
        assert_eq!(cache.lookup(&owner), Some(NativeCode(40)));
    }
    release.join().unwrap();
    assert_eq!(Arc::strong_count(&owner), 1);
    assert_eq!(cache.lookup(&owner), Some(NativeCode(40)));
    drop(owner);
    assert!(cache.lookup(&Arc::new(vec![1, 2, 3])).is_none());
    assert_eq!(cache.entries(), 0);
}

#[cfg(all(
    feature = "std",
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
#[test]
fn native_selection_tracks_allocation_replacement_and_arena_reset() {
    use crate::execution::platform::Mapping;
    use stela_compiler::{GuestAddress, GuestState};

    struct ExecutableArena {
        cache: InstalledCodeCache,
        mappings: Vec<Mapping>,
        installs: usize,
    }
    impl ExecutableArena {
        fn run(&mut self, owner: &Arc<Vec<u8>>) -> u64 {
            let installed = match self.cache.lookup(owner) {
                Some(code) => code,
                None => {
                    let mapping = Mapping::new(owner).unwrap();
                    let code = NativeCode(mapping.entry());
                    self.mappings.push(mapping);
                    self.cache.record(owner, code);
                    self.installs += 1;
                    code
                }
            };
            let mapping = self
                .mappings
                .iter()
                .find(|mapping| mapping.entry() == installed.0)
                .unwrap();
            let mut state = GuestState::default();
            // SAFETY: only compiler-produced baseline leaf code is
            // recorded; this exact RX mapping keeps it through return.
            unsafe { mapping.call(&mut state) }.unwrap();
            state.x[0]
        }
        fn reset(&mut self) {
            self.cache.clear();
            self.mappings.clear();
        }
    }
    let compile = |value: u32| {
        // MOVZ X0, #imm16; RET X30. This fixture uses the real compiler
        // and leaf ABI, with no hand-authored native execution shortcut.
        let source: Vec<_> = [0xd2800000 | (value << 5), 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let leaf = stela_compiler::Options::new(
            stela_compiler::block::BlockProfile::new(stela_compiler::block::Features::LEAF),
            stela_compiler::TargetCpu::Baseline,
        );
        stela_compiler::compile(&source, GuestAddress(0x1000), &leaf)
            .unwrap()
            .native
            .x86_64_code
    };
    let mut arena = ExecutableArena {
        cache: InstalledCodeCache::default(),
        mappings: Vec::new(),
        installs: 0,
    };
    let original = Arc::new(compile(7));
    assert_eq!(arena.run(&original), 7);
    for _ in 0..16 {
        assert_eq!(arena.run(&original), 7);
    }
    assert_eq!(arena.installs, 1);
    let equal = Arc::new(original.as_ref().clone());
    assert_eq!(arena.run(&equal), 7);
    assert_eq!(arena.installs, 2);
    // Reuse the exact payload allocation under a different Arc header.
    let payload = original.as_ptr();
    let mut replacement = Arc::new(Arc::try_unwrap(original).unwrap());
    assert_eq!(replacement.as_ptr(), payload);
    assert_eq!(arena.run(&replacement), 7);
    assert_eq!(arena.installs, 3);
    *Arc::make_mut(&mut replacement) = compile(11);
    assert_eq!(arena.run(&replacement), 11);
    assert_eq!(arena.run(&equal), 7);
    assert_eq!(arena.installs, 4);
    // Stale hint metadata names the different, still-live seven body.
    // The translated execution must still return eleven.
    arena.cache.hints[InstalledCodeCache::hint_slot(&replacement)] = 1;
    assert_eq!(arena.run(&replacement), 11);
    assert_eq!(arena.installs, 4);
    arena.reset();
    assert_eq!(arena.run(&replacement), 11);
    assert_eq!(arena.installs, 5);
    assert_eq!(arena.run(&equal), 7);
    assert_eq!(arena.installs, 6);
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
