use super::*;
use std::alloc::{Layout, alloc_zeroed, dealloc};

const STORAGE_BYTES: usize = 64;
const STORAGE_ALIGNMENT: usize = 16;
const GUEST_BASE: u64 = 0x1000;
const ALIAS_BASE: u64 = 0x8000;
const READ_WRITE: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: this test owner exposes no accesses and releases storage only once.
unsafe impl Send for Storage {}
// SAFETY: sharing ownership never reads/writes the raw allocation.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: the owner uniquely owns the allocation and its layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn backing() -> Arc<MemoryBacking> {
    let layout = Layout::from_size_align(STORAGE_BYTES, STORAGE_ALIGNMENT).unwrap();
    // SAFETY: the valid nonzero layout is held for the matching dealloc.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let owner = Arc::new(Storage { pointer, layout });
    // SAFETY: owner keeps a raw allocation with read/write rights and no
    // Rust references to its contents; tests do not perform native accesses.
    unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, READ_WRITE, owner) }.unwrap()
}

#[test]
fn aliases_share_physical_offsets_but_have_distinct_mapping_generations() {
    let backing = backing();
    let first = MemoryView::new(Arc::clone(&backing), GUEST_BASE, 8, 32, READ_WRITE).unwrap();
    let alias = MemoryView::new(Arc::clone(&backing), ALIAS_BASE, 16, 16, READ_WRITE).unwrap();
    let first_access = first
        .resolve(GUEST_BASE + 12, 4, AccessKind::Write)
        .unwrap();
    let alias_access = alias.resolve(ALIAS_BASE + 4, 4, AccessKind::Read).unwrap();
    assert_eq!(first_access.backing_id(), alias_access.backing_id());
    assert_eq!(first_access.backing_offset(), 20);
    assert_eq!(alias_access.backing_offset(), 20);
    assert_eq!(first_access.host_ptr(), alias_access.host_ptr());
    assert_ne!(first_access.mapping_id(), alias_access.mapping_id());
    assert_eq!(first_access.guest_address(), GUEST_BASE + 12);
    assert_eq!(first_access.bytes(), 4);
    assert_eq!(first_access.kind(), AccessKind::Write);
}

#[test]
fn aliases_share_tags_and_private_backings_initialize_independently() {
    let physical = backing();
    let first = MemoryView::new(Arc::clone(&physical), GUEST_BASE, 0, 32, READ_WRITE).unwrap();
    let alias = MemoryView::new(Arc::clone(&physical), ALIAS_BASE, 16, 16, READ_WRITE).unwrap();
    assert_eq!(
        physical.allocation_tags().read(16).unwrap(),
        AllocationTag::ZERO
    );
    let tag = AllocationTag::new(7).unwrap();
    first.backing().allocation_tags().write(16, tag).unwrap();
    assert_eq!(alias.backing().allocation_tags().read(16).unwrap(), tag);
    let private_copy = backing();
    assert_eq!(
        private_copy.allocation_tags().read(16).unwrap(),
        AllocationTag::ZERO
    );
}

#[test]
fn replacement_and_private_copy_cannot_reuse_view_or_backing_identity() {
    let original = backing();
    let view = MemoryView::new(
        Arc::clone(&original),
        GUEST_BASE,
        0,
        STORAGE_BYTES,
        READ_WRITE,
    )
    .unwrap();
    let access = view.resolve(GUEST_BASE, 1, AccessKind::Read).unwrap();
    view.retire();
    assert_eq!(
        view.resolve(GUEST_BASE, 1, AccessKind::Read).unwrap_err(),
        AccessError::RetiredMapping
    );
    assert!(!access.view().is_current());
    let replacement = MemoryView::new(
        Arc::clone(&original),
        GUEST_BASE,
        0,
        STORAGE_BYTES,
        READ_WRITE,
    )
    .unwrap();
    assert_ne!(view.id(), replacement.id());
    assert_eq!(view.backing().id(), replacement.backing().id());
    let private_copy = backing();
    assert_ne!(original.id(), private_copy.id());
}

#[test]
fn kept_access_keeps_mapping_and_storage_alive() {
    let backing = backing();
    let weak = Arc::downgrade(&backing);
    let view = MemoryView::new(
        Arc::clone(&backing),
        GUEST_BASE,
        0,
        STORAGE_BYTES,
        READ_WRITE,
    )
    .unwrap();
    let access = view.resolve(GUEST_BASE + 1, 1, AccessKind::Read).unwrap();
    drop(backing);
    drop(view);
    assert!(weak.upgrade().is_some());
    drop(access);
    assert!(weak.upgrade().is_none());
}

#[test]
fn identities_are_stable_across_threads_and_distinguish_live_owners() {
    let original = backing();
    let copy = backing();
    let expected = original.id();
    let from_thread = std::thread::spawn(move || original.id()).join().unwrap();
    assert_eq!(expected, from_thread);
    let identities = std::collections::HashSet::from([expected.clone(), from_thread, copy.id()]);
    assert_eq!(identities.len(), 2);
    let ordered = std::collections::BTreeSet::from([expected.clone(), expected, copy.id()]);
    assert_eq!(ordered.len(), 2);
}

#[test]
fn live_aliases_accept_only_the_same_coherence_owner() {
    let backing = backing();
    let owner = Arc::new(());
    backing.bind_coherence(&owner).unwrap();
    backing.bind_coherence(&Arc::clone(&owner)).unwrap();
    assert_eq!(
        backing.bind_coherence(&Arc::new(())),
        Err(AccessError::CoherenceDomain)
    );
    backing.bind_coherence(&owner).unwrap();
}

#[test]
fn expired_coherence_owner_allows_a_new_system_to_bind() {
    let backing = backing();
    let owner = Arc::new(());
    backing.bind_coherence(&owner).unwrap();
    let retained = Arc::clone(&owner);
    drop(owner);
    let replacement = Arc::new(());
    assert_eq!(
        backing.bind_coherence(&replacement),
        Err(AccessError::CoherenceDomain)
    );
    drop(retained);
    backing.bind_coherence(&replacement).unwrap();
}

#[test]
fn concurrent_coherence_claims_admit_exactly_one_live_owner() {
    let backing = backing();
    let owners = [Arc::new(()), Arc::new(())];
    let barrier = Arc::new(std::sync::Barrier::new(owners.len()));
    let handles = owners
        .iter()
        .map(|owner| {
            let owner = Arc::clone(owner);
            let backing = Arc::clone(&backing);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                backing.bind_coherence(&owner)
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(AccessError::CoherenceDomain))
            .count(),
        1
    );
}

#[test]
fn exact_part_bounds_do_not_include_padding_or_prevalidate_later_parts() {
    let backing = backing();
    let view = MemoryView::new(backing, GUEST_BASE, 3, 7, READ_WRITE).unwrap();
    assert!(view.resolve(GUEST_BASE + 6, 1, AccessKind::Write).is_ok());
    for (address, bytes, error) in [
        (GUEST_BASE, 0, AccessError::EmptyRange),
        (GUEST_BASE - 1, 1, AccessError::UnmappedRange),
        (GUEST_BASE + 7, 1, AccessError::UnmappedRange),
        (GUEST_BASE + 6, 2, AccessError::UnmappedRange),
        (u64::MAX, 1, AccessError::AddressOverflow),
    ] {
        assert_eq!(
            view.resolve(address, bytes, AccessKind::Read).unwrap_err(),
            error
        );
    }
}

#[test]
fn permissions_decline_escalation_and_forbidden_accesses() {
    let backing = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..READ_WRITE
    };
    let view =
        MemoryView::new(Arc::clone(&backing), GUEST_BASE, 0, STORAGE_BYTES, readonly).unwrap();
    assert!(view.resolve(GUEST_BASE, 1, AccessKind::Read).is_ok());
    for kind in [AccessKind::Write, AccessKind::Execute] {
        assert_eq!(
            view.resolve(GUEST_BASE, 1, kind).unwrap_err(),
            AccessError::PermissionDenied(kind)
        );
    }
    let executable = AccessPermissions {
        executable: true,
        ..readonly
    };
    assert_eq!(
        MemoryView::new(backing, GUEST_BASE, 0, 1, executable).unwrap_err(),
        AccessError::MaximumPermissions
    );
}

#[test]
fn constructors_reject_empty_overflowing_and_out_of_backing_extents() {
    let backing = backing();
    for (guest_base, offset, bytes, error) in [
        (GUEST_BASE, 0, 0, AccessError::EmptyRange),
        (u64::MAX, 0, 1, AccessError::AddressOverflow),
        (GUEST_BASE, STORAGE_BYTES, 1, AccessError::BackingBounds),
        (GUEST_BASE, usize::MAX, 2, AccessError::BackingBounds),
    ] {
        assert_eq!(
            MemoryView::new(Arc::clone(&backing), guest_base, offset, bytes, READ_WRITE)
                .unwrap_err(),
            error
        );
    }
    // SAFETY: invalid extents are rejected before the pointer can be exposed.
    let empty = unsafe { MemoryBacking::new(NonNull::dangling(), 0, READ_WRITE, Arc::new(())) };
    assert_eq!(empty.unwrap_err(), AccessError::EmptyRange);
    // SAFETY: invalid extents are rejected before the pointer can be exposed.
    let huge =
        unsafe { MemoryBacking::new(NonNull::dangling(), usize::MAX, READ_WRITE, Arc::new(())) };
    assert_eq!(huge.unwrap_err(), AccessError::HostBounds);
}

#[test]
fn physical_envelope_checks_do_not_grant_logical_view_permissions() {
    let backing = backing();
    assert!(
        backing
            .host_pointer(STORAGE_BYTES - 1, 1, AccessKind::Write)
            .is_ok()
    );
    for (offset, bytes, error) in [
        (0, 0, AccessError::EmptyRange),
        (STORAGE_BYTES, 1, AccessError::BackingBounds),
        (usize::MAX, 2, AccessError::BackingBounds),
    ] {
        assert_eq!(
            backing
                .host_pointer(offset, bytes, AccessKind::Read)
                .unwrap_err(),
            error
        );
    }
    assert_eq!(
        backing.host_pointer(0, 1, AccessKind::Execute).unwrap_err(),
        AccessError::PermissionDenied(AccessKind::Execute)
    );
    let readonly = AccessPermissions {
        writable: false,
        ..READ_WRITE
    };
    let view =
        MemoryView::new(Arc::clone(&backing), GUEST_BASE, 0, STORAGE_BYTES, readonly).unwrap();
    assert!(backing.host_pointer(0, 1, AccessKind::Write).is_ok());
    assert_eq!(
        view.resolve(GUEST_BASE, 1, AccessKind::Write).unwrap_err(),
        AccessError::PermissionDenied(AccessKind::Write)
    );
}
