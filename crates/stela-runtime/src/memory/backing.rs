//! Physical backing and logical mapping identities for native guest memory.
//!
//! Resolution validates one architectural access part. It neither performs the
//! access nor supplies synchronization, tag checks, or exclusive monitors.

use super::tag_store::TagStore;
use super::tags::AllocationTag;
use std::hash::{Hash, Hasher};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

// Retaining an identity retains its allocation, preventing address reuse while
// it can still participate in a reservation, cache key, or comparison.
#[derive(Clone)]
struct Identity(Arc<()>);

impl Identity {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn address(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Pointer::fmt(&Arc::as_ptr(&self.0), f)
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Identity {}

impl PartialOrd for Identity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address().cmp(&other.address())
    }
}

impl Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address().hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackingId(Identity);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MappingId(Identity);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
    Execute,
}

/// Guest rights. Execute permission never grants host execute permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl AccessPermissions {
    fn permits(self, kind: AccessKind) -> bool {
        match kind {
            AccessKind::Read => self.readable,
            AccessKind::Write => self.writable,
            AccessKind::Execute => self.executable,
        }
    }

    fn contains(self, requested: Self) -> bool {
        (!requested.readable || self.readable)
            && (!requested.writable || self.writable)
            && (!requested.executable || self.executable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    EmptyRange,
    AddressOverflow,
    BackingBounds,
    HostBounds,
    UnmappedRange,
    PermissionDenied(AccessKind),
    MaximumPermissions,
    RetiredMapping,
    CoherenceDomain,
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "guest memory resolution failed: {self:?}")
    }
}

impl std::error::Error for AccessError {}

/// A fixed live native storage extent. Aliases must share this same owner;
/// private copies and COW replacements require a fresh backing identity.
///
/// No API here creates Rust references to the guest bytes. Native accesses must
/// obey the execution domain's synchronization and fault-handling contract.
pub struct MemoryBacking {
    id: BackingId,
    pub(in crate::memory) source_mutation: super::domain::source_mutation::SourceMutationTracker,
    host_base: NonNull<u8>,
    bytes: usize,
    maximum_permissions: AccessPermissions,
    allocation_tags: TagStore,
    coherence: Mutex<Option<Weak<()>>>,
    _lifetime_owner: Arc<dyn Send + Sync>,
}

impl std::fmt::Debug for MemoryBacking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryBacking")
            .field("id", &self.id)
            .field("host_base", &self.host_base)
            .field("bytes", &self.bytes)
            .field("maximum_permissions", &self.maximum_permissions)
            .finish_non_exhaustive()
    }
}

// SAFETY: construction requires a shared native storage lifetime and external
// access discipline. These types expose only immutable metadata and raw pointers;
// sending or sharing them does not access the pointed-to guest bytes.
unsafe impl Send for MemoryBacking {}
// SAFETY: the same construction and raw-access contract applies to shared owners.
unsafe impl Sync for MemoryBacking {}

impl MemoryBacking {
    /// Bind a native mapping to a stable physical identity and lifetime owner.
    ///
    /// # Safety
    /// `host_base..host_base + bytes` must remain one live native storage extent
    /// with a stable address until the last retained backing/access is dropped.
    /// `lifetime_owner` must retain that storage; an unrelated token is not enough.
    /// Storage must be coherent Normal-WB RAM. MMIO and device mappings are not
    /// admitted by this native backing contract.
    /// Host rights must support every permitted data read/write and guest execute
    /// must permit reading instruction bytes. They must not be revoked while any
    /// retained access can execute. Never bind storage subject to incompatible
    /// Rust reference aliasing. All accesses, including external aliases, must
    /// obey one synchronization/fault contract; this constructor enforces none.
    /// Each physical storage must have one backing owner, shared by every alias.
    pub unsafe fn new<O: Send + Sync + 'static>(
        host_base: NonNull<u8>,
        bytes: usize,
        maximum_permissions: AccessPermissions,
        lifetime_owner: Arc<O>,
    ) -> Result<Arc<Self>, AccessError> {
        Self::construct(host_base, bytes, maximum_permissions, lifetime_owner)
    }

    /// Canonical owner-managed host rights over one stable physical identity.
    ///
    /// # Safety
    /// The real storage owner retains this extent and excludes all native access
    /// through the same domain's execution/service loans before changing rights.
    /// Every current view and host publication must validate the actual current
    /// rights. Maximum permissions are the immutable owner authorization, not
    /// permission to access a protected page. Do not expose this backing to an
    /// independently constructed domain/view or raw consumer. The original
    /// constructor's alias, storage, coherence and reference rules still apply.
    pub(in crate::memory) unsafe fn new_managed<O: Send + Sync + 'static>(
        host_base: NonNull<u8>,
        bytes: usize,
        maximum_permissions: AccessPermissions,
        lifetime_owner: Arc<O>,
    ) -> Result<Arc<Self>, AccessError> {
        Self::construct(host_base, bytes, maximum_permissions, lifetime_owner)
    }

    fn construct<O: Send + Sync + 'static>(
        host_base: NonNull<u8>,
        bytes: usize,
        maximum_permissions: AccessPermissions,
        lifetime_owner: Arc<O>,
    ) -> Result<Arc<Self>, AccessError> {
        if bytes == 0 {
            return Err(AccessError::EmptyRange);
        }
        if bytes > isize::MAX as usize || (host_base.as_ptr() as usize).checked_add(bytes).is_none()
        {
            return Err(AccessError::HostBounds);
        }
        Ok(Arc::new(Self {
            id: BackingId(Identity::new()),
            source_mutation: super::domain::source_mutation::SourceMutationTracker::new(),
            host_base,
            bytes,
            maximum_permissions,
            // Fresh software-owned physical storage begins with zero tags.
            // This policy does not initialize native RAM or import hardware tags.
            allocation_tags: TagStore::new(bytes, AllocationTag::ZERO)
                .map_err(|_| AccessError::EmptyRange)?,
            coherence: Mutex::new(None),
            _lifetime_owner: lifetime_owner,
        }))
    }

    pub fn id(&self) -> BackingId {
        self.id.clone()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn maximum_permissions(&self) -> AccessPermissions {
        self.maximum_permissions
    }

    /// Physical allocation tags shared by all aliases. Execution-domain owners
    /// must apply permissions, tag-access controls and writer synchronization.
    pub fn allocation_tags(&self) -> &TagStore {
        &self.allocation_tags
    }

    /// Bind every live alias to one guest machine's physical writer domain.
    /// Rebinding is permitted only after the previous system token expires.
    /// Poisoned ownership metadata declines rather than admitting a new owner.
    pub(super) fn bind_coherence(&self, owner: &Arc<()>) -> Result<(), AccessError> {
        let mut coherence = self
            .coherence
            .lock()
            .map_err(|_| AccessError::CoherenceDomain)?;
        if let Some(current) = coherence.as_ref().and_then(Weak::upgrade) {
            return if Arc::ptr_eq(&current, owner) {
                Ok(())
            } else {
                Err(AccessError::CoherenceDomain)
            };
        }
        *coherence = Some(Arc::downgrade(owner));
        Ok(())
    }

    /// Check a physical storage envelope and obtain its raw native address.
    /// This does not validate any logical mapping's rights or lifetime state;
    /// the caller must resolve every participating view before one native access.
    pub fn host_pointer(
        &self,
        backing_offset: usize,
        bytes: usize,
        kind: AccessKind,
    ) -> Result<NonNull<u8>, AccessError> {
        if bytes == 0 {
            return Err(AccessError::EmptyRange);
        }
        let end = backing_offset
            .checked_add(bytes)
            .ok_or(AccessError::BackingBounds)?;
        if end > self.bytes {
            return Err(AccessError::BackingBounds);
        }
        if !self.maximum_permissions.permits(kind) {
            return Err(AccessError::PermissionDenied(kind));
        }
        // SAFETY: the constructor binds one live native extent; the checked
        // nonempty envelope lies wholly within it. No pointed-to bytes are read.
        Ok(unsafe { self.host_base.add(backing_offset) })
    }
}

/// One logical guest mapping generation over part of a physical backing.
/// Replacing a mapping or changing its rights creates a new view, even when the
/// backing and guest address remain unchanged. Retire the old view explicitly.
#[derive(Debug)]
pub struct MemoryView {
    id: MappingId,
    backing: Arc<MemoryBacking>,
    guest_base: u64,
    backing_offset: usize,
    bytes: usize,
    permissions: AccessPermissions,
    retired: AtomicBool,
}

impl MemoryView {
    pub fn new(
        backing: Arc<MemoryBacking>,
        guest_base: u64,
        backing_offset: usize,
        bytes: usize,
        permissions: AccessPermissions,
    ) -> Result<Arc<Self>, AccessError> {
        if bytes == 0 {
            return Err(AccessError::EmptyRange);
        }
        let guest_bytes = u64::try_from(bytes).map_err(|_| AccessError::AddressOverflow)?;
        guest_base
            .checked_add(guest_bytes)
            .ok_or(AccessError::AddressOverflow)?;
        let backing_end = backing_offset
            .checked_add(bytes)
            .ok_or(AccessError::BackingBounds)?;
        if backing_end > backing.bytes {
            return Err(AccessError::BackingBounds);
        }
        if !backing.maximum_permissions.contains(permissions) {
            return Err(AccessError::MaximumPermissions);
        }
        Ok(Arc::new(Self {
            id: MappingId(Identity::new()),
            backing,
            guest_base,
            backing_offset,
            bytes,
            permissions,
            retired: AtomicBool::new(false),
        }))
    }

    pub fn id(&self) -> MappingId {
        self.id.clone()
    }

    pub fn backing(&self) -> &Arc<MemoryBacking> {
        &self.backing
    }

    pub fn guest_base(&self) -> u64 {
        self.guest_base
    }

    pub fn backing_offset(&self) -> usize {
        self.backing_offset
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn permissions(&self) -> AccessPermissions {
        self.permissions
    }

    /// Reject future resolutions through this mapping generation. This is not a
    /// barrier against in-flight native accesses: the address-space owner must
    /// serialize mapping retirement/protection changes with guest execution.
    pub(super) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }

    pub fn is_current(&self) -> bool {
        !self.retired.load(Ordering::Acquire)
    }

    /// Validate one nonempty architectural access part, preserving the caller's
    /// responsibility to execute ordered parts and commit completed prefixes.
    /// This does not prevalidate a whole instruction, pin host protections, or
    /// prove alignment, tags, ordering, reservation validity, or race freedom.
    pub fn resolve(
        self: &Arc<Self>,
        guest_address: u64,
        bytes: usize,
        kind: AccessKind,
    ) -> Result<ResolvedAccess, AccessError> {
        if !self.is_current() {
            return Err(AccessError::RetiredMapping);
        }
        if bytes == 0 {
            return Err(AccessError::EmptyRange);
        }
        let guest_bytes = u64::try_from(bytes).map_err(|_| AccessError::AddressOverflow)?;
        guest_address
            .checked_add(guest_bytes)
            .ok_or(AccessError::AddressOverflow)?;
        let offset = guest_address
            .checked_sub(self.guest_base)
            .ok_or(AccessError::UnmappedRange)?;
        let offset = usize::try_from(offset).map_err(|_| AccessError::UnmappedRange)?;
        let end = offset
            .checked_add(bytes)
            .ok_or(AccessError::UnmappedRange)?;
        if end > self.bytes {
            return Err(AccessError::UnmappedRange);
        }
        if !self.permissions.permits(kind) {
            return Err(AccessError::PermissionDenied(kind));
        }
        Ok(ResolvedAccess {
            view: Arc::clone(self),
            backing_offset: self.backing_offset + offset,
            guest_address,
            bytes,
            kind,
        })
    }
}

/// Exact access metadata retaining its mapping generation and physical owner.
/// A resolution is not authorization to dereference without the native access
/// contract. In particular, a current-generation check does not lock remapping.
#[derive(Debug, Clone)]
pub struct ResolvedAccess {
    view: Arc<MemoryView>,
    backing_offset: usize,
    guest_address: u64,
    bytes: usize,
    kind: AccessKind,
}

impl ResolvedAccess {
    pub fn view(&self) -> &Arc<MemoryView> {
        &self.view
    }

    pub fn backing_id(&self) -> BackingId {
        self.view.backing.id.clone()
    }

    pub fn mapping_id(&self) -> MappingId {
        self.view.id.clone()
    }

    pub fn backing_offset(&self) -> usize {
        self.backing_offset
    }

    pub fn guest_address(&self) -> u64 {
        self.guest_address
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn kind(&self) -> AccessKind {
        self.kind
    }

    /// Obtain an address only. Dereferencing remains unsafe and requires the
    /// execution domain's synchronization, fault, and mapping-lifetime contract.
    pub fn host_ptr(&self) -> NonNull<u8> {
        // SAFETY: the constructor binds one live native extent; resolution
        // checks this nonempty access lies wholly within it, retaining its owner.
        unsafe { self.view.backing.host_base.add(self.backing_offset) }
    }
}

#[cfg(test)]
mod tests {
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
            // SAFETY: the owner uniquely owns the original allocation/layout.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    fn backing() -> Arc<MemoryBacking> {
        let layout = Layout::from_size_align(STORAGE_BYTES, STORAGE_ALIGNMENT).unwrap();
        // SAFETY: the valid nonzero layout is retained for the matching dealloc.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let owner = Arc::new(Storage { pointer, layout });
        // SAFETY: owner retains a raw allocation with read/write rights and no
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
    fn retained_access_keeps_mapping_and_storage_alive() {
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
        let identities =
            std::collections::HashSet::from([expected.clone(), from_thread, copy.id()]);
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
        let huge = unsafe {
            MemoryBacking::new(NonNull::dangling(), usize::MAX, READ_WRITE, Arc::new(()))
        };
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
}
