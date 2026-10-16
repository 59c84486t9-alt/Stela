//! Physical backing and mapping identities of guest memory.

use super::tag_store::TagStore;
use super::tags::AllocationTag;
use crate::platform::sync::Mutex;
use alloc::sync::{Arc, Weak};
use core::hash::{Hash, Hasher};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

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

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Pointer::fmt(&Arc::as_ptr(&self.0), f)
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Identity {}

impl PartialOrd for Identity {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identity {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
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

impl core::fmt::Display for AccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "guest memory resolution failed: {self:?}")
    }
}

impl core::error::Error for AccessError {}

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

impl core::fmt::Debug for MemoryBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    /// `host_base..host_base + bytes` must stay one live native extent at a
    /// stable address until the last backing or access is dropped, and
    /// `lifetime_owner` must keep that storage alive. The storage must be
    /// coherent write-back RAM, not MMIO or device memory. Host rights must
    /// allow every permitted data read and write, guest execute must allow
    /// reading instruction bytes, and these rights must not be revoked while
    /// any access can run. Never bind storage that incompatible Rust references
    /// alias. Every access, including through external aliases, must follow one
    /// synchronization and fault contract, which this constructor does not
    /// enforce. Each physical storage has exactly one backing, shared by all
    /// its aliases.
    pub unsafe fn new<O: Send + Sync + 'static>(
        host_base: NonNull<u8>,
        bytes: usize,
        maximum_permissions: AccessPermissions,
        lifetime_owner: Arc<O>,
    ) -> Result<Arc<Self>, AccessError> {
        Self::construct(host_base, bytes, maximum_permissions, lifetime_owner)
    }

    /// A backing whose host rights are managed by its owner.
    ///
    /// # Safety
    /// The storage owner keeps this extent alive and excludes all native access
    /// through the domain's execution and service borrows before changing
    /// rights. Every view and host publication validates the current rights;
    /// the maximum permissions are an upper bound, not permission to access a
    /// protected page. Do not give this backing to another domain, view or raw
    /// consumer. The rules of `new` also apply.
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
            // New software-owned storage starts with zero tags.
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

/// One generation of a guest mapping over part of a backing. Replacing the
/// mapping or changing its rights creates a new view even when the backing and
/// address are unchanged; the old view must be retired explicitly.
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
mod tests;
