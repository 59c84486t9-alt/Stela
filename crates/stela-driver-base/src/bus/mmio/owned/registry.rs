//! The registry of owned MMIO mappings: installation, leases, quarantine and retirement.
use super::*;
use alloc::{sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
use triomphe::{Arc as Shared, UniqueArc};
mod metadata;

static ACTIVATED: AtomicBool = AtomicBool::new(false);
const INSTALLING: u8 = 0;
const LIVE: u8 = 1;
const UNCERTAIN: u8 = 2;
const QUARANTINED: u8 = 3;
const RETIRED: u8 = 4;
const RETIRING: u8 = 5;
// Native removal acknowledged; original counted use still awaits release.
const UNMAPPED: u8 = 6;

struct Record {
    resource: Resource,
    request: MapRequest,
    phase: AtomicU8,
    cpu: AtomicUsize,
    token: AtomicU64,
    mapping_use: UnsafeCell<Option<OpaqueUse>>,
}
// SAFETY: token storage is initialized only in unpublished INSTALLING and
// consumed only by the unique retiring lease or its unchanged-map completion.
// Inventory readers never borrow it. Every view shares the same live record.
unsafe impl Send for Record {}
// SAFETY: phase publication and unique lease retirement exclude token mutation
// races; mapping/use release callbacks run outside the inventory lock.
unsafe impl Sync for Record {}
fn release_mapping_use(record: &Record) -> Result<(), Error> {
    if record.phase.load(Ordering::Acquire) != UNMAPPED {
        return Err(Error::InvalidPlatformReply);
    }
    // SAFETY: caller owns the unique completion/retirement phase; no observer
    // reads this slot. Every actual user ended or mapping was never published.
    let usage = unsafe { &mut *record.mapping_use.get() }
        .take()
        .ok_or(Error::InvalidPlatformReply)?;
    // SAFETY: invoked only after provider unchanged ACK, or acknowledged native
    // unmap with no views and caller's CPU/IRQ/cache/raw-tail drain contract.
    match unsafe { usage.release() } {
        Ok(()) => Ok(()),
        Err((error, usage)) => {
            // SAFETY: same exclusive token slot; keep THIS exact unreleased use.
            unsafe { *record.mapping_use.get() = Some(usage) };
            Err(Error::Assignment(error))
        }
    }
}
/// Opaque identity of one registered native alias/cache-policy reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AliasId(u64);
impl AliasId {
    pub fn value(self) -> u64 {
        self.0
    }
}
/// Opaque lookup identity for one registered device/resource owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceId(u64);
impl ResourceId {
    pub fn value(self) -> u64 {
        self.0
    }
}
struct RegisteredResource {
    id: ResourceId,
    resource: Resource,
}
struct AliasRecord {
    id: AliasId,
    alias: ExistingAlias,
}
struct Inventory {
    next: u64,
    records: Vec<Shared<Record>>,
    aliases: Vec<AliasRecord>,
    resources: Vec<RegisteredResource>,
    pending_maps: usize,
    unmapping: usize,
}
struct Inner {
    platform: Arc<dyn MappingPlatform>,
    address_space: AddressSpace,
    held: AtomicBool,
    inventory: UnsafeCell<Inventory>,
    quarantined: AtomicU64,
}
// SAFETY: the inventory is accessible only under held; other fields are
// immutable or atomic and both providers/resource backings are Send + Sync.
unsafe impl Send for Inner {}
// SAFETY: the same inventory lock and immutable/atomic field invariants apply.
unsafe impl Sync for Inner {}
struct Guard<'a>(&'a Inner);
impl Guard<'_> {
    fn inventory(&mut self) -> &mut Inventory {
        // SAFETY: a Guard exists only after exclusive held acquisition.
        unsafe { &mut *self.0.inventory.get() }
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}
impl Inner {
    fn lock(&self) -> Result<Guard<'_>, Error> {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        Ok(Guard(self))
    }
    fn finish_lock(&self) -> Guard<'_> {
        // Mandatory completion/retirement cannot abandon a valid publication
        // because another process-context reservation is in progress.
        // No provider/user callbacks or final resource releases run while held.
        loop {
            if let Ok(guard) = self.lock() {
                return guard;
            }
            core::hint::spin_loop();
        }
    }
    fn remove(&self, id: u64) {
        let removed = {
            let mut guard = self.finish_lock();
            let records = &mut guard.inventory().records;
            records
                .iter()
                .position(|record| record.request.id == id)
                .map(|at| records.swap_remove(at))
        };
        // Any last resource/platform release is outside the inventory lock.
        drop(removed);
    }
}
fn quarantine(inner: &Arc<Inner>, record: &Record) {
    if record
        .phase
        .try_update(Ordering::AcqRel, Ordering::Acquire, |phase| {
            (!matches!(phase, QUARANTINED | RETIRED)).then_some(QUARANTINED)
        })
        .is_ok()
    {
        let _ = inner
            .quarantined
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
        // Keep the inventory, resource and native root/table provider
        // alive even after every public permission/mapping/view is dropped.
        core::mem::forget(Arc::clone(inner));
    }
}

/// Cloneable handle to the single activated native root-set permission. It is
/// never possible to create a second production inventory after its last Drop.
#[derive(Clone)]
pub struct Authority {
    inner: Arc<Inner>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub installing: usize,
    pub live: usize,
    pub uncertain: usize,
    pub quarantined: u64,
}
impl Authority {
    /// Build an isolated hosted fixture through the real registry. This is not
    /// a production permission and never changes the native activation latch.
    ///
    /// # Safety
    /// The platform, resources and aliases belong exclusively to this isolated
    /// model. They do not share mappings or native ownership with production or
    /// another permission. The ordinary platform and alias contracts still apply.
    #[cfg(any(test, feature = "test-support"))]
    pub unsafe fn isolated_model(
        platform: Arc<dyn MappingPlatform>,
        address_space: AddressSpace,
        aliases: Vec<ExistingAlias>,
    ) -> Result<Self, Error> {
        Self::prepare(platform, address_space, aliases)
    }

    /// Import the participating native roots and all preexisting aliases.
    /// Successful activation is permanent; clone this handle for other users.
    ///
    /// # Safety
    /// `address_space` identifies the complete native root set, with real
    /// physical/canonical widths. `platform` keeps its ownership. `aliases`
    /// lists every existing mapping of device resources and RAM (including
    /// physical-map aliases), with the effective PAT/MTRR/cache policy.
    /// Compatible generic aliases may coexist only as raw-access mappings: no
    /// Rust references may alias a device/driver access. All outside mapping,
    /// cache-policy and root-set changes, including future SMP roots, must
    /// serialize through this same permission and preserve this inventory.
    /// No competing driver/resource mapping inventory may exist. Activation
    /// does not remove or retype a preexisting WB alias to permit UC/WC.
    pub unsafe fn activate(
        platform: Arc<dyn MappingPlatform>,
        address_space: AddressSpace,
        aliases: Vec<ExistingAlias>,
    ) -> Result<Self, Error> {
        let authority = Self::prepare(platform, address_space, aliases)?;
        ACTIVATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyActive)?;
        // The single native root-set service remains installed for this boot's
        // lifetime, independently of transient public handles.
        core::mem::forget(Arc::clone(&authority.inner));
        Ok(authority)
    }
    fn prepare(
        platform: Arc<dyn MappingPlatform>,
        address_space: AddressSpace,
        mut aliases: Vec<ExistingAlias>,
    ) -> Result<Self, Error> {
        if !address_space.valid() {
            return Err(Error::InvalidRange);
        }
        platform.check_context(address_space)?;
        for alias in &mut aliases {
            alias.physical = alias.physical.pages()?;
            if !address_space.physical(alias.physical) {
                return Err(Error::InvalidRange);
            }
        }
        for (at, a) in aliases.iter().enumerate() {
            if aliases[..at].iter().any(|b| {
                a.physical.overlaps(b.physical)
                    && a.attribute.is_some()
                    && b.attribute.is_some()
                    && a.attribute != b.attribute
            }) {
                return Err(Error::CacheConflict);
            }
        }
        let mut next = 1u64;
        let mut imported = Vec::new();
        imported
            .try_reserve(aliases.len())
            .map_err(|_| Error::Unavailable)?;
        for alias in aliases {
            let id = AliasId(next);
            next = next.checked_add(1).ok_or(Error::Exhausted)?;
            imported.push(AliasRecord { id, alias });
        }
        Ok(Self {
            inner: Arc::new(Inner {
                platform,
                address_space,
                held: AtomicBool::new(false),
                inventory: UnsafeCell::new(Inventory {
                    next,
                    records: Vec::new(),
                    aliases: imported,
                    resources: Vec::new(),
                    pending_maps: 0,
                    unmapping: 0,
                }),
                quarantined: AtomicU64::new(0),
            }),
        })
    }
    /// Register a resource owner for physical-address-only
    /// consumers such as an unchanged native GPU mapping ABI. A BAR tuple is
    /// never sufficient; the caller must already possess ResourceBacking.
    pub fn register_resource(&self, resource: Resource) -> Result<ResourceId, RegistrationFailure> {
        let original = resource.clone();
        self.register_resource_inner(resource)
            .map_err(|error| RegistrationFailure {
                error,
                resource: ManuallyDrop::new(original),
            })
    }
    fn register_resource_inner(&self, resource: Resource) -> Result<ResourceId, Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        if !self.inner.address_space.physical(resource.physical_span()) {
            return Err(Error::InvalidRange);
        }
        let mut guard = self.inner.lock()?;
        let inventory = guard.inventory();
        if let Some(existing) = inventory
            .resources
            .iter()
            .find(|r| Arc::ptr_eq(&r.resource.backing, &resource.backing))
        {
            return Ok(existing.id);
        }
        if inventory.resources.iter().any(|r| {
            r.resource
                .physical_span()
                .overlaps(resource.physical_span())
        }) || inventory.records.iter().any(|r| {
            r.phase.load(Ordering::Acquire) != RETIRED
                && r.resource
                    .physical_span()
                    .overlaps(resource.physical_span())
                && !Arc::ptr_eq(&r.resource.backing, &resource.backing)
        }) {
            return Err(Error::ResourceConflict);
        }
        let id = ResourceId(inventory.next);
        inventory.next = inventory.next.checked_add(1).ok_or(Error::Exhausted)?;
        inventory
            .resources
            .try_reserve(1)
            .map_err(|_| Error::Unavailable)?;
        inventory
            .resources
            .push(RegisteredResource { id, resource });
        Ok(id)
    }
    /// Resolve complete page-rounded coverage to the owner.
    /// Unknown, partial or unregistered physical spans refuse before mapping.
    pub fn resolve_resource(&self, physical: PhysicalSpan) -> Result<Resource, Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        let pages = physical.pages()?;
        let mut guard = self.inner.lock()?;
        guard
            .inventory()
            .resources
            .iter()
            .find(|r| r.resource.physical_span().contains(pages))
            .map(|r| r.resource.clone())
            .ok_or(Error::OutsideResource)
    }
    /// Native physical-address-only ABI entry: ownership lookup and mapping
    /// use the same permission. This never invents ownership from the address.
    pub fn map_physical(
        &self,
        physical: PhysicalSpan,
        attribute: CacheAttribute,
        protection: Protection,
    ) -> Result<Mapping, Error> {
        let resource = self.resolve_resource(physical)?;
        let offset = usize::try_from(physical.start() - resource.physical_span().start())
            .map_err(|_| Error::InvalidRange)?;
        let bytes = usize::try_from(physical.bytes()).map_err(|_| Error::InvalidRange)?;
        self.map(resource, offset, bytes, attribute, protection)
    }
    /// Remove lookup only after all mappings of this resource have retired.
    /// Independently kept Resource pins continue to own the reservation.
    pub fn unregister_resource(&self, id: ResourceId) -> Result<(), Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        let removed = {
            let mut guard = self.inner.lock()?;
            let inventory = guard.inventory();
            let at = inventory
                .resources
                .iter()
                .position(|r| r.id == id)
                .ok_or(Error::Retired)?;
            if inventory.records.iter().any(|r| {
                r.phase.load(Ordering::Acquire) != RETIRED
                    && Arc::ptr_eq(
                        &r.resource.backing,
                        &inventory.resources[at].resource.backing,
                    )
            }) {
                return Err(Error::Busy);
            }
            inventory.resources.swap_remove(at)
        };
        drop(removed);
        Ok(())
    }
    /// Snapshot of imported or reserved aliases. IDs are valid only for
    /// this one permission and never reused, including after removal.
    pub fn aliases(&self) -> Result<Vec<(AliasId, ExistingAlias)>, Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        let mut guard = self.inner.lock()?;
        Ok(guard
            .inventory()
            .aliases
            .iter()
            .map(|record| (record.id, record.alias))
            .collect())
    }
    /// Reserve the full cache-policy span *before* an outside RAM/physmap/root
    /// table change. This does not establish the mapping or cache type.
    /// Failed/uncertain outside publication keeps this reservation until a
    /// removal/rollback acknowledgement permits `retire_alias`.
    ///
    /// # Safety
    /// The native table owner serializes its publication with this permission,
    /// covers the entire alias in every participating root, keeps ownership
    /// through removal, and checks the effective cache policy. No
    /// Rust reference may alias a simultaneously accessed device resource.
    pub unsafe fn reserve_alias(&self, mut alias: ExistingAlias) -> Result<AliasId, Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        alias.physical = alias.physical.pages()?;
        if !self.inner.address_space.physical(alias.physical) {
            return Err(Error::InvalidRange);
        }
        let mut guard = self.inner.lock()?;
        let inventory = guard.inventory();
        if inventory.aliases.iter().any(|record| {
            record.alias.physical.overlaps(alias.physical)
                && record.alias.attribute != alias.attribute
        }) || inventory.records.iter().any(|record| {
            record.phase.load(Ordering::Acquire) != RETIRED
                && record.request.physical.overlaps(alias.physical)
                && Some(record.request.attribute) != alias.attribute
        }) {
            return Err(Error::CacheConflict);
        }
        let id = AliasId(inventory.next);
        inventory.next = inventory.next.checked_add(1).ok_or(Error::Exhausted)?;
        inventory
            .aliases
            .try_reserve(1)
            .map_err(|_| Error::Unavailable)?;
        inventory.aliases.push(AliasRecord { id, alias });
        Ok(id)
    }
    /// # Safety
    /// Every mapping represented by this ID has been removed or never
    /// published, with real cache/WC completion and all participating root/CPU
    /// TLB acknowledgements. No future outside publication can use the retired
    /// reservation. This operation never removes a page table by itself.
    pub unsafe fn retire_alias(&self, id: AliasId) -> Result<(), Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        let mut guard = self.inner.lock()?;
        let aliases = &mut guard.inventory().aliases;
        let at = aliases
            .iter()
            .position(|record| record.id == id)
            .ok_or(Error::Retired)?;
        aliases.swap_remove(at);
        Ok(())
    }
    pub fn address_space(&self) -> AddressSpace {
        self.inner.address_space
    }
    pub fn status(&self) -> Result<Status, Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        let mut guard = self.inner.lock()?;
        let mut result = Status {
            installing: 0,
            live: 0,
            uncertain: 0,
            quarantined: self.inner.quarantined.load(Ordering::Relaxed),
        };
        for record in &guard.inventory().records {
            match record.phase.load(Ordering::Acquire) {
                INSTALLING => result.installing += 1,
                LIVE => result.live += 1,
                UNCERTAIN | RETIRING | UNMAPPED => result.uncertain += 1,
                _ => {}
            }
        }
        Ok(result)
    }
    /// Reserve before calling the native table adapter. Separate driver
    /// mappings may not overlap even when requesting the same cache policy;
    /// obtain bounded subviews from an existing mapping instead.
    pub fn map(
        &self,
        resource: Resource,
        offset: usize,
        bytes: usize,
        attribute: CacheAttribute,
        protection: Protection,
    ) -> Result<Mapping, Error> {
        self.inner
            .platform
            .check_context(self.inner.address_space)?;
        if attribute == CacheAttribute::WriteBack {
            return Err(Error::UnsupportedCache);
        }
        let start = resource
            .physical_span()
            .start()
            .checked_add(u64::try_from(offset).map_err(|_| Error::InvalidRange)?)
            .ok_or(Error::InvalidRange)?;
        let requested = PhysicalSpan::new(
            start,
            u64::try_from(bytes).map_err(|_| Error::InvalidRange)?,
        )?;
        let physical = requested.pages()?;
        if !resource.physical_span().contains(physical) {
            return Err(Error::OutsideResource);
        }
        if !self.inner.address_space.physical(physical) || physical.bytes() > isize::MAX as u64 {
            return Err(Error::InvalidRange);
        }
        if !resource.permits_device_cache(physical, attribute) {
            return Err(Error::UnsupportedCache);
        }
        // Reserve empty shared storage before the inventory lock. Allocation
        // failure cannot drop a final resource owner under that lock.
        let mut record_storage = metadata::reserve::<Record>()?;
        let mut lease_storage = metadata::reserve::<Lease>()?;
        let (record, mut lease) = {
            let mut guard = self.inner.lock()?;
            let inventory = guard.inventory();
            if inventory.unmapping != 0 {
                return Err(Error::Busy);
            }
            let pending_maps = inventory
                .pending_maps
                .checked_add(1)
                .ok_or(Error::Exhausted)?;
            if inventory.aliases.iter().any(|record| {
                record.alias.physical.overlaps(physical)
                    && record.alias.attribute != Some(attribute)
            }) {
                return Err(Error::CacheConflict);
            }
            if inventory.resources.iter().any(|r| {
                r.resource
                    .physical_span()
                    .overlaps(resource.physical_span())
                    && !Arc::ptr_eq(&r.resource.backing, &resource.backing)
            }) || inventory.records.iter().any(|record| {
                record.phase.load(Ordering::Acquire) != RETIRED
                    && (record.request.physical.overlaps(physical)
                        || (record
                            .resource
                            .physical_span()
                            .overlaps(resource.physical_span())
                            && !Arc::ptr_eq(&record.resource.backing, &resource.backing)))
            }) {
                return Err(Error::ResourceConflict);
            }
            let id = inventory.next;
            inventory.next = id.checked_add(1).ok_or(Error::Exhausted)?;
            #[cfg(test)]
            metadata::allocation::reserve()?;
            inventory
                .records
                .try_reserve(1)
                .map_err(|_| Error::Unavailable)?;
            record_storage.write(Record {
                resource,
                request: MapRequest {
                    id,
                    address_space: self.inner.address_space,
                    physical,
                    attribute,
                    protection,
                },
                phase: AtomicU8::new(INSTALLING),
                cpu: AtomicUsize::new(0),
                token: AtomicU64::new(0),
                mapping_use: UnsafeCell::new(None),
            });
            // SAFETY: the entire Record was initialized exactly once above.
            let record = unsafe { UniqueArc::assume_init(record_storage) }.shareable();
            // Both shared allocations must succeed before any native effect.
            // This complete lease is private until its reply is filled
            // and the corresponding record becomes LIVE.
            lease_storage.write(Lease {
                authority: Arc::clone(&self.inner),
                record: record.clone(),
                installed: None,
                offset: (requested.start() - physical.start()) as usize,
                bytes,
            });
            // SAFETY: the entire Lease was initialized exactly once above;
            // installed remains explicitly absent until the provider replies.
            let lease = unsafe { UniqueArc::assume_init(lease_storage) };
            inventory.records.push(record.clone());
            inventory.pending_maps = pending_maps;
            (record, lease)
        };
        // Backing admission is outside the inventory lock and BEFORE any
        // mapper effect. A closed real assignment cannot be revived by Resource
        // clones or this inventory's numerical resource metadata.
        let usage = match record.resource.begin_mapping() {
            Ok(usage) => usage,
            Err(error) => {
                let removed = {
                    let mut guard = self.inner.finish_lock();
                    guard.inventory().pending_maps -= 1;
                    record
                        .phase
                        .compare_exchange(INSTALLING, RETIRED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                };
                if removed {
                    self.inner.remove(record.request.id);
                } else {
                    quarantine(&self.inner, &record);
                }
                return Err(error);
            }
        };
        // SAFETY: private unpublished lease; no public borrower can retire it.
        unsafe { *record.mapping_use.get() = Some(usage) };
        // SAFETY: inventory reserved exact span/cache/id; same counted original
        // backing stays held through every reply, view and native unmap.
        let installed = match unsafe { self.inner.platform.map(&record.resource, record.request) } {
            Ok(mapping) => mapping,
            Err(MapFailure::Unchanged(error)) => {
                {
                    let mut guard = self.inner.finish_lock();
                    guard.inventory().pending_maps -= 1;
                    if record
                        .phase
                        .compare_exchange(INSTALLING, UNMAPPED, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        quarantine(&self.inner, &record);
                        return Err(error);
                    }
                }
                if let Err(release) = release_mapping_use(&record) {
                    // No handle escaped: retain original record/use/root graph
                    // permanently rather than discard its failed completion.
                    quarantine(&self.inner, &record);
                    return Err(release);
                }
                record.phase.store(RETIRED, Ordering::Release);
                self.inner.remove(record.request.id);
                return Err(error);
            }
            Err(MapFailure::Uncertain(error)) => {
                let mut guard = self.inner.finish_lock();
                guard.inventory().pending_maps -= 1;
                quarantine(&self.inner, &record);
                return Err(error);
            }
        };
        // Keep even a malformed reply's nonzero teardown identity. Another
        // response must not reuse a token because its first owner is
        // uncertain/quarantined or has not reached publication yet.
        record.token.store(installed.token, Ordering::Release);
        let base = installed.cpu_base.as_ptr() as usize;
        let valid_virtual = base.is_multiple_of(PAGE_BYTES as usize)
            && self
                .inner
                .address_space
                .virtual_span(base, physical.bytes() as usize);
        if valid_virtual {
            record.cpu.store(base, Ordering::Release);
        }
        let valid_metadata = installed.token != 0
            && installed.physical == physical
            && installed.attribute == attribute
            && installed.protection == protection
            && valid_virtual;
        // No handle to this complete lease has escaped or been cloned. Fill
        // its provider reply before any usable mapping is published.
        lease.installed = Some(installed);
        let published = {
            let mut guard = self.inner.finish_lock();
            let inventory = guard.inventory();
            inventory.pending_maps -= 1;
            let mut collision = false;
            for other in &inventory.records {
                if other.request.id == record.request.id
                    || other.phase.load(Ordering::Acquire) == RETIRED
                {
                    continue;
                }
                let other_token = other.token.load(Ordering::Acquire);
                let other_base = other.cpu.load(Ordering::Acquire);
                let same_token = installed.token != 0 && other_token == installed.token;
                let same_virtual = valid_virtual
                    && other_base != 0
                    && base < other_base + other.request.physical.bytes() as usize
                    && other_base < base + physical.bytes() as usize;
                if same_token || same_virtual {
                    // Neither identity is trustworthy for teardown after a
                    // collision, including an already usable older lease.
                    quarantine(&self.inner, other);
                    collision = true;
                }
            }
            if !valid_metadata || collision {
                quarantine(&self.inner, &record);
                false
            } else {
                // A peer may already have quarantined this INSTALLING reply.
                // Never resurrect it with an unconditional LIVE store.
                record
                    .phase
                    .compare_exchange(INSTALLING, LIVE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            }
        };
        if !published {
            quarantine(&self.inner, &record);
            return Err(Error::InvalidPlatformReply);
        }
        Ok(Mapping {
            lease: Some(lease.shareable()),
        })
    }
}

struct Lease {
    authority: Arc<Inner>,
    record: Shared<Record>,
    installed: Option<InstalledMapping>,
    offset: usize,
    bytes: usize,
}
// SAFETY: addresses remain raw only; provider establishes the same mapping in
// every participating context. Mutation is consumer-unsafe; lease metadata is
// immutable and phases atomic, so access takes no lock and may run in an
// interrupt handler. Teardown is process/deferred and explicit.
unsafe impl Send for Lease {}
// SAFETY: same raw-only provider and immutable/atomic lifetime invariants.
unsafe impl Sync for Lease {}
impl Lease {
    fn address(&self, range: Range<usize>) -> Result<NonNull<u8>, Error> {
        if self.record.phase.load(Ordering::Acquire) != LIVE {
            return Err(Error::Unavailable);
        }
        if range.start >= range.end || range.end > self.bytes {
            return Err(Error::InvalidRange);
        }
        NonNull::new(
            self.installed
                .ok_or(Error::Unavailable)?
                .cpu_base
                .as_ptr()
                .wrapping_add(self.offset + range.start),
        )
        .ok_or(Error::InvalidPlatformReply)
    }
}

/// One installed mapping. Raw pointers never authorize a Rust reference or a
/// wider register width; the device consumer owns access/ordering semantics.
/// Dropping without successful retirement permanently quarantines the mapping.
pub struct Mapping {
    lease: Option<Shared<Lease>>,
}
impl Mapping {
    fn lease(&self) -> Result<&Shared<Lease>, Error> {
        self.lease.as_ref().ok_or(Error::Retired)
    }
    /// Observe provider execution context and kept lease lifetime,
    /// without a device access, root mutation, allocation or retirement.
    pub fn check_current(&self) -> Result<(), Error> {
        let lease = self.lease()?;
        lease
            .authority
            .platform
            .check_context(lease.authority.address_space)?;
        lease.address(0..lease.bytes).map(|_| ())
    }
    pub fn bytes(&self) -> Result<usize, Error> {
        Ok(self.lease()?.bytes)
    }
    pub fn physical_span(&self) -> Result<PhysicalSpan, Error> {
        let lease = self.lease()?;
        PhysicalSpan::new(
            lease.record.request.physical.start() + lease.offset as u64,
            lease.bytes as u64,
        )
    }
    pub fn attribute(&self) -> Result<CacheAttribute, Error> {
        Ok(self.lease()?.record.request.attribute)
    }
    pub fn protection(&self) -> Result<Protection, Error> {
        Ok(self.lease()?.record.request.protection)
    }
    pub fn address(&self, offset: usize, bytes: usize) -> Result<NonNull<u8>, Error> {
        self.check_current()?;
        self.lease()?
            .address(offset..offset.checked_add(bytes).ok_or(Error::InvalidRange)?)
    }
    /// The little-endian 32-bit register at `offset`, by one naturally aligned
    /// volatile load.
    pub fn read32(&self, offset: usize) -> Result<u32, Error> {
        let register = register::<u32>(self.address(offset, 4)?)?;
        // SAFETY: `address` checked that the live lease covers these bytes and
        // `register` their alignment; retirement requires `&mut self`.
        Ok(u32::from_le(unsafe { register.read_volatile() }))
    }
    /// Store `value` to the little-endian 32-bit register at `offset`, as one
    /// naturally aligned volatile store.
    pub fn write32(&self, offset: usize, value: u32) -> Result<(), Error> {
        let register = register::<u32>(self.address(offset, 4)?)?;
        // SAFETY: as for `read32`.
        unsafe { register.write_volatile(value.to_le()) };
        Ok(())
    }
    pub fn view(&self, range: Range<usize>) -> Result<MappingView, Error> {
        self.check_current()?;
        let lease = self.lease()?;
        lease.address(range.clone())?;
        Ok(MappingView {
            lease: lease.clone(),
            range,
        })
    }
    /// Match the SAME original resource backing, not matching physical/BDF
    /// metadata. Grants no config writer/reset/root permission by itself.
    pub fn retains_resource(&self, resource: &Resource) -> Result<bool, Error> {
        self.check_current()?;
        let lease = self.lease()?;
        Ok(Arc::ptr_eq(
            &lease.record.resource.backing,
            &resource.backing,
        ))
    }
    /// Compare the original mapping-platform permission, checking both
    /// mappings are still live. Equal numeric root identities are insufficient.
    /// This establishes mapping-service provenance only; it grants no PCI
    /// root, IOMMU route, device, alias, reset, writer or completion permission.
    pub fn shares_authority(&self, view: &MappingView) -> Result<bool, Error> {
        self.check_current()?;
        view.check_current()?;
        let lease = self.lease()?;
        lease.address(0..lease.bytes)?;
        view.address(0, view.bytes())?;
        Ok(Arc::ptr_eq(&lease.authority, &view.lease.authority))
    }
    /// Compare the original installed lease, rather than another mapping
    /// managed by the same platform permission. Both views must still be live.
    pub fn shares_mapping(&self, view: &MappingView) -> Result<bool, Error> {
        self.check_current()?;
        view.check_current()?;
        let lease = self.lease()?;
        lease.address(0..lease.bytes)?;
        view.address(0, view.bytes())?;
        Ok(Shared::ptr_eq(lease, &view.lease))
    }
    /// # Safety
    /// All device, CPU, callback and worker accesses through every raw pointer
    /// obtained from this mapping have stopped/drained, including posted/WC
    /// writes; no new access may begin. Provider context rules apply. A failed
    /// unmap blocks subsequent address/view access and keeps the exact
    /// reservation/token for acknowledged retry or permanent quarantine. Busy
    /// refusal before a native callback leaves the mapping unchanged; an
    /// ambiguous/quarantined identity can never authorize a native unmap.
    pub unsafe fn retire(&mut self) -> Result<(), Error> {
        let lease = self.lease()?;
        if Shared::strong_count(lease) != 1 {
            return Err(Error::Busy);
        }
        lease
            .authority
            .platform
            .check_context(lease.record.request.address_space)?;
        if lease.record.phase.load(Ordering::Acquire) == UNMAPPED {
            release_mapping_use(&lease.record)?;
            lease.record.phase.store(RETIRED, Ordering::Release);
            lease.authority.remove(lease.record.request.id);
            self.lease = None;
            return Ok(());
        }
        let installed = lease.installed.ok_or(Error::Unavailable)?;
        {
            let mut guard = lease.authority.lock()?;
            let inventory = guard.inventory();
            if !matches!(lease.record.phase.load(Ordering::Acquire), LIVE | UNCERTAIN) {
                return Err(Error::InvalidPlatformReply);
            }
            // A not-yet-validated map reply could reveal an aliased token.
            // Do not enter real unmap while any such response is in flight;
            // block new map callbacks until this unmap has acknowledged.
            if inventory.pending_maps != 0 {
                return Err(Error::Busy);
            }
            inventory.unmapping = inventory.unmapping.checked_add(1).ok_or(Error::Exhausted)?;
            lease.record.phase.store(RETIRING, Ordering::Release);
        }
        // SAFETY: kept, non-ambiguous token; caller proves consumer
        // drain. The inventory excludes new maps and all pending replies.
        let outcome = unsafe {
            lease
                .authority
                .platform
                .unmap(lease.record.request, installed)
        };
        let retired = {
            let mut guard = lease.authority.finish_lock();
            guard.inventory().unmapping -= 1;
            match outcome {
                Ok(()) => {
                    let acknowledged = lease
                        .record
                        .phase
                        .compare_exchange(RETIRING, UNMAPPED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok();
                    if acknowledged {
                        // Cleared before new map callbacks can reuse this native
                        // token/VA; its original use still blocks physical close.
                        lease.record.token.store(0, Ordering::Release);
                        lease.record.cpu.store(0, Ordering::Release);
                    }
                    acknowledged
                }
                Err(_) => {
                    let _ = lease.record.phase.compare_exchange(
                        RETIRING,
                        UNCERTAIN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    false
                }
            }
        };
        outcome?;
        if !retired {
            quarantine(&lease.authority, &lease.record);
            return Err(Error::InvalidPlatformReply);
        }
        // Native alias/token no longer exists. Count release may still refuse;
        // leave UNMAPPED so retry never issues a second hardware unmap.
        release_mapping_use(&lease.record)?;
        lease.record.phase.store(RETIRED, Ordering::Release);
        lease.authority.remove(lease.record.request.id);
        self.lease = None;
        Ok(())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            quarantine(&lease.authority, &lease.record);
        }
    }
}

/// `pointer` as a register of type `T`, if it is naturally aligned.
fn register<T>(pointer: NonNull<u8>) -> Result<*mut T, Error> {
    let pointer = pointer.as_ptr();
    if !(pointer as usize).is_multiple_of(core::mem::align_of::<T>()) {
        return Err(Error::InvalidRange);
    }
    Ok(pointer.cast())
}

/// Independently kept bounded view of precisely the same installed mapping.
#[derive(Clone)]
pub struct MappingView {
    lease: Shared<Lease>,
    range: Range<usize>,
}
impl MappingView {
    /// Compare the actual original installed mapping lease in current scope.
    /// Different bounded ranges may share that lease. This supplies no writer,
    /// device, root route, reset or completion permission from pointer values.
    pub fn shares_mapping(&self, other: &Self) -> Result<bool, Error> {
        self.check_current()?;
        other.check_current()?;
        Ok(Shared::ptr_eq(&self.lease, &other.lease))
    }
    /// Pure current-context/lifetime observation of this exact view.
    pub fn check_current(&self) -> Result<(), Error> {
        self.lease
            .authority
            .platform
            .check_context(self.lease.authority.address_space)?;
        self.lease.address(self.range.clone()).map(|_| ())
    }
    pub fn bytes(&self) -> usize {
        self.range.end - self.range.start
    }
    pub fn address(&self, offset: usize, bytes: usize) -> Result<NonNull<u8>, Error> {
        self.check_current()?;
        let end = offset
            .checked_add(bytes)
            .filter(|end| *end <= self.bytes())
            .ok_or(Error::InvalidRange)?;
        self.lease
            .address(self.range.start + offset..self.range.start + end)
    }
    /// The 32-bit register at `offset` in this view ([`Mapping::read32`]).
    pub fn read32(&self, offset: usize) -> Result<u32, Error> {
        let register = register::<u32>(self.address(offset, 4)?)?;
        // SAFETY: `address` checked that the live lease covers these bytes and
        // `register` their alignment; the view keeps the lease.
        Ok(u32::from_le(unsafe { register.read_volatile() }))
    }
    /// Store `value` to the 32-bit register at `offset` in this view.
    pub fn write32(&self, offset: usize, value: u32) -> Result<(), Error> {
        let register = register::<u32>(self.address(offset, 4)?)?;
        // SAFETY: as for `read32`.
        unsafe { register.write_volatile(value.to_le()) };
        Ok(())
    }
}

#[cfg(test)]
mod tests;
