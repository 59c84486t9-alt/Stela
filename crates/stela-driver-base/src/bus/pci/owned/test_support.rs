//! The owned-configuration model other drivers' tests attach functions to.
#[cfg(test)]
mod retirement_tests;
extern crate std;
use super::grant::Grant;
use super::*;
use crate::bus::mmio::owned::{
    AddressSpace, Authority, CacheAttribute, InstalledMapping, MapFailure, MapRequest,
    MappingPlatform, PhysicalSpan, Protection, Resource, ResourceBacking, ResourceKind,
    model::{MappingOwner, MappingRetention},
};
use crate::bus::pci::{
    ConfigFailure,
    assignment::{self, OpaqueUse, UseKind},
    owned::grant::{ConfigCustody, ConfigEpoch, DriverCustody, DriverGrant, Operation},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    any::Any,
    cell::UnsafeCell,
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::sync::Mutex;

pub const SPACE: AddressSpace = AddressSpace {
    identity: 19,
    physical_bits: 48,
    virtual_bits: 48,
};
pub const FUNCTION_BYTES: usize = 4096;
pub const BUS_SHIFT: u32 = 20;
pub const BASE: u64 = 0x8000_0000;
pub const ADDRESS: Address = Address {
    segment: 0x1234,
    bus: 0xab,
    device: 0x1f,
    function: 7,
};

#[derive(Default)]
pub struct Counters {
    pub maps: AtomicUsize,
    pub unmaps: AtomicUsize,
    pub fail_unmap_after_effect: AtomicUsize,
    pub resource_drops: AtomicUsize,
    pub platform_drops: AtomicUsize,
    pub contexts: AtomicUsize,
    pub fail_context_at: AtomicUsize,
    pub fail_after_word: AtomicUsize,
    pub fail_after_value: AtomicUsize,
}

pub struct Backing {
    span: PhysicalSpan,
    kind: ResourceKind,
    counters: Arc<Counters>,
    mapping: MappingRetention<Arc<Ram>>,
}
// SAFETY: isolated symbolic physical inventory, kept alongside
// owned CPU fixture storage; no hardware or production permission is used.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        self.kind
    }
    fn begin_mapping(&self) -> Result<OpaqueUse, MappingError> {
        self.mapping.begin_mapping()
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.counters.resource_drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[repr(align(4096))]
pub struct Pages([u8; 8192]);
/// Actual hosted RAM only: no Source/control/Authority/Resource backedge.
#[repr(align(4096))]
pub struct Ram {
    pages: UnsafeCell<Pages>,
}
// SAFETY: actual isolated RAM publishes raw bounded volatile accesses only.
unsafe impl Send for Ram {}
// SAFETY: no safe payload references alias those raw accesses.
unsafe impl Sync for Ram {}
impl Ram {
    fn pointer(&self) -> NonNull<u8> {
        // SAFETY: stable real UnsafeCell allocation, never a PA conversion.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.pages.get()).0).cast()) }
    }
}
fn ram_context(ram: &Arc<Ram>) -> Result<(), assignment::Error> {
    let base = ram.pointer().as_ptr() as usize;
    if base.is_multiple_of(FUNCTION_BYTES) && base.checked_add(8192).is_some() {
        Ok(())
    } else {
        Err(assignment::Error::Context)
    }
}
pub struct Model {
    memory: Arc<Ram>,
    installed: Mutex<Option<MapRequest>>,
    unmap_pending: Mutex<Option<MapRequest>>,
    counters: Arc<Counters>,
}
// SAFETY: storage is stable and only accessed through raw volatile pointers;
// the fixture owns a single config handle, and metadata uses the mutex.
unsafe impl Send for Model {}
// SAFETY: no safe references to mutable storage; all mapping metadata is
// locked, and retirement requires the ordinary stopped-consumer contract.
unsafe impl Sync for Model {}
impl Model {
    fn pointer(&self) -> NonNull<u8> {
        self.memory.pointer()
    }
}
impl Drop for Model {
    fn drop(&mut self) {
        self.counters.platform_drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: aligned CPU RAM models exactly the requested
// symbolic device pages. This proves registry/transport lifetimes only,
// not physical ECAM, effective cache attributes or native page tables.
unsafe impl MappingPlatform for Model {
    fn check_context(&self, space: AddressSpace) -> Result<(), MappingError> {
        assert_eq!(space, SPACE);
        let call = self.counters.contexts.fetch_add(1, Ordering::Relaxed) + 1;
        if self.counters.fail_context_at.load(Ordering::Relaxed) == call {
            return Err(MappingError::Unavailable);
        }
        let watched = self.counters.fail_after_word.load(Ordering::Relaxed);
        if watched != 0 {
            let offset = watched - 1;
            assert!(offset <= 8188 && offset.is_multiple_of(4));
            // SAFETY: isolated fixture owns this aligned RAM and
            // all operations are sequential; observe the real store.
            let value = unsafe {
                self.pointer()
                    .as_ptr()
                    .add(offset)
                    .cast::<u32>()
                    .read_volatile()
            };
            if value as usize == self.counters.fail_after_value.load(Ordering::Relaxed) {
                return Err(MappingError::Unavailable);
            }
        }
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert!(resource.backing().is::<Backing>());
        let resource_span = resource.physical_span();
        assert!(
            resource_span.start() <= request.physical.start()
                && request.physical.end() <= resource_span.end()
        );
        assert!(request.physical.bytes() <= 8192);
        if self.unmap_pending.lock().unwrap().is_some() {
            return Err(MapFailure::Unchanged(MappingError::Busy));
        }
        let mut installed = self.installed.lock().unwrap();
        assert!(installed.is_none());
        *installed = Some(request);
        self.counters.maps.fetch_add(1, Ordering::Relaxed);
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: self.pointer(),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> Result<(), MappingError> {
        let installed = self.installed.lock().unwrap().take();
        let already_removed = installed.is_none();
        let original = installed.or_else(|| self.unmap_pending.lock().unwrap().take());
        assert_eq!(original, Some(request));
        assert_eq!(mapping.token, request.id);
        assert_eq!(mapping.cpu_base, self.pointer());
        if !already_removed {
            self.counters.unmaps.fetch_add(1, Ordering::Relaxed);
        }
        if self
            .counters
            .fail_unmap_after_effect
            .swap(0, Ordering::Relaxed)
            != 0
        {
            // Retain the SAME original mapper transaction after its removal
            // prefix. A checked same-token retry can ACK without repeating it.
            *self.unmap_pending.lock().unwrap() = original;
            return Err(MappingError::UnmapFailed);
        }
        Ok(())
    }
}

pub fn window(address: Address) -> EcamWindow {
    EcamWindow {
        base: BASE,
        segment: address.segment,
        start_bus: address.bus,
        end_bus: address.bus,
    }
}
pub fn physical(address: Address) -> u64 {
    BASE + (u64::from(address.bus) << 20)
        + (u64::from(address.device) << 15)
        + (u64::from(address.function) << 12)
}
/// External fixture controller. Resource inventories contain only its actual
/// retention projection; config and mapping use the SAME original count gate.
pub struct FixtureCustody {
    owner: MappingOwner<Arc<Ram>>,
    resource: Option<Resource>,
    retention: Option<MappingRetention<Arc<Ram>>>,
    memory: Arc<Ram>,
    address: Address,
    window: EcamWindow,
}
struct Epoch {
    retention: MappingRetention<Arc<Ram>>,
    memory: Arc<Ram>,
}
// SAFETY: same actual isolated RAM and source retention, never a controller,
// mapping view or native physical/code/IRQ ownership assertion.
unsafe impl ConfigEpoch for Epoch {
    fn check(&self) -> Result<(), MappingError> {
        self.retention.check_admission()
    }
    fn retain(&self) -> Result<Box<dyn ConfigEpoch>, MappingError> {
        self.check()?;
        Ok(Box::new(Self {
            retention: self.retention.clone(),
            memory: self.memory.clone(),
        }))
    }
    fn same_epoch(&self, other: &dyn ConfigEpoch) -> Result<bool, MappingError> {
        self.check()?;
        let Some(other) = other.as_any().downcast_ref::<Self>() else {
            return Ok(false);
        };
        other.check()?;
        Ok(self.retention.same_owner(&other.retention))
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
// SAFETY: same actual hosted allocation and exclusive controller constructed
// together below; data geometry cannot create an independent owner or gate.
unsafe impl ConfigCustody for FixtureCustody {
    fn admission_close(&self) -> Result<assignment::AdmissionClose, MappingError> {
        self.owner.admission_close()
    }

    fn address(&self) -> Address {
        self.address
    }
    fn window(&self) -> EcamWindow {
        self.window
    }
    fn resource(&self) -> &Resource {
        self.resource.as_ref().expect("live fixture resource")
    }
    fn begin(&self, operation: Operation) -> Result<OpaqueUse, ConfigError> {
        let (offset, width) = match operation {
            Operation::Read { offset, width } | Operation::Write { offset, width, .. } => {
                (offset, width)
            }
        };
        if !matches!(width, 1 | 2 | 4)
            || !usize::from(offset).is_multiple_of(width)
            || usize::from(offset)
                .checked_add(width)
                .is_none_or(|end| end > FUNCTION_BYTES)
        {
            return Err(ConfigError::before_effect(ConfigFailure::Access {
                offset,
                width,
            }));
        }
        self.retention
            .as_ref()
            .ok_or(ConfigError::before_effect(ConfigFailure::ForeignGrant))?
            .begin_use(UseKind::Configuration)
            .map_err(|error| {
                ConfigError::before_effect(match error {
                    MappingError::Assignment(error) => ConfigFailure::Ownership(error),
                    error => ConfigFailure::Mapping(error),
                })
            })
    }
    fn abandon(&mut self) {
        self.owner.abandon_admission();
    }
    fn retirement_context(&self) -> Result<(), MappingError> {
        self.retention
            .as_ref()
            .ok_or(MappingError::Retired)?
            .check_context()
    }
    fn retain_epoch(&self) -> Result<Box<dyn ConfigEpoch>, MappingError> {
        let retention = self.retention.as_ref().ok_or(MappingError::Retired)?;
        retention.check_admission()?;
        Ok(Box::new(Epoch {
            retention: retention.clone(),
            memory: self.memory.clone(),
        }))
    }
}
// SAFETY: cfg-only actual RAM fixture owns the sole model controller. It models
// driver policy, never native firmware/root/IRQ/DMA retirement or a PCI Source.
unsafe impl DriverCustody for FixtureCustody {}
impl FixtureCustody {
    pub fn into_grant(self) -> DriverGrant {
        DriverGrant::from_owned(self)
    }
    pub fn retention(&self) -> MappingRetention<Arc<Ram>> {
        self.retention.as_ref().expect("live fixture epoch").clone()
    }
    pub fn close(&mut self) -> Result<(), MappingError> {
        self.owner.close()
    }
    pub fn uses(&self) -> usize {
        self.owner.uses()
    }
    /// # Safety
    /// Source caller completed actual model unmap and every raw/callback user.
    /// Failure keeps the complete SAME source actor, never recreates a grant.
    #[expect(
        clippy::result_large_err,
        reason = "retirement refusal keeps the same original fixture ownership graph without allocating"
    )]
    unsafe fn finish(mut self: Box<Self>) -> Result<(), RetireFailure> {
        if let Err(error) = self.owner.close() {
            return Err(RetireFailure::source(error, self));
        }
        drop(self.resource.take());
        drop(self.retention.take());
        // SAFETY: caller supplied exact model drain; actual original gate also
        // checks every retained epoch and config operation has ended.
        match unsafe { self.owner.retire() } {
            Ok(allocation) => {
                drop(allocation);
                Ok(())
            }
            Err(error) => Err(RetireFailure::source(error, self)),
        }
    }
}
/// Original source plus mapping. Geometry remains model DATA and never creates
/// a new physical source, independent gate or native ownership assertion.
pub fn mapped(
    address: Address,
    window: EcamWindow,
    span: PhysicalSpan,
    offset: usize,
    bytes: usize,
    attribute: CacheAttribute,
    protection: Protection,
) -> (FixtureCustody, Mapping, Arc<Counters>) {
    let counters = Arc::new(Counters::default());
    let memory = Arc::new(Ram {
        pages: UnsafeCell::new(Pages([0; 8192])),
    });
    // SAFETY: this real allocation has one isolated creator/controller; no
    // firmware, native device, external reset, guest or backedge exists.
    let owner = unsafe { MappingOwner::from_owned(memory.clone(), ram_context) };
    let retention = owner.retention().unwrap();
    let platform = Arc::new(Model {
        memory: memory.clone(),
        installed: Mutex::new(None),
        unmap_pending: Mutex::new(None),
        counters: counters.clone(),
    });
    // SAFETY: actual isolated RAM and original exclusive fixture inventory.
    let authority = unsafe { Authority::isolated_model(platform, SPACE, Vec::new()) }.unwrap();
    let resource = Resource::new(Box::new(Backing {
        span,
        kind: if attribute == CacheAttribute::WriteCombining {
            ResourceKind::PrefetchableMemory
        } else {
            ResourceKind::Registers
        },
        counters: counters.clone(),
        mapping: retention.clone(),
    }));
    let mapping = authority
        .map(resource.clone(), offset, bytes, attribute, protection)
        .unwrap();
    drop(authority);
    (
        FixtureCustody {
            owner,
            resource: Some(resource),
            retention: Some(retention),
            memory,
            address,
            window,
        },
        mapping,
        counters,
    )
}
/// Sibling fixture entry. The actual final grant owns its external controller.
pub fn fixture(address: Address) -> (OwnedConfig, Arc<Counters>) {
    let span = PhysicalSpan::new(physical(address), FUNCTION_BYTES as u64).unwrap();
    let (source, mapping, counters) = mapped(
        address,
        window(address),
        span,
        0,
        FUNCTION_BYTES,
        CacheAttribute::Uncached,
        Protection::ReadWrite,
    );
    let config = match OwnedConfig::attach(source.into_grant(), mapping) {
        Ok(config) => config,
        Err((error, grant, mapping)) => {
            core::mem::forget((grant, mapping));
            panic!("valid original owned fixture refused: {error:?}")
        }
    };
    (config, counters)
}
/// Hosted RAM inspection only. It never resumes terminal configuration IO or
/// creates a writer/source from an address. Stop raw users before retirement.
pub fn fixture_pointer(config: &OwnedConfig, offset: u16) -> NonNull<u8> {
    assert!(usize::from(offset) < FUNCTION_BYTES);
    let epoch = config.retain_epoch().unwrap();
    let original = epoch
        .custody
        .as_any()
        .downcast_ref::<Epoch>()
        .expect("actual fixture epoch");
    // SAFETY: same real RAM is still owned by config custody. This pointer is
    // not native MMIO or a mutable reference and grants no hardware access.
    unsafe { NonNull::new_unchecked(original.memory.pointer().as_ptr().add(usize::from(offset))) }
}
/// Failure keeps exact original parts/source. Cause inspection cannot release.
pub struct RetireFailure {
    pub error: MappingError,
    _parts: Option<(DriverGrant, Mapping)>,
    _source: Option<ManuallyDrop<Box<FixtureCustody>>>,
    _grant: Option<DriverGrant>,
}
impl Drop for RetireFailure {
    fn drop(&mut self) {
        // Losing the real source controller must deny NEW admission even while
        // its whole original object remains retained. Ordinary DriverGrant and
        // Mapping fields below run their own close/quarantine-only Drop paths;
        // neither acknowledges hardware or frees an unfinished graph.
        if let Some(source) = &mut self._source {
            source.owner.abandon_admission();
        }
    }
}
impl core::fmt::Debug for RetireFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RetireFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl RetireFailure {
    fn parts(error: MappingError, grant: DriverGrant, mapping: Mapping) -> Self {
        Self {
            error,
            _parts: Some((grant, mapping)),
            _source: None,
            _grant: None,
        }
    }
    fn source(error: MappingError, source: Box<FixtureCustody>) -> Self {
        Self {
            error,
            _parts: None,
            _source: Some(ManuallyDrop::new(source)),
            _grant: None,
        }
    }
}
/// Pure negative checks BEFORE asking the mapper to remove CPU access. The
/// one expected count is this exact mapping's own retained use; a pending
/// config/DMA/IRQ/other use must veto teardown of the whole original graph.
/// Counts are not source-drain permission: callers still supply that proof,
/// and the actual mapper/source retirement must independently acknowledge.
fn preflight_unmap(grant: &DriverGrant, mapping: &Mapping) -> Result<(), MappingError> {
    if grant.custody().type_id() != core::any::TypeId::of::<FixtureCustody>() {
        return Err(MappingError::InvalidPlatformReply);
    }
    // SAFETY: exact concrete Any identity above; borrow of this SAME original
    // fixture actor, not a new source/grant or numeric geometry reconstruction.
    let fixture =
        unsafe { &*(grant.custody() as *const dyn ConfigCustody).cast::<FixtureCustody>() };
    if fixture.uses() != 1 {
        return Err(MappingError::Busy);
    }
    fixture.retirement_context()?;
    let resource = fixture.resource.as_ref().ok_or(MappingError::Retired)?;
    if !mapping.retains_resource(resource)? {
        return Err(MappingError::InvalidPlatformReply);
    }
    Ok(())
}
/// Caller already retired this actual mapping; extract only the SAME actual
/// hosted source. A native/foreign grant is retained and explicitly refused.
/// # Safety
/// Actual model mapping unmap acknowledged and every raw/callback user ended.
#[expect(
    clippy::result_large_err,
    reason = "retirement refusal keeps the same original fixture ownership graph without allocating"
)]
unsafe fn finish_original(grant: DriverGrant) -> Result<(), RetireFailure> {
    if grant.custody().type_id() != core::any::TypeId::of::<FixtureCustody>() {
        // Keep foreign admission/state/control entirely unchanged. Never call
        // unsafe native extraction merely to inspect its Rust identity.
        return Err(RetireFailure {
            error: MappingError::InvalidPlatformReply,
            _parts: None,
            _source: None,
            _grant: Some(grant),
        });
    }
    // SAFETY: exact Any identity above makes this an immutable observation of
    // the SAME actual fixture actor. Count is a negative veto only, not proof.
    let fixture =
        unsafe { &*(grant.custody() as *const dyn ConfigCustody).cast::<FixtureCustody>() };
    if fixture.uses() != 0 {
        return Err(RetireFailure {
            error: MappingError::Busy,
            _parts: None,
            _source: None,
            _grant: Some(grant),
        });
    }
    // SAFETY: known actual hosted source transfers intact to its retirement
    // owner. It will only close/retire; no seal/terminal state resumes IO.
    let source = unsafe { grant.into_original() };
    // SAFETY: exact original Any identity determines the SAME Box/layout;
    // no source or control is reconstructed from descriptors or numbers.
    let source = unsafe { Box::from_raw(Box::into_raw(source).cast::<FixtureCustody>()) };
    // SAFETY: the exact acknowledged model drain contract above.
    unsafe { source.finish() }
}
/// # Safety
/// Same complete acknowledged source drain as finish_original; no raw user or
/// callback may restart. Counter assertions inspect effects, never prove them.
#[expect(
    clippy::result_large_err,
    reason = "retirement refusal keeps the same original fixture ownership graph without allocating"
)]
pub unsafe fn finish_retired(grant: DriverGrant, counters: &Counters) -> Result<(), RetireFailure> {
    // SAFETY: caller supplies the exact original model retirement contract.
    unsafe { finish_original(grant) }?;
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
    Ok(())
}
/// # Safety
/// Every raw fixture pointer/callback/borrower stopped; no actor can restart.
#[expect(
    clippy::result_large_err,
    reason = "retirement refusal keeps the same original fixture ownership graph without allocating"
)]
pub unsafe fn retire(
    grant: DriverGrant,
    mut mapping: Mapping,
    counters: &Counters,
) -> Result<(), RetireFailure> {
    if let Err(error) = preflight_unmap(&grant, &mapping) {
        return Err(RetireFailure::parts(error, grant, mapping));
    }
    // SAFETY: ordinary fixtures explicitly ended every synchronous raw user;
    // original same-resource/pending-use vetoes ran before this unmap effect.
    if let Err(error) = unsafe { mapping.retire() } {
        return Err(RetireFailure::parts(error, grant, mapping));
    }
    drop(mapping);
    // SAFETY: caller completed this exact fixture's raw/borrowed users and the
    // actual mapping retirement above acknowledged before source extraction.
    unsafe { finish_retired(grant, counters) }
}
/// # Safety
/// Same complete synchronous model drain as retire; no raw user can restart.
#[expect(
    clippy::result_large_err,
    reason = "retirement refusal keeps the same original fixture ownership graph without allocating"
)]
pub unsafe fn retire_config(config: OwnedConfig, counters: &Counters) -> Result<(), RetireFailure> {
    let (grant, mapping) = config.into_parts();
    // SAFETY: same exact original model drain supplied by this caller.
    unsafe { retire(grant, mapping, counters) }
}

/// Complete one original hosted config fixture without needing its counters.
/// Failure retains the SAME grant/mapping/source. No native source is admitted.
/// # Safety
/// Every actual model producer, callback, raw pointer and alias has ended and
/// cannot restart. This is the owning fixture's acknowledged retirement path.
#[expect(
    clippy::result_large_err,
    reason = "retirement refusal keeps the same original fixture ownership graph without allocating"
)]
pub unsafe fn retire_owned(config: OwnedConfig) -> Result<(), RetireFailure> {
    let (grant, mut mapping) = config.into_parts();
    if let Err(error) = preflight_unmap(&grant, &mapping) {
        return Err(RetireFailure::parts(error, grant, mapping));
    }
    // SAFETY: exact model raw-user/drain obligations supplied by this caller;
    // original same-resource/pending-use vetoes ran before this unmap effect.
    if let Err(error) = unsafe { mapping.retire() } {
        return Err(RetireFailure::parts(error, grant, mapping));
    }
    drop(mapping);
    // SAFETY: acknowledged SAME mapping and caller's source exclusion above.
    unsafe { finish_original(grant) }
}
