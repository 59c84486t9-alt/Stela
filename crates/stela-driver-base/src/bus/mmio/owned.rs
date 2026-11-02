//! Owned native physical-device mappings. This service reserves device
//! resources and cache aliases; it does not allocate RAM or construct DMA IOVAs.
//!
//! The mount must supply the real page-table/PAT/MTRR and cross-core TLB adapter.
//! An activated permission is not itself proof that such an adapter exists.
mod registry;

pub use crate::bus::dma::memory::CacheAttribute;
use crate::bus::pci::assignment::{OpaqueUse, UseKind};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{any::Any, mem::ManuallyDrop, ptr::NonNull};
#[cfg(any(test, feature = "test-support"))]
pub mod model;
pub use registry::{AliasId, Authority, Mapping, MappingView, ResourceId, Status};

pub const PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidRange,
    OutsideResource,
    ResourceConflict,
    CacheConflict,
    UnsupportedCache,
    Unavailable,
    AlreadyActive,
    Busy,
    Exhausted,
    InvalidPlatformReply,
    Retired,
    MappingFailed,
    UnmapFailed,
    Assignment(crate::bus::pci::assignment::Error),
}

/// Checked nonempty half-open physical interval. Whole-page coverage is checked
/// separately: rounding a request must never acquire an unowned neighbor page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalSpan {
    start: u64,
    end: u64,
}
impl PhysicalSpan {
    pub fn new(start: u64, bytes: u64) -> Result<Self, Error> {
        let end = start
            .checked_add(bytes)
            .filter(|end| *end > start)
            .ok_or(Error::InvalidRange)?;
        Ok(Self { start, end })
    }
    pub fn start(self) -> u64 {
        self.start
    }
    pub fn end(self) -> u64 {
        self.end
    }
    pub fn bytes(self) -> u64 {
        self.end - self.start
    }
    pub(super) fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
    pub(super) fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
    pub(super) fn pages(self) -> Result<Self, Error> {
        let end = self
            .end
            .checked_add(PAGE_BYTES - 1)
            .ok_or(Error::InvalidRange)?
            & !(PAGE_BYTES - 1);
        Ok(Self {
            start: self.start & !(PAGE_BYTES - 1),
            end,
        })
    }
}

/// Native address-space/root-set metadata, not an address or an inferred
/// identity map. `Authority::activate` establishes its real platform meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressSpace {
    pub identity: u64,
    pub physical_bits: u8,
    pub virtual_bits: u8,
}
impl AddressSpace {
    pub(super) fn valid(self) -> bool {
        self.identity != 0
            && (32..=52).contains(&self.physical_bits)
            && matches!(self.virtual_bits, 48 | 57)
    }
    pub(super) fn physical(self, span: PhysicalSpan) -> bool {
        span.end <= 1u64 << self.physical_bits
    }
    pub(super) fn virtual_span(self, base: usize, bytes: usize) -> bool {
        let Some(last) = bytes.checked_sub(1).and_then(|n| base.checked_add(n)) else {
            return false;
        };
        if base.checked_add(bytes).is_none() {
            return false;
        }
        let canonical = |address: usize| {
            let shift = 64 - self.virtual_bits;
            (((address as u64) << shift) as i64 >> shift) as u64 == address as u64
        };
        canonical(base)
            && canonical(last)
            && ((base as u64 >> (self.virtual_bits - 1))
                == (last as u64 >> (self.virtual_bits - 1)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    Registers,
    PrefetchableMemory,
}

/// Device-checked permission for one complete page-aligned subrange of an
/// exclusive resource. This is not proof of the CPU's effective policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceCacheRegion {
    pub physical: PhysicalSpan,
    pub attribute: CacheAttribute,
}

/// Real, exclusive platform/PCI resource owner. Metadata cannot change while
/// kept. A BAR address and size alone do not implement this ownership.
///
/// # Safety
/// The entire span is a device resource exclusively reserved from all
/// other drivers, firmware and RAM/guest allocators. Keep its device/reset
/// epoch, parent bridge/resource assignment and physical reservation until Drop.
/// No resource relocation, reset or removal may invalidate a mapping.
/// `PrefetchableMemory` must reflect the hardware resource; it does not
/// by itself establish WC support. Implementations must keep metadata immutable.
/// Final Drop is process/deferred context, never implicitly IRQ-safe.
pub unsafe trait ResourceBacking: Any + Send + Sync {
    fn physical_span(&self) -> PhysicalSpan;
    fn kind(&self) -> ResourceKind;
    /// Acquire one counted use from the SAME actual physical/model backing.
    /// This must precede mapper effects; no address/metadata stand-in or
    /// independent gate may replace the original assignment/reset epoch.
    fn begin_mapping(&self) -> Result<OpaqueUse, Error>;
}

/// Failed registration returns the SAME original resource. Default abandonment
/// keeps its full backing; inspecting the cause never authorizes final release.
pub struct RegistrationFailure {
    pub error: Error,
    resource: ManuallyDrop<Resource>,
}
impl RegistrationFailure {
    pub fn into_resource(mut self) -> Resource {
        // SAFETY: consumed once; this transfers original custody, not teardown.
        unsafe { ManuallyDrop::take(&mut self.resource) }
    }
}
impl core::fmt::Debug for RegistrationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Cloneable pin on one exclusive resource reservation.
#[derive(Clone)]
pub struct Resource {
    backing: Arc<dyn ResourceBacking>,
    span: PhysicalSpan,
    kind: ResourceKind,
    cache_regions: Option<triomphe::Arc<Vec<DeviceCacheRegion>>>,
}
impl Resource {
    pub fn new(backing: Box<dyn ResourceBacking>) -> Self {
        Self {
            span: backing.physical_span(),
            kind: backing.kind(),
            backing: Arc::from(backing),
            cache_regions: None,
        }
    }
    /// Keep one original resource with explicit, immutable UC/WC subranges.
    /// Gaps and requests crossing region boundaries are not authorized. The
    /// resource kind is preserved; default permissions are replaced.
    ///
    /// # Safety
    /// `backing` binds the native requester identity, exclusive whole
    /// device resource and current reset/assignment epoch. Every region's
    /// UC/WC permission must be checked from that device family's
    /// source-backed hardware register/aperture layout and valid for this
    /// epoch. A numeric BAR tuple or prefetchable flag alone does not
    /// check a WC exception. This cannot authorize RAM, cached firmware or
    /// system-memory ranges, nor relabel the hardware resource classification.
    /// The native platform must still prove the complete effective PTE/PAT/MTRR
    /// policy, compatible aliases, all participating roots and TLB/cache drains.
    pub unsafe fn with_device_cache_regions(
        backing: Box<dyn ResourceBacking>,
        regions: Vec<DeviceCacheRegion>,
    ) -> Result<Self, Error> {
        if regions.is_empty() {
            return Err(Error::InvalidRange);
        }
        let span = backing.physical_span();
        for (at, region) in regions.iter().enumerate() {
            if region.attribute == CacheAttribute::WriteBack {
                return Err(Error::UnsupportedCache);
            }
            if region.physical.pages()? != region.physical {
                return Err(Error::InvalidRange);
            }
            if !span.contains(region.physical) {
                return Err(Error::OutsideResource);
            }
            if regions[..at]
                .iter()
                .any(|prior| prior.physical.overlaps(region.physical))
            {
                return Err(Error::ResourceConflict);
            }
        }
        let regions = triomphe::Arc::try_new(regions).map_err(|_| Error::Unavailable)?;
        let mut resource = Self::new(backing);
        resource.cache_regions = Some(regions);
        Ok(resource)
    }
    /// Explicit device permissions, if supplied by the native owner.
    /// None keeps the conservative default for the original resource kind.
    pub fn device_cache_regions(&self) -> Option<&[DeviceCacheRegion]> {
        self.cache_regions.as_deref().map(Vec::as_slice)
    }
    fn permits_device_cache(&self, physical: PhysicalSpan, attribute: CacheAttribute) -> bool {
        if attribute == CacheAttribute::WriteBack {
            return false;
        }
        match self.device_cache_regions() {
            Some(regions) => regions
                .iter()
                .any(|region| region.attribute == attribute && region.physical.contains(physical)),
            None => {
                attribute == CacheAttribute::Uncached
                    || self.kind == ResourceKind::PrefetchableMemory
            }
        }
    }
    /// Count an accepted mapping from this original backing. Existing bounded
    /// views retain that SAME use; closed assignment denies every new map.
    pub fn begin_mapping(&self) -> Result<OpaqueUse, Error> {
        let usage = self.backing.begin_mapping()?;
        if usage.kind() != UseKind::Mapping {
            // Wrong-kind use cannot grant mapping or safe release. Its Drop
            // retains the actual original count/product for the owning source.
            return Err(Error::InvalidPlatformReply);
        }
        Ok(usage)
    }
    pub fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    pub fn kind(&self) -> ResourceKind {
        self.kind
    }
    /// The native adapter may downcast its reservation implementation;
    /// it must refuse reservations from a different owner/platform.
    pub fn backing(&self) -> &dyn Any {
        self.backing.as_ref()
    }
}

/// Imported mapping (including generic physical-map RAM aliases). The permission
/// rounds it to complete pages before comparing effective cache policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingAlias {
    pub physical: PhysicalSpan,
    /// Combined PAT/MTRR/PTE policy; None is unknown/unsupported and
    /// blocks every overlapping new mapping until acknowledged removal.
    pub attribute: Option<CacheAttribute>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protection {
    ReadOnly,
    ReadWrite,
}

/// Validated platform request. `physical` covers whole reserved pages; callers
/// only receive a bounded view of their original unaligned requested bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapRequest {
    pub id: u64,
    pub address_space: AddressSpace,
    pub physical: PhysicalSpan,
    pub attribute: CacheAttribute,
    pub protection: Protection,
}

/// A platform mapping and unique native page-table reservation token.
#[derive(Clone, Copy, Debug)]
pub struct InstalledMapping {
    pub token: u64,
    pub cpu_base: NonNull<u8>,
    pub physical: PhysicalSpan,
    pub attribute: CacheAttribute,
    pub protection: Protection,
}

/// A failed map is either proven unchanged (no live mappings/aliases/table
/// reservations remain), or uncertain and permanently quarantined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapFailure {
    Unchanged(Error),
    Uncertain(Error),
}

/// Native page-table and effective-cache adapter. No implementation is
/// supplied here; the mount owns real root publication and TLB acknowledgements.
///
/// # Safety
/// `check_context` must reject unsupported CPU/address-space and ISR contexts.
/// It is a pure admission observation: no allocation, device-register/DMA operation,
/// root/cache mutation, Linux reentry, waiting or unwinding is permitted.
/// Architectural CPU/root/control-register observations are permitted.
/// Map validates the ResourceBacking/epoch and maps the reserved
/// full span into every participating native root, writable iff requested and
/// always NX. It must prove the *effective* requested UC/WC type across
/// PAT/MTRRs, caches and all aliases over the entire span, not just set PTE
/// cache bits. A WB PTE may have effective UC policy through MTRRs; a
/// prefetchable BAR alone never authorizes WC. Explicit device-cache-region
/// permissions check device access, not the CPU mapping policy.
/// Unknown/conflicting effective policy must refuse the request, never report
/// guessed WC/UC. Returned CPU
/// addresses must be live, canonical, page-aligned and mapped to precisely the
/// given physical pages in every participating context. Tokens and virtual
/// ranges must be unique until acknowledged unmap. Concurrent calls for
/// disjoint reservations must be safe. New roots/outside mapping changes must
/// serialize with this same permission and preserve its alias inventory.
///
/// Unchanged failure may be returned only before changes, or after complete
/// rollback/TLB acknowledgement with no kept native mapping. An uncertain
/// failure keeps all partial table/virtual reservations and native root-set
/// owners; the permission keeps its resource/physical reservation permanently.
/// `unmap` success proves CPU accesses, posted writes, cache/write-combining
/// effects and all participating CPU TLBs/root changes have drained, and the
/// mapping/table/virtual reservation is removed. Failure must keep
/// every possibly live table/virtual reservation; successful retry targets the
/// same exact token. A provider's final release never invalidates a live lease.
///
/// Access through an existing mapping may run inside an interrupt handler:
/// `check_context` succeeds there on a CPU that takes part in the address
/// space, so a handler reads and writes registers through a live lease.
/// `map`, `unmap` and final drops require process or deferred context, and
/// the provider refuses `map` and `unmap` inside an interrupt handler.
pub unsafe trait MappingPlatform: Send + Sync {
    /// Whether this CPU may reach `address_space` through an existing
    /// mapping now, including from an interrupt handler.
    fn check_context(&self, address_space: AddressSpace) -> Result<(), Error>;
    /// # Safety
    /// The one active permission already atomically reserved this request's
    /// complete physical/cache span and keeps the resource owner.
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure>;
    /// # Safety
    /// The token was returned by this provider for this exact request; all
    /// consumers and callback/worker access are stopped/drained, and no new
    /// access can begin. The permission still keeps the resource reservation.
    unsafe fn unmap(&self, request: MapRequest, mapping: InstalledMapping) -> Result<(), Error>;
}
