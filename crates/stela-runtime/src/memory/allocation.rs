//! Anonymous guest data allocation.

#[cfg(host_memory)]
use super::DIRECT_RAM_USER_END;
#[cfg(host_memory)]
use super::host_protection;
#[cfg(host_memory)]
use super::storage::NativeMapping;
use super::storage::NativeStorage;
#[cfg(host_memory)]
use super::{Allocation, MemoryRegion};
use super::{MAX_FILE_MEMORY_BYTES, MAX_IMAGE_MEMORY_BYTES, OwnedMemory};
use alloc::sync::Arc;
#[cfg(not(host_memory))]
use alloc::vec::Vec;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DataPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl DataPermissions {
    fn contains(self, permissions: Self) -> bool {
        (!permissions.readable || self.readable)
            && (!permissions.writable || self.writable)
            && (!permissions.executable || self.executable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlacement {
    /// An already guest-page-normalized address, without replacement.
    Fixed(u64),
    /// Search at or above this guest-page-normalized hint; zero means no hint.
    Anywhere { hint: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DataInheritance {
    Copy,
}

/// Logical guest extent and rights, after the platform's argument normalization.
/// Unknown platform flags must be rejected by that adapter, never discarded here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocateDataRequest {
    pub placement: DataPlacement,
    pub bytes: u64,
    pub alignment_mask: u64,
    pub current: DataPermissions,
    pub maximum: DataPermissions,
    pub alias_tag: u8,
    pub inheritance: DataInheritance,
}

/// Immutable allocation metadata; `OwnedMemory` retains the mapping lifetime.
/// Current permissions are represented by its possibly split `MemoryRegion`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DataAllocation {
    pub guest_address: u64,
    pub virtual_bytes: u64,
    pub mapped_bytes: u64,
    pub maximum: DataPermissions,
    pub alias_tag: u8,
    pub inheritance: DataInheritance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationOperation {
    Map,
    Trim,
    Protect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocateDataError {
    InvalidRange,
    InvalidAlignment,
    UnsupportedAlignmentMask,
    UnsupportedPlatform,
    UnsupportedExecutable,
    UnsupportedWriteOnly,
    MaximumProtection,
    AddressUnavailable,
    AddressSpaceUnusable,
    SharedDomainBound,
    ResourceLimit,
    MetadataAllocation,
    HostFailure {
        operation: AllocationOperation,
        errno: Option<i32>,
    },
}

impl core::fmt::Display for AllocateDataError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "guest data allocation failed: {self:?}")
    }
}

impl core::error::Error for AllocateDataError {}

impl OwnedMemory {
    /// Allocate and publish data before returning. A later platform copyout
    /// failure does not roll back this successfully published allocation.
    pub fn allocate_data(
        &mut self,
        request: AllocateDataRequest,
    ) -> Result<DataAllocation, AllocateDataError> {
        self.begin_data_allocation(request)?.publish()
    }

    /// Reserve fresh private storage without exposing it through `regions` or
    /// ordinary byte APIs. The borrowed owner excludes concurrent native use.
    /// Dropping the transaction releases only its new mapping. Callers can reject
    /// overlap with immutable compiler source snapshots before publication.
    pub fn begin_data_allocation(
        &mut self,
        request: AllocateDataRequest,
    ) -> Result<PendingDataAllocation<'_>, AllocateDataError> {
        use AllocateDataError as E;
        let service = self
            .shared
            .as_ref()
            .map(|shared| shared.domain.service_loan())
            .transpose()
            .map_err(|_| E::SharedDomainBound)?
            .map(AllocationServiceLoan::Owned);
        self.begin_data_allocation_with_service(request, service)
    }

    pub(in crate::memory) fn begin_data_allocation_in_service<'a>(
        &'a mut self,
        request: AllocateDataRequest,
        service: &'a super::domain::MemoryServiceLoan,
    ) -> Result<PendingDataAllocation<'a>, AllocateDataError> {
        let shared = self
            .shared
            .as_ref()
            .ok_or(AllocateDataError::SharedDomainBound)?;
        shared
            .check()
            .map_err(|_| AllocateDataError::AddressSpaceUnusable)?;
        if !service.belongs_to(&shared.domain) {
            return Err(AllocateDataError::SharedDomainBound);
        }
        self.begin_data_allocation_with_service(
            request,
            Some(AllocationServiceLoan::Borrowed(service)),
        )
    }

    fn begin_data_allocation_with_service<'a>(
        &'a mut self,
        request: AllocateDataRequest,
        service: Option<AllocationServiceLoan<'a>>,
    ) -> Result<PendingDataAllocation<'a>, AllocateDataError> {
        use AllocateDataError as E;
        if !self.usable {
            return Err(E::AddressSpaceUnusable);
        }
        if !cfg!(all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "macos")
        )) {
            return Err(E::UnsupportedPlatform);
        }
        if request.bytes == 0 {
            return Err(E::InvalidRange);
        }
        if !request.maximum.contains(request.current) {
            return Err(E::MaximumProtection);
        }
        if request.current.executable {
            return Err(E::UnsupportedExecutable);
        }
        if request.current.writable && !request.current.readable {
            return Err(E::UnsupportedWriteOnly);
        }
        let alignment = request
            .alignment_mask
            .checked_add(1)
            .filter(|alignment| alignment.is_power_of_two())
            .ok_or(E::UnsupportedAlignmentMask)?
            .max(self.page_bytes);
        let mapped_bytes = request
            .bytes
            .checked_add(self.page_bytes - 1)
            .map(|bytes| bytes & !(self.page_bytes - 1))
            .ok_or(E::InvalidRange)?;
        let total = self
            .allocations
            .iter()
            .try_fold(mapped_bytes, |total, allocation| {
                total.checked_add(allocation.bytes)
            })
            .ok_or(E::ResourceLimit)?;
        if total > MAX_FILE_MEMORY_BYTES || alignment > MAX_FILE_MEMORY_BYTES {
            return Err(E::ResourceLimit);
        }
        self.regions
            .try_reserve(1)
            .map_err(|_| E::MetadataAllocation)?;
        self.allocations
            .try_reserve(1)
            .map_err(|_| E::MetadataAllocation)?;
        let mapping = map_anonymous(request.placement, mapped_bytes, alignment, self.page_bytes)?;
        // Create the retained owner before final protection/publication. Failure
        // or rejection drops only this unpublished native allocation.
        let storage = mapping.into_storage();
        let allocation = DataAllocation {
            guest_address: storage.primary_base().as_ptr() as usize as u64,
            virtual_bytes: request.bytes,
            mapped_bytes,
            maximum: request.maximum,
            alias_tag: request.alias_tag,
            inheritance: request.inheritance,
        };
        Ok(PendingDataAllocation {
            owner: self,
            storage: Some(storage),
            allocation,
            current: request.current,
            initialized_bytes: 0,
            service,
        })
    }

    /// Query immutable bounds/maximum rights independently of current views.
    /// Native host padding is not a logical guest allocation address.
    pub fn data_allocation_at(&self, address: u64) -> Option<DataAllocation> {
        self.allocations
            .iter()
            .find(|allocation| {
                address >= allocation.base && address - allocation.base < allocation.logical_bytes
            })
            .map(|allocation| DataAllocation {
                guest_address: allocation.base,
                virtual_bytes: allocation.logical_bytes,
                mapped_bytes: allocation.storage.bytes() as u64,
                maximum: DataPermissions {
                    readable: allocation.maximum_readable,
                    writable: allocation.maximum_writable,
                    executable: allocation.maximum_executable,
                },
                alias_tag: allocation.alias_tag,
                inheritance: allocation.inheritance,
            })
    }
}

/// An unpublished mapping borrowing the same non-Send/Sync `OwnedMemory` owner.
/// Initialization is private and serialized; it never grants host execute rights.
// The freestanding mount does not create host mappings.
#[cfg_attr(not(host_memory), allow(dead_code))]
pub struct PendingDataAllocation<'a> {
    owner: &'a mut OwnedMemory,
    storage: Option<Arc<NativeStorage>>,
    allocation: DataAllocation,
    current: DataPermissions,
    initialized_bytes: usize,
    service: Option<AllocationServiceLoan<'a>>,
}

enum AllocationServiceLoan<'a> {
    Owned(super::domain::MemoryServiceLoan),
    Borrowed(&'a super::domain::MemoryServiceLoan),
}

impl core::ops::Deref for AllocationServiceLoan<'_> {
    type Target = super::domain::MemoryServiceLoan;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(loan) => loan,
            Self::Borrowed(loan) => loan,
        }
    }
}

impl core::fmt::Debug for PendingDataAllocation<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingDataAllocation")
            .field("allocation", &self.allocation)
            .finish_non_exhaustive()
    }
}

impl PendingDataAllocation<'_> {
    pub fn allocation(&self) -> &DataAllocation {
        &self.allocation
    }

    fn extent(&self, offset: usize, bytes: usize) -> Result<(), AllocateDataError> {
        if bytes as u64 > MAX_IMAGE_MEMORY_BYTES {
            return Err(AllocateDataError::ResourceLimit);
        }
        if offset
            .checked_add(bytes)
            .is_some_and(|end| end as u64 <= self.allocation.virtual_bytes)
        {
            Ok(())
        } else {
            Err(AllocateDataError::InvalidRange)
        }
    }

    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), AllocateDataError> {
        self.extent(offset, bytes.len())?;
        // SAFETY: this transaction owns fresh RW native storage; the source is
        // independent and no API lends references into the unpublished mapping.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (self.allocation.guest_address as usize as *mut u8).add(offset),
                bytes.len(),
            );
        }
        if !bytes.is_empty() {
            self.initialized_bytes = self.initialized_bytes.max(offset + bytes.len());
        }
        Ok(())
    }

    pub fn read_snapshot(&self, offset: usize, bytes: usize) -> Result<Vec<u8>, AllocateDataError> {
        self.extent(offset, bytes)?;
        let mut snapshot = Vec::new();
        snapshot
            .try_reserve_exact(bytes)
            .map_err(|_| AllocateDataError::MetadataAllocation)?;
        snapshot.resize(bytes, 0);
        // SAFETY: the transaction's storage is live, writable and exclusively
        // owned; the snapshot is a separate buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.allocation.guest_address as usize as *const u8).add(offset),
                snapshot.as_mut_ptr(),
                bytes,
            );
        }
        Ok(snapshot)
    }

    #[cfg(host_memory)]
    pub fn publish(self) -> Result<DataAllocation, AllocateDataError> {
        self.publish_with(|base, bytes, protection| {
            // SAFETY: the transaction exclusively owns this complete mapping.
            if unsafe {
                libc::mprotect(
                    base as usize as *mut libc::c_void,
                    bytes as usize,
                    protection,
                )
            } == 0
            {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().raw_os_error())
            }
        })
    }

    #[cfg(not(host_memory))]
    pub fn publish(self) -> Result<DataAllocation, AllocateDataError> {
        Err(AllocateDataError::UnsupportedPlatform)
    }

    #[cfg(host_memory)]
    fn publish_with(
        mut self,
        protect: impl FnOnce(u64, u64, i32) -> Result<(), Option<i32>>,
    ) -> Result<DataAllocation, AllocateDataError> {
        let (shared_backing, candidate) = if let Some(service) = &self.service {
            let storage = self.storage.as_ref().expect("unpublished storage");
            let maximum = super::backing::AccessPermissions {
                readable: self.allocation.maximum.readable,
                writable: self.allocation.maximum.writable,
                executable: self.allocation.maximum.executable,
            };
            // SAFETY: new, privately initialized anonymous storage. The service
            // borrow excludes native entry until the view is published, and the
            // logical rights below limit each host access after mprotect.
            let backing = unsafe {
                super::backing::MemoryBacking::new_managed(
                    storage.primary_base(),
                    storage.bytes(),
                    maximum,
                    Arc::clone(storage),
                )
            }
            .map_err(|_| AllocateDataError::MetadataAllocation)?;
            let view = super::backing::MemoryView::new(
                Arc::clone(&backing),
                self.allocation.guest_address,
                0,
                self.allocation.virtual_bytes as usize,
                super::backing::AccessPermissions {
                    readable: self.current.readable,
                    writable: self.current.writable,
                    executable: false,
                },
            )
            .map_err(|_| AllocateDataError::MetadataAllocation)?;
            let mut views = service
                .views()
                .map_err(|_| AllocateDataError::AddressSpaceUnusable)?;
            views.push((
                view,
                self.owner
                    .shared
                    .as_ref()
                    .expect("bound pending allocation")
                    .attributes,
            ));
            let candidate = service
                .prepare(views)
                .map_err(|_| AllocateDataError::MetadataAllocation)?;
            (Some(backing), Some(candidate))
        } else {
            (None, None)
        };
        protect(
            self.allocation.guest_address,
            self.allocation.mapped_bytes,
            host_protection(self.current.readable, self.current.writable),
        )
        .map_err(|errno| AllocateDataError::HostFailure {
            operation: AllocationOperation::Protect,
            errno,
        })?;
        let region = MemoryRegion {
            guest_address: self.allocation.guest_address,
            virtual_bytes: self.allocation.virtual_bytes,
            mapped_bytes: self.allocation.mapped_bytes,
            initial_bytes: self.initialized_bytes,
            readable: self.current.readable,
            writable: self.current.writable,
            executable: false,
        };
        let storage = self
            .storage
            .take()
            .expect("unpublished storage retains ownership");
        let allocation = Allocation {
            shared_backing,
            storage,
            base: self.allocation.guest_address,
            bytes: self.allocation.mapped_bytes,
            logical_bytes: self.allocation.virtual_bytes,
            maximum_readable: self.allocation.maximum.readable,
            maximum_writable: self.allocation.maximum.writable,
            maximum_executable: self.allocation.maximum.executable,
            executable: false,
            alias_tag: self.allocation.alias_tag,
            inheritance: self.allocation.inheritance,
        };
        if let Some(candidate) = candidate {
            let service = self.service.as_ref().expect("bound candidate");
            if service.commit(candidate).is_err() {
                service.poison();
                self.owner.usable = false;
                return Err(AllocateDataError::AddressSpaceUnusable);
            }
        }
        // Both vectors reserved their insertion capacity before mmap. Publication
        // cannot allocate or fail after the final host protection succeeds.
        let allocation_index = self
            .owner
            .allocations
            .partition_point(|old| old.base < allocation.base);
        let region_index = self
            .owner
            .regions
            .partition_point(|old| old.guest_address < region.guest_address);
        self.owner.allocations.insert(allocation_index, allocation);
        self.owner.regions.insert(region_index, region);
        Ok(self.allocation)
    }
}

// Uninhabited without std: the freestanding mount creates no host mappings.
#[cfg_attr(not(host_memory), allow(dead_code))]
struct NewMapping {
    #[cfg(not(host_memory))]
    _unmounted: core::convert::Infallible,
    base: u64,
    bytes: u64,
}

impl NewMapping {
    #[cfg(host_memory)]
    fn into_storage(self) -> Arc<NativeStorage> {
        // SAFETY: native placement/trim checked this complete fresh RW extent;
        // initialization is serialized and exposes no Rust guest references.
        let mapping = unsafe {
            NativeMapping::adopt(
                core::ptr::NonNull::new(self.base as usize as *mut u8)
                    .expect("native placement rejects zero"),
                self.bytes as usize,
            )
        };
        // The single unmap obligation moved into NativeMapping above.
        core::mem::forget(self);
        NativeStorage::anonymous(mapping)
    }

    #[cfg(not(host_memory))]
    fn into_storage(self) -> Arc<NativeStorage> {
        match self._unmounted {}
    }
}

impl Drop for NewMapping {
    #[cfg(host_memory)]
    fn drop(&mut self) {
        // SAFETY: this newly created extent is still exclusively owned.
        unsafe {
            libc::munmap(self.base as usize as *mut libc::c_void, self.bytes as usize);
        }
    }
    #[cfg(not(host_memory))]
    fn drop(&mut self) {
        match self._unmounted {}
    }
}

#[cfg(host_memory)]
fn map_anonymous(
    placement: DataPlacement,
    bytes: u64,
    alignment: u64,
    page: u64,
) -> Result<NewMapping, AllocateDataError> {
    use AllocateDataError as E;
    let (hint, exact) = match placement {
        DataPlacement::Fixed(address) => {
            if !address.is_multiple_of(page) {
                return Err(E::InvalidAlignment);
            }
            if address & (alignment - 1) != 0 {
                return Err(E::AddressUnavailable);
            }
            (address, true)
        }
        DataPlacement::Anywhere { hint } => {
            let hint = hint
                .checked_add(alignment - 1)
                .map(|value| value & !(alignment - 1))
                .ok_or(E::AddressUnavailable)?;
            (hint, false)
        }
    };
    if (exact && hint < page)
        || hint
            .checked_add(bytes)
            .is_none_or(|end| end > DIRECT_RAM_USER_END)
    {
        return Err(E::AddressUnavailable);
    }
    let reserved = if exact {
        bytes
    } else {
        bytes
            .checked_add(alignment - page)
            .ok_or(E::ResourceLimit)?
    };
    let native_length = usize::try_from(reserved).map_err(|_| E::ResourceLimit)?;
    let flags = libc::MAP_ANON | libc::MAP_PRIVATE;
    #[cfg(target_os = "linux")]
    let flags = if exact {
        flags | libc::MAP_FIXED_NOREPLACE
    } else {
        flags
    };
    // SAFETY: new private allocation only. MAP_FIXED is never used; Linux's
    // NOREPLACE rejects collisions and Darwin's substituted hint is checked.
    let pointer = unsafe {
        libc::mmap(
            hint as usize as *mut libc::c_void,
            native_length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if pointer == libc::MAP_FAILED {
        let errno = std::io::Error::last_os_error().raw_os_error();
        return Err(if exact && errno == Some(libc::EEXIST) {
            E::AddressUnavailable
        } else {
            E::HostFailure {
                operation: AllocationOperation::Map,
                errno,
            }
        });
    }
    let mut mapping = NewMapping {
        base: pointer as usize as u64,
        bytes: reserved,
    };
    if exact {
        if mapping.base != hint {
            return Err(E::AddressUnavailable);
        }
        return Ok(mapping);
    }
    let base = mapping
        .base
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(E::AddressUnavailable)?;
    let end = base.checked_add(bytes).ok_or(E::AddressUnavailable)?;
    let reserved_end = mapping
        .base
        .checked_add(reserved)
        .ok_or(E::AddressUnavailable)?;
    if base < hint || base < page || end > DIRECT_RAM_USER_END || end > reserved_end {
        return Err(E::AddressUnavailable);
    }
    let prefix = base - mapping.base;
    if prefix != 0 {
        // SAFETY: release only complete prefix pages of this fresh reservation.
        if unsafe { libc::munmap(mapping.base as usize as *mut libc::c_void, prefix as usize) } != 0
        {
            return Err(E::HostFailure {
                operation: AllocationOperation::Trim,
                errno: std::io::Error::last_os_error().raw_os_error(),
            });
        }
        mapping.base = base;
        mapping.bytes -= prefix;
    }
    let suffix = reserved_end - end;
    if suffix != 0 {
        // SAFETY: release only complete suffix pages of the remaining mapping.
        if unsafe { libc::munmap(end as usize as *mut libc::c_void, suffix as usize) } != 0 {
            return Err(E::HostFailure {
                operation: AllocationOperation::Trim,
                errno: std::io::Error::last_os_error().raw_os_error(),
            });
        }
        mapping.bytes -= suffix;
    }
    Ok(mapping)
}

#[cfg(not(host_memory))]
fn map_anonymous(
    placement: DataPlacement,
    bytes: u64,
    alignment: u64,
    page: u64,
) -> Result<NewMapping, AllocateDataError> {
    let _ = (placement, bytes, alignment, page);
    Err(AllocateDataError::UnsupportedPlatform)
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;

    const GUEST_PAGE_BYTES: u64 = 16 * 1024;
    const ALLOCATION_HINT: u64 = 1 << 32;
    const ALIAS_TAG: u8 = 60;
    const ALLOCATION_ATTEMPTS: usize = 32;
    const READ_WRITE: DataPermissions = DataPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    const ALL_RIGHTS: DataPermissions = DataPermissions {
        executable: true,
        ..READ_WRITE
    };

    fn request(bytes: u64) -> AllocateDataRequest {
        AllocateDataRequest {
            placement: DataPlacement::Anywhere {
                hint: ALLOCATION_HINT,
            },
            bytes,
            alignment_mask: GUEST_PAGE_BYTES - 1,
            current: READ_WRITE,
            maximum: ALL_RIGHTS,
            alias_tag: ALIAS_TAG,
            inheritance: DataInheritance::Copy,
        }
    }

    fn empty() -> OwnedMemory {
        OwnedMemory::map(vec![]).unwrap()
    }

    fn fixed(address: u64, bytes: u64) -> AllocateDataRequest {
        AllocateDataRequest {
            placement: DataPlacement::Fixed(address),
            alignment_mask: 0,
            ..request(bytes)
        }
    }

    #[test]
    fn observed_anywhere_shape_preserves_zero_bytes_rights_tag_and_inheritance() {
        let mut memory = empty();
        let size = 8 * GUEST_PAGE_BYTES;
        let allocation = memory.allocate_data(request(size)).unwrap();
        assert!(allocation.guest_address >= ALLOCATION_HINT);
        assert_eq!(allocation.guest_address & (GUEST_PAGE_BYTES - 1), 0);
        assert_eq!(allocation.virtual_bytes, size);
        assert_eq!(allocation.mapped_bytes, size);
        assert_eq!(allocation.maximum, ALL_RIGHTS);
        assert_eq!(allocation.alias_tag, ALIAS_TAG);
        assert_eq!(allocation.inheritance, DataInheritance::Copy);
        assert_eq!(
            memory.data_allocation_at(allocation.guest_address),
            Some(allocation)
        );
        assert_eq!(
            memory.data_allocation_at(allocation.guest_address + size),
            None
        );
        assert_eq!(
            memory
                .read_snapshot(allocation.guest_address, size as usize)
                .unwrap(),
            vec![0; size as usize]
        );
        assert_eq!(
            host_rights(allocation.guest_address),
            Some(libc::PROT_READ | libc::PROT_WRITE)
        );
        memory.write(allocation.guest_address, &[7, 9]).unwrap();
        memory
            .protect_data(allocation.guest_address, size, true, false)
            .unwrap();
        assert!(memory.write(allocation.guest_address, &[3]).is_err());
        assert_eq!(
            memory.read_snapshot(allocation.guest_address, 2).unwrap(),
            [7, 9]
        );
        assert_eq!(host_rights(allocation.guest_address), Some(libc::PROT_READ));
        assert_eq!(
            memory.data_allocation_at(allocation.guest_address),
            Some(allocation)
        );
        memory
            .protect_data(allocation.guest_address, size, true, true)
            .unwrap();
        assert!(!memory.regions()[0].executable);
    }

    #[test]
    fn unpublished_initialization_applies_final_readonly_rights_on_commit() {
        let mut memory = empty();
        let mut transaction = memory
            .begin_data_allocation(AllocateDataRequest {
                current: DataPermissions {
                    writable: false,
                    ..READ_WRITE
                },
                ..request(GUEST_PAGE_BYTES)
            })
            .unwrap();
        let address = transaction.allocation().guest_address;
        transaction.write(3, &[0x21, 0x43]).unwrap();
        transaction.write(GUEST_PAGE_BYTES as usize, &[]).unwrap();
        assert_eq!(
            transaction.read_snapshot(0, 7).unwrap(),
            [0, 0, 0, 0x21, 0x43, 0, 0]
        );
        assert!(transaction.write(GUEST_PAGE_BYTES as usize, &[1]).is_err());
        assert!(transaction.read_snapshot(usize::MAX, 2).is_err());
        let allocation = transaction.publish().unwrap();
        assert_eq!(allocation.guest_address, address);
        assert_eq!(memory.regions()[0].initial_bytes, 5);
        assert_eq!(host_rights(address), Some(libc::PROT_READ));
        assert_eq!(memory.read_snapshot(address + 3, 2).unwrap(), [0x21, 0x43]);
        assert!(memory.write(address, &[1]).is_err());
    }

    #[test]
    fn dropping_unpublished_mapping_and_owner_releases_exact_native_extent() {
        for _ in 0..ALLOCATION_ATTEMPTS {
            let mut memory = empty();
            let transaction = memory
                .begin_data_allocation(request(GUEST_PAGE_BYTES))
                .unwrap();
            let allocation = *transaction.allocation();
            drop(transaction);
            assert!(memory.regions().is_empty() && memory.allocations.is_empty());
            let Ok(reused) =
                memory.allocate_data(fixed(allocation.guest_address, allocation.virtual_bytes))
            else {
                continue;
            };
            assert_eq!(reused.guest_address, allocation.guest_address);
            drop(memory);
            let mut next_owner = empty();
            if next_owner
                .allocate_data(fixed(allocation.guest_address, allocation.virtual_bytes))
                .is_ok()
            {
                return;
            }
        }
        panic!("cannot prove release without a racing host allocation");
    }

    #[test]
    fn fixed_collision_preserves_existing_source_and_all_metadata() {
        let mut memory = empty();
        let allocation = memory.allocate_data(request(GUEST_PAGE_BYTES)).unwrap();
        memory
            .write(allocation.guest_address, &[0x5a, 0xa5])
            .unwrap();
        let before = memory.regions().to_vec();
        assert_eq!(
            memory.allocate_data(fixed(allocation.guest_address, GUEST_PAGE_BYTES)),
            Err(AllocateDataError::AddressUnavailable)
        );
        assert_eq!(memory.regions(), before);
        assert_eq!(
            memory.read_snapshot(allocation.guest_address, 2).unwrap(),
            [0x5a, 0xa5]
        );
        assert_eq!(memory.allocations.len(), 1);
    }

    #[test]
    fn allocation_cannot_replace_or_unseal_an_immutable_code_source() {
        for _ in 0..ALLOCATION_ATTEMPTS {
            let mut reservation = empty();
            let reserved = reservation
                .allocate_data(request(GUEST_PAGE_BYTES))
                .unwrap();
            drop(reservation);
            let Ok(mut memory) = OwnedMemory::map(vec![super::super::MemoryRegionSpec {
                guest_address: reserved.guest_address,
                virtual_bytes: GUEST_PAGE_BYTES,
                initial_bytes: vec![0x1f, 0x20, 0x03, 0xd5],
                readable: true,
                writable: false,
                executable: true,
            }]) else {
                continue;
            };
            let before = memory.regions().to_vec();
            assert_eq!(
                memory.allocate_data(fixed(reserved.guest_address, GUEST_PAGE_BYTES)),
                Err(AllocateDataError::AddressUnavailable)
            );
            assert_eq!(memory.regions(), before);
            assert_eq!(
                memory.read_snapshot(reserved.guest_address, 4).unwrap(),
                [0x1f, 0x20, 0x03, 0xd5]
            );
            assert_eq!(
                memory.protect_data(reserved.guest_address, GUEST_PAGE_BYTES, true, true),
                Err(super::super::ProtectionError::ExecutableRegion)
            );
            let maximum = memory
                .data_allocation_at(reserved.guest_address)
                .unwrap()
                .maximum;
            assert!(maximum.executable && maximum.readable && !maximum.writable);
            assert_eq!(host_rights(reserved.guest_address), Some(libc::PROT_READ));
            return;
        }
        panic!("cannot reserve a temporary code-source address without a race");
    }

    #[test]
    fn failed_final_protection_rolls_back_new_mapping_without_changing_old_memory() {
        for _ in 0..ALLOCATION_ATTEMPTS {
            let mut memory = empty();
            let old = memory.allocate_data(request(GUEST_PAGE_BYTES)).unwrap();
            memory.write(old.guest_address, &[0x39]).unwrap();
            let before = memory.regions().to_vec();
            let transaction = memory
                .begin_data_allocation(request(2 * GUEST_PAGE_BYTES))
                .unwrap();
            let failed = *transaction.allocation();
            let page = memory_page();
            let error = transaction.publish_with(|base, _, _| {
                // Change one owned page, then simulate a partial host failure.
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            base as usize as *mut libc::c_void,
                            page as usize,
                            libc::PROT_READ,
                        )
                    },
                    0
                );
                Err(Some(libc::ENOMEM))
            });
            assert_eq!(
                error,
                Err(AllocateDataError::HostFailure {
                    operation: AllocationOperation::Protect,
                    errno: Some(libc::ENOMEM)
                })
            );
            assert_eq!(memory.regions(), before);
            assert!(memory.is_usable());
            assert_eq!(memory.read_snapshot(old.guest_address, 1).unwrap(), [0x39]);
            if memory
                .allocate_data(fixed(failed.guest_address, failed.virtual_bytes))
                .is_ok()
            {
                return;
            }
        }
        panic!("cannot prove protection-failure rollback without a racing allocation");
    }

    fn memory_page() -> u64 {
        super::super::host_page_size().unwrap() as u64
    }

    #[test]
    fn invalid_ranges_masks_and_unsupported_rights_decline_before_mapping() {
        let mut memory = empty();
        let page = memory_page();
        let cases = [
            (request(0), AllocateDataError::InvalidRange),
            (request(u64::MAX), AllocateDataError::InvalidRange),
            (
                request(MAX_FILE_MEMORY_BYTES + page),
                AllocateDataError::ResourceLimit,
            ),
            (
                AllocateDataRequest {
                    alignment_mask: 5,
                    ..request(page)
                },
                AllocateDataError::UnsupportedAlignmentMask,
            ),
            (
                AllocateDataRequest {
                    alignment_mask: u64::MAX,
                    ..request(page)
                },
                AllocateDataError::UnsupportedAlignmentMask,
            ),
            (
                AllocateDataRequest {
                    current: ALL_RIGHTS,
                    ..request(page)
                },
                AllocateDataError::UnsupportedExecutable,
            ),
            (
                AllocateDataRequest {
                    current: DataPermissions {
                        readable: false,
                        ..READ_WRITE
                    },
                    ..request(page)
                },
                AllocateDataError::UnsupportedWriteOnly,
            ),
            (
                AllocateDataRequest {
                    maximum: DataPermissions {
                        writable: false,
                        ..ALL_RIGHTS
                    },
                    ..request(page)
                },
                AllocateDataError::MaximumProtection,
            ),
            (fixed(page + 1, page), AllocateDataError::InvalidAlignment),
            (fixed(0, page), AllocateDataError::AddressUnavailable),
            (
                AllocateDataRequest {
                    placement: DataPlacement::Fixed(page),
                    alignment_mask: 2 * page - 1,
                    ..request(page)
                },
                AllocateDataError::AddressUnavailable,
            ),
            (
                AllocateDataRequest {
                    placement: DataPlacement::Anywhere {
                        hint: DIRECT_RAM_USER_END,
                    },
                    ..request(page)
                },
                AllocateDataError::AddressUnavailable,
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(memory.allocate_data(request), Err(expected));
            assert!(memory.regions().is_empty() && memory.allocations.is_empty());
        }
    }

    #[test]
    fn exact_logical_extent_excludes_padding_and_sorted_ownership_survives_new_views() {
        let mut memory = empty();
        let allocation = memory.allocate_data(request(3)).unwrap();
        assert_eq!(allocation.virtual_bytes, 3);
        assert_eq!(allocation.mapped_bytes, memory_page());
        assert_eq!(
            memory.data_allocation_at(allocation.guest_address + 3),
            None
        );
        assert!(
            memory
                .read_snapshot(allocation.guest_address + 3, 1)
                .is_err()
        );
        let next = memory.allocate_data(request(GUEST_PAGE_BYTES)).unwrap();
        assert!(
            memory
                .allocations
                .windows(2)
                .all(|pair| pair[0].base < pair[1].base)
        );
        assert!(
            memory
                .regions()
                .windows(2)
                .all(|pair| pair[0].guest_address < pair[1].guest_address)
        );
        memory
            .protect_data(next.guest_address, GUEST_PAGE_BYTES, false, false)
            .unwrap();
        assert_eq!(host_rights(next.guest_address), Some(libc::PROT_NONE));
        assert!(memory.read_snapshot(next.guest_address, 1).is_err());
        assert_eq!(
            memory.read_snapshot(allocation.guest_address, 3).unwrap(),
            [0, 0, 0]
        );
    }

    #[test]
    fn maximum_rights_are_exact_and_cannot_be_raised_by_later_protection() {
        let mut memory = empty();
        let readonly = DataPermissions {
            writable: false,
            executable: false,
            ..READ_WRITE
        };
        let allocation = memory
            .allocate_data(AllocateDataRequest {
                current: readonly,
                maximum: readonly,
                ..request(GUEST_PAGE_BYTES)
            })
            .unwrap();
        assert_eq!(
            memory.protect_data(allocation.guest_address, GUEST_PAGE_BYTES, true, true),
            Err(super::super::ProtectionError::MaximumProtection)
        );
        assert_eq!(host_rights(allocation.guest_address), Some(libc::PROT_READ));
        assert_eq!(
            memory
                .data_allocation_at(allocation.guest_address)
                .unwrap()
                .maximum,
            readonly
        );
    }

    #[cfg(target_os = "linux")]
    fn host_rights(address: u64) -> Option<i32> {
        for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
            let mut fields = line.split_whitespace();
            let (begin, end) = fields.next().unwrap().split_once('-').unwrap();
            if !(u64::from_str_radix(begin, 16).unwrap()..u64::from_str_radix(end, 16).unwrap())
                .contains(&address)
            {
                continue;
            }
            let permissions = fields.next().unwrap().as_bytes();
            return Some(
                (if permissions[0] == b'r' {
                    libc::PROT_READ
                } else {
                    0
                }) | (if permissions[1] == b'w' {
                    libc::PROT_WRITE
                } else {
                    0
                }) | (if permissions[2] == b'x' {
                    libc::PROT_EXEC
                } else {
                    0
                }),
            );
        }
        None
    }

    #[cfg(target_os = "macos")]
    fn host_rights(address: u64) -> Option<i32> {
        const VM_REGION_BASIC_INFO_64: i32 = 9;
        const VM_REGION_BASIC_INFO_WORDS: usize = 9;
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn mach_vm_region(
                task: libc::mach_port_t,
                address: *mut u64,
                size: *mut u64,
                flavor: i32,
                info: *mut i32,
                count: *mut u32,
                object: *mut libc::mach_port_t,
            ) -> i32;
            fn mach_port_deallocate(task: u32, name: u32) -> i32;
        }
        let mut found = address;
        let mut size = 0;
        let mut info = [0i32; VM_REGION_BASIC_INFO_WORDS];
        let mut count = info.len() as u32;
        let mut object = 0;
        // SAFETY: all outputs are correctly sized writable native query storage.
        let status = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut found,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if object != 0 {
            // SAFETY: release only the object-name right returned by this query.
            unsafe {
                mach_port_deallocate(mach_task_self_, object);
            }
        }
        if status == 0 && found <= address && address - found < size {
            Some(info[0])
        } else {
            None
        }
    }
}
