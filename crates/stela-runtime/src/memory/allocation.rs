//! Serialized anonymous data allocation within the existing private owner.
//!
//! Platform adapters normalize guest pages and parse guest flags. This leaf
//! owns native placement, unpublished initialization and atomic metadata commit.

use super::storage::{NativeMapping, NativeStorage};
use super::{
    Allocation, DIRECT_RAM_USER_END, MAX_FILE_MEMORY_BYTES, MAX_IMAGE_MEMORY_BYTES, MemoryRegion,
    OwnedMemory, host_protection,
};
use serde::Serialize;
use std::sync::Arc;

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

impl std::fmt::Display for AllocateDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "guest data allocation failed: {self:?}")
    }
}

impl std::error::Error for AllocateDataError {}

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
        if self.shared.is_some() {
            return Err(E::SharedDomainBound);
        }
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
pub struct PendingDataAllocation<'a> {
    owner: &'a mut OwnedMemory,
    storage: Option<Arc<NativeStorage>>,
    allocation: DataAllocation,
    current: DataPermissions,
    initialized_bytes: usize,
}

impl std::fmt::Debug for PendingDataAllocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            std::ptr::copy_nonoverlapping(
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
        // SAFETY: the transaction's raw storage is live RW and exclusively owned;
        // snapshot is independent, without any guest-memory Rust references.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (self.allocation.guest_address as usize as *const u8).add(offset),
                snapshot.as_mut_ptr(),
                bytes,
            );
        }
        Ok(snapshot)
    }

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

    fn publish_with(
        mut self,
        protect: impl FnOnce(u64, u64, i32) -> Result<(), Option<i32>>,
    ) -> Result<DataAllocation, AllocateDataError> {
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
            shared_backing: None,
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

struct NewMapping {
    base: u64,
    bytes: u64,
}

impl NewMapping {
    fn into_storage(self) -> Arc<NativeStorage> {
        // SAFETY: native placement/trim checked this complete fresh RW extent;
        // initialization is serialized and exposes no Rust guest references.
        let mapping = unsafe {
            NativeMapping::adopt(
                std::ptr::NonNull::new(self.base as usize as *mut u8)
                    .expect("native placement rejects zero"),
                self.bytes as usize,
            )
        };
        // The single unmap obligation moved into NativeMapping above.
        std::mem::forget(self);
        NativeStorage::anonymous(mapping)
    }
}

impl Drop for NewMapping {
    fn drop(&mut self) {
        // SAFETY: this exact newly created extent remains exclusively owned.
        unsafe {
            libc::munmap(self.base as usize as *mut libc::c_void, self.bytes as usize);
        }
    }
}

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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "allocation/tests.rs"]
mod tests;
