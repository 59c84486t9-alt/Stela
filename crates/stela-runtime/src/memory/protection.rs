//! Changing the protection of owned guest data pages.
use super::OwnedMemory;
#[cfg(feature = "std")]
use super::{MemoryRegion, domain};

/// Maximum data rights supplied by the address-space loader. Omitted entries
/// default to initial rights; executable snapshots are never mutable here.
#[derive(Debug, Clone, Copy)]
pub struct DataProtectionLimit {
    pub guest_address: u64,
    pub readable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionError {
    InvalidRange,
    #[cfg(not(feature = "std"))]
    PlatformUnavailable,
    UnmappedRange,
    MaximumProtection,
    ExecutableRegion,
    WriteWithoutRead,
    AddressSpaceUnusable,
    SharedDomainBound,
    AllocationFailure,
    HostFailure {
        errno: Option<i32>,
        rollback_succeeded: bool,
    },
}
impl core::fmt::Display for ProtectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "guest data protection failed: {self:?}")
    }
}
impl core::error::Error for ProtectionError {}

impl OwnedMemory {
    /// Change the protection of owned data pages; host execute permission is
    /// never granted. Address and length must be multiples of the host page
    /// size; allocation padding may be protected but stays outside the
    /// byte-access bounds. Source snapshots would need invalidation and are
    /// refused. The caller excludes concurrent translated execution.
    #[cfg(feature = "std")]
    pub fn protect_data(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
    ) -> core::result::Result<(), ProtectionError> {
        self.protect_data_with(
            address,
            bytes,
            readable,
            writable,
            |base, length, protection| {
                // SAFETY: preflight proves exclusive ownership of every covered page.
                let result = unsafe {
                    libc::mprotect(
                        base as usize as *mut libc::c_void,
                        length as usize,
                        protection,
                    )
                };
                if result == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error().raw_os_error())
                }
            },
        )
    }

    #[cfg(not(feature = "std"))]
    pub fn protect_data(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
    ) -> core::result::Result<(), ProtectionError> {
        let _ = (address, bytes, readable, writable);
        Err(ProtectionError::PlatformUnavailable)
    }

    #[cfg(feature = "std")]
    pub(super) fn protect_data_with(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
        protect: impl FnMut(u64, u64, i32) -> core::result::Result<(), Option<i32>>,
    ) -> core::result::Result<(), ProtectionError> {
        self.protect_data_with_service(address, bytes, readable, writable, None, protect)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "std")]
    pub(super) fn protect_data_with_service(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
        service: Option<&domain::MemoryServiceLoan>,
        mut protect: impl FnMut(u64, u64, i32) -> core::result::Result<(), Option<i32>>,
    ) -> core::result::Result<(), ProtectionError> {
        use ProtectionError as E;
        if let Some(loan) = service {
            let shared = self.shared.as_ref().ok_or(E::SharedDomainBound)?;
            shared.check().map_err(|_| E::AddressSpaceUnusable)?;
            if !loan.belongs_to(&shared.domain) {
                return Err(E::SharedDomainBound);
            }
        }
        if !self.usable {
            return Err(E::AddressSpaceUnusable);
        }
        if writable && !readable {
            return Err(E::WriteWithoutRead);
        }
        let end = address.checked_add(bytes).ok_or(E::InvalidRange)?;
        if bytes == 0
            || !address.is_multiple_of(self.page_bytes)
            || !bytes.is_multiple_of(self.page_bytes)
        {
            return Err(E::InvalidRange);
        }
        let mut cursor = address;
        for allocation in &self.allocations {
            let limit = allocation.base + allocation.bytes;
            if limit <= cursor {
                continue;
            }
            if allocation.base > cursor {
                return Err(E::UnmappedRange);
            }
            if allocation.executable {
                return Err(E::ExecutableRegion);
            }
            if (readable && !allocation.maximum_readable)
                || (writable && !allocation.maximum_writable)
            {
                return Err(E::MaximumProtection);
            }
            cursor = limit.min(end);
            if cursor == end {
                break;
            }
        }
        if cursor != end {
            return Err(E::UnmappedRange);
        }
        // Allocate the complete replacement metadata/rollback recipe before
        // changing OS rights. No fallible allocation follows successful protect.
        let mut next = Vec::new();
        next.try_reserve(self.regions.len().saturating_mul(3))
            .map_err(|_| E::AllocationFailure)?;
        let mut rollback = Vec::new();
        rollback
            .try_reserve(self.regions.len())
            .map_err(|_| E::AllocationFailure)?;
        for region in &self.regions {
            let physical_end = region.guest_address + region.mapped_bytes;
            let begin = region.guest_address.max(address);
            let stop = physical_end.min(end);
            if begin >= stop {
                next.push(region.clone());
                continue;
            }
            rollback.push((
                begin,
                stop - begin,
                host_protection(region.readable, region.writable),
            ));
            for (base, limit, r, w) in [
                (
                    region.guest_address,
                    begin,
                    region.readable,
                    region.writable,
                ),
                (begin, stop, readable, writable),
                (stop, physical_end, region.readable, region.writable),
            ] {
                if base >= limit {
                    continue;
                }
                let virtual_end = region.end().min(limit);
                if base >= virtual_end {
                    continue;
                }
                let initialized_end = region.guest_address + region.initial_bytes as u64;
                next.push(MemoryRegion {
                    guest_address: base,
                    virtual_bytes: virtual_end - base,
                    mapped_bytes: limit - base,
                    initial_bytes: initialized_end.saturating_sub(base).min(virtual_end - base)
                        as usize,
                    readable: r,
                    writable: w,
                    executable: region.executable,
                });
            }
        }
        if self.shared.is_some() {
            return self.protect_shared(
                address, bytes, readable, writable, next, rollback, service, protect,
            );
        }
        if let Err(errno) = protect(address, bytes, host_protection(readable, writable)) {
            // Some host kernels can partially change a failed range. Restore
            // every covered old view, including the failed call's own pages.
            let mut restored = true;
            for (base, length, rights) in rollback {
                if protect(base, length, rights).is_err() {
                    restored = false;
                }
            }
            if !restored {
                self.usable = false;
            }
            return Err(E::HostFailure {
                errno,
                rollback_succeeded: restored,
            });
        }
        self.regions = next;
        Ok(())
    }
}

#[cfg(feature = "std")]
pub(super) fn host_protection(readable: bool, writable: bool) -> i32 {
    (if readable {
        libc::PROT_READ
    } else {
        libc::PROT_NONE
    }) | (if writable { libc::PROT_WRITE } else { 0 })
}
