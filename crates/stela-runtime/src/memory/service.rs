//! A serialized guest service over the actual owner, executing thread and domain.
//! This borrow carries no CPU bank, source authority or execution admission.

use super::{
    AllocateDataError, AllocateDataRequest, DataAllocation, MemoryRegion, OwnedMemory,
    PendingDataAllocation, ProtectionError, SharedBindingError,
    domain::{DataPolicy, MemoryServiceLoan, MemoryThread},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_compiler::context::memory::MemoryStatus;

/// Holds the original canonical service guard and the actual mutable resources.
/// Drop this borrow before source renewal and native execution requalification.
/// Whole-request writes are a component operation: callers retain responsibility
/// for source-defined copy store order and fault-prefix semantics.
pub struct GuestServiceMemory<'a, P: DataPolicy> {
    owner: &'a mut OwnedMemory,
    service: MemoryServiceLoan,
    _thread: &'a mut MemoryThread<P>,
}

impl OwnedMemory {
    /// Borrow only this owner's actual executing thread and original domain.
    /// An outstanding native execution loan rejects service admission. Equal
    /// numeric address-space identifiers cannot substitute for domain identity.
    pub fn service_memory<'a, P: DataPolicy>(
        &'a mut self,
        thread: &'a mut MemoryThread<P>,
    ) -> Result<GuestServiceMemory<'a, P>, MemoryStatus> {
        self.check_execution_thread(thread)?;
        if !self.usable {
            return Err(MemoryStatus::Domain);
        }
        let service = self
            .shared
            .as_ref()
            .ok_or(MemoryStatus::Unsupported)?
            .domain
            .service_loan()?;
        Ok(GuestServiceMemory {
            owner: self,
            service,
            _thread: thread,
        })
    }
}

impl<P: DataPolicy> GuestServiceMemory<'_, P> {
    fn check(&self) -> Result<(), MemoryStatus> {
        if !self.owner.is_usable() {
            return Err(MemoryStatus::Domain);
        }
        let shared = self
            .owner
            .shared
            .as_ref()
            .ok_or(MemoryStatus::Unsupported)?;
        shared.check()?;
        if !self.service.belongs_to(&shared.domain) {
            return Err(MemoryStatus::Domain);
        }
        Ok(())
    }

    /// Copy current readable logical bytes into independent owned staging.
    /// Domain aliases owned by another facade are not admitted by this facade.
    pub fn read_snapshot(&self, address: u64, bytes: usize) -> anyhow::Result<Vec<u8>> {
        self.check().map_err(SharedBindingError::Domain)?;
        self.owner.validate_access(address, bytes, false)?;
        Ok(self
            .service
            .snapshot(address, bytes)
            .map_err(SharedBindingError::Domain)?)
    }

    /// Check logical write bounds without changing bytes or reservations.
    pub fn validate_write(&self, address: u64, bytes: usize) -> anyhow::Result<()> {
        self.check().map_err(SharedBindingError::Domain)?;
        self.owner.validate_write(address, bytes)
    }

    /// Publish a validated whole request through the original backing monitor.
    /// PublicationFault preserves the actual completed prefix on domain failure.
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> anyhow::Result<()> {
        self.owner
            .write_shared_in_service(&self.service, address, bytes)
    }

    /// Stage a fresh anonymous allocation under this same original guard.
    /// The returned transaction borrows this wrapper until publication or drop.
    pub fn begin_data_allocation(
        &mut self,
        request: AllocateDataRequest,
    ) -> Result<PendingDataAllocation<'_>, AllocateDataError> {
        self.check()
            .map_err(|_| AllocateDataError::AddressSpaceUnusable)?;
        self.owner
            .begin_data_allocation_in_service(request, &self.service)
    }

    /// Protect only actual owned data, preserving the original transaction's
    /// view retirement, host rollback and quarantine semantics.
    #[cfg(feature = "std")]
    pub fn protect_data(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
    ) -> Result<(), ProtectionError> {
        self.check()
            .map_err(|_| ProtectionError::AddressSpaceUnusable)?;
        self.owner.protect_data_with_service(
            address,
            bytes,
            readable,
            writable,
            Some(&self.service),
            |base, length, protection| {
                // SAFETY: original owned transaction preflights all pages;
                // this same service guard excludes every native invocation.
                if unsafe {
                    libc::mprotect(
                        base as usize as *mut libc::c_void,
                        length as usize,
                        protection,
                    )
                } == 0
                {
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
    ) -> Result<(), ProtectionError> {
        let _ = (address, bytes, readable, writable);
        Err(ProtectionError::PlatformUnavailable)
    }

    /// Current logical view metadata, carrying no guest references or authority.
    pub fn regions(&self) -> &[MemoryRegion] {
        self.owner.regions()
    }

    /// Original allocation metadata; this does not establish current rights.
    pub fn data_allocation_at(&self, address: u64) -> Option<DataAllocation> {
        self.owner.data_allocation_at(address)
    }

    /// Whether the actual memory owner remains usable after service effects.
    pub fn is_usable(&self) -> bool {
        self.check().is_ok()
    }

    /// Preserve an indeterminate publication as a terminal domain failure.
    /// This does not settle registers, retire a PC or admit reentry.
    pub fn poison(&mut self) {
        self.service.poison();
        self.owner.usable = false;
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;
