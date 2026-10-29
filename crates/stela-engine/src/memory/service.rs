//! A guest service's access to the memory owner, thread and domain.

#[cfg(host_memory)]
use super::protection::ProtectionChange;
use super::{
    AllocateDataError, AllocateDataRequest, DataAllocation, MemoryRegion, OwnedMemory,
    PendingDataAllocation, ProtectionError, SharedBindingError,
    domain::{DataPolicy, MemoryServiceLoan, MemoryThread},
};
#[cfg(not(host_memory))]
use alloc::vec::Vec;
use stela_compiler::context::memory::MemoryStatus;

/// Holds the service guard and the mutable resources; drop it before source
/// renewal and native re-entry. Whole-request writes do not order stores as the
/// source instruction would, so callers handle store order and fault prefixes.
pub struct GuestServiceMemory<'a, P: DataPolicy> {
    owner: &'a mut OwnedMemory,
    service: MemoryServiceLoan,
    _thread: &'a mut MemoryThread<P>,
}

impl OwnedMemory {
    /// Borrow this owner's executing thread and domain. Refused while a native
    /// execution borrow is outstanding; equal address-space numbers do not
    /// stand in for domain identity.
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

    /// Copy the current readable bytes into owned staging. Aliases owned by
    /// another facade are refused.
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

    /// Publish a validated request through the backing's monitor. On a domain
    /// failure, PublicationFault keeps the completed prefix.
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> anyhow::Result<()> {
        self.owner
            .write_shared_in_service(&self.service, address, bytes)
    }

    /// Stage a new anonymous allocation under this guard; the transaction
    /// borrows the wrapper until it is published or dropped.
    pub fn begin_data_allocation(
        &mut self,
        request: AllocateDataRequest,
    ) -> Result<PendingDataAllocation<'_>, AllocateDataError> {
        self.check()
            .map_err(|_| AllocateDataError::AddressSpaceUnusable)?;
        self.owner
            .begin_data_allocation_in_service(request, &self.service)
    }

    /// Protect owned data only, with the transaction's view retirement, host
    /// rollback and quarantine.
    #[cfg(host_memory)]
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
            ProtectionChange {
                address,
                bytes,
                readable,
                writable,
            },
            Some(&self.service),
            |base, length, protection| {
                // SAFETY: the transaction validated every page, and the service
                // guard excludes native calls.
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

    #[cfg(not(host_memory))]
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

    /// The current view metadata.
    pub fn regions(&self) -> &[MemoryRegion] {
        self.owner.regions()
    }

    /// Original allocation metadata; this does not establish current rights.
    pub fn data_allocation_at(&self, address: u64) -> Option<DataAllocation> {
        self.owner.data_allocation_at(address)
    }

    /// Whether the memory owner is still usable after service effects.
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
mod tests {
    use crate::memory::{
        binding::tests::{config, owned},
        domain::MemorySystem,
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    };

    #[test]
    fn actual_guard_poison_invalidates_health_and_preflight_without_owner_flag() {
        let (mut owner, base) = owned();
        // SAFETY: new anonymous storage with every software writer.
        let domain = unsafe {
            owner.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 76), &mut [])
        }
        .unwrap();
        let mut thread = domain.thread(MemoryControls::new(
            LowerAddressProfile::new(47, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ));
        {
            let mut service = owner.service_memory(&mut thread).unwrap();
            assert!(service.is_usable());
            service.service.poison();
            assert!(service.owner.is_usable());
            assert!(!service.is_usable());
            assert!(service.validate_write(base, 1).is_err());
            assert!(service.validate_write(base, 0).is_err());
            assert!(service.read_snapshot(base, 1).is_err());
            assert!(service.write(base, &[1]).is_err());
        }
        assert!(owner.is_usable());
        assert!(domain.execution_loan().is_err());
        assert!(owner.service_memory(&mut thread).is_err());
    }
}
