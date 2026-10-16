//! Raw observations of source RAM for tests.

use super::{PhysicalAddressSpace, PhysicalReadPlatformError};
use crate::memory::{MAX_IMAGE_MEMORY_BYTES, backing::AccessKind, domain::MemoryServiceLoan};
use stela_compiler::context::memory::MemoryStatus;

impl PhysicalAddressSpace {
    /// Let source-owner tests observe quiescent bytes. Refused while execution
    /// or a service is active.
    pub(crate) fn source_diagnostic_snapshot_quiescent(
        &self,
        address: u64,
        bytes: usize,
    ) -> Result<Vec<u8>, PhysicalReadPlatformError> {
        let service = self
            .domain
            .service_loan()
            .map_err(PhysicalReadPlatformError::Domain)?;
        self.source_diagnostic_snapshot(&service, address, bytes)
    }

    /// Read bytes for diagnostics under the domain's service exclusion. This is
    /// not a guest fetch, and execute-only views keep denying guest reads. The
    /// source-RAM factory mapped these bytes host-readable, never
    /// host-executable or MMIO.
    pub(in crate::memory) fn source_diagnostic_snapshot(
        &self,
        service: &MemoryServiceLoan,
        address: u64,
        bytes: usize,
    ) -> Result<Vec<u8>, PhysicalReadPlatformError> {
        if !service.belongs_to(&self.domain) {
            return Err(PhysicalReadPlatformError::Domain(MemoryStatus::Domain));
        }
        self.check_source_binding()?;
        let length = u64::try_from(bytes)
            .map_err(|_| PhysicalReadPlatformError::Domain(MemoryStatus::InvalidRequest))?;
        if length > MAX_IMAGE_MEMORY_BYTES || address.checked_add(length).is_none() {
            return Err(PhysicalReadPlatformError::Domain(
                MemoryStatus::InvalidRequest,
            ));
        }
        let views = service.views().map_err(PhysicalReadPlatformError::Domain)?;
        if views
            .iter()
            .any(|(view, _)| !self.binding.owns_view(view) || !view.is_current())
        {
            return Err(PhysicalReadPlatformError::Unavailable);
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(bytes)
            .map_err(|_| PhysicalReadPlatformError::Domain(MemoryStatus::Domain))?;
        result.resize(bytes, 0);
        let mut completed = 0;
        while completed < bytes {
            let current = address + completed as u64;
            let view = views
                .iter()
                .find(|(view, _)| {
                    current >= view.guest_base()
                        && current - view.guest_base() < view.bytes() as u64
                })
                .map(|(view, _)| view)
                .ok_or(PhysicalReadPlatformError::Unavailable)?;
            let within = usize::try_from(current - view.guest_base())
                .map_err(|_| PhysicalReadPlatformError::Unavailable)?;
            let reached = (bytes - completed).min(view.bytes() - within);
            let permissions = view.permissions();
            let kind = if permissions.readable {
                AccessKind::Read
            } else if permissions.executable {
                // Only source-factory execute views come here; resolving one
                // neither executes nor grants guest read.
                AccessKind::Execute
            } else {
                return Err(PhysicalReadPlatformError::Unavailable);
            };
            let access = view
                .resolve(current, reached, kind)
                .map_err(|_| PhysicalReadPlatformError::Unavailable)?;
            // SAFETY: the source binding owns this view and its host-readable
            // backing, the service borrow excludes native calls and other
            // writers during the copy, and the destination is a new Vec.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    access.host_ptr().as_ptr(),
                    result.as_mut_ptr().add(completed),
                    reached,
                );
            }
            completed += reached;
        }
        self.check_source_binding()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
