//! Host-service writes to one materialized writable RAM extent.
use super::{MemoryDomain, MemorySystem, MemoryView, SourcePhysicalRamBinding};
use crate::memory::{
    backing::{AccessError, AccessKind},
    domain::{PublicationFault, ServiceLoanAttempt},
};
use alloc::sync::Arc;
use stela_compiler::context::memory::MemoryStatus;

/// Keeps the native storage and physical domain alive and exposes neither a
/// pointer nor a MemoryThread. The machine must register every host
/// producer it hands one to before sealing its producer set.
pub(crate) struct SourceRamPublisher {
    domain: Arc<MemoryDomain>,
    system: Arc<MemorySystem>,
    view: Arc<MemoryView>,
    generation: u64,
    source_pa: u64,
    bytes: usize,
}

#[cfg(test)]
impl super::MaterializedSourceRam {
    pub(crate) fn publisher(
        &mut self,
        source_pa: u64,
        bytes: usize,
    ) -> Result<SourceRamPublisher, MemoryStatus> {
        self.binding.publisher(source_pa, bytes)
    }
}

impl SourcePhysicalRamBinding {
    /// Create a writer before the binding moves into its PE. Only initialized,
    /// writable, non-executable RAM qualifies.
    pub(in crate::memory) fn publisher(
        &mut self,
        source_pa: u64,
        bytes: usize,
    ) -> Result<SourceRamPublisher, MemoryStatus> {
        let end = source_pa
            .checked_add(u64::try_from(bytes).map_err(|_| MemoryStatus::Translation)?)
            .filter(|_| bytes != 0)
            .ok_or(MemoryStatus::Translation)?;
        let view = self
            .views
            .iter()
            .find(|view| {
                view.guest_base() <= source_pa
                    && view
                        .guest_base()
                        .checked_add(view.bytes() as u64)
                        .is_some_and(|view_end| end <= view_end)
            })
            .ok_or(MemoryStatus::Translation)?;
        let permissions = view.permissions();
        if !permissions.readable || !permissions.writable || permissions.executable {
            return Err(MemoryStatus::Permission);
        }
        if !self.current_views() || self.domain.generation()? != self.generation {
            return Err(MemoryStatus::Domain);
        }
        Ok(SourceRamPublisher {
            domain: Arc::clone(&self.domain),
            system: Arc::clone(&self.system),
            view: Arc::clone(view),
            generation: self.generation,
            source_pa,
            bytes,
        })
    }
}

/// Publication status; a busy result grants nothing.
pub(crate) enum SourceRamPublication {
    Published,
    ExecutionBusy,
    ServiceBusy,
}

impl SourceRamPublisher {
    /// Copy `bytes` into RAM through the physical writer. The service loan
    /// excludes native execution and mapping changes, so an outstanding PE
    /// loan makes this fail. The loan is released before returning, so the
    /// caller can then assert its device IRQ. This is a host copy, not guest
    /// DMA completion or exception delivery; host faults still need their own
    /// adapter.
    pub(crate) fn publish(&mut self, offset: usize, bytes: &[u8]) -> Result<(), PublicationFault> {
        match self.try_publish(offset, bytes)? {
            SourceRamPublication::Published => Ok(()),
            SourceRamPublication::ExecutionBusy | SourceRamPublication::ServiceBusy => {
                Err(PublicationFault {
                    status: MemoryStatus::Domain,
                    completed: 0,
                })
            }
        }
    }

    /// Like `publish` but without failing on contention, which is checked
    /// under the domain lock. Permission, currency, poison and partial
    /// failures are errors.
    pub(crate) fn try_publish(
        &mut self,
        offset: usize,
        bytes: &[u8],
    ) -> Result<SourceRamPublication, PublicationFault> {
        let fault = |status| PublicationFault {
            status,
            completed: 0,
        };
        if bytes.is_empty()
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > self.bytes)
        {
            return Err(fault(MemoryStatus::Translation));
        }
        let source_pa = self
            .source_pa
            .checked_add(u64::try_from(offset).map_err(|_| fault(MemoryStatus::Translation))?)
            .ok_or_else(|| fault(MemoryStatus::Translation))?;
        let service = match self.domain.try_service_loan().map_err(fault)? {
            ServiceLoanAttempt::Acquired(service) => service,
            ServiceLoanAttempt::ExecutionBusy => return Ok(SourceRamPublication::ExecutionBusy),
            ServiceLoanAttempt::ServiceBusy => return Ok(SourceRamPublication::ServiceBusy),
        };
        service
            .check_registered_view(&self.view, self.generation)
            .map_err(fault)?;
        let reached = self
            .view
            .resolve(source_pa, bytes.len(), AccessKind::Write)
            .map_err(|error| {
                fault(match error {
                    AccessError::PermissionDenied(_) => MemoryStatus::Permission,
                    AccessError::RetiredMapping => MemoryStatus::Domain,
                    _ => MemoryStatus::Translation,
                })
            })?;
        // SAFETY: the factory kept this initialized native allocation with RW
        // host and guest rights, fixed placement and no safe RAM aliases. The
        // service pins its generation, excludes native execution and mapping
        // changes, and serializes every physical writer. Callers can supply only
        // private staging, not a RAM slice.
        unsafe {
            self.system
                .publish(self.view.backing(), reached.backing_offset(), bytes)?;
        }
        Ok(SourceRamPublication::Published)
    }
}

#[cfg(test)]
mod tests;
