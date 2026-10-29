//! Transactions that pause a domain for a service.
use super::*;
use crate::memory::{MemoryRegion, ProtectionError, host_protection, protection::ProtectionChange};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

impl OwnedMemory {
    fn replacement_views(
        &self,
        regions: &[MemoryRegion],
    ) -> Result<Vec<(Arc<MemoryView>, MappingAttributes)>, SharedBindingError> {
        let shared = self.shared.as_ref().expect("bound lifecycle");
        let mut views = Vec::with_capacity(regions.len());
        for region in regions {
            let allocation = self
                .allocations
                .iter()
                .find(|allocation| {
                    region.guest_address >= allocation.base
                        && region.guest_address - allocation.base < allocation.logical_bytes
                })
                .ok_or(SharedBindingError::Bounds)?;
            let view = MemoryView::new(
                Arc::clone(
                    allocation
                        .shared_backing
                        .as_ref()
                        .expect("canonical allocation"),
                ),
                region.guest_address,
                usize::try_from(region.guest_address - allocation.base)
                    .map_err(|_| SharedBindingError::Bounds)?,
                usize::try_from(region.virtual_bytes).map_err(|_| SharedBindingError::Bounds)?,
                AccessPermissions {
                    readable: region.readable,
                    writable: region.writable,
                    executable: region.executable,
                },
            )
            .map_err(SharedBindingError::Backing)?;
            views.push((view, shared.attributes));
        }
        Ok(views)
    }

    pub(in crate::memory) fn protect_shared(
        &mut self,
        change: ProtectionChange,
        next: Vec<MemoryRegion>,
        rollback: Vec<(u64, u64, i32)>,
        service: Option<&super::super::domain::MemoryServiceLoan>,
        mut protect: impl FnMut(u64, u64, i32) -> Result<(), Option<i32>>,
    ) -> Result<(), ProtectionError> {
        let ProtectionChange {
            address,
            bytes,
            readable,
            writable,
        } = change;
        use ProtectionError as E;
        let shared = self.shared.as_ref().expect("bound lifecycle");
        shared.check().map_err(|_| E::AddressSpaceUnusable)?;
        let acquired;
        let loan = if let Some(service) = service {
            if !service.belongs_to(&shared.domain) {
                return Err(E::SharedDomainBound);
            }
            service
        } else {
            acquired = shared
                .domain
                .service_loan()
                .map_err(|_| E::SharedDomainBound)?;
            &acquired
        };
        let old = loan.views().map_err(|_| E::AddressSpaceUnusable)?;
        let end = address + bytes;
        let affected = |view: &MemoryView| {
            view.guest_base() < end && address < view.guest_base() + view.bytes() as u64
        };
        // Preserve every other facade and untouched logical mapping identity.
        let mut next_views: Vec<_> = old
            .iter()
            .filter(|(view, _)| !affected(view))
            .cloned()
            .collect();
        let changed_regions: Vec<_> = next
            .iter()
            .filter(|region| {
                self.regions.iter().any(|old_region| {
                    old_region.guest_address < end
                        && address < old_region.guest_address + old_region.mapped_bytes
                        && region.guest_address >= old_region.guest_address
                        && region.guest_address < old_region.guest_address + old_region.mapped_bytes
                })
            })
            .cloned()
            .collect();
        next_views.extend(
            self.replacement_views(&changed_regions)
                .map_err(|_| E::AllocationFailure)?,
        );
        let changed: Vec<_> = old
            .iter()
            .filter(|(view, _)| affected(view))
            .map(|(view, _)| Arc::clone(view))
            .collect();
        let mut rollback_views: Vec<_> = old
            .iter()
            .filter(|(view, _)| !affected(view))
            .cloned()
            .collect();
        let old_regions: Vec<_> = self
            .regions
            .iter()
            .filter(|region| {
                region.guest_address < end && address < region.guest_address + region.mapped_bytes
            })
            .cloned()
            .collect();
        rollback_views.extend(
            self.replacement_views(&old_regions)
                .map_err(|_| E::AllocationFailure)?,
        );
        let candidate = loan.prepare(next_views).map_err(|_| E::AllocationFailure)?;
        let restored = loan
            .prepare(rollback_views)
            .map_err(|_| E::AllocationFailure)?;
        // Revoking rights invalidates every reservation on each affected view;
        // new generations are required even if a host rollback restores the old
        // rights.
        if loan.retire(&changed).is_err() {
            loan.poison();
            self.usable = false;
            return Err(E::AddressSpaceUnusable);
        }
        if let Err(errno) = protect(address, bytes, host_protection(readable, writable)) {
            let mut rollback_succeeded = true;
            for (base, length, rights) in rollback {
                if protect(base, length, rights).is_err() {
                    rollback_succeeded = false;
                }
            }
            if rollback_succeeded {
                rollback_succeeded = loan.commit(restored).is_ok();
            }
            if !rollback_succeeded {
                loan.poison();
                self.usable = false;
            }
            return Err(E::HostFailure {
                errno,
                rollback_succeeded,
            });
        }
        if loan.commit(candidate).is_err() {
            loan.poison();
            self.usable = false;
            return Err(E::AddressSpaceUnusable);
        }
        self.regions = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
