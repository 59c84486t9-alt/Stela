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
mod tests {
    //! Service exclusion over materialized storage.
    use super::*;
    use crate::memory::{
        domain::physical::PhysicalAddressSpace,
        source_ram::{
            MaterializedSourceRam, OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration,
            SourceRamPermissions, SourceRamSystemConfig, materialize_source_ram,
        },
    };
    use stela_compiler::TargetCpu;

    const ADDRESS_SPACE: u64 = 391;
    const SOURCE_PA: u64 = 0x100000;
    const DATA_PA: u64 = 0x200000;
    const DATA_BYTES: usize = 16;
    const NOP: u32 = 0xd503_201f;
    const PUBLISHED: [u8; 8] = 0x0123_4567_89ab_cdef_u64.to_le_bytes();

    fn materialized() -> MaterializedSourceRam {
        materialize_source_ram(
            SourceRamDeclaration {
                address_space: ADDRESS_SPACE,
                target: TargetCpu::Baseline,
                declared_capacity: vec![PhysicalRamRange {
                    source_pa: SOURCE_PA,
                    bytes: DATA_PA + DATA_BYTES as u64 - SOURCE_PA,
                }],
                initialized: vec![
                    OwnedRamExtent {
                        source_pa: SOURCE_PA,
                        bytes: NOP.to_le_bytes().to_vec(),
                        permissions: SourceRamPermissions {
                            readable: true,
                            writable: false,
                            executable: true,
                        },
                    },
                    OwnedRamExtent {
                        source_pa: DATA_PA,
                        bytes: vec![0; DATA_BYTES],
                        permissions: SourceRamPermissions {
                            readable: true,
                            writable: true,
                            executable: false,
                        },
                    },
                ],
            },
            SourceRamSystemConfig {
                reservation_granule_bytes: 16,
                reservation_stripe_count: 8,
            },
        )
        .unwrap()
    }

    #[test]
    fn source_ram_publisher_excludes_outer_and_releases_service() {
        fn assert_send<T: Send>() {}
        assert_send::<SourceRamPublisher>();
        let mut materialized = materialized();
        let mut publisher = materialized.publisher(DATA_PA, DATA_BYTES).unwrap();
        let (binding, _immutable) = materialized.into_parts();
        let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
        let outer = physical.initial_source_execution_loan().unwrap();
        assert!(matches!(
            publisher.try_publish(0, &PUBLISHED),
            Ok(SourceRamPublication::ExecutionBusy)
        ));
        let blocked = publisher.publish(0, &PUBLISHED).unwrap_err();
        assert_eq!(blocked.status, MemoryStatus::Domain);
        assert_eq!(blocked.completed, 0);
        drop(outer);
        // Only the service writer moves to the other thread; the physical source,
        // domain and MemoryThread stay here.
        let worker = std::thread::spawn(move || publisher.publish(0, &PUBLISHED));
        worker.join().unwrap().unwrap();
        let resumed = physical.initial_source_execution_loan().unwrap();
        physical.check_execution_loan(&resumed).unwrap();
        drop(resumed);
        let observation = physical.domain().service_loan().unwrap();
        assert_eq!(observation.snapshot(DATA_PA, 8).unwrap(), PUBLISHED);
        assert_eq!(observation.snapshot(DATA_PA + 8, 8).unwrap(), [0; 8]);
    }

    #[test]
    fn publisher_requires_writable_extent_and_preflights_entire_range() {
        let mut materialized = materialized();
        assert!(matches!(
            materialized.publisher(SOURCE_PA, size_of::<u32>()),
            Err(MemoryStatus::Permission)
        ));
        assert!(matches!(
            materialized.publisher(DATA_PA + DATA_BYTES as u64, 1),
            Err(MemoryStatus::Translation)
        ));
        let mut publisher = materialized.publisher(DATA_PA, DATA_BYTES).unwrap();
        let blocked = publisher.publish(DATA_BYTES - 1, &PUBLISHED).unwrap_err();
        assert_eq!(blocked.status, MemoryStatus::Translation);
        assert_eq!(blocked.completed, 0);
        let (binding, _immutable) = materialized.into_parts();
        let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
        let observation = physical.domain().service_loan().unwrap();
        assert_eq!(
            observation.snapshot(DATA_PA, DATA_BYTES).unwrap(),
            [0; DATA_BYTES]
        );
    }

    #[test]
    fn service_busy_is_distinct_from_a_poisoned_domain() {
        use crate::memory::domain::ExecutionLoanAttempt;
        let materialized = materialized();
        let (binding, _immutable) = materialized.into_parts();
        let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
        let service = physical.domain().service_loan().unwrap();
        assert!(matches!(
            physical.domain().try_execution_loan(),
            Ok(ExecutionLoanAttempt::ServiceBusy)
        ));
        assert!(matches!(
            physical.domain().execution_loan(),
            Err(MemoryStatus::Domain)
        ));
        assert!(matches!(
            physical.domain().try_service_loan(),
            Ok(ServiceLoanAttempt::ServiceBusy)
        ));
        service.poison();
        assert!(matches!(
            physical.domain().try_service_loan(),
            Err(MemoryStatus::Domain)
        ));
        assert!(matches!(
            physical.domain().try_execution_loan(),
            Err(MemoryStatus::Domain)
        ));
        drop(service);
        assert!(matches!(
            physical.domain().try_execution_loan(),
            Err(MemoryStatus::Domain)
        ));
    }
}
