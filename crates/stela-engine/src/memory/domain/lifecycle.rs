//! Mapping publication and exclusion of native calls within a domain.
use super::*;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub(in crate::memory) struct DomainSnapshot {
    pub(super) views: Vec<RegisteredView>,
    pub(super) profile: MemoryProfile,
    pub(super) generation: u64,
}
pub(super) struct DomainState {
    pub(super) snapshot: DomainSnapshot,
    pub(super) native_loans: usize,
    pub(super) servicing: bool,
}

/// Across native execution, finalization and source PC settlement.
/// It owns the domain, without borrowing a policy or exposing guest storage.
pub struct MemoryExecutionLoan {
    domain: Arc<MemoryDomain>,
}
/// Result of a non-blocking execution-loan request.
pub enum ExecutionLoanAttempt {
    Acquired(MemoryExecutionLoan),
    ServiceBusy,
}

impl MemoryExecutionLoan {
    /// Whether this mapping-exclusion pin belongs to `domain`.
    pub(crate) fn belongs_to(&self, domain: &Arc<MemoryDomain>) -> bool {
        Arc::ptr_eq(&self.domain, domain)
    }
    /// Check membership in the thread's domain (not thread or PE identity).
    /// Equal address-space numbers do not prove membership.
    pub fn check_thread_domain<P: DataPolicy>(
        &self,
        thread: &MemoryThread<P>,
    ) -> Result<(), MemoryStatus> {
        self.check_domain(&thread.domain)
    }

    /// Check the physical memory system without exposing it.
    pub fn check_memory_system(&self, system: &Arc<MemorySystem>) -> Result<(), MemoryStatus> {
        if !Arc::ptr_eq(&self.domain.system, system) {
            return Err(MemoryStatus::Domain);
        }
        self.check_domain(&self.domain)
    }

    pub(super) fn check_domain(&self, domain: &Arc<MemoryDomain>) -> Result<(), MemoryStatus> {
        if !Arc::ptr_eq(&self.domain, domain) {
            return Err(MemoryStatus::Domain);
        }
        // This borrow excludes every service borrow, so only a domain failure
        // can make it unusable.
        self.domain.check_execution()
    }
}

impl Drop for MemoryExecutionLoan {
    fn drop(&mut self) {
        match self.domain.state.lock() {
            Ok(mut state) => state.native_loans -= 1,
            Err(_) => self.domain.system.failed.store(true, Ordering::Release),
        }
    }
}

pub(in crate::memory) struct MemoryServiceLoan {
    domain: Arc<MemoryDomain>,
}
/// Result of a non-blocking service-loan request.
pub(in crate::memory) enum ServiceLoanAttempt {
    Acquired(MemoryServiceLoan),
    ExecutionBusy,
    ServiceBusy,
}
/// Read-only observations of the executing thread's domain.
pub struct MemoryObservationLoan {
    service: MemoryServiceLoan,
}
impl MemoryObservationLoan {
    pub fn snapshot(&self, address: u64, bytes: usize) -> Result<Vec<u8>, MemoryStatus> {
        self.service.snapshot(address, bytes)
    }
}

impl Drop for MemoryServiceLoan {
    fn drop(&mut self) {
        match self.domain.state.lock() {
            Ok(mut state) => state.servicing = false,
            Err(_) => self.domain.system.failed.store(true, Ordering::Release),
        }
    }
}

impl MemoryDomain {
    pub(super) fn observation_loan(
        self: &Arc<Self>,
    ) -> Result<MemoryObservationLoan, MemoryStatus> {
        Ok(MemoryObservationLoan {
            service: self.service_loan()?,
        })
    }

    /// The current mapping generation.
    pub fn generation(&self) -> Result<u64, MemoryStatus> {
        self.check_execution()?;
        Ok(self.generation.load(Ordering::Acquire))
    }

    pub fn execution_loan(self: &Arc<Self>) -> Result<MemoryExecutionLoan, MemoryStatus> {
        match self.try_execution_loan()? {
            ExecutionLoanAttempt::Acquired(loan) => Ok(loan),
            ExecutionLoanAttempt::ServiceBusy => Err(MemoryStatus::Domain),
        }
    }

    /// Like `execution_loan`, but report a busy host service without waiting.
    /// Only `ServiceBusy` may be retried; errors remain failures.
    pub fn try_execution_loan(self: &Arc<Self>) -> Result<ExecutionLoanAttempt, MemoryStatus> {
        self.check_execution()?;
        let mut state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()?;
        if state.servicing {
            return Ok(ExecutionLoanAttempt::ServiceBusy);
        }
        state.native_loans = state
            .native_loans
            .checked_add(1)
            .ok_or(MemoryStatus::Domain)?;
        Ok(ExecutionLoanAttempt::Acquired(MemoryExecutionLoan {
            domain: Arc::clone(self),
        }))
    }

    pub(in crate::memory) fn service_loan(
        self: &Arc<Self>,
    ) -> Result<MemoryServiceLoan, MemoryStatus> {
        match self.try_service_loan()? {
            ServiceLoanAttempt::Acquired(loan) => Ok(loan),
            ServiceLoanAttempt::ExecutionBusy | ServiceLoanAttempt::ServiceBusy => {
                Err(MemoryStatus::Domain)
            }
        }
    }

    pub(in crate::memory) fn try_service_loan(
        self: &Arc<Self>,
    ) -> Result<ServiceLoanAttempt, MemoryStatus> {
        self.check_execution()?;
        let mut state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()?;
        if state.servicing {
            return Ok(ServiceLoanAttempt::ServiceBusy);
        }
        if state.native_loans != 0 {
            return Ok(ServiceLoanAttempt::ExecutionBusy);
        }
        state.servicing = true;
        Ok(ServiceLoanAttempt::Acquired(MemoryServiceLoan {
            domain: Arc::clone(self),
        }))
    }
}

impl MemoryServiceLoan {
    pub(in crate::memory) fn belongs_to(&self, domain: &Arc<MemoryDomain>) -> bool {
        Arc::ptr_eq(&self.domain, domain)
    }

    pub(in crate::memory) fn views(
        &self,
    ) -> Result<Vec<(Arc<MemoryView>, MappingAttributes)>, MemoryStatus> {
        let state = self.domain.state.lock().map_err(|_| MemoryStatus::Domain)?;
        Ok(state
            .snapshot
            .views
            .iter()
            .map(|registered| {
                (
                    Arc::clone(&registered.view),
                    *registered.monitor.attributes(),
                )
            })
            .collect())
    }

    /// Prepare every fallible view/profile/monitor operation before host effects.
    #[cfg(host_memory)]
    pub(in crate::memory) fn prepare(
        &self,
        mut views: Vec<(Arc<MemoryView>, MappingAttributes)>,
    ) -> Result<DomainSnapshot, MemoryStatus> {
        views.sort_unstable_by_key(|(view, _)| view.guest_base());
        if views
            .windows(2)
            .any(|pair| pair[0].0.guest_base() + pair[0].0.bytes() as u64 > pair[1].0.guest_base())
        {
            return Err(MemoryStatus::InvalidRequest);
        }
        let generation = self
            .domain
            .generation()?
            .checked_add(1)
            .ok_or(MemoryStatus::Domain)?;
        let profile = MemoryProfile::inspect(&views);
        let views = views
            .into_iter()
            .map(|(view, attributes)| {
                Ok(RegisteredView {
                    monitor: self.domain.system.register_view(&view, attributes)?,
                    view,
                })
            })
            .collect::<Result<_, MemoryStatus>>()?;
        Ok(DomainSnapshot {
            views,
            profile,
            generation,
        })
    }

    #[cfg(host_memory)]
    pub(in crate::memory) fn retire(&self, views: &[Arc<MemoryView>]) -> Result<(), MemoryStatus> {
        for view in views {
            self.domain.retire_view(view)?;
        }
        Ok(())
    }

    #[cfg(host_memory)]
    pub(in crate::memory) fn commit(&self, snapshot: DomainSnapshot) -> Result<(), MemoryStatus> {
        let mut state = self.domain.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.domain.check_execution()?;
        self.domain
            .generation
            .store(snapshot.generation, Ordering::Release);
        state.snapshot = snapshot;
        Ok(())
    }

    pub(in crate::memory) fn poison(&self) {
        self.domain.system.failed.store(true, Ordering::Release);
    }

    /// Copy current logical readable views without architectural memory effects.
    pub(in crate::memory) fn snapshot(
        &self,
        address: u64,
        bytes: usize,
    ) -> Result<Vec<u8>, MemoryStatus> {
        self.domain.check_execution()?;
        address
            .checked_add(bytes as u64)
            .ok_or(MemoryStatus::Translation)?;
        if bytes as u64 > crate::memory::MAX_IMAGE_MEMORY_BYTES {
            return Err(MemoryStatus::InvalidRequest);
        }
        let views = self.views()?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(bytes)
            .map_err(|_| MemoryStatus::Domain)?;
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
                .ok_or(MemoryStatus::Translation)?;
            let reached =
                (bytes - completed).min(view.bytes() - (current - view.guest_base()) as usize);
            let access = view
                .resolve(current, reached, AccessKind::Read)
                .map_err(|error| match error {
                    super::super::backing::AccessError::PermissionDenied(_) => {
                        MemoryStatus::Permission
                    }
                    _ => MemoryStatus::Translation,
                })?;
            // SAFETY: the service borrow excludes native calls and mapping
            // changes, the current view pins rights and storage, and the result
            // goes to separate staging.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    access.host_ptr().as_ptr(),
                    result.as_mut_ptr().add(completed),
                    reached,
                )
            };
            completed += reached;
        }
        Ok(result)
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;

    #[test]
    fn retained_execution_membership_requires_same_domain_system_and_health() {
        use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
        let system = MemorySystem::new(16, 8).unwrap();
        let domain = MemoryDomain::new_for_address_space(
            7,
            Arc::clone(&system),
            Vec::new(),
            TargetCpu::Baseline,
        )
        .unwrap();
        let other_domain = MemoryDomain::new_for_address_space(
            7,
            Arc::clone(&system),
            Vec::new(),
            TargetCpu::Baseline,
        )
        .unwrap();
        let policy = MemoryControls::new(
            LowerAddressProfile::new(44, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let thread = domain.thread(policy);
        let same_domain_thread = domain.thread(policy);
        let other_thread = other_domain.thread(policy);
        let other_system = MemorySystem::new(16, 8).unwrap();
        let execution = thread.execution_loan().unwrap();
        assert_eq!(execution.check_thread_domain(&thread), Ok(()));
        assert_eq!(execution.check_thread_domain(&same_domain_thread), Ok(()));
        assert_eq!(execution.check_memory_system(&system), Ok(()));
        assert_eq!(
            execution.check_thread_domain(&other_thread),
            Err(MemoryStatus::Domain)
        );
        assert_eq!(
            execution.check_memory_system(&other_system),
            Err(MemoryStatus::Domain)
        );
        assert_eq!(domain.state.lock().unwrap().native_loans, 1);
        assert!(thread.observation_loan().is_err());
        // A kept identity does not bypass a published failure, and checking
        // does not change the invocation count.
        system.failed.store(true, Ordering::Release);
        assert_eq!(
            execution.check_thread_domain(&thread),
            Err(MemoryStatus::Domain)
        );
        assert_eq!(
            execution.check_memory_system(&system),
            Err(MemoryStatus::Domain)
        );
        assert_eq!(domain.state.lock().unwrap().native_loans, 1);
        drop(execution);
        assert_eq!(domain.state.lock().unwrap().native_loans, 0);
    }

    #[test]
    fn exhausted_generation_rejects_retirement_without_revoking_view_or_reservation() {
        use crate::memory::binding::tests::{config, native, owned};
        use crate::system::{
            process_memory::{
                FixedProcessMemoryControls, ProcessMemoryFeatures, SourceNormalWbDomain,
            },
            profile::BaseSpeAbsence,
        };
        const SOURCE_MMU_CACHE_ENABLED: u64 = 1 | (1 << 2);
        const SOURCE_LSE2: u64 = 1 << 32;
        const SOURCE_LOWER_BITS: u8 = 47;
        let (mut owner, base) = owned();
        let system = MemorySystem::new(16, 8).unwrap();
        // SAFETY: the test owns the anonymous storage and every source and writer
        // of this untagged, shareable write-back address space.
        let domain =
            unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 99), &mut []) }.unwrap();
        domain.generation.store(u64::MAX, Ordering::Release);
        domain.state.lock().unwrap().snapshot.generation = u64::MAX;
        let view = domain.registered_views()[0].clone();
        let backing = Arc::clone(view.view.backing());
        let access = monitor::Access::new(
            Arc::clone(&backing),
            Arc::clone(&view.monitor),
            0,
            8,
            monitor::Shape::Scalar,
        )
        .unwrap();
        let mut reservation = system.reservations.thread();
        system
            .reservations
            .load(&mut reservation, &access, || {
                Ok::<_, ()>(native(&backing, 0, 8))
            })
            .unwrap();
        // SAFETY: the same source map throughout, with no native call running.
        let before =
            unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(&domain)) }.unwrap();
        let features = ProcessMemoryFeatures::from_id_registers(
            0,
            SOURCE_LSE2,
            0,
            0,
            BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
        )
        .unwrap();
        // SAFETY: the same source declaration, captured again for the fixed-control
        // owner.
        let source =
            unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(&domain)) }.unwrap();
        let mut controls = FixedProcessMemoryControls::new(
            features,
            SOURCE_MMU_CACHE_ENABLED,
            u64::from(64 - SOURCE_LOWER_BITS),
            SOURCE_LOWER_BITS,
            source,
        )
        .unwrap();
        assert_eq!(domain.retire(&view.view), Err(MemoryStatus::Domain));
        assert_eq!(domain.generation().unwrap(), u64::MAX);
        assert!(view.view.is_current());
        controls.renew_source_resolved(before).unwrap();
        assert_eq!(owner.read_snapshot(base, 8).unwrap(), [0; 8]);
        assert_eq!(
            system
                .reservations
                .store(&mut reservation, &access, || Ok::<_, ()>(()))
                .unwrap(),
            monitor::ConditionalWrite::Stored(())
        );
    }

    #[test]
    fn actual_thread_observation_pins_views_and_preserves_reservation_without_writers() {
        use crate::memory::binding::tests::{config, native, owned, published};
        use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
        let (mut owner, base) = owned();
        let mut publisher = published();
        let published_base = publisher.region().guest_address;
        let system = MemorySystem::new(16, 8).unwrap();
        // SAFETY: owned anonymous RAM and publisher aliases, serialized through
        // this domain and all its physical writers.
        let domain = unsafe {
            owner.bind_shared_memory(config(Arc::clone(&system), 7), &mut [&mut publisher])
        }
        .unwrap();
        let view = domain
            .registered_views()
            .into_iter()
            .find(|view| view.view.guest_base() == base)
            .unwrap();
        let backing = Arc::clone(view.view.backing());
        let access = monitor::Access::new(
            Arc::clone(&backing),
            Arc::clone(&view.monitor),
            0,
            8,
            monitor::Shape::Scalar,
        )
        .unwrap();
        let mut reservation = system.reservations.thread();
        system
            .reservations
            .load(&mut reservation, &access, || {
                Ok::<_, ()>(native(&backing, 0, 8))
            })
            .unwrap();
        let thread = domain.thread(MemoryControls::new(
            LowerAddressProfile::new(47, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ));
        let execution = thread.execution_loan().unwrap();
        assert!(thread.observation_loan().is_err());
        drop(execution);
        let observation = thread.observation_loan().unwrap();
        assert_eq!(observation.snapshot(base, 8).unwrap(), [0; 8]);
        assert_eq!(observation.snapshot(published_base, 32).unwrap(), [7; 32]);
        assert_eq!(
            observation.snapshot(base, crate::memory::MAX_IMAGE_MEMORY_BYTES as usize + 1),
            Err(MemoryStatus::InvalidRequest)
        );
        assert!(owner.write(base, &[9]).is_err());
        assert!(publisher.publish(0, &[9]).is_err());
        assert!(thread.execution_loan().is_err());
        drop(observation);
        assert_eq!(
            system
                .reservations
                .store(&mut reservation, &access, || Ok::<_, ()>(()))
                .unwrap(),
            monitor::ConditionalWrite::Stored(())
        );
        assert_eq!(domain.generation().unwrap(), 0);
        owner.write(base, &[9]).unwrap();
        assert_eq!(owner.read_snapshot(base, 1).unwrap(), [9]);
    }
}
