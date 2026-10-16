//! Serialized mapping publication and native-invocation exclusion in one domain.
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

/// Retained across native execution, finalization and source PC settlement.
/// It owns the domain, without borrowing a policy or exposing guest storage.
pub struct MemoryExecutionLoan {
    domain: Arc<MemoryDomain>,
}
impl MemoryExecutionLoan {
    /// Domain identity of this actual live mapping-exclusion pin, not PE or
    /// thread identity, source-attribute authority or a copied epoch permit.
    pub(crate) fn belongs_to(&self, domain: &Arc<MemoryDomain>) -> bool {
        Arc::ptr_eq(&self.domain, domain)
    }
    /// Check membership in the supplied thread's actual domain, not Thread/PE
    /// identity. A loan retains a domain and counted invocation, not its acquirer.
    /// Equal address-space numbers or a shared machine do not prove membership.
    pub fn check_thread_domain<P: DataPolicy>(
        &self,
        thread: &MemoryThread<P>,
    ) -> Result<(), MemoryStatus> {
        self.check_domain(&thread.domain)
    }

    /// Check the actual physical coherence owner without exposing it or
    /// minting another invocation, source witness or mapping capability.
    pub fn check_memory_system(&self, system: &Arc<MemorySystem>) -> Result<(), MemoryStatus> {
        if !Arc::ptr_eq(&self.domain.system, system) {
            return Err(MemoryStatus::Domain);
        }
        self.check_domain(&self.domain)
    }

    /// Borrow the actual machine's order serializer through this retained loan.
    /// This is only lock/lifetime exclusion, not CPU, PA, Thread or PE authority.
    pub(super) fn device_ram_order(
        &self,
    ) -> Result<crate::platform::sync::MutexGuard<'_, ()>, MemoryStatus> {
        self.check_domain(&self.domain)?;
        let order = self
            .domain
            .system
            .device_ram_order
            .try_lock()
            .map_err(|_| MemoryStatus::Domain)?;
        self.check_domain(&self.domain)?;
        Ok(order)
    }

    pub(super) fn check_domain(&self, domain: &Arc<MemoryDomain>) -> Result<(), MemoryStatus> {
        if !Arc::ptr_eq(&self.domain, domain) {
            return Err(MemoryStatus::Domain);
        }
        let state = self.domain.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.domain.check_execution()?;
        if state.servicing || state.native_loans == 0 {
            return Err(MemoryStatus::Domain);
        }
        Ok(())
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
/// Read-only observations from the actual executing thread's canonical domain.
/// This non-Clone loan exposes no writer, epoch mutation or authority constructor.
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

    /// Current mapping generation. This number is not source authority by itself.
    pub fn generation(&self) -> Result<u64, MemoryStatus> {
        let state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()?;
        Ok(state.snapshot.generation)
    }

    pub fn execution_loan(self: &Arc<Self>) -> Result<MemoryExecutionLoan, MemoryStatus> {
        self.check_execution()?;
        let mut state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()?;
        if state.servicing {
            return Err(MemoryStatus::Domain);
        }
        state.native_loans = state
            .native_loans
            .checked_add(1)
            .ok_or(MemoryStatus::Domain)?;
        Ok(MemoryExecutionLoan {
            domain: Arc::clone(self),
        })
    }

    pub(in crate::memory) fn service_loan(
        self: &Arc<Self>,
    ) -> Result<MemoryServiceLoan, MemoryStatus> {
        self.check_execution()?;
        let mut state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()?;
        if state.servicing || state.native_loans != 0 {
            return Err(MemoryStatus::Domain);
        }
        state.servicing = true;
        Ok(MemoryServiceLoan {
            domain: Arc::clone(self),
        })
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
    #[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
    pub(in crate::memory) fn retire(&self, views: &[Arc<MemoryView>]) -> Result<(), MemoryStatus> {
        for view in views {
            self.domain.retire_view(view)?;
        }
        Ok(())
    }

    #[cfg(feature = "std")]
    pub(in crate::memory) fn commit(&self, snapshot: DomainSnapshot) -> Result<(), MemoryStatus> {
        let mut state = self.domain.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.domain.check_execution()?;
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
            // SAFETY: the actual service loan excludes every native invocation and
            // mapping change. Current canonical view pins rights/storage; result
            // is independent staging and no guest references are created.
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
        // A retained identity is not a health bypass after the actual owner
        // publishes failure; checking does not change the invocation count.
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
    fn retained_execution_order_serializes_same_machine_across_domains() {
        let system = MemorySystem::new(16, 8).unwrap();
        let first =
            MemoryDomain::new(Arc::clone(&system), Vec::new(), TargetCpu::Baseline).unwrap();
        let second =
            MemoryDomain::new(Arc::clone(&system), Vec::new(), TargetCpu::Baseline).unwrap();
        let first_execution = first.execution_loan().unwrap();
        let second_execution = second.execution_loan().unwrap();
        let first_order = first_execution.device_ram_order().unwrap();
        assert!(matches!(
            second_execution.device_ram_order(),
            Err(MemoryStatus::Domain)
        ));
        assert!(first.observation_loan().is_err());
        drop(first_order);
        let second_order = second_execution.device_ram_order().unwrap();
        assert!(matches!(
            first_execution.device_ram_order(),
            Err(MemoryStatus::Domain)
        ));
        drop(second_order);
        system.failed.store(true, Ordering::Release);
        assert!(matches!(
            first_execution.device_ram_order(),
            Err(MemoryStatus::Domain)
        ));
        assert_eq!(first.state.lock().unwrap().native_loans, 1);
        assert_eq!(second.state.lock().unwrap().native_loans, 1);
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
        // SAFETY: fixture owns actual anonymous storage and every source/writer
        // in this fresh untagged/shareable Normal-WB software address space.
        let domain =
            unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 99), &mut []) }.unwrap();
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
        // SAFETY: this fixture's explicit complete current source map is the
        // same fresh software machine throughout; no native invocation runs.
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
        // SAFETY: same complete source declaration, independently captured for
        // the immutable fixed-control owner; no epoch number grants authority.
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
        // SAFETY: actual owned anonymous RAM and publisher aliases, serialized
        // through this single domain and all its existing physical writers.
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
