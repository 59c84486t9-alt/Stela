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
        // This outstanding loan excludes every service loan, so only domain
        // failure can make it unusable.
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
        self.check_execution()?;
        Ok(self.generation.load(Ordering::Acquire))
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
mod tests;
