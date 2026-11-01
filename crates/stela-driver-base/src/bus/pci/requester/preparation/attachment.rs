//! Unique attachment control and receipts from its actual native backend.
use super::{AttachmentBackend, ConfigRetention, DetachError, DmaDomain, DmaError};
use crate::bus::{
    irq::{RetiredRoute, RouteId, posted_msi::MsiRoute},
    pci::requester::RequesterId,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{marker::PhantomData, mem::ManuallyDrop};
#[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
extern crate std;
enum Retention {
    Native(ConfigRetention),
    #[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
    SynchronousModel(std::thread::ThreadId),
}
impl Retention {
    fn check(&self) -> Result<(), DmaError> {
        match self {
            Self::Native(retained) => retained.check_live().map_err(|_| DmaError::MappingFailed),
            #[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
            Self::SynchronousModel(thread) if *thread == std::thread::current().id() => Ok(()),
            #[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
            Self::SynchronousModel(_) => Err(DmaError::MappingFailed),
        }
    }
}

/// Acknowledged detach of this exact requester and registered route, if any.
/// It carries no configuration writer, mapping pin or replacement permission.
pub struct DetachedRequester {
    requester: RequesterId,
    routes: Vec<RouteId>,
    local: PhantomData<*mut ()>,
}
impl DetachedRequester {
    pub fn requester(&self) -> &RequesterId {
        &self.requester
    }
    pub(crate) fn matches_route(&self, route: &RouteId) -> bool {
        self.routes.iter().any(|own| own.same(route))
    }
}
pub struct RetainActionFailure {
    pub error: crate::bus::irq::IrqError,
    pub retired: RetiredRoute,
}
pub struct PinReleaseFailure {
    pub error: crate::bus::irq::IrqError,
    pub detached: DetachedRequester,
}
pub struct CancelFailure {
    pub error: DmaError,
    pub grant: MsiRoute,
}
/// The original native backend, with one generic IRQ-publication/detach owner.
/// Original Root::bind creates its backend; only this wrapper mints receipts.
pub struct Attachment {
    backend: ManuallyDrop<Option<Box<dyn AttachmentBackend>>>,
    retention: ManuallyDrop<Option<Retention>>,
    domain: ManuallyDrop<Arc<dyn DmaDomain>>,
    requester: RequesterId,
    retired: ManuallyDrop<Vec<RetiredRoute>>,
    detached: bool,
    poisoned: bool,
    local: PhantomData<*mut ()>,
}
impl Attachment {
    /// # Safety
    /// backend is the unique attached control produced for this exact original
    /// configuration/root/reset epoch. Its real methods and Drop obey the
    /// AttachmentBackend contract. retained was checked in actual original
    /// process context after binding; it introduces no second config writer.
    pub unsafe fn new(backend: Box<dyn AttachmentBackend>, retained: ConfigRetention) -> Self {
        // Keep affine inputs before the external domain callback can unwind.
        let backend = ManuallyDrop::new(Some(backend));
        let retention = ManuallyDrop::new(Some(Retention::Native(retained)));
        let domain = backend.as_ref().expect("new attachment backend").domain();
        Self {
            backend,
            retention,
            domain: ManuallyDrop::new(domain),
            requester: RequesterId::new(),
            retired: ManuallyDrop::new(Vec::new()),
            detached: false,
            poisoned: false,
            local: PhantomData,
        }
    }
    /// Construct only the original isolated RAM attachment peer.
    ///
    /// # Safety
    /// backend owns actual fixture translation/lease/stop state, performs its
    /// real modeled detach and contains no native root/configuration resource.
    /// This current-thread scope is not a native process or device grant.
    #[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
    pub unsafe fn bounded_fixture(backend: Box<dyn AttachmentBackend>) -> Self {
        let backend = ManuallyDrop::new(Some(backend));
        let domain = backend.as_ref().expect("model attachment backend").domain();
        Self {
            backend,
            retention: ManuallyDrop::new(Some(Retention::SynchronousModel(
                std::thread::current().id(),
            ))),
            domain: ManuallyDrop::new(domain),
            requester: RequesterId::new(),
            retired: ManuallyDrop::new(Vec::new()),
            detached: false,
            poisoned: false,
            local: PhantomData,
        }
    }
    fn check(&self) -> Result<(), DmaError> {
        if self.detached || self.poisoned {
            return Err(DmaError::Unmapped);
        }
        self.retention.as_ref().ok_or(DmaError::Unmapped)?.check()
    }
    /// Compare actual original configuration allocation/epoch, never BDF.
    /// This grants no access, writer or root permission to the caller.
    pub fn matches_config(
        &self,
        config: &crate::bus::pci::owned::OwnedConfig,
    ) -> Result<bool, DmaError> {
        self.check()?;
        match self.retention.as_ref().ok_or(DmaError::Unmapped)? {
            Retention::Native(retained) => config
                .matches_retention(retained)
                .map_err(|_| DmaError::MappingFailed),
            #[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
            Retention::SynchronousModel(_) => Ok(false),
        }
    }
    /// Compare an actual source's retained native configuration allocation.
    /// No I/O, entry or root permission is issued; model-only custody cannot
    /// match a native source by metadata or equal addresses.
    pub fn matches_retention(&self, source: &ConfigRetention) -> Result<bool, DmaError> {
        self.check()?;
        match self.retention.as_ref().ok_or(DmaError::Unmapped)? {
            Retention::Native(retained) => retained
                .same_allocation(source)
                .map_err(|_| DmaError::MappingFailed),
            #[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
            Retention::SynchronousModel(_) => Ok(false),
        }
    }
    pub fn domain(&self) -> Arc<dyn DmaDomain> {
        Arc::clone(&self.domain)
    }
    pub fn requester(&self) -> &RequesterId {
        &self.requester
    }
    pub fn irq_route(&mut self) -> Result<MsiRoute, DmaError> {
        self.check()?;
        let config = match self.retention.as_ref().ok_or(DmaError::Unmapped)? {
            Retention::Native(config) => Some(config),
            #[cfg(all(any(test, feature = "test-support"), not(target_os = "uefi")))]
            Retention::SynchronousModel(_) => None,
        };
        let mut owner = ManuallyDrop::new(
            self.backend
                .as_mut()
                .ok_or(DmaError::Unmapped)?
                .irq_owner(&self.requester, config)?,
        );
        self.check()?;
        // SAFETY: no affine owner is extracted before the repeated original
        // native context/epoch check; attached preserves it on every refusal.
        MsiRoute::attached(self.requester.clone(), unsafe {
            ManuallyDrop::take(&mut owner)
        })
        .map_err(|_| DmaError::DrainUnavailable)
    }
    pub fn cancel_unpublished_irq(&mut self, grant: MsiRoute) -> Result<(), CancelFailure> {
        if let Err(error) = self.check() {
            return Err(CancelFailure { error, grant });
        }
        grant
            .cancel(&self.requester)
            .map_err(|(_, grant)| CancelFailure {
                error: DmaError::MappingFailed,
                grant,
            })
    }
    /// Adopt the exact joined action while retaining its old root/config pin.
    /// This permits another action in the same original ownership epoch; it
    /// supplies no engine/payload/DMA detach or native replacement permission.
    pub fn retain_irq_action(
        &mut self,
        mut retired: RetiredRoute,
    ) -> Result<(), RetainActionFailure> {
        let result = (|| {
            self.check()
                .map_err(|_| crate::bus::irq::IrqError::WrongCpu)?;
            retired.validate_requester(&self.requester)?;
            self.retired
                .try_reserve(1)
                .map_err(|_| crate::bus::irq::IrqError::Exhausted)?;
            retired.join_action(&self.requester)?;
            Ok(())
        })();
        match result {
            // Capacity is reserved; no callback or allocation follows join.
            Ok(()) => {
                self.retired.push(retired);
                Ok(())
            }
            Err(error) => Err(RetainActionFailure { error, retired }),
        }
    }
    pub fn validate_irq_actions(&self) -> Result<(), crate::bus::irq::IrqError> {
        for route in self.retired.iter() {
            route.validate()?;
        }
        Ok(())
    }
    /// Release old-action pins only after actual all-actions plus
    /// engine/payload/DMA-unmap/detach, keeping root terminal metadata.
    pub fn release_irq_pins(
        &mut self,
        detached: DetachedRequester,
    ) -> Result<(), PinReleaseFailure> {
        let result = (|| {
            if !self.detached || !self.requester.same_requester(detached.requester()) {
                return Err(crate::bus::irq::IrqError::Route);
            }
            for route in self.retired.iter_mut() {
                route.validate()?;
                route
                    .release_endpoint(&detached)
                    .map_err(crate::bus::irq::IrqError::Delivery)?;
            }
            Ok(())
        })();
        result.map_err(|error| PinReleaseFailure { error, detached })
    }
    /// # Safety
    /// This original requester is stopped and cannot resume. Own payload and
    /// bypass users are drained, all DMA leases quiescently unmapped, and paired
    /// configuration/BAR/root owners remain held. Every issued grant must be
    /// explicitly canceled or its exact independently joined action adopted.
    /// Source/entry non-overlap and engine stop remain independent obligations.
    pub unsafe fn detach(&mut self) -> Result<DetachedRequester, DmaError> {
        self.check()?;
        self.validate_irq_actions()
            .map_err(|_| DmaError::DrainUnavailable)?;
        self.requester
            .check_detach()
            .map_err(|_| DmaError::DrainUnavailable)?;
        let routes: Vec<RouteId> = self
            .retired
            .iter()
            .map(|route| route.id().clone())
            .collect();
        // A callback panic/error after this point cannot expose a retryable or
        // detached success. Backend failure retains its uncertain native graph.
        self.poisoned = true;
        // SAFETY: caller supplies original engine/payload/unmap exclusions;
        // exact route checks above supply the separate interrupt boundary.
        match unsafe { self.backend.as_mut().ok_or(DmaError::Unmapped)?.detach() } {
            Ok(()) => {}
            Err(DetachError::Unexposed(error)) => {
                // A typed before-effect refusal is retryable only after the
                // actual original process/configuration epoch still checks.
                self.retention.as_ref().ok_or(DmaError::Unmapped)?.check()?;
                self.poisoned = false;
                return Err(error);
            }
            Err(DetachError::Uncertain(error)) => return Err(error),
        }
        self.retention.as_ref().ok_or(DmaError::Unmapped)?.check()?;
        self.requester
            .detached()
            .map_err(|_| DmaError::DrainUnavailable)?;
        // Release native control only here in the checked acknowledged context.
        // Later stale Domain Arc drops remain governed by DmaDomain's contract.
        drop(self.backend.take());
        drop(self.retention.take());
        self.detached = true;
        self.poisoned = false;
        Ok(DetachedRequester {
            requester: self.requester.clone(),
            routes,
            local: PhantomData,
        })
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        if self.detached && self.validate_irq_actions().is_ok() {
            // SAFETY: actual detach released the unique affine backend/pin in
            // its checked context. Only a Send+Sync stale domain view remains.
            unsafe {
                ManuallyDrop::drop(&mut self.domain);
                ManuallyDrop::drop(&mut self.retired);
            };
        }
        // Unclosed/uncertain backend, domain and original seal stay retained.
    }
}
