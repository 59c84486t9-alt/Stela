//! Original requester/root route ownership, distinct from payload and CPU drain.
use super::{CpuTarget, MsiMessage, RouteId};
use crate::bus::pci::requester::{RequesterId, preparation::DetachedRequester};
use alloc::{boxed::Box, sync::Arc};
use core::{marker::PhantomData, mem::ManuallyDrop};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RootUnavailable,
    Unsupported,
    RootFailed,
    Unbound,
    AlreadyBound,
    WrongRequester,
    Context,
    NotRetired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationError {
    Unexposed(Error),
    Uncertain(Error),
}
impl AllocationError {
    pub fn error(self) -> Error {
        match self {
            Self::Unexposed(e) | Self::Uncertain(e) => e,
        }
    }
    pub(crate) fn untouched(self) -> bool {
        matches!(self, Self::Unexposed(_))
    }
}

/// Original stable CPU/root/format and live resource guard for ordinary IRQ
/// notification. This is not all-issued MSI completion or a DMA drain.
/// # Safety
/// Construct only from actual retained original ownership. check is IRQ-safe,
/// allocation-free/nonblocking and checks original immutable/atomic scope
/// before locks or native I/O. No number or mutable !Send Source substitutes
/// for the real root/format and source-resource lifetime. Old ordinary messages
/// may notify a current valid handler; every handler checks its own state/rings.
/// Format/root/CPU ownership stays frozen for that admitted notification domain.
/// Endpoint-specific pins belong only to per-action leaves and end in the
/// actual checked action/endpoint teardown; global root domains do not pin them.
/// Dropping a guard is not permission for hardware teardown. Any physical owner
/// retained by a guard must conservatively retain on foreign context or an
/// unresolved epoch, including refused prepublication return and unwind.
pub unsafe trait NotificationDomain: Send + Sync {
    fn check(&self) -> Result<(), Error>;
}

/// An original attached root/source grant, never a numeric message owner.
///
/// # Safety
/// Allocation joins only the supplied checked Registry reservation and this
/// exact original configuration/root/reset/source identity. Unexposed errors
/// return that grant without any possible hardware publication. Every method
/// checks actual process/root/source epochs. notification_domain is genuine
/// original ordinary fixed/edge admission, never fabric completion. Strong
/// Intel fencing remains separate optional evidence. Existing index/root ledger
/// obligations are retained independently; notification does not reclaim them. release_endpoint consumes the exact higher retirement proof before
/// ending its source/config pin. The terminal root ledger must survive final
/// owner Drop; failed/abandoned state retains every uncertain native owner.
/// No borrowed native entered permit may escape or span a blocking operation.
pub unsafe trait RouteOwner {
    fn allocate(&mut self, target: &CpuTarget<'_>) -> Result<MsiMessage, AllocationError>;
    fn validate(&self) -> Result<(), Error>;
    /// Original process-mode checks plus a retained IRQ-safe notification guard.
    /// Missing root/source/format admission is an error, never None-as-success.
    fn notification_domain(&self) -> Result<Arc<dyn NotificationDomain>, Error>;
    /// Optional stronger original fabric fence, distinct from generic action
    /// notification retirement. No all-issued proof is invented by the default.
    /// # Safety
    /// This actual original route is masked and its admitted source/pending
    /// cause protocol is quiescent; all covered native owners stay retained.
    unsafe fn strong_fence(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// # Safety
    /// The private proof names this exact route after CPU/callback/work
    /// retirement and, for native endpoints, actual DMA unmap/requester detach.
    unsafe fn release_endpoint(&mut self, proof: &EndpointRetirement<'_>) -> Result<(), Error>;
}

/// Borrowed proof constructed only by the canonical retirement transitions.
/// It supplies no independent native entered permission.
pub struct EndpointRetirement<'a> {
    pub(crate) route: &'a RouteId,
    pub(crate) detached: Option<&'a DetachedRequester>,
}
impl EndpointRetirement<'_> {
    pub fn requester(&self) -> Option<&RequesterId> {
        self.detached.map(DetachedRequester::requester)
    }
    pub fn vector(&self) -> u8 {
        self.route.target().vector
    }
}

enum Origin {
    Unavailable,
    Attached,
    #[cfg(any(test, feature = "test-support", feature = "irq-diagnostics"))]
    BoundedFixture,
}
/// One affine IRQ route: original grant, notification admission and explicit endpoint
/// pin release. Registry owns it through source/CPU/work retirement.
pub struct MsiRoute {
    owner: ManuallyDrop<Option<Box<dyn RouteOwner>>>,
    origin: Origin,
    requester: Option<RequesterId>,
    action_joined: bool,
    route: Option<RouteId>,
    message: Option<MsiMessage>,
    published: bool,
    domain: ManuallyDrop<Option<Arc<dyn NotificationDomain>>>,
    cpu_retired: bool,
    released: bool,
    local: PhantomData<*mut ()>,
}
impl MsiRoute {
    pub fn unavailable() -> Self {
        Self {
            owner: ManuallyDrop::new(None),
            origin: Origin::Unavailable,
            requester: None,
            action_joined: false,
            route: None,
            message: None,
            published: false,
            domain: ManuallyDrop::new(None),
            cpu_retired: false,
            released: false,
            local: PhantomData,
        }
    }
    pub(crate) fn attached(
        requester: RequesterId,
        owner: Option<Box<dyn RouteOwner>>,
    ) -> Result<Self, Error> {
        let mut route = Self::unavailable();
        *route.owner = owner;
        requester.issue().map_err(|_| Error::WrongRequester)?;
        route.requester = Some(requester);
        route.origin = Origin::Attached;
        Ok(route)
    }
    /// Construct only the explicit synchronous diagnostic/model peer.
    ///
    /// # Safety
    /// Provider owns/validates the exact bounded fixture route and context.
    /// It carries NO native requester/configuration pin, cannot satisfy native
    /// Attachment detach/reset and is never a NativeServices capability.
    #[cfg(any(test, feature = "test-support", feature = "irq-diagnostics"))]
    pub unsafe fn bounded_fixture(owner: Box<dyn RouteOwner>) -> Self {
        let mut route = Self::unavailable();
        *route.owner = Some(owner);
        route.origin = Origin::BoundedFixture;
        route
    }
    pub fn requester(&self) -> Option<&RequesterId> {
        self.requester.as_ref()
    }
    pub fn is_unavailable(&self) -> bool {
        self.owner.is_none()
    }
    pub fn belongs_to(&self, requester: &RequesterId) -> bool {
        self.requester
            .as_ref()
            .is_some_and(|own| own.same_requester(requester))
    }
    /// Cancel an unattached unavailable/fixture request before allocation.
    /// This performs no hardware drain and cannot acknowledge a native endpoint.
    pub fn cancel_unattached(mut self) -> Result<(), (Error, Self)> {
        let result = (|| {
            if self.requester.is_some() || self.route.is_some() || self.published {
                return Err(Error::AlreadyBound);
            }
            if let Some(owner) = self.owner.as_ref() {
                owner.validate()?;
            }
            drop(self.owner.take());
            self.released = true;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }

    pub(crate) fn check_unpublished(&self) -> Result<(), Error> {
        if self.published || self.route.is_some() {
            return Err(Error::AlreadyBound);
        }
        if let Some(owner) = self.owner.as_ref() {
            owner.validate()?;
        }
        Ok(())
    }
    pub(crate) fn allocation(
        &mut self,
        target: &CpuTarget<'_>,
    ) -> Result<MsiMessage, AllocationError> {
        if self.route.is_some() {
            return Err(AllocationError::Unexposed(Error::AlreadyBound));
        }
        target
            .check_current()
            .map_err(|_| AllocationError::Unexposed(Error::Context))?;
        if self
            .requester
            .as_ref()
            .is_some_and(|id| !target.matches_requester(id))
        {
            return Err(AllocationError::Unexposed(Error::WrongRequester));
        }
        if let Some(owner) = self.owner.as_mut() {
            owner.validate().map_err(AllocationError::Unexposed)?;
            let domain = owner
                .notification_domain()
                .map_err(AllocationError::Unexposed)?;
            domain.check().map_err(AllocationError::Unexposed)?;
            *self.domain = Some(domain);
            let message = match owner.allocate(target) {
                Ok(message) => message,
                Err(error) => {
                    if !error.untouched() {
                        self.route = Some(target.id().clone());
                    }
                    return Err(error);
                }
            };
            self.route = Some(target.id().clone());
            self.message = Some(message);
            self.published = true;
            owner.validate().map_err(AllocationError::Uncertain)?;
            target
                .check_current()
                .map_err(|_| AllocationError::Uncertain(Error::Context))?;
            Ok(message)
        } else {
            Err(AllocationError::Unexposed(Error::RootUnavailable))
        }
    }
    pub(crate) fn domain(&self) -> Result<Arc<dyn NotificationDomain>, Error> {
        let domain = self.domain.as_ref().ok_or(Error::RootUnavailable)?;
        domain.check()?;
        Ok(domain.clone())
    }

    pub(crate) fn programming(&mut self) -> Result<(), Error> {
        let route = self.route.as_ref().ok_or(Error::Unbound)?;
        route.check_process().map_err(|_| Error::Context)?;
        self.owner
            .as_ref()
            .ok_or(Error::RootUnavailable)?
            .validate()?;
        self.domain
            .as_ref()
            .ok_or(Error::RootUnavailable)?
            .check()?;
        self.published = true;
        Ok(())
    }
    pub(crate) fn check_rearm(&self) -> Result<(), Error> {
        let id = self.route.as_ref().ok_or(Error::Unbound)?;
        id.check_process().map_err(|_| Error::Context)?;
        if self.cpu_retired || self.released {
            return Err(Error::NotRetired);
        }
        self.owner
            .as_ref()
            .ok_or(Error::RootUnavailable)?
            .validate()?;
        self.domain.as_ref().ok_or(Error::RootUnavailable)?.check()
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.route
            .as_ref()
            .ok_or(Error::Unbound)?
            .check_process()
            .map_err(|_| Error::Context)?;
        self.owner
            .as_ref()
            .ok_or(Error::RootUnavailable)?
            .validate()
    }
    pub(crate) fn cpu_retired(&mut self) -> Result<(), Error> {
        self.validate()?;
        self.domain
            .as_ref()
            .ok_or(Error::RootUnavailable)?
            .check()?;
        self.cpu_retired = true;
        // Same checked process context after the actual old action join. Slot
        // retains its own immutable guard until final locked withdrawal.
        drop(self.domain.take());
        Ok(())
    }
    pub(crate) fn join_action(
        &mut self,
        requester: &RequesterId,
        route: &RouteId,
    ) -> Result<(), Error> {
        if self.action_joined
            || !self.cpu_retired
            || !self.route.as_ref().is_some_and(|own| own.same(route))
            || !self.belongs_to(requester)
        {
            return Err(Error::NotRetired);
        }
        self.validate()?;
        requester
            .complete_action()
            .map_err(|_| Error::WrongRequester)?;
        self.action_joined = true;
        Ok(())
    }
    pub(crate) fn release(
        &mut self,
        route: &RouteId,
        detached: &DetachedRequester,
    ) -> Result<(), Error> {
        if !self.cpu_retired
            || !self.action_joined
            || !self.route.as_ref().is_some_and(|own| own.same(route))
        {
            return Err(Error::NotRetired);
        }
        if !self
            .requester
            .as_ref()
            .is_some_and(|own| own.same_requester(detached.requester()))
            || !detached.matches_route(route)
        {
            return Err(Error::WrongRequester);
        }
        if self.released {
            return self.validate();
        }
        self.validate()?;
        let proof = EndpointRetirement {
            route,
            detached: Some(detached),
        };
        // SAFETY: exact private route/requester proof and acknowledged detach
        // follow real action/CPU/work retirement; source pin is still retained.
        unsafe {
            self.owner
                .as_mut()
                .ok_or(Error::RootUnavailable)?
                .release_endpoint(&proof)
        }?;
        self.released = true;
        Ok(())
    }
    #[cfg(any(test, feature = "test-support", feature = "irq-diagnostics"))]
    pub(crate) fn release_fixture(&mut self, route: &RouteId) -> Result<(), Error> {
        if !matches!(self.origin, Origin::BoundedFixture)
            || self.requester.is_some()
            || !self.cpu_retired
            || self.released
            || !self.route.as_ref().is_some_and(|own| own.same(route))
        {
            return Err(Error::NotRetired);
        }
        self.validate()?;
        let proof = EndpointRetirement {
            route,
            detached: None,
        };
        // SAFETY: this constructor is scoped to an explicit no-native-pin
        // fixture provider, with exact action/CPU/work retirement, not a native
        // requester/DMA detach or a successful empty endpoint resource.
        unsafe {
            self.owner
                .as_mut()
                .ok_or(Error::RootUnavailable)?
                .release_endpoint(&proof)
        }?;
        self.released = true;
        Ok(())
    }
    pub(crate) fn cancel(mut self, requester: &RequesterId) -> Result<(), (Error, Self)> {
        let result = (|| {
            if self.published
                || self.route.is_some()
                || !self
                    .requester
                    .as_ref()
                    .is_some_and(|own| own.same_requester(requester))
            {
                return Err(Error::WrongRequester);
            }
            if let Some(owner) = self.owner.as_ref() {
                owner.validate()?;
            }
            // The original Attachment checked its live native context before
            // this explicit prepublication cancellation. No hardware was armed.
            drop(self.owner.take());
            requester
                .complete_action()
                .map_err(|_| Error::WrongRequester)?;
            self.released = true;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }
}
impl Drop for MsiRoute {
    fn drop(&mut self) {
        if self.released
            && self
                .owner
                .as_ref()
                .is_none_or(|owner| owner.validate().is_ok())
        {
            // SAFETY: explicit checked release already ended any config pin;
            // the provider now owns only terminal observation whose Drop must
            // leave the canonical root ledger and blocking resources retained.
            unsafe {
                ManuallyDrop::drop(&mut self.owner);
                ManuallyDrop::drop(&mut self.domain);
            };
        }
        // Every other path retains the actual Box, even after action join.
    }
}
