//! Typed immutable publication on the exact retained event transport.
use super::{Domain, NativeDomain, WorkError};
use crate::platform::work::service::RaisedWork;
use core::marker::PhantomData;
/// No conversion exists between domains; this owns only its same-domain event.
/// ```compile_fail
/// use stela_driver_base::platform::work::kernel_domain::{DomainRaised,HostedDomain,NativeDomain};
/// fn no_domain_promotion(host:DomainRaised<HostedDomain>)->DomainRaised<NativeDomain> {host}
/// ```
pub struct DomainRaised<D: Domain> {
    inner: D::Raised,
    _domain: PhantomData<D>,
}
impl<D: Domain> Clone for DomainRaised<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _domain: PhantomData,
        }
    }
}
impl<D: Domain> DomainRaised<D> {
    pub fn raise(&self) -> Result<(), WorkError> {
        D::raise(&self.inner)
    }
}
impl DomainRaised<NativeDomain> {
    pub fn from_native(raised: &RaisedWork) -> Self {
        Self {
            inner: raised.clone(),
            _domain: PhantomData,
        }
    }
}
#[cfg(all(feature = "test-support", unix))]
impl DomainRaised<super::HostedDomain> {
    pub(super) fn from_hosted(inner: super::hosted::HostedRaisedWork) -> Self {
        Self {
            inner,
            _domain: PhantomData,
        }
    }
}
