// SPDX-License-Identifier: GPL-2.0-only
//! Held permission for a PMF authentication/association exchange.
//! This never invents a successful AssociationContext or authenticates RSN.
use super::{
    AssociationOwner, Error, HardwareLease, HardwarePolicy, NativeContext, OsLease, OsPolicy, Owner,
};
use crate::wifi::{
    scan::result::Bss,
    station::{Join, NativeBssObservation, Station, Ticket},
};
use alloc::sync::Arc;

/// Original selected request and completed native BSS observation. The
/// pending Ticket is created by canonical Station, not supplied by a frontend.
/// Providers must check the entire enabled pre-association native envelope,
/// including peer configuration, baseline rates, ROC, retries and native RX/TX.
#[derive(Debug)]
pub struct PmfAuthenticationOperation<'a> {
    ticket: Ticket,
    join: &'a Join,
    observation: &'a Arc<NativeBssObservation>,
    transmit: Option<&'a [u8]>,
}
impl PmfAuthenticationOperation<'_> {
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }
    pub fn join(&self) -> &Join {
        self.join
    }
    pub fn observation(&self) -> &Arc<NativeBssObservation> {
        self.observation
    }
    pub fn beacon(&self) -> &Bss {
        self.observation.bss()
    }
    /// Canonical bytes about to be published; None checks receive/
    /// timeout servicing only. Providers must never infer TX from None.
    pub const fn transmit(&self) -> Option<&[u8]> {
        self.transmit
    }
}

/// Inert identity fence. Only another held guard can use it. The
/// original private native observation remains held by its exact Arc.
#[derive(Clone)]
pub(crate) struct PmfAuthenticationBinding {
    owner: u64,
    native: NativeContext,
    revision: u64,
    epoch: u64,
    observation: Arc<NativeBssObservation>,
}
/// Private lifetime-bound borrow of both provider leases. It cannot be
/// constructed externally, copied, stored in a native packet or outlive either.
pub(crate) struct PmfAuthenticationGuard<'a> {
    owner: u64,
    native: NativeContext,
    hardware: &'a mut dyn HardwareLease,
    os: &'a mut dyn OsLease,
}
impl PmfAuthenticationGuard<'_> {
    pub(crate) fn qualify(
        &mut self,
        station: &Station,
        observed: &Arc<NativeBssObservation>,
        binding: Option<&PmfAuthenticationBinding>,
        transmit: Option<(Ticket, &[u8])>,
    ) -> Result<PmfAuthenticationBinding, Error> {
        let (ticket, join, beacon) = station.pmf_authentication().map_err(|_| Error::Stale)?;
        if transmit.is_some_and(|(expected, _)| expected != ticket)
            || !Arc::ptr_eq(beacon, observed)
        {
            return Err(Error::Mismatch);
        }
        let next = PmfAuthenticationBinding {
            owner: self.owner,
            native: self.native,
            revision: self.os.revision(),
            epoch: ticket.epoch(),
            observation: observed.clone(),
        };
        if binding.is_some_and(|old| {
            old.owner != next.owner
                || old.native != next.native
                || old.revision != next.revision
                || old.epoch != next.epoch
                || !Arc::ptr_eq(&old.observation, &next.observation)
        }) {
            return Err(Error::Stale);
        }
        let operation = PmfAuthenticationOperation {
            ticket,
            join,
            observation: observed,
            transmit: transmit.map(|(_, bytes)| bytes),
        };
        let channel = join.channel;
        if self.hardware.lookup_channel(channel.band, channel.number) != Some(channel)
            || !self.hardware.allows_pmf_authentication(&operation)
        {
            return Err(Error::HardwareDenied);
        }
        if !self.os.allows_pmf_authentication(&operation) {
            return Err(Error::OsDenied);
        }
        Ok(next)
    }
}
impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    /// Acquire the real providers before pure native preparation. The callback
    /// must check the newly generated Ticket before any native effect.
    /// No Station borrow survives the exclusive native callback.
    ///
    /// # Safety
    /// Same requester, kept policy/board/radio resources and real
    /// revocation/stop/drain contract as publish_association. An observation or
    /// matching copied numbers alone never proves hardware ownership.
    pub(crate) unsafe fn with_pmf_authentication<N: AssociationOwner, T>(
        &mut self,
        native_owner: &mut N,
        consume: impl FnOnce(&mut N, &mut PmfAuthenticationGuard<'_>) -> T,
    ) -> Result<T, Error> {
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        let mut guard = PmfAuthenticationGuard {
            owner: self.identity,
            native,
            hardware: &mut hardware,
            os: &mut os,
        };
        let result = consume(native_owner, &mut guard);
        drop(os);
        drop(hardware);
        Ok(result)
    }
}
