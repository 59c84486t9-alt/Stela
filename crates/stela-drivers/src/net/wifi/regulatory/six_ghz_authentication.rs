// SPDX-License-Identifier: GPL-2.0-only
//! Fresh held board and OS permission for finite6GHz SAE transport only.
//! None of these observations authenticate SAE or permit an association.
use super::{
    AssociationOwner, Error, HardwareLease, HardwarePolicy, NativeContext, OsLease, OsPolicy, Owner,
};
use crate::net::wifi::{frame::Mpdu, station::external::Session};
use alloc::sync::Arc;

/// Source-enabled native initial peer envelope. Public fields are
/// inspection facts, never a constructor for held permission or native state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SixGhzTransportProfile {
    pub interface: [u8; 5],
    pub wcid: u16,
    pub broadcast_wcid: u16,
    pub antenna_mask: u8,
    pub basic_rates: u16,
    pub supported_rates: u16,
    pub fixed_rate_table_index: u8,
    pub beacon_interval: u16,
    pub dtim_period: u8,
    pub slot_time: u16,
    pub raw_ap_power_type: u8,
}
#[derive(Clone, Copy, Debug)]
pub enum SixGhzAuthenticationUse<'a> {
    PreparePeer,
    ReserveChannel,
    Transmit(&'a [u8]),
    Receive(&'a Mpdu),
    Service,
}
/// Providers must inspect real kept board CLC/domain/SKU/calibration,
/// antenna/power/SAR/indoor policy, HE20/OFDM retry/ACK footprint and exact OS
/// selected BSS/session/security. The OS selects transport, never SAE success.
#[derive(Debug)]
pub struct SixGhzAuthenticationOperation<'a> {
    session: &'a Arc<Session>,
    profile: &'a SixGhzTransportProfile,
    purpose: SixGhzAuthenticationUse<'a>,
}
impl SixGhzAuthenticationOperation<'_> {
    pub fn session(&self) -> &Arc<Session> {
        self.session
    }
    pub fn profile(&self) -> &SixGhzTransportProfile {
        self.profile
    }
    pub const fn purpose(&self) -> SixGhzAuthenticationUse<'_> {
        self.purpose
    }
}
/// Equality fences keep original identity, never prior permission.
#[derive(Clone)]
pub(crate) struct SixGhzAuthenticationBinding {
    owner: u64,
    native: NativeContext,
    revision: u64,
    session: Arc<Session>,
    profile: SixGhzTransportProfile,
}
pub(crate) struct SixGhzAuthenticationGuard<'a> {
    owner: u64,
    native: NativeContext,
    hardware: &'a mut dyn HardwareLease,
    os: &'a mut dyn OsLease,
}
impl SixGhzAuthenticationGuard<'_> {
    pub(crate) fn qualify(
        &mut self,
        session: &Arc<Session>,
        profile: &SixGhzTransportProfile,
        old: Option<&SixGhzAuthenticationBinding>,
        purpose: SixGhzAuthenticationUse<'_>,
    ) -> Result<SixGhzAuthenticationBinding, Error> {
        if session.six_ghz_observation().is_none()
            || session.six_ghz_selection().is_none()
            || session.six_ghz_local_capabilities().is_none()
        {
            return Err(Error::Mismatch);
        }
        let revision = self.os.revision();
        if old.is_some_and(|old| {
            old.owner != self.owner
                || old.native != self.native
                || old.revision != revision
                || !Arc::ptr_eq(&old.session, session)
                || old.profile != *profile
        }) {
            return Err(Error::Stale);
        }
        let operation = SixGhzAuthenticationOperation {
            session,
            profile,
            purpose,
        };
        let channel = session.channel();
        if self.hardware.lookup_channel(channel.band, channel.number) != Some(channel)
            || !self.hardware.allows_six_ghz_authentication(&operation)
        {
            return Err(Error::HardwareDenied);
        }
        if !self.os.allows_six_ghz_authentication(&operation) {
            return Err(Error::OsDenied);
        }
        Ok(SixGhzAuthenticationBinding {
            owner: self.owner,
            native: self.native,
            revision,
            session: session.clone(),
            profile: profile.clone(),
        })
    }
}
impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    /// # Safety
    /// Same requester/policy/board retention and revocation,
    /// enforcement, cancellation and independent drain contract as
    /// publish_association. Transport selection is not supplicant completion.
    /// Cleanup of original armed work remains possible without new permission.
    pub(crate) unsafe fn with_six_ghz_authentication<N: AssociationOwner, T>(
        &mut self,
        native_owner: &mut N,
        consume: impl FnOnce(&mut N, &mut SixGhzAuthenticationGuard<'_>) -> T,
    ) -> Result<T, Error> {
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        let mut guard = SixGhzAuthenticationGuard {
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
