// SPDX-License-Identifier: GPL-2.0-only
// The power type follows pinned Linux include/net/cfg80211.h and
// net/wireless/scan.c; full source notices in THIRD_PARTY.md.
//! Fresh held board and OS permission for finite6GHz SAE transport only.
//! None of these observations authenticate SAE or permit an association.
use super::{
    AssociationOwner, Error, HardwareLease, HardwarePolicy, NativeContext, OsLease, OsPolicy,
    Owner,
    channel::{NO_6GHZ_AFC_CLIENT, NO_6GHZ_VLP_CLIENT},
};
use crate::wifi::{frame::Mpdu, station::external::Session};
use alloc::sync::Arc;

/// `enum ieee80211_ap_reg_power` of a 6 GHz AP a client may know.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerType {
    LowPowerIndoor,
    StandardPower,
    VeryLowPower,
}
impl PowerType {
    /// `cfg80211_6ghz_power_type`: the type of an AP whose HE 6 GHz operation
    /// carries Regulatory Info `info`, for a client on a channel with `flags`;
    /// None is IEEE80211_REG_UNSET_AP.
    pub const fn of(info: u8, flags: u32) -> Option<Self> {
        match info {
            // LPI, indoor LPI, the old indoor SP and AP-role-not-relevant.
            0 | 3 | 4 | 7 => Some(Self::LowPowerIndoor),
            1 => Some(Self::StandardPower),
            2 => Some(Self::VeryLowPower),
            // Indoor SP: an LPI AP to a client without AFC.
            8 if flags & NO_6GHZ_AFC_CLIENT != 0 => Some(Self::LowPowerIndoor),
            8 => Some(Self::StandardPower),
            _ => None,
        }
    }
    /// `cfg80211_6ghz_power_type_valid`: whether a client may use an AP whose
    /// Regulatory Info is `info` on a channel with `flags`.
    pub const fn usable(info: u8, flags: u32) -> bool {
        match Self::of(info, flags) {
            Some(Self::LowPowerIndoor) => true,
            Some(Self::StandardPower) => flags & NO_6GHZ_AFC_CLIENT == 0,
            Some(Self::VeryLowPower) => flags & NO_6GHZ_VLP_CLIENT == 0,
            None => false,
        }
    }
}

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
