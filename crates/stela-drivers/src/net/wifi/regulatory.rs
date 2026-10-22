// SPDX-License-Identifier: GPL-2.0-only
//! Shared channel admission; the hardware and OS retain their own policy data.
//!
//! The distinction between disabled channels, no-IR, DFS and indoor constraints
//! follows pinned Linux cfg80211/mac80211 semantics; see THIRD_PARTY.md.
//! This module supplies no regulatory database, country, DFS exception, default
//! rate or power. Parsed vendor receipts and channel flags are observations.
//! Only qualified providers holding genuine authority leases may admit work.

use super::{Band, Channel, scan, station};

mod association;
pub use association::{AssociationAdmission, AssociationOperation, AssociationUse};

static NEXT_OWNER: super::Identities = super::Identities::new();

/// Actual retained device/reset/firmware owner and fully applied radio policy.
/// Numbers are provider provenance, not authority or a raw hardware fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeContext {
    pub device: u64,
    pub reset_epoch: u64,
    pub firmware_epoch: u64,
    pub policy_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Probe,
    Management,
    Data,
}

/// Deliberately limited to the shared station's initial non-HT profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Legacy20,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyRate {
    Cck1,
    Cck2,
    Cck5_5,
    Cck11,
    Ofdm6,
    Ofdm9,
    Ofdm12,
    Ofdm18,
    Ofdm24,
    Ofdm36,
    Ofdm48,
    Ofdm54,
}

impl LegacyRate {
    fn cck(self) -> bool {
        matches!(self, Self::Cck1 | Self::Cck2 | Self::Cck5_5 | Self::Cck11)
    }
}

/// Exact planned TX settings, never settings inferred from a channel/country.
/// EIRP is in hundredths of dBm; providers must account for antenna/calibration,
/// hardware rate limits and actual applied power programming. It is a ceiling
/// for this submission, not a claim of measured radiated power.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxProfile {
    pub width: Width,
    pub rate: LegacyRate,
    pub short_preamble: bool,
    pub max_eirp_mbm: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Receive(Channel),
    Transmit {
        channel: Channel,
        purpose: Purpose,
        profile: TxProfile,
    },
}

impl Operation {
    pub const fn channel(self) -> Channel {
        match self {
            Self::Receive(channel) | Self::Transmit { channel, .. } => channel,
        }
    }

    fn validate(self) -> Result<(), Error> {
        let channel = self.channel();
        if channel.band == Band::Ghz6 {
            return Err(Error::Unsupported);
        }
        if let Self::Transmit { profile, .. } = self
            && ((profile.rate.cck() && channel.band != Band::Ghz2)
                || (profile.short_preamble
                    && (!profile.rate.cck() || profile.rate == LegacyRate::Cck1)))
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    OwnerExhausted,
    HardwareUnavailable,
    OsUnavailable,
    HardwareDenied,
    OsDenied,
    Stale,
    Mismatch,
    Unsupported,
}

/// A view usable only while its qualified HardwarePolicy holds the real guard.
/// An implementation alone does not confer authority.
pub trait HardwareLease {
    fn context(&self) -> NativeContext;
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel>;
    fn allows(&mut self, operation: Operation) -> bool;
    /// Qualify the complete context-bound autonomous radio profile. The default
    /// refuses; legacy single-rate permission never implies this permission.
    fn allows_association(&mut self, _operation: &AssociationOperation<'_>) -> bool {
        false
    }
}

/// Actual physical radio owner, not an adapter around caller-copied flags.
///
/// # Safety
/// Each acquired lease must bind the same exclusively retained native device,
/// actual reset/firmware epochs, board/calibration and fully applied policy.
/// Context revisions must never repeat after any relevant change. Return None
/// while observations, reset, partial programming or lifecycle are uncertain.
/// `allows` must enforce all hardware/firmware restrictions for the exact
/// operation, including no-IR/DFS/indoor, rate/preamble/width and actual power.
/// The fixed legacy TX profile must cover every hardware retry; refuse if
/// firmware can choose unqualified fallback rates, widths or power. Receive
/// here is normal station/scan reception, not a disabled-channel monitor mode.
/// `allows_association` must additionally qualify the exact current context's
/// complete source-enabled rate/PHY envelope: local/peer negotiated fields,
/// basic/automatic ACK and BA responses, firmware rate selection and retries,
/// all enabled GI/RU/STBC/LDPC/DCM modes, NSS, width/puncture/full channel
/// footprint, and actually applied per-rate power/calibration/antenna limits.
/// The context and local source words must be bound to the genuine retained
/// native capability issuer; parsed/copied facts cannot establish authority.
/// Do not approve a context using one legacy rate or an unqualified firmware
/// fallback. Missing any necessary qualification must refuse the operation.
/// No source default, parsed receipt, country guess or receive observation can
/// establish these permissions. Missing TX qualification must deny TX while
/// separately qualified receive may remain possible.
///
/// The lease must serialize controlled resets, restriction changes and native
/// submission until dropped. Its concrete type must let the submit closure use
/// this same physical owner; publication cannot target a different device.
/// Shared operations acquire hardware authority before OS authority. Provider
/// and revocation callbacks must preserve this order: never hold OS authority
/// while synchronously blocking on hardware authority. Use ordered acquisition
/// or release/coordinate/revalidate without treating released authority as live.
/// After publication, restrictive revocation must actually stop/cancel/drain
/// pending radio work and already armed autonomous MAC responses (or
/// hardware-enforce the new restriction before emission). Stopping/removing a
/// restricted context must remain possible without a new transmit permission.
/// Retain old DMA/key/policy resources through actual completions and users.
/// Closure return is not air completion, cancellation or retirement proof.
pub unsafe trait HardwarePolicy {
    type Lease<'a>: HardwareLease
    where
        Self: 'a;
    fn acquire(&mut self) -> Option<Self::Lease<'_>>;
}

/// A view of a genuine OS/location policy service's held authority lease.
pub trait OsLease {
    fn revision(&self) -> u64;
    fn allows(&mut self, operation: Operation) -> bool;
    /// Qualify the complete context-bound autonomous radio profile. The default
    /// refuses; legacy single-rate permission never implies this permission.
    fn allows_association(&mut self, _operation: &AssociationOperation<'_>) -> bool {
        false
    }
}

/// Trusted OS policy boundary. A frontend message or copied country is not it.
///
/// # Safety
/// Acquire only current authenticated OS/location authority applicable to this
/// exact native device/reset/firmware context. Return None when absent, expired,
/// revoked or unqualified. Revisions must not repeat after any relevant change;
/// `allows` must intersect all current location/DFS/indoor and operation-specific
/// rate/width/power restrictions. The lease must genuinely synchronize policy
/// revocation through native publication, not merely snapshot flags/revisions.
/// `allows_association` must qualify that same complete enabled context profile,
/// not one selected rate or metadata observation, for all current location,
/// full channel footprint, DFS/no-IR/indoor and per-rate power constraints.
/// Shared operations acquire hardware then OS authority. OS provider/revocation
/// callbacks must not hold OS authority while synchronously waiting for hardware
/// authority in reverse order. Use compatible ordered acquisition or release,
/// coordinate and revalidate authority before resuming protected work.
/// Revocation must also coordinate the HardwarePolicy's real pending-work
/// stop/enforcement/drain obligation. There is no in-driver OS service default.
pub unsafe trait OsPolicy {
    type Lease<'a>: OsLease
    where
        Self: 'a;
    fn acquire(&mut self, native: NativeContext) -> Option<Self::Lease<'_>>;
}

/// Preflight result only. Publication consumes this and reacquires both guards.
/// Fields are private; source receipts and copied flags cannot forge admission.
///
/// ```compile_fail
/// use stela_drivers::net::wifi::regulatory::Admission;
/// let admission = Admission { owner: 1 }; // No public authority constructor.
/// ```
#[derive(Debug)]
pub struct Admission {
    owner: u64,
    native: NativeContext,
    os_revision: u64,
    operation: Operation,
}

impl Admission {
    pub const fn operation(&self) -> Operation {
        self.operation
    }
}

pub struct Owner<H, O> {
    identity: u64,
    hardware: H,
    os: O,
}

fn check(
    hardware: &mut impl HardwareLease,
    os: &mut impl OsLease,
    operation: Operation,
) -> Result<(), Error> {
    operation.validate()?;
    let channel = operation.channel();
    if hardware.lookup_channel(channel.band, channel.number) != Some(channel)
        || !hardware.allows(operation)
    {
        return Err(Error::HardwareDenied);
    }
    if !os.allows(operation) {
        return Err(Error::OsDenied);
    }
    Ok(())
}

impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    pub fn new(hardware: H, os: O) -> Result<Self, Error> {
        let identity = NEXT_OWNER.next().ok_or(Error::OwnerExhausted)?;
        Ok(Self {
            identity,
            hardware,
            os,
        })
    }

    pub fn admit(&mut self, operation: Operation) -> Result<Admission, Error> {
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        check(&mut hardware, &mut os, operation)?;
        Ok(Admission {
            owner: self.identity,
            native,
            os_revision: os.revision(),
            operation,
        })
    }

    /// Revalidate the exact native plan immediately at publication. Both real
    /// authority guards remain held throughout `submit`. It returns the
    /// backend's actual result; this method does not invent ACK, emission,
    /// cancellation or air completion.
    ///
    /// # Safety
    /// The callback must use the supplied concrete hardware guard's native
    /// submission path and encode this exact operation/profile. It may not
    /// target another device or bypass the held providers' restriction checks.
    pub unsafe fn publish<'a, T>(
        &'a mut self,
        admission: Admission,
        operation: Operation,
        submit: impl FnOnce(&mut H::Lease<'a>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        if admission.operation != operation {
            return Err(Error::Mismatch);
        }
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        if admission.native != native {
            return Err(Error::Stale);
        }
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        if admission.os_revision != os.revision() {
            return Err(Error::Stale);
        }
        check(&mut hardware, &mut os, operation)?;
        let result = submit(&mut hardware);
        // Explicit drops document that both guards cover the native closure.
        drop(os);
        drop(hardware);
        Ok(result)
    }

    /// Existing frame/scan policies are preflight checks. Their bool results
    /// never replace `publish` at the exact vendor descriptor/command boundary.
    pub fn preflight(&mut self, profiles: Profiles) -> Preflight<'_, H, O> {
        Preflight {
            owner: self,
            profiles,
        }
    }

    fn lookup(&mut self, band: Band, number: u16) -> Option<Channel> {
        let mut hardware = self.hardware.acquire()?;
        let channel = hardware.lookup_channel(band, number)?;
        let mut os = self.os.acquire(hardware.context())?;
        check(&mut hardware, &mut os, Operation::Receive(channel)).ok()?;
        Some(channel)
    }
}

/// Every TX purpose needs an explicitly qualified profile. None denies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profiles {
    pub probe: Option<TxProfile>,
    pub management: Option<TxProfile>,
    pub data: Option<TxProfile>,
}

pub struct Preflight<'a, H, O> {
    owner: &'a mut Owner<H, O>,
    profiles: Profiles,
}

impl<H: HardwarePolicy, O: OsPolicy> Preflight<'_, H, O> {
    fn tx(&mut self, channel: Channel, purpose: Purpose, profile: Option<TxProfile>) -> bool {
        profile.is_some_and(|profile| {
            self.owner
                .admit(Operation::Transmit {
                    channel,
                    purpose,
                    profile,
                })
                .is_ok()
        })
    }
}

impl<H: HardwarePolicy, O: OsPolicy> scan::Policy for Preflight<'_, H, O> {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        self.owner.admit(Operation::Receive(channel)).is_ok()
    }
    fn allow_probe(&mut self, channel: Channel) -> bool {
        self.tx(channel, Purpose::Probe, self.profiles.probe)
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.owner.lookup(band, number)
    }
}

impl<H: HardwarePolicy, O: OsPolicy> station::RegulatoryPolicy for Preflight<'_, H, O> {
    fn allow_management_tx(&mut self, channel: Channel) -> bool {
        self.tx(channel, Purpose::Management, self.profiles.management)
    }
    fn allow_data_tx(&mut self, channel: Channel) -> bool {
        self.tx(channel, Purpose::Data, self.profiles.data)
    }
}

#[cfg(test)]
mod tests;
