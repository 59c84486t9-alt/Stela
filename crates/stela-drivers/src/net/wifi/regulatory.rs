// SPDX-License-Identifier: GPL-2.0-only
// Channel-definition checks follow Linux net/wireless/chan.c:
// Copyright 2009 Johannes Berg; 2013-2014 Intel Mobile Communications GmbH;
// 2018-2026 Intel Corporation. See THIRD_PARTY.md.
//! Shared channel admission; the hardware and OS retain their own policy data.
//!
//! The distinction between disabled channels, no-IR, DFS and indoor constraints
//! follows pinned Linux cfg80211/mac80211 semantics; see THIRD_PARTY.md.
//! Database inputs are explicitly content-pinned and country-selected by the
//! normal OS/setup source. No country, DFS exception, default rate or power is
//! inferred. Parsed vendor receipts and channel flags alone are observations;
//! native providers must retain the actual programmed controller and policy.

use super::{Band, Channel, scan, station};

mod association;
pub mod database;
pub mod wmm;
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
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::Cell;

    const CHANNEL: Channel = Channel {
        band: Band::Ghz2,
        number: 1,
        frequency_mhz: 2412,
    };
    const PROFILE: TxProfile = TxProfile {
        width: Width::Legacy20,
        rate: LegacyRate::Ofdm6,
        short_preamble: false,
        max_eirp_mbm: 1234,
    };
    const NATIVE: NativeContext = NativeContext {
        device: 7,
        reset_epoch: 2,
        firmware_epoch: 3,
        policy_revision: 4,
    };

    fn operation(purpose: Purpose) -> Operation {
        Operation::Transmit {
            channel: CHANNEL,
            purpose,
            profile: PROFILE,
        }
    }

    fn permission(operation: Operation) -> u8 {
        match operation {
            Operation::Receive(_) => 1,
            Operation::Transmit { purpose, .. } => match purpose {
                Purpose::Probe => 2,
                Purpose::Management => 4,
                Purpose::Data => 8,
            },
        }
    }

    struct State {
        available: Cell<bool>,
        held: Cell<bool>,
        native: Cell<NativeContext>,
        revision: Cell<u64>,
        permissions: Cell<u8>,
        max_power: Cell<Option<i32>>,
        pending: Cell<bool>,
        submissions: Cell<u32>,
    }

    impl State {
        fn new() -> Rc<Self> {
            Rc::new(Self {
                available: Cell::new(true),
                held: Cell::new(false),
                native: Cell::new(NATIVE),
                revision: Cell::new(1),
                permissions: Cell::new(15),
                max_power: Cell::new(Some(1234)),
                pending: Cell::new(false),
                submissions: Cell::new(0),
            })
        }

        fn revoke(&self) -> bool {
            if self.held.get() {
                return false;
            }
            self.available.set(false);
            true
        }

        fn allows(&self, operation: Operation) -> bool {
            if self.permissions.get() & permission(operation) == 0 {
                return false;
            }
            match operation {
                Operation::Receive(_) => true,
                Operation::Transmit { profile, .. } => self
                    .max_power
                    .get()
                    .is_some_and(|limit| profile.max_eirp_mbm <= limit),
            }
        }
    }

    struct Hardware(Rc<State>);
    struct Os(Rc<State>);
    struct HardwareGuard(Rc<State>);
    struct OsGuard(Rc<State>);

    impl Drop for HardwareGuard {
        fn drop(&mut self) {
            self.0.held.set(false);
        }
    }
    impl Drop for OsGuard {
        fn drop(&mut self) {
            self.0.held.set(false);
        }
    }

    impl HardwareGuard {
        fn submit(&mut self, _: Operation) -> u32 {
            assert!(self.0.held.get());
            self.0.pending.set(true);
            let serial = self.0.submissions.get() + 1;
            self.0.submissions.set(serial);
            serial
        }
    }

    impl HardwareLease for HardwareGuard {
        fn context(&self) -> NativeContext {
            self.0.native.get()
        }
        fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
            (band == CHANNEL.band && number == CHANNEL.number).then_some(CHANNEL)
        }
        fn allows(&mut self, operation: Operation) -> bool {
            self.0.allows(operation)
        }
    }

    impl OsLease for OsGuard {
        fn revision(&self) -> u64 {
            self.0.revision.get()
        }
        fn allows(&mut self, operation: Operation) -> bool {
            self.0.allows(operation)
        }
    }

    // SAFETY: pure model's held flag serializes its only revoke/submit paths.
    // All authority data is explicit synthetic input; no physical claims are made.
    unsafe impl HardwarePolicy for Hardware {
        type Lease<'a> = HardwareGuard;
        fn acquire(&mut self) -> Option<Self::Lease<'_>> {
            (self.0.available.get() && !self.0.held.replace(true))
                .then(|| HardwareGuard(Rc::clone(&self.0)))
        }
    }

    // SAFETY: same serialized pure model, qualified only for its exact native owner.
    unsafe impl OsPolicy for Os {
        type Lease<'a> = OsGuard;
        fn acquire(&mut self, native: NativeContext) -> Option<Self::Lease<'_>> {
            (self.0.available.get() && self.0.native.get() == native && !self.0.held.replace(true))
                .then(|| OsGuard(Rc::clone(&self.0)))
        }
    }

    fn fixture() -> (Owner<Hardware, Os>, Rc<State>, Rc<State>) {
        let hardware = State::new();
        let os = State::new();
        let owner = Owner::new(Hardware(Rc::clone(&hardware)), Os(Rc::clone(&os))).unwrap();
        (owner, hardware, os)
    }

    #[test]
    fn permissions_are_independent_intersections_for_all_masks() {
        let operations = [
            Operation::Receive(CHANNEL),
            operation(Purpose::Probe),
            operation(Purpose::Management),
            operation(Purpose::Data),
        ];
        for hardware_mask in 0..16 {
            for os_mask in 0..16 {
                let (mut owner, hardware, os) = fixture();
                hardware.permissions.set(hardware_mask);
                os.permissions.set(os_mask);
                for op in operations {
                    let expected = hardware_mask & os_mask & permission(op) != 0;
                    assert_eq!(owner.admit(op).is_ok(), expected);
                    assert!(!hardware.held.get());
                    assert!(!os.held.get());
                }
            }
        }
    }

    #[test]
    fn absent_os_or_hardware_never_admits_even_passive_receive() {
        let (mut owner, hardware, os) = fixture();
        os.available.set(false);
        assert_eq!(
            owner.admit(Operation::Receive(CHANNEL)).unwrap_err(),
            Error::OsUnavailable
        );
        assert!(!hardware.held.get());
        os.available.set(true);
        hardware.available.set(false);
        assert_eq!(
            owner.admit(operation(Purpose::Data)).unwrap_err(),
            Error::HardwareUnavailable
        );
    }

    #[test]
    fn source_power_absence_and_limits_never_get_defaults() {
        let (mut owner, hardware, os) = fixture();
        for source in [&hardware, &os] {
            source.max_power.set(None);
            assert!(owner.admit(Operation::Receive(CHANNEL)).is_ok());
            for purpose in [Purpose::Probe, Purpose::Management, Purpose::Data] {
                assert!(owner.admit(operation(purpose)).is_err());
            }
            source.max_power.set(Some(1233));
            assert!(owner.admit(operation(Purpose::Data)).is_err());
            source.max_power.set(Some(1234));
            assert!(owner.admit(operation(Purpose::Data)).is_ok());
        }
    }

    #[test]
    fn no_channel_alias_six_ghz_or_invalid_rate_preamble_profile() {
        let (mut owner, _, _) = fixture();
        for channel in [
            Channel {
                frequency_mhz: 2417,
                ..CHANNEL
            },
            Channel {
                number: 2,
                ..CHANNEL
            },
            Channel {
                band: Band::Ghz6,
                ..CHANNEL
            },
        ] {
            assert!(owner.admit(Operation::Receive(channel)).is_err());
        }
        for profile in [
            TxProfile {
                short_preamble: true,
                ..PROFILE
            },
            TxProfile {
                rate: LegacyRate::Cck1,
                short_preamble: true,
                ..PROFILE
            },
        ] {
            assert_eq!(
                owner
                    .admit(Operation::Transmit {
                        channel: CHANNEL,
                        purpose: Purpose::Probe,
                        profile
                    })
                    .unwrap_err(),
                Error::Unsupported
            );
        }
        assert!(
            Operation::Transmit {
                channel: Channel {
                    band: Band::Ghz5,
                    ..CHANNEL
                },
                purpose: Purpose::Data,
                profile: TxProfile {
                    rate: LegacyRate::Cck11,
                    ..PROFILE
                },
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn preflight_traits_preserve_receive_probe_management_data_distinctions() {
        use scan::Policy;
        use station::RegulatoryPolicy;
        let (mut owner, hardware, _) = fixture();
        hardware.permissions.set(1 | 4);
        let mut view = owner.preflight(Profiles {
            probe: Some(PROFILE),
            management: Some(PROFILE),
            data: Some(PROFILE),
        });
        assert_eq!(
            view.lookup_channel(CHANNEL.band, CHANNEL.number),
            Some(CHANNEL)
        );
        assert!(view.allow_receive(CHANNEL));
        assert!(!view.allow_probe(CHANNEL));
        assert!(view.allow_management_tx(CHANNEL));
        assert!(!view.allow_data_tx(CHANNEL));
        let mut no_profiles = owner.preflight(Profiles {
            probe: None,
            management: None,
            data: None,
        });
        assert!(no_profiles.allow_receive(CHANNEL));
        assert!(!no_profiles.allow_probe(CHANNEL));
        assert!(!no_profiles.allow_management_tx(CHANNEL));
        assert!(!no_profiles.allow_data_tx(CHANNEL));
    }

    #[test]
    fn publication_refuses_cross_owner_changed_operation_profile_and_context() {
        let (mut owner, _, _) = fixture();
        let (mut other, _, _) = fixture();
        let op = operation(Purpose::Data);
        let admission = owner.admit(op).unwrap();
        // SAFETY: closure would use only the synthetic guard and exact operation.
        assert_eq!(
            unsafe { other.publish(admission, op, |_| panic!("stale publish")) },
            Err::<(), _>(Error::Stale)
        );
        for changed in [
            operation(Purpose::Probe),
            Operation::Transmit {
                channel: CHANNEL,
                purpose: Purpose::Data,
                profile: TxProfile {
                    max_eirp_mbm: 1200,
                    ..PROFILE
                },
            },
        ] {
            let admission = owner.admit(op).unwrap();
            assert_eq!(
                unsafe { owner.publish(admission, changed, |_| panic!("changed publish")) },
                Err::<(), _>(Error::Mismatch)
            );
        }
        for field in 0..4 {
            let (mut owner, hardware, os) = fixture();
            let admission = owner.admit(op).unwrap();
            let mut context = hardware.native.get();
            match field {
                0 => context.device += 1,
                1 => context.reset_epoch += 1,
                2 => context.firmware_epoch += 1,
                _ => context.policy_revision += 1,
            }
            hardware.native.set(context);
            os.native.set(context);
            assert_eq!(
                unsafe { owner.publish(admission, op, |_| panic!("context publish")) },
                Err::<(), _>(Error::Stale)
            );
        }
    }

    #[test]
    fn changed_or_revoked_policy_rechecks_before_any_submission() {
        let op = operation(Purpose::Data);
        let (mut owner, hardware, os) = fixture();
        let admission = owner.admit(op).unwrap();
        os.revision.set(2);
        assert_eq!(
            unsafe { owner.publish(admission, op, |_| panic!("old OS revision")) },
            Err::<(), _>(Error::Stale)
        );
        let admission = owner.admit(op).unwrap();
        // Even an incorrectly unchanged source revision cannot bypass live denial.
        hardware.permissions.set(1);
        assert_eq!(
            unsafe { owner.publish(admission, op, |_| panic!("hardware revoked")) },
            Err::<(), _>(Error::HardwareDenied)
        );
        hardware.permissions.set(15);
        let admission = owner.admit(op).unwrap();
        assert!(os.revoke());
        assert_eq!(
            unsafe { owner.publish(admission, op, |_| panic!("OS revoked")) },
            Err::<(), _>(Error::OsUnavailable)
        );
        assert_eq!(owner.admit(op).unwrap_err(), Error::OsUnavailable);
        assert_eq!(hardware.submissions.get(), 0);
    }

    #[test]
    fn both_guards_cover_native_publication_but_do_not_claim_queued_air_retirement() {
        let (mut owner, hardware, os) = fixture();
        let op = operation(Purpose::Data);
        let admission = owner.admit(op).unwrap();
        // SAFETY: callback uses the passed native model guard and exact operation.
        let result = unsafe {
            owner.publish(admission, op, |guard| {
                assert!(hardware.held.get());
                assert!(os.held.get());
                assert!(!hardware.revoke());
                assert!(!os.revoke());
                guard.submit(op)
            })
        };
        assert_eq!(result, Ok(1));
        assert!(!hardware.held.get());
        assert!(!os.held.get());
        assert!(hardware.pending.get());
        assert!(hardware.revoke());
        assert!(owner.admit(op).is_err());
        // Actual completion/cancel/drain is still a separate vendor obligation.
        assert!(hardware.pending.get());
        hardware.pending.set(false);
    }

    #[test]
    fn native_submission_failure_is_returned_with_both_guards_released() {
        let (mut owner, hardware, os) = fixture();
        let op = operation(Purpose::Data);
        let admission = owner.admit(op).unwrap();
        // SAFETY: no hardware is submitted; model guard covers the exact attempt.
        let result =
            unsafe { owner.publish(admission, op, |_| Err::<(), _>("actual native failure")) };
        assert_eq!(result, Ok(Err("actual native failure")));
        assert!(!hardware.held.get());
        assert!(!os.held.get());
        assert_eq!(hardware.submissions.get(), 0);
    }
}
