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
    let result = unsafe { owner.publish(admission, op, |_| Err::<(), _>("actual native failure")) };
    assert_eq!(result, Ok(Err("actual native failure")));
    assert!(!hardware.held.get());
    assert!(!os.held.get());
    assert_eq!(hardware.submissions.get(), 0);
}
