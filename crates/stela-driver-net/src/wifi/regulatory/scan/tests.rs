use super::*;
use crate::wifi::{
    Band, Channel,
    regulatory::{HardwareLease, HardwarePolicy, LegacyRate, OsPolicy, Width},
};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
const FIRST: Channel = Channel {
    band: Band::Ghz2,
    number: 1,
    frequency_mhz: 2412,
};
const SECOND: Channel = Channel {
    band: Band::Ghz2,
    number: 6,
    frequency_mhz: 2437,
};
const NATIVE: NativeContext = NativeContext {
    device: 3,
    reset_epoch: 4,
    firmware_epoch: 5,
    policy_revision: 6,
};
const PROFILE: TxProfile = TxProfile {
    width: Width::Legacy20,
    rate: LegacyRate::Ofdm6,
    short_preamble: false,
    max_eirp_mbm: 1700,
};
#[derive(Clone)]
struct Model {
    native: Rc<Cell<NativeContext>>,
    revision: Rc<Cell<u64>>,
    hardware_available: Rc<Cell<bool>>,
    os_available: Rc<Cell<bool>>,
    hardware_denied: Rc<Cell<Option<u16>>>,
    os_denied: Rc<Cell<Option<u16>>>,
    hardware_held: Rc<Cell<bool>>,
    os_held: Rc<Cell<bool>>,
    hardware_acquires: Rc<Cell<usize>>,
    os_acquires: Rc<Cell<usize>>,
    events: Rc<RefCell<Vec<&'static str>>>,
    checked: Rc<RefCell<Vec<Operation>>>,
}
impl Default for Model {
    fn default() -> Self {
        Self {
            native: Rc::new(Cell::new(NATIVE)),
            revision: Rc::new(Cell::new(9)),
            hardware_available: Rc::new(Cell::new(true)),
            os_available: Rc::new(Cell::new(true)),
            hardware_denied: Rc::new(Cell::new(None)),
            os_denied: Rc::new(Cell::new(None)),
            hardware_held: Rc::new(Cell::new(false)),
            os_held: Rc::new(Cell::new(false)),
            hardware_acquires: Rc::new(Cell::new(0)),
            os_acquires: Rc::new(Cell::new(0)),
            events: Rc::new(RefCell::new(Vec::new())),
            checked: Rc::new(RefCell::new(Vec::new())),
        }
    }
}
struct Hardware(Model);
struct Os(Model);
struct HardwareGuard<'a>(&'a Model);
struct OsGuard<'a>(&'a Model);
impl Drop for HardwareGuard<'_> {
    fn drop(&mut self) {
        assert!(!self.0.os_held.get());
        self.0.hardware_held.set(false);
        self.0.events.borrow_mut().push("drop hardware");
    }
}
impl Drop for OsGuard<'_> {
    fn drop(&mut self) {
        assert!(self.0.hardware_held.get());
        self.0.os_held.set(false);
        self.0.events.borrow_mut().push("drop OS");
    }
}
impl HardwareLease for HardwareGuard<'_> {
    fn context(&self) -> NativeContext {
        self.0.native.get()
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        [FIRST, SECOND]
            .into_iter()
            .find(|ch| ch.band == band && ch.number == number)
    }
    fn allows(&mut self, operation: Operation) -> bool {
        assert!(self.0.hardware_held.get() && self.0.os_held.get());
        self.0.checked.borrow_mut().push(operation);
        if self.0.hardware_denied.get() == Some(operation.channel().number) {
            return false;
        }
        match operation {
            Operation::Receive(_) => true,
            Operation::Transmit {
                purpose, profile, ..
            } => purpose == Purpose::Probe && profile == PROFILE,
        }
    }
}
impl OsLease for OsGuard<'_> {
    fn revision(&self) -> u64 {
        self.0.revision.get()
    }
    fn allows(&mut self, operation: Operation) -> bool {
        assert!(self.0.hardware_held.get() && self.0.os_held.get());
        self.0.os_denied.get() != Some(operation.channel().number)
    }
}
// SAFETY: bounded permission/ordering model with no physical device.
unsafe impl HardwarePolicy for Hardware {
    type Lease<'a> = HardwareGuard<'a>;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        assert!(!self.0.hardware_held.get() && !self.0.os_held.get());
        self.0
            .hardware_acquires
            .set(self.0.hardware_acquires.get() + 1);
        self.0.events.borrow_mut().push("acquire hardware");
        if !self.0.hardware_available.get() {
            return None;
        }
        self.0.hardware_held.set(true);
        Some(HardwareGuard(&self.0))
    }
}
// SAFETY: modeled native context and live revision; no real OS grant.
unsafe impl OsPolicy for Os {
    type Lease<'a> = OsGuard<'a>;
    fn acquire(&mut self, native: NativeContext) -> Option<Self::Lease<'_>> {
        assert!(self.0.hardware_held.get() && !self.0.os_held.get());
        assert_eq!(native, self.0.native.get());
        self.0.os_acquires.set(self.0.os_acquires.get() + 1);
        self.0.events.borrow_mut().push("acquire OS");
        if !self.0.os_available.get() {
            return None;
        }
        self.0.os_held.set(true);
        Some(OsGuard(&self.0))
    }
}
fn owner(model: &Model) -> Owner<Hardware, Os> {
    Owner::new(Hardware(model.clone()), Os(model.clone())).unwrap()
}
fn request(active: bool) -> Request {
    Request::new(
        vec![FIRST, SECOND],
        if active { vec![Vec::new()] } else { Vec::new() },
        Vec::new(),
    )
    .unwrap()
}
#[test]
fn exact_request_and_every_channel_share_one_pair_of_guards_through_native_result() {
    for active in [false, true] {
        let model = Model::default();
        let mut owner = owner(&model);
        let request = request(active);
        let admission = owner
            .admit_scan(&request, active.then_some(PROFILE))
            .unwrap();
        assert!(!core::ptr::eq(admission.operation().request(), &request));
        assert_eq!(
            admission.operation().request().channels(),
            request.channels()
        );
        assert_eq!(admission.operation().request().ssids(), request.ssids());
        assert_eq!(
            admission.operation().request().extra_elements(),
            request.extra_elements()
        );
        assert_eq!(admission.operation().request().six_ghz(), request.six_ghz());
        assert!(!model.hardware_held.get() && !model.os_held.get());
        assert_eq!(model.hardware_acquires.get(), 1);
        assert_eq!(model.os_acquires.get(), 1);
        // SAFETY: the admission belongs to this test, and the callback runs synchronously on
        // this thread.
        let result = unsafe {
            owner.publish_scan(admission, |guard, operation| {
                assert_eq!(guard.context(), NATIVE);
                assert!(model.hardware_held.get() && model.os_held.get());
                assert_eq!(operation.request().channels(), request.channels());
                assert_eq!(operation.request().ssids(), request.ssids());
                assert_eq!(operation.probe_profile(), active.then_some(PROFILE));
                model.events.borrow_mut().push("publish");
                Err::<(), _>(0x91u32)
            })
        }
        .unwrap();
        assert_eq!(result, Err(0x91));
        assert_eq!(model.hardware_acquires.get(), 2);
        assert_eq!(model.os_acquires.get(), 2);
        assert!(!model.hardware_held.get() && !model.os_held.get());
        let mut expected = Vec::new();
        for channel in [FIRST, SECOND] {
            expected.push(Operation::Receive(channel));
            if active {
                expected.push(Operation::Transmit {
                    channel,
                    purpose: Purpose::Probe,
                    profile: PROFILE,
                });
            }
        }
        expected.extend(expected.clone());
        assert_eq!(*model.checked.borrow(), expected);
        assert_eq!(
            *model.events.borrow(),
            [
                "acquire hardware",
                "acquire OS",
                "drop OS",
                "drop hardware",
                "acquire hardware",
                "acquire OS",
                "publish",
                "drop OS",
                "drop hardware"
            ]
        );
    }
}
#[test]
fn later_channel_failure_and_active_profile_never_publish_a_partial_scan() {
    for hardware in [false, true] {
        let model = Model::default();
        let mut owner = owner(&model);
        let request = request(false);
        let admission = owner.admit_scan(&request, None).unwrap();
        if hardware {
            model.hardware_denied.set(Some(SECOND.number));
        } else {
            model.os_denied.set(Some(SECOND.number));
        }
        assert_eq!(
            // SAFETY: the admission belongs to this test, and the callback runs synchronously
            // on this thread.
            unsafe {
                owner.publish_scan(admission, |_, _| -> () {
                    panic!("partial request publication")
                })
            },
            Err(if hardware {
                Error::HardwareDenied
            } else {
                Error::OsDenied
            })
        );
        assert_eq!(model.hardware_acquires.get(), 2);
        assert_eq!(model.os_acquires.get(), 2);
        assert!(!model.hardware_held.get() && !model.os_held.get());
    }
    let model = Model::default();
    let mut owner = owner(&model);
    let passive = request(false);
    assert!(matches!(
        owner.admit_scan(&passive, Some(PROFILE)),
        Err(Error::Mismatch)
    ));
    let request = request(true);
    assert!(matches!(
        owner.admit_scan(&request, None),
        Err(Error::Unsupported)
    ));
    let mut wrong = PROFILE;
    wrong.max_eirp_mbm += 1;
    assert!(matches!(
        owner.admit_scan(&request, Some(wrong)),
        Err(Error::HardwareDenied)
    ));
    let six = Request::new(
        vec![
            FIRST,
            Channel {
                band: Band::Ghz6,
                number: 1,
                frequency_mhz: 5955,
            },
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        owner.admit_scan(&six, None),
        Err(Error::Unsupported)
    ));
}
#[test]
fn revocation_epochs_other_owner_and_missing_services_refuse_before_callback() {
    for case in 0..5 {
        let model = Model::default();
        let mut original = owner(&model);
        let request = request(false);
        let admission = original.admit_scan(&request, None).unwrap();
        let expected = match case {
            0 => {
                model.revision.set(10);
                Error::Stale
            }
            1 => {
                let mut native = NATIVE;
                native.policy_revision += 1;
                model.native.set(native);
                Error::Stale
            }
            2 => {
                model.hardware_available.set(false);
                Error::HardwareUnavailable
            }
            3 => {
                model.os_available.set(false);
                Error::OsUnavailable
            }
            _ => Error::Stale,
        };
        let mut other = owner(&model);
        let target = if case == 4 { &mut other } else { &mut original };
        assert_eq!(
            // SAFETY: the admission belongs to this test, and the callback runs synchronously
            // on this thread.
            unsafe {
                target.publish_scan(admission, |_, _| -> () { panic!("revoked publication") })
            },
            Err(expected)
        );
        assert!(!model.hardware_held.get() && !model.os_held.get());
        if case == 4 {
            assert_eq!(model.hardware_acquires.get(), 1);
            assert_eq!(model.os_acquires.get(), 1);
        }
    }
}
#[test]
fn owned_snapshot_preserves_every_nested_byte_and_six_ghz_field_after_input_drop() {
    let six_channel = Channel {
        band: Band::Ghz6,
        number: 1,
        frequency_mhz: 5955,
    };
    let target = SixGhz {
        channel_index: 0,
        bssid: crate::Mac([2, 3, 4, 5, 6, 7]),
        short_ssid: Some(0xdeadbeef),
        unsolicited_probe: true,
        psc_no_listen: true,
        psd_20: -77,
    };
    let copied = {
        let original = Request::with_six_ghz(
            vec![six_channel],
            vec![vec![0, 255, 1]],
            vec![221, 3, 1, 2, 3],
            vec![target],
        )
        .unwrap();
        let copied = snapshot(&original).unwrap();
        assert!(!core::ptr::eq(
            copied.ssids()[0].as_ptr(),
            original.ssids()[0].as_ptr()
        ));
        copied
    };
    assert_eq!(copied.channels(), [six_channel]);
    assert_eq!(copied.ssids(), [vec![0, 255, 1]]);
    assert_eq!(copied.extra_elements(), [221, 3, 1, 2, 3]);
    assert_eq!(copied.six_ghz(), [target]);
    let model = Model::default();
    let mut owner = owner(&model);
    let admission = {
        let original = request(false);
        owner.admit_scan(&original, None).unwrap()
    };
    // SAFETY: the admission belongs to this test, and the callback runs synchronously on this
    // thread.
    unsafe {
        owner.publish_scan(admission, |_, operation| {
            assert_eq!(operation.request().channels(), [FIRST, SECOND])
        })
    }
    .unwrap();
}
#[test]
fn every_snapshot_allocation_length_is_checked_against_canonical_request_limits() {
    let ssids = vec![vec![0; crate::wifi::network::SSID_BYTES]; protocol::MAX_SSIDS];
    let channels = vec![FIRST; protocol::MAX_CHANNELS];
    let elements = vec![0; protocol::MAX_EXTRA_ELEMENTS];
    let target = SixGhz {
        channel_index: 0,
        bssid: crate::Mac([2; 6]),
        short_ssid: None,
        unsolicited_probe: false,
        psc_no_listen: false,
        psd_20: 0,
    };
    let six = vec![target; protocol::MAX_SIX_GHZ];
    assert_eq!(validate_lengths(&channels, &ssids, &elements, &six), Ok(()));
    assert_eq!(validate_lengths(&[], &[], &[], &[]), Err(Error::Mismatch));
    assert_eq!(
        validate_lengths(&vec![FIRST; protocol::MAX_CHANNELS + 1], &[], &[], &[]),
        Err(Error::Mismatch)
    );
    assert_eq!(
        validate_lengths(
            &[FIRST],
            &vec![Vec::new(); protocol::MAX_SSIDS + 1],
            &[],
            &[]
        ),
        Err(Error::Mismatch)
    );
    assert_eq!(
        validate_lengths(
            &[FIRST],
            &[vec![0; crate::wifi::network::SSID_BYTES + 1]],
            &[],
            &[]
        ),
        Err(Error::Mismatch)
    );
    assert_eq!(
        validate_lengths(
            &[FIRST],
            &[],
            &vec![0; protocol::MAX_EXTRA_ELEMENTS + 1],
            &[]
        ),
        Err(Error::Mismatch)
    );
    assert_eq!(
        validate_lengths(&[FIRST], &[], &[], &vec![target; protocol::MAX_SIX_GHZ + 1]),
        Err(Error::Mismatch)
    );
}
struct ProtocolPolicy;
impl protocol::Policy for ProtocolPolicy {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        [FIRST, SECOND].contains(&channel)
    }
    fn allow_probe(&mut self, channel: Channel) -> bool {
        self.allow_receive(channel)
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        [FIRST, SECOND]
            .into_iter()
            .find(|c| c.band == band && c.number == number)
    }
}
#[test]
fn scanner_handoff_occurs_inside_guards_and_failed_admission_keeps_unsubmitted_request() {
    let model = Model::default();
    let mut owner = owner(&model);
    let mut scanner = protocol::Scanner::new(crate::Mac([2, 3, 4, 5, 6, 7])).unwrap();
    let ticket = scanner
        .begin(request(false), 0, 1000, &mut ProtocolPolicy)
        .unwrap();
    let admission = owner.admit_scan(scanner.request().unwrap(), None).unwrap();
    model.os_denied.set(Some(SECOND.number));
    assert_eq!(
        // SAFETY: the admission belongs to this test, and the callback runs synchronously on
        // this thread.
        unsafe { owner.publish_scan(admission, |_, _| -> () { panic!("partial scan") }) },
        Err(Error::OsDenied)
    );
    assert_eq!(scanner.phase(), protocol::Phase::Starting);
    model.os_denied.set(None);
    let admission = owner.admit_scan(scanner.request().unwrap(), None).unwrap();
    // SAFETY: the admission belongs to this test, and the callback runs synchronously on this
    // thread.
    let actual = unsafe {
        owner.publish_scan(admission, |_, operation| {
            assert!(model.hardware_held.get() && model.os_held.get());
            assert_eq!(
                operation.request().channels(),
                scanner.request().unwrap().channels()
            );
            scanner.submitted(ticket).unwrap();
            Err::<(), _>(0x92u32)
        })
    }
    .unwrap();
    assert_eq!(actual, Err(0x92));
    // Actual/uncertain publication must keep submitted request state.
    // Admission release is never command completion, cancellation or drain.
    assert_eq!(scanner.phase(), protocol::Phase::Submitted);
    assert!(scanner.request().is_some());
}
