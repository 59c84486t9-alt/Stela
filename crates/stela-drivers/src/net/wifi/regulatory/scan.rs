//! Exact-request, multi-channel scan admission and guarded native publication.
//!
//! Every requested receive channel and active probe profile is checked while
//! one original hardware lease and then one OS lease remain held. This issues
//! no completion, cancellation or retirement proof for firmware-owned work.
use super::{
    Error, HardwarePolicy, NativeContext, Operation, OsLease, OsPolicy, Owner, Purpose, TxProfile,
    check,
};
use crate::net::wifi::{
    Channel,
    scan::{self as protocol, Request, SixGhz},
};
use alloc::vec::Vec;

/// Exact immutable request snapshot and its qualified active-probe profile. This
/// is an operation description, never a stand-alone device or radio permit.
#[derive(Clone, Copy, Debug)]
pub struct ScanOperation<'a> {
    request: &'a Request,
    probe: Option<TxProfile>,
}
impl<'a> ScanOperation<'a> {
    pub fn request(self) -> &'a Request {
        self.request
    }
    pub fn probe_profile(self) -> Option<TxProfile> {
        self.probe
    }
}
/// Single-use admission owning the complete immutable request snapshot.
/// Publication takes no replacement request/profile; its callback receives this
/// exact one. The snapshot is input data: original native/OS guards supply the
/// authority. Owning it permits the vendor to mark its Scanner submitted inside
/// the guarded native handoff without aliasing Scanner::request().
///
/// ```compile_fail
/// use stela_drivers::net::wifi::regulatory::ScanAdmission;
/// let admission = ScanAdmission { owner: 1 };
/// ```
#[derive(Debug)]
pub struct ScanAdmission {
    owner: u64,
    native: NativeContext,
    os_revision: u64,
    request: Request,
    probe: Option<TxProfile>,
}
impl ScanAdmission {
    pub fn operation(&self) -> ScanOperation<'_> {
        ScanOperation {
            request: &self.request,
            probe: self.probe,
        }
    }
}
fn validate_lengths(
    channels: &[Channel],
    ssids: &[Vec<u8>],
    elements: &[u8],
    six_ghz: &[SixGhz],
) -> Result<(), Error> {
    if channels.is_empty()
        || channels.len() > protocol::MAX_CHANNELS
        || ssids.len() > protocol::MAX_SSIDS
        || ssids
            .iter()
            .any(|ssid| ssid.len() > protocol::MAX_SSID_BYTES)
        || elements.len() > protocol::MAX_EXTRA_ELEMENTS
        || six_ghz.len() > protocol::MAX_SIX_GHZ
    {
        return Err(Error::Mismatch);
    }
    Ok(())
}
fn snapshot(request: &Request) -> Result<Request, Error> {
    // Bound every nested allocation before allocating even the first channel.
    validate_lengths(
        request.channels(),
        request.ssids(),
        request.extra_elements(),
        request.six_ghz(),
    )?;
    request.try_snapshot().map_err(|_| Error::NoMemory)
}
fn check_request(
    hardware: &mut impl super::HardwareLease,
    os: &mut impl OsLease,
    operation: ScanOperation<'_>,
) -> Result<(), Error> {
    if operation.request.active() != operation.probe.is_some() {
        return Err(if operation.request.active() {
            Error::Unsupported
        } else {
            Error::Mismatch
        });
    }
    for &channel in operation.request.channels() {
        check(hardware, os, Operation::Receive(channel))?;
        if operation.request.active() {
            check(
                hardware,
                os,
                Operation::Transmit {
                    channel,
                    purpose: Purpose::Probe,
                    profile: operation.probe.ok_or(Error::Unsupported)?,
                },
            )?;
        }
    }
    Ok(())
}
impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    /// Check the complete request under one hardware then OS lease pair.
    /// Individual preflight channel checks cannot replace this admission.
    pub fn admit_scan(
        &mut self,
        request: &Request,
        probe: Option<TxProfile>,
    ) -> Result<ScanAdmission, Error> {
        let request = snapshot(request)?;
        let operation = ScanOperation {
            request: &request,
            probe,
        };
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = super::HardwareLease::context(&hardware);
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        check_request(&mut hardware, &mut os, operation)?;
        Ok(ScanAdmission {
            owner: self.identity,
            native,
            os_revision: os.revision(),
            request,
            probe,
        })
    }
    /// Recheck every operation for the same immutable request and same native
    /// context/OS revision; retain both genuine leases across native submission.
    /// # Safety
    /// The callback must encode the supplied exact request/profile and publish
    /// through this concrete hardware guard's actual native owner. It may not
    /// target another requester or supply an unqualified firmware rate/power,
    /// active/passive, channel/width or probe-frame variation. Revocation must
    /// enforce the providers' existing pending/autonomous-work stop/drain
    /// contracts after publication; closure return is no terminal completion.
    pub unsafe fn publish_scan<'hardware, T>(
        &'hardware mut self,
        admission: ScanAdmission,
        submit: impl FnOnce(&mut H::Lease<'hardware>, ScanOperation<'_>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = super::HardwareLease::context(&hardware);
        if admission.native != native {
            return Err(Error::Stale);
        }
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        if admission.os_revision != os.revision() {
            return Err(Error::Stale);
        }
        let operation = admission.operation();
        check_request(&mut hardware, &mut os, operation)?;
        let result = submit(&mut hardware, operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wifi::{
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
    // SAFETY: bounded authority/ordering model with no physical device.
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
    // SAFETY: exact modeled native context and live revision; no real OS grant.
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
            bssid: crate::net::Mac([2, 3, 4, 5, 6, 7]),
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
        let ssids = vec![vec![0; protocol::MAX_SSID_BYTES]; protocol::MAX_SSIDS];
        let channels = vec![FIRST; protocol::MAX_CHANNELS];
        let elements = vec![0; protocol::MAX_EXTRA_ELEMENTS];
        let target = SixGhz {
            channel_index: 0,
            bssid: crate::net::Mac([2; 6]),
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
            validate_lengths(&[FIRST], &[vec![0; protocol::MAX_SSID_BYTES + 1]], &[], &[]),
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
        let mut scanner = protocol::Scanner::new(crate::net::Mac([2, 3, 4, 5, 6, 7])).unwrap();
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
        // Actual/uncertain publication must retain submitted request state.
        // Admission release is never command completion, cancellation or drain.
        assert_eq!(scanner.phase(), protocol::Phase::Submitted);
        assert!(scanner.request().is_some());
    }
}
