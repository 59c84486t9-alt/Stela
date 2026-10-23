use super::*;
use crate::{
    firmware::{Catalog, Image, Provenance, Provider, Requirement, Resource},
    usb::bluetooth::Pipe,
};
use alloc::{collections::VecDeque, rc::Rc, string::String};
use core::cell::{Cell, RefCell};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    Read(u8, Vec<u8>),
    Write(u8, Vec<u8>),
    Body(Vec<u8>),
}
#[derive(Default)]
struct Trace {
    steps: Vec<(u64, Step)>,
    closed: usize,
}
struct Model {
    steps: VecDeque<Step>,
    trace: Rc<RefCell<Trace>>,
    clock: Cell<u64>,
    fail: Option<usize>,
    close_error: bool,
}
impl Model {
    fn step(&mut self, actual: Step) -> core::result::Result<Vec<u8>, BlockError> {
        assert_eq!(self.trace.borrow().closed, 0);
        let expected = self
            .steps
            .pop_front()
            .expect("unexpected raw USB operation");
        let bytes = match (&actual, expected) {
            (Step::Read(a, _), Step::Read(e, bytes)) => {
                assert_eq!(*a, e);
                bytes
            }
            (Step::Write(a, b), Step::Write(e, bytes)) => {
                assert_eq!(*a, e);
                assert_eq!(*b, bytes);
                Vec::new()
            }
            (Step::Body(a), Step::Body(b)) => {
                assert_eq!(*a, b);
                Vec::new()
            }
            other => panic!("wrong raw USB operation {other:?}"),
        };
        self.trace
            .borrow_mut()
            .steps
            .push((self.clock.get(), actual));
        if self.fail == Some(self.trace.borrow().steps.len()) {
            Err(BlockError::Device { status: 0x55 })
        } else {
            Ok(bytes)
        }
    }
}
impl Io for Model {
    fn control(&mut self, s: [u8; 8], data: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(s[0], 0x40);
        assert_eq!(s[2..6], [0, 0, 0, 0]);
        assert_eq!(usize::from(u16::from_le_bytes([s[6], s[7]])), data.len());
        self.step(Step::Write(s[1], data.to_vec())).map(|_| ())
    }
    fn control_read(&mut self, s: [u8; 8]) -> core::result::Result<Vec<u8>, BlockError> {
        assert_eq!(s[0], 0xc0);
        assert_eq!(s[2..6], [0, 0, 0, 0]);
        assert_eq!(
            u16::from_le_bytes([s[6], s[7]]),
            if s[1] == 5 { 1 } else { 20 }
        );
        self.step(Step::Read(s[1], Vec::new()))
    }
    fn write_firmware(&mut self, b: &[u8], timeout: u64) -> core::result::Result<(), BlockError> {
        assert_eq!(timeout, 3_000_000);
        assert!((1..=4096).contains(&b.len()));
        self.step(Step::Body(b.to_vec())).map(|_| ())
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        panic!("raw bootloader cannot send HCI")
    }
    fn receive(&mut self, _: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        panic!("raw bootloader has no HCI receive")
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        panic!("raw bootloader has no posted receive")
    }
    fn close(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().closed += 1;
        if self.close_error {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn now_us(&self) -> u64 {
        let t = self.clock.get();
        self.clock.set(t.wrapping_add(1));
        t
    }
}
fn device(kind: Kind, revision: u16) -> Device {
    // Intentionally raw vendor interface: no interrupt IN or bulk IN exists.
    let config = vec![
        9, 2, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 0xff, 0, 0, 0, 7, 5, 2, 2, 64, 0, 0,
    ];
    let (v, p) = if kind == Kind::Ar3011 {
        (0x0cf3u16, 0x3000u16)
    } else {
        (0x0489, 0xe04d)
    };
    let mut descriptor = [18, 1, 0, 2, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    descriptor[8..10].copy_from_slice(&v.to_le_bytes());
    descriptor[10..12].copy_from_slice(&p.to_le_bytes());
    descriptor[12..14].copy_from_slice(&revision.to_le_bytes());
    Device {
        id: crate::usb::xhci::SlotId::fixture(1),
        vendor_ethernet_revision: None,
        vendor_ethernet_tcr: None,
        slot: 1,
        speed: xhci::FULL_SPEED,
        location: "ATH3K independent bootloader model".into(),
        descriptor,
        configurations: vec![config.clone()],
        configuration: config,
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
    }
}
fn version(build: u32, clock: u8) -> Version {
    let mut raw = [0; 20];
    raw[..4].copy_from_slice(&0x01020201u32.to_le_bytes());
    raw[4..8].copy_from_slice(&build.to_le_bytes());
    raw[8..12].copy_from_slice(&0x3344u32.to_le_bytes());
    raw[12] = clock;
    Version { raw }
}
fn resource<'a>(
    name: &'a str,
    hardware: &'a str,
    revision: &'a str,
    bytes: Vec<u8>,
) -> Resource<'a> {
    Resource {
        name,
        target: identity::target(hardware, revision),
        provenance: Provenance {
            source: "independent raw USB firmware model",
            revision: "ath3k-model-v1",
            member: name,
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    }
}
fn image(body: usize) -> Vec<u8> {
    let mut b = vec![0x5a; 20 + body];
    let n = b.len();
    b[n - 8..n - 4].copy_from_slice(&version(1, 0).rom().to_le_bytes());
    b[n - 4..].copy_from_slice(&2u32.to_le_bytes());
    b
}
fn transfer(steps: &mut VecDeque<Step>, bytes: &[u8]) {
    steps.push_back(Step::Write(1, bytes[..20].to_vec()));
    for chunk in bytes[20..].chunks(4096) {
        steps.push_back(Step::Body(chunk.to_vec()));
    }
}
fn model(
    kind: Kind,
    status: u8,
    normal: bool,
    clock: u8,
    body: usize,
) -> (Bootloader<Model>, Catalog, Rc<RefCell<Trace>>) {
    let device = device(kind, 1);
    let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
    let hardware = UsbIdentity::read(&device).hardware();
    let patch = image(body);
    let config = vec![0xa5; 20 + body];
    let before = version(1, clock);
    let after = version(if status & 0x80 == 0 { 2 } else { 1 }, clock);
    let patch_name = before.patch_name();
    let config_name = after.config_name();
    let before_rev = before.revision();
    let after_rev = after.revision();
    let mut steps = VecDeque::new();
    let resources = if kind == Kind::Ar3011 {
        transfer(&mut steps, &patch);
        vec![resource(
            "ath3k-1.fw",
            &hardware,
            "ar3011-monolithic",
            patch,
        )]
    } else {
        steps.push_back(Step::Read(5, vec![status]));
        if status & 0x80 == 0 {
            steps.push_back(Step::Read(9, before.raw.to_vec()));
            transfer(&mut steps, &patch);
        }
        steps.push_back(Step::Read(5, vec![status | 0x80]));
        steps.push_back(Step::Read(9, after.raw.to_vec()));
        transfer(&mut steps, &config);
        steps.push_back(Step::Read(5, vec![if normal { 0xce } else { 0xc0 }]));
        if !normal {
            steps.push_back(Step::Write(7, vec![]));
        }
        steps.push_back(Step::Write(0x0a, vec![]));
        vec![
            resource(&patch_name, &hardware, &before_rev, patch),
            resource(&config_name, &hardware, &after_rev, config),
        ]
    };
    let catalog = Catalog::from_handoff(resources).unwrap();
    let trace = Rc::new(RefCell::new(Trace::default()));
    (
        Bootloader::from_io(
            binding,
            Model {
                steps,
                trace: trace.clone(),
                clock: Cell::new(0),
                fail: None,
                close_error: false,
            },
        ),
        catalog,
        trace,
    )
}
fn attempt(e: &Error) -> (&Error, &Attempt) {
    match e {
        Error::Attempt { cause, observation } => (cause, observation),
        Error::Cleanup { cause, .. } => attempt(cause),
        other => panic!("missing observations {other:?}"),
    }
}
#[test]
fn source_alias_revision_and_actual_raw_interface_selection_is_exact() {
    assert_eq!(SOURCE_USB_IDS.len(), 62);
    assert_eq!(
        SOURCE_USB_IDS
            .iter()
            .filter(|(_, _, k)| *k == Kind::Ar3012)
            .count(),
        52
    );
    for &(v, p, k) in SOURCE_USB_IDS {
        assert_eq!(
            UsbIdentity {
                vendor: v,
                product: p,
                revision: 1
            }
            .kind(),
            Some(k)
        );
        assert_eq!(
            UsbIdentity {
                vendor: v,
                product: p,
                revision: 2
            }
            .kind(),
            if k == Kind::Ar3012 { None } else { Some(k) }
        );
    }
    assert_eq!(
        UsbIdentity {
            vendor: 0x0cf3,
            product: 0xffff,
            revision: 1
        }
        .kind(),
        None
    );
    for kind in [Kind::Ar3011, Kind::Ar3012] {
        let d = device(kind, 1);
        let mut i = xhci::interfaces(&d.configuration)[0].clone();
        assert!(Binding::new(&d, &i).is_ok());
        i.number = 1;
        assert!(Binding::new(&d, &i).is_err());
        let mut d = d.clone();
        d.configuration[20] = 3;
        let i = &xhci::interfaces(&d.configuration)[0];
        assert!(Binding::new(&d, i).is_err());
    }
    let d = device(Kind::Ar3012, 2);
    assert!(Binding::new(&d, &xhci::interfaces(&d.configuration)[0]).is_err());
}
#[test]
fn monolithic_and_split_images_complete_real_raw_protocol_with_exact_body_boundaries() {
    for kind in [Kind::Ar3011, Kind::Ar3012] {
        for body in [0, 1, 4095, 4096, 4097, 8193] {
            for status in [0, 0x40, 0x80, 0xc0] {
                let (mut owner, catalog, trace) = model(kind, status, false, 0, body);
                let report = owner.initialize_with_provider(&catalog).unwrap();
                assert_eq!(report.kind, kind);
                assert!(report.observation.pending.is_none());
                assert_eq!(
                    report.observation.patch_already_present,
                    kind == Kind::Ar3012 && status & 0x80 != 0
                );
                assert!(owner.io.steps.is_empty());
                assert_eq!(owner.state(), State::AwaitingReenumeration);
                let trace = trace.borrow();
                assert_eq!(trace.closed, 1);
                for pair in trace.steps.windows(2) {
                    if matches!(pair[1].1, Step::Body(_)) {
                        assert!(pair[1].0 - pair[0].0 >= 50);
                    }
                }
                if kind == Kind::Ar3012 {
                    assert!(
                        trace
                            .steps
                            .iter()
                            .any(|(_, s)| matches!(s,Step::Write(1,b) if b[0]==0xa5))
                    );
                    assert!(matches!(
                        trace.steps.last().unwrap().1,
                        Step::Write(0x0a, _)
                    ));
                }
            }
        }
    }
}
struct Recording<'a> {
    catalog: &'a Catalog,
    names: RefCell<Vec<String>>,
}
impl Provider for Recording<'_> {
    fn load(&self, r: Requirement<'_>) -> core::result::Result<Image<'_>, crate::firmware::Error> {
        self.names.borrow_mut().push(r.name.into());
        self.catalog.load(r)
    }
}
#[test]
fn crystal_selection_syscfg_always_loads_and_normal_mode_is_not_resubmitted() {
    for (clock, expected) in [(0, 26), (1, 40), (2, 19), (3, 0), (255, 0)] {
        let (mut owner, catalog, trace) = model(Kind::Ar3012, 0xc0, true, clock, 1);
        let recording = Recording {
            catalog: &catalog,
            names: RefCell::new(Vec::new()),
        };
        let report = owner.initialize_with_provider(&recording).unwrap();
        assert!(report.observation.patch.is_none());
        assert!(report.observation.configuration.is_some());
        assert_eq!(
            *recording.names.borrow(),
            [alloc::format!("ar3k/ramps_0x01020201_{expected}.dfu")]
        );
        assert!(
            !trace
                .borrow()
                .steps
                .iter()
                .any(|(_, s)| matches!(s, Step::Write(7, _)))
        );
        let count = trace.borrow().steps.len();
        owner.initialize_with_provider(&recording).unwrap();
        assert_eq!(trace.borrow().steps.len(), count);
        assert_eq!(trace.borrow().closed, 1);
    }
}
#[test]
fn every_operation_failure_is_terminal_and_retains_pending_bytes_and_first_error() {
    for kind in [Kind::Ar3011, Kind::Ar3012] {
        let (owner, _, _) = model(kind, 0, false, 0, 4097);
        let operations = owner.io.steps.len();
        for failed in 1..=operations {
            let (mut owner, catalog, trace) = model(kind, 0, false, 0, 4097);
            owner.io.fail = Some(failed);
            owner.io.close_error = true;
            let error = owner.initialize_with_provider(&catalog).unwrap_err();
            let (cause, obs) = attempt(error);
            assert!(matches!(
                cause,
                Error::Usb(BlockError::Device { status: 0x55 })
            ));
            assert!(matches!(
                error,
                Error::Cleanup {
                    cleanup: BlockError::Timeout,
                    ..
                }
            ));
            assert_eq!(
                obs.pending.is_some(),
                matches!(
                    trace.borrow().steps.last().unwrap().1,
                    Step::Write(..) | Step::Body(_)
                )
            );
            assert_eq!(owner.state(), State::Failed);
            let count = trace.borrow().steps.len();
            assert!(owner.initialize_with_provider(&catalog).is_err());
            assert_eq!(trace.borrow().steps.len(), count);
            assert_eq!(trace.borrow().closed, 1);
        }
    }
}
#[test]
fn missing_resource_short_control_and_unapplied_patch_never_advance_to_identity_switch() {
    let empty = Catalog::from_handoff(vec![]).unwrap();
    for kind in [Kind::Ar3011, Kind::Ar3012] {
        let (mut owner, _, trace) = model(kind, 0, false, 0, 1);
        let error = owner.initialize_with_provider(&empty).unwrap_err();
        assert!(matches!(attempt(error).0, Error::Resource(_)));
        assert_eq!(trace.borrow().closed, 1);
        assert!(
            !trace
                .borrow()
                .steps
                .iter()
                .any(|(_, s)| matches!(s, Step::Write(..)))
        );
    }
    for index in [0, 1, 5, 6, 9] {
        let (mut owner, catalog, _) = model(Kind::Ar3012, 0, false, 0, 1);
        if let Step::Read(_, bytes) = &mut owner.io.steps[index] {
            bytes.pop();
        } else {
            continue;
        }
        let error = owner.initialize_with_provider(&catalog).unwrap_err();
        assert!(matches!(attempt(error).0, Error::Protocol { .. }));
    }
    let (mut owner, catalog, trace) = model(Kind::Ar3012, 0, false, 0, 1);
    for step in &mut owner.io.steps {
        if let Step::Read(9, bytes) = step {
            bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        }
    }
    let error = owner.initialize_with_provider(&catalog).unwrap_err();
    assert!(matches!(attempt(error).0, Error::Protocol { .. }));
    assert!(
        !trace
            .borrow()
            .steps
            .iter()
            .any(|(_, s)| matches!(s, Step::Write(0x0a, _)))
    );
}

#[test]
fn successful_upload_with_failed_retirement_keeps_full_historical_evidence() {
    let (mut owner, catalog, trace) = model(Kind::Ar3012, 0, false, 0, 1);
    owner.io.close_error = true;
    let error = owner.initialize_with_provider(&catalog).unwrap_err();
    let (_, obs) = attempt(error);
    assert_eq!(obs.completed.last(), Some(&Operation::SwitchIdentity));
    assert!(obs.patch.is_some() && obs.configuration.is_some());
    assert!(obs.pending.is_none());
    assert_eq!(owner.state(), State::Failed);
    assert_eq!(trace.borrow().closed, 1);
}

#[test]
fn real_bind_configures_only_raw_output_and_retains_the_completed_uploader() {
    use crate::bus::dma::RegionAllocator;
    let mut backing = vec![0u64; 64 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: backing exclusively owns these DMA pages and outlives every owner.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, hardware) = xhci::model::unconfigured_cancellation_controller(&mut dma);
    controller.clock.ticks_per_microsecond = 1000;
    let shared = Rc::new(RefCell::new(controller));
    let (_, catalog, _) = model(Kind::Ar3011, 0, false, 0, 4097);
    let mut found = xhci::Found::default();
    xhci::model::bind_with_provider(
        &shared,
        device(Kind::Ar3011, 1),
        &mut dma,
        &mut found,
        &catalog,
    );
    assert!(found.failures.is_empty() && found.unused.is_empty());
    assert!(found.bluetooth.is_empty());
    assert_eq!(found.bootloaders.len(), 1);
    let owner = &mut found.bootloaders[0];
    assert_eq!(owner.state(), State::AwaitingReenumeration);
    let report = owner.initialization().unwrap().unwrap();
    assert!(report.observation.monolithic.is_some());
    let count = hardware.borrow().setup.len();
    owner.initialize_with_provider(&catalog).unwrap();
    assert_eq!(hardware.borrow().setup.len(), count);
    let observed = hardware.borrow();
    let bytes = image(4097);
    assert_eq!(
        observed
            .setup
            .iter()
            .filter(|(s, _)| s[0] == 0x40)
            .collect::<Vec<_>>(),
        [&(xhci::setup(0x40, 1, 0, 0, 20), bytes[..20].to_vec())]
    );
    assert_eq!(
        observed.outgoing,
        bytes[20..]
            .chunks(4096)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    );
    assert!(observed.active.iter().all(Option::is_none));
    assert!(observed.rings[3] == 0 && observed.rings[5] == 0 && observed.rings[4] != 0);
}

#[test]
fn native_body_timeout_and_failed_stop_preserve_bytes_and_terminal_raw_owner() {
    use crate::bus::dma::RegionAllocator;
    let mut backing = vec![0u64; 64 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: retained backing exclusively owns all controller and raw DMA pages.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, hardware) = xhci::model::unconfigured_cancellation_controller(&mut dma);
    controller.clock.ticks_per_microsecond = 1000;
    hardware.borrow_mut().silence_transfer = Some(4);
    const STOP_ENDPOINT: u32 = 15;
    const CONTEXT_STATE_ERROR: u32 = 19;
    hardware.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
    let shared = Rc::new(RefCell::new(controller));
    let (_, catalog, _) = model(Kind::Ar3011, 0, false, 0, 1);
    let mut found = xhci::Found::default();
    xhci::model::bind_with_provider(
        &shared,
        device(Kind::Ar3011, 1),
        &mut dma,
        &mut found,
        &catalog,
    );
    assert_eq!(found.bootloaders.len(), 1);
    let owner = &mut found.bootloaders[0];
    assert_eq!(owner.state(), State::Failed);
    let error = owner.initialization().unwrap().unwrap_err();
    assert!(matches!(error, Error::Cleanup { .. }));
    let (cause, obs) = attempt(error);
    assert!(matches!(cause, Error::Usb(BlockError::Timeout)));
    assert_eq!(
        obs.pending,
        Some(Operation::Body {
            component: Component::Monolithic,
            offset: 20,
            bytes: 1
        })
    );
    let before = backing.clone();
    let setup = hardware.borrow().setup.len();
    assert!(owner.initialize_with_provider(&catalog).is_err());
    assert_eq!(backing, before);
    assert_eq!(hardware.borrow().setup.len(), setup);
    assert!(hardware.borrow().active[4].is_some());
}

#[test]
fn patch_target_rom_build_and_minimum_size_are_validated_before_header() {
    for case in 0..5 {
        let (mut owner, _, trace) = model(Kind::Ar3012, 0, false, 0, 1);
        let before = version(1, 0);
        let name = before.patch_name();
        let revision = before.revision();
        let hardware = UsbIdentity::read(owner.device()).hardware();
        let mut bytes = image(1);
        let n = bytes.len();
        match case {
            1 => bytes.truncate(19),
            2 => bytes[n - 8] ^= 1,
            3 => bytes[n - 4..].copy_from_slice(&1u32.to_le_bytes()),
            4 => bytes[n - 4..].copy_from_slice(&0u32.to_le_bytes()),
            _ => {}
        }
        let mut r = resource(&name, &hardware, &revision, bytes);
        if case == 0 {
            r.target.hardware = "usb:ffff:ffff:ffff";
        }
        let catalog = Catalog::from_handoff(vec![r]).unwrap();
        let error = owner.initialize_with_provider(&catalog).unwrap_err();
        let (cause, obs) = attempt(error);
        match case {
            0 => assert!(matches!(
                cause,
                Error::Resource(crate::firmware::Error {
                    kind: crate::firmware::ErrorKind::WrongTarget,
                    ..
                })
            )),
            1 => assert!(matches!(
                cause,
                Error::Resource(crate::firmware::Error {
                    kind: crate::firmware::ErrorKind::Truncated { .. },
                    ..
                })
            )),
            _ => assert!(matches!(cause, Error::Protocol { .. })),
        }
        assert!(obs.completed.is_empty() && obs.pending.is_none());
        assert_eq!(trace.borrow().steps.len(), 2);
        assert_eq!(trace.borrow().closed, 1);
    }
}
