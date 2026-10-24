use super::*;
use crate::{
    block::BlockError,
    firmware::{Catalog, Image, Provenance, Provider, Requirement, Resource},
    usb::{
        bluetooth::{
            Binding, InitializationError, InitializationReport, Pipe, State, intel::PlatformInputs,
        },
        xhci::{self, Device},
    },
};
use alloc::{collections::VecDeque, rc::Rc, string::String};
use core::cell::{Cell, RefCell};
use sha2::{Digest, Sha256};

struct Step {
    command: Vec<u8>,
    responses: Vec<(Vec<u8>, Option<u8>)>,
}
#[derive(Default)]
struct Trace {
    commands: Vec<(u64, Vec<u8>)>,
    closed: usize,
}
struct Model {
    steps: VecDeque<Step>,
    events: VecDeque<(Vec<u8>, Option<u8>)>,
    time: Cell<u64>,
    trace: Rc<RefCell<Trace>>,
    credits: u8,
    fail_command: Option<usize>,
    fail_close: bool,
}
impl Io for Model {
    fn validate(&self) -> core::result::Result<(), BlockError> {
        Ok(()) // This in-memory model has no physical device-generation owner.
    }
    fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(setup[..6], [0x20, 0, 0, 0, 0, 0]);
        assert_eq!(
            u16::from_le_bytes([setup[6], setup[7]]) as usize,
            packet.len()
        );
        assert_eq!(self.trace.borrow().closed, 0);
        assert!(
            self.credits > 0,
            "controller received command without credits"
        );
        self.credits -= 1;
        let step = self.steps.pop_front().expect("unexpected command");
        assert_eq!(packet, step.command);
        self.trace
            .borrow_mut()
            .commands
            .push((self.time.get(), packet.to_vec()));
        if self.fail_command == Some(self.trace.borrow().commands.len()) {
            return Err(BlockError::Device { status: 0x55 });
        }
        for (event, grant) in step.responses {
            // Native HCI assembly must span transfer boundaries.
            if event.len() > 1 {
                self.events.push_back((event[..1].to_vec(), None));
                self.events.push_back((event[1..].to_vec(), grant));
            } else {
                self.events.push_back((event, grant));
            }
        }
        Ok(())
    }
    fn receive(&mut self, pipe: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        if pipe != Pipe::Event {
            return Ok(None);
        }
        Ok(self.events.pop_front().map(|(data, grant)| {
            if let Some(grant) = grant {
                self.credits = grant;
            }
            data
        }))
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        panic!("PatchRAM uses EP0")
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        panic!("PatchRAM never enters Intel bulk mode")
    }
    fn close(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().closed += 1;
        if self.fail_close {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn now_us(&self) -> u64 {
        let now = self.time.get();
        self.time.set(now.wrapping_add(1000));
        now
    }
}
fn wire(op: u16, p: &[u8]) -> Vec<u8> {
    let mut packet = op.to_le_bytes().to_vec();
    packet.push(p.len() as u8);
    packet.extend_from_slice(p);
    packet
}
fn cc(op: u16, p: &[u8], credits: u8) -> Vec<u8> {
    let mut packet = vec![0x0e, (p.len() + 3) as u8, credits];
    packet.extend_from_slice(&op.to_le_bytes());
    packet.extend_from_slice(p);
    packet
}
fn version(sub: u16, build: u16) -> Vec<u8> {
    let mut p = vec![0, 6];
    p.extend_from_slice(&build.to_le_bytes());
    p.extend_from_slice(&[6, 15, 0]);
    p.extend_from_slice(&sub.to_le_bytes());
    p
}
fn identity(sub: u16) -> Identity {
    Identity {
        usb: UsbIdentity {
            vendor: 0x0a5c,
            product: 0x21e8,
            revision: 0x112,
        },
        version: LocalVersion {
            raw: version(sub, 0x1000).try_into().unwrap(),
        },
        verbose: [0, 0x32, 1, 2, 3, 4, 5],
        features: [0, 1, 2, 3, 4, 5, 6, 7, 8],
        local_name: vec![0; 249],
        product: [0, 0x5c, 0x0a, 0xe8, 0x21],
    }
}
fn device(vendor: u16, product: u16, class: u8) -> Device {
    let mut configuration = vec![
        9, 2, 0, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, class, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1, 7,
        5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0,
    ];
    let length = configuration.len() as u16;
    configuration[2..4].copy_from_slice(&length.to_le_bytes());
    let mut descriptor = [18, 1, 0, 2, 0, 0, 0, 64, 0, 0, 0, 0, 0x12, 1, 0, 0, 0, 1];
    descriptor[8..10].copy_from_slice(&vendor.to_le_bytes());
    descriptor[10..12].copy_from_slice(&product.to_le_bytes());
    Device {
        id: crate::usb::xhci::SlotId::fixture(1),
        vendor_ethernet_revision: None,
        vendor_ethernet_tcr: None,
        slot: 1,
        speed: xhci::FULL_SPEED,
        location: "Broadcom stateful fixture".into(),
        descriptor,
        configurations: vec![configuration.clone()],
        configuration,
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
    }
}
fn image_bytes() -> Vec<u8> {
    let mut bytes = wire(0xfc4c, &[0x00, 0x10, 0, 0, 0xaa, 0xbb]);
    bytes.extend(wire(0xfc4e, &[0, 0x10, 0, 0]));
    bytes
}
fn catalog(sub: u16, generic: bool, bytes: Vec<u8>) -> Catalog {
    let id = identity(sub);
    let hardware = id.usb.hardware_label();
    let revision = id.revision_label();
    let names = id.firmware_names();
    let name = &names[usize::from(generic && names.len() > 1)];
    Catalog::from_handoff(vec![Resource {
        name,
        target: id.target(&hardware, &revision),
        provenance: Provenance {
            source: "original stateful model",
            revision: "model-v1",
            member: name,
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap()
}
fn model(sub: u16) -> (Hci<Model>, Rc<RefCell<Trace>>) {
    let device = device(0x0a5c, 0x21e8, 0xff);
    let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
    let mut steps = VecDeque::new();
    let mut add = |op, p: &[u8], reply: &[u8]| {
        steps.push_back(Step {
            command: wire(op, p),
            responses: vec![(cc(op, reply, 1), Some(1))],
        });
    };
    add(0x0c03, &[], &[0]);
    add(0x1001, &[], &version(sub, 0x1000));
    add(0xfc79, &[], &identity(sub).verbose);
    add(0xfc6e, &[], &identity(sub).features);
    add(0x0c14, &[], &[0; 249]);
    add(0xfc5a, &[], &identity(sub).product);
    add(0xfc2e, &[], &[0]);
    add(0xfc4c, &[0, 0x10, 0, 0, 0xaa, 0xbb], &[0]);
    add(0xfc4e, &[0, 0x10, 0, 0], &[0]);
    add(0x0c03, &[], &[0]);
    add(0x1001, &[], &version(sub, 0x1001));
    add(0xfc6e, &[], &identity(sub).features);
    add(0x0c14, &[], &[0; 249]);
    add(0x1009, &[], &[0, 1, 2, 3, 4, 5, 6]);
    let trace = Rc::new(RefCell::new(Trace::default()));
    (
        Hci::from_io(
            binding,
            Model {
                steps,
                events: VecDeque::new(),
                time: Cell::new(0),
                trace: trace.clone(),
                credits: 1,
                fail_command: None,
                fail_close: false,
            },
        ),
        trace,
    )
}
fn attempt(error: &Error) -> (&Error, &Attempt) {
    match error {
        Error::Attempt { cause, observation } => (cause, observation),
        Error::Cleanup { cause, .. } => attempt(cause),
        _ => panic!("lost attempt {error:?}"),
    }
}
struct Recording<'a> {
    catalog: &'a Catalog,
    requests: RefCell<Vec<(String, String, String)>>,
}
impl Provider for Recording<'_> {
    fn load(&self, r: Requirement<'_>) -> core::result::Result<Image<'_>, crate::firmware::Error> {
        self.requests.borrow_mut().push((
            r.name.into(),
            r.target.hardware.into(),
            r.target.revision.into(),
        ));
        self.catalog.load(r)
    }
}

#[test]
fn all_usb_chip_profiles_replay_source_order_and_required_delays() {
    for sub in [
        0x2105, 0x210b, 0x2112, 0x2118, 0x2126, 0x220e, 0x230f, 0x4106, 0x410e, 0x6109, 0x610c,
        0x6607, 0xabcd,
    ] {
        let (mut hci, trace) = model(sub);
        let catalog = catalog(sub, false, image_bytes());
        let report = initialize(&mut hci, &catalog).unwrap();
        assert_eq!(report.before, identity(sub));
        assert_eq!(report.after.raw, version(sub, 0x1001).as_slice());
        assert_eq!(report.address, [1, 2, 3, 4, 5, 6]);
        assert_eq!(report.patch_commands, 2);
        assert_eq!(report.command_credits, 1);
        assert_eq!(
            report.firmware.sha256,
            <[u8; 32]>::from(Sha256::digest(image_bytes()))
        );
        assert!(report.strict_duplicate_filter);
        assert!(report.asynchronous.is_empty());
        assert!(hci.io.steps.is_empty());
        let commands = &trace.borrow().commands;
        for (before, after, minimum) in [
            (0, 1, 100_000),
            (6, 7, 50_000),
            (8, 9, 250_000),
            (9, 10, 100_000),
        ] {
            assert!(commands[after].0 - commands[before].0 >= minimum);
        }
        assert_eq!(hci.state(), State::Open);
    }
}
#[test]
fn fallback_only_permits_missing_and_retains_exact_runtime_target() {
    let (mut hci, _) = model(0x220e);
    let cat = catalog(0x220e, true, image_bytes());
    let p = Recording {
        catalog: &cat,
        requests: RefCell::new(Vec::new()),
    };
    let report = initialize(&mut hci, &p).unwrap();
    assert_eq!(p.requests.borrow().len(), 2);
    assert_eq!(report.firmware.name, "brcm/BCM-0a5c-21e8.hcd");
    assert!(
        p.requests
            .borrow()
            .iter()
            .all(|(_, hardware, revision)| hardware == "usb:0a5c:21e8:0112"
                && revision == &identity(0x220e).revision_label())
    );
    let (mut hci, trace) = model(0x220e);
    let id = identity(0x220e);
    let name = id.firmware_names().remove(0);
    let bytes = image_bytes();
    let wrong = Catalog::from_handoff(vec![Resource {
        name: &name,
        target: crate::firmware::Target {
            driver: "broadcom-bluetooth-usb-patchram",
            hardware: "foreign-board",
            revision: "wrong-rom",
            board: None,
        },
        provenance: Provenance {
            source: "original fixture",
            revision: "wrong-target-v1",
            member: &name,
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap();
    let p = Recording {
        catalog: &wrong,
        requests: RefCell::new(Vec::new()),
    };
    let error = initialize(&mut hci, &p).unwrap_err();
    assert!(
        matches!(attempt(&error).0, Error::Resource(e) if e.kind == crate::firmware::ErrorKind::WrongTarget)
    );
    assert_eq!(p.requests.borrow().len(), 1);
    assert_eq!(trace.borrow().commands.len(), 6);
    assert_eq!(trace.borrow().closed, 1);
}
#[test]
fn malformed_images_are_rejected_before_download_mode() {
    for bytes in [
        vec![],
        vec![0x4c],
        vec![0x4c, 0xfc],
        vec![0x4c, 0xfc, 2, 1],
        {
            let mut b = image_bytes();
            b.push(0xff);
            b
        },
    ] {
        let (mut hci, trace) = model(0x220e);
        let cat = catalog(0x220e, false, bytes);
        let error = initialize(&mut hci, &cat).unwrap_err();
        assert!(matches!(
            attempt(&error).0,
            Error::MalformedPatch { .. } | Error::Resource(_)
        ));
        assert_eq!(trace.borrow().commands.len(), 6);
        assert_eq!(trace.borrow().closed, 1);
    }
    for n in 0..=255 {
        let bytes = wire(0xfc4c, &vec![0xab; n]);
        let patch = Hcd::parse(&bytes).unwrap();
        assert_eq!(patch.len(), 1);
        assert_eq!(patch.records().next().unwrap().parameters.len(), n);
    }
}
#[test]
fn every_submission_failure_retains_observations_and_never_reuses_attachment() {
    for failed in 1..=14 {
        let (mut hci, trace) = model(0x220e);
        hci.io.fail_command = Some(failed);
        let cat = catalog(0x220e, false, image_bytes());
        let error = initialize(&mut hci, &cat).unwrap_err();
        let (cause, observed) = attempt(&error);
        assert!(matches!(cause, Error::Transport(_)));
        assert_eq!(trace.borrow().commands.len(), failed);
        assert_eq!(trace.borrow().closed, 1);
        assert_eq!(hci.state(), State::Failed);
        if failed > 6 {
            assert!(observed.identity.is_some());
            assert!(observed.firmware.is_some());
        }
        assert!(initialize(&mut hci, &cat).is_err());
        assert_eq!(trace.borrow().commands.len(), failed);
    }
}
#[test]
fn status_wrong_duplicate_and_silent_completions_do_not_credit_commands() {
    for variant in 0..5 {
        let (mut hci, trace) = model(0x220e);
        let step = &mut hci.io.steps[6];
        step.responses = match variant {
            0 => vec![(vec![0x0f, 4, 0, 1, 0x2e, 0xfc], Some(1))],
            1 => vec![(cc(0xfc4c, &[0], 1), Some(1))],
            2 => {
                let mut b = cc(0xfc2e, &[0], 1);
                b.extend(cc(0xfc2e, &[0], 1));
                vec![(b, Some(1))]
            }
            3 => vec![(cc(0xfc2e, &[0x0c], 1), Some(1))],
            _ => vec![],
        };
        let error = initialize(&mut hci, &catalog(0x220e, false, image_bytes())).unwrap_err();
        assert!(matches!(
            attempt(&error).0,
            Error::Timeout(_) | Error::Protocol { .. } | Error::Controller { .. }
        ));
        assert_eq!(trace.borrow().commands.len(), 7);
        assert_eq!(trace.borrow().closed, 1);
    }
}
#[test]
fn zero_credits_wait_for_real_statusless_nop_and_asynchronous_packets_are_retained() {
    let (mut hci, _) = model(0x220e);
    hci.io.steps[7].responses = vec![
        (cc(0xfc4c, &[0], 0), Some(0)),
        (vec![0xff, 1, 0x42], None),
        (vec![0x0e, 3, 1, 0, 0], Some(1)),
    ];
    let report = initialize(&mut hci, &catalog(0x220e, false, image_bytes())).unwrap();
    assert_eq!(report.asynchronous, [Packet::Event(vec![0xff, 1, 0x42])]);
    assert_eq!(report.patch_commands, 2);
    let (mut hci, trace) = model(0x220e);
    hci.io.steps[7].responses = vec![(cc(0xfc4c, &[0], 0), Some(0))];
    let error = initialize(&mut hci, &catalog(0x220e, false, image_bytes())).unwrap_err();
    assert!(matches!(
        attempt(&error).0,
        Error::Timeout("genuine command credits")
    ));
    assert_eq!(trace.borrow().commands.len(), 8);
}
#[test]
fn default_address_needs_real_platform_value_and_readback() {
    let default = [0, 0xa0, 2, 0x70, 0x20, 0];
    let (mut hci, trace) = model(0x220e);
    let mut p = vec![0];
    p.extend(default);
    hci.io.steps[13].responses = vec![(cc(0x1009, &p, 1), Some(1))];
    let error = initialize(&mut hci, &catalog(0x220e, false, image_bytes())).unwrap_err();
    assert!(matches!(attempt(&error).0,Error::InvalidAddress(a) if *a==default));
    assert_eq!(trace.borrow().closed, 1);
    let (mut hci, _) = model(0x220e);
    hci.io.steps[13].responses = vec![(cc(0x1009, &p, 1), Some(1))];
    hci.io.steps.push_back(Step {
        command: wire(0xfc01, &[1, 2, 3, 4, 5, 6]),
        responses: vec![(cc(0xfc01, &[0], 1), Some(1))],
    });
    hci.io.steps.push_back(Step {
        command: wire(0x1009, &[]),
        responses: vec![(cc(0x1009, &[0, 1, 2, 3, 4, 5, 6], 1), Some(1))],
    });
    let report = initialize_with_address(
        &mut hci,
        &catalog(0x220e, false, image_bytes()),
        [1, 2, 3, 4, 5, 6],
    )
    .unwrap();
    assert_eq!(report.address, [1, 2, 3, 4, 5, 6]);
}
#[test]
fn retained_native_initialization_and_cleanup_failure_are_explicit() {
    let (mut hci, trace) = model(0x220e);
    let cat = catalog(0x220e, false, image_bytes());
    assert!(matches!(
        hci.initialize_with_provider(&cat, PlatformInputs::default())
            .unwrap(),
        InitializationReport::Broadcom(_)
    ));
    let commands = trace.borrow().commands.len();
    let empty = Catalog::from_handoff(vec![]).unwrap();
    assert!(
        hci.initialize_with_provider(&empty, PlatformInputs::default())
            .is_ok()
    );
    assert_eq!(trace.borrow().commands.len(), commands);
    let (mut hci, trace) = model(0x220e);
    hci.io.fail_close = true;
    let result = hci
        .initialize_with_provider(&empty, PlatformInputs::default())
        .unwrap_err();
    assert!(matches!(
        result,
        InitializationError::Broadcom(Error::Cleanup { .. })
    ));
    assert_eq!(hci.state(), State::Failed);
    assert_eq!(trace.borrow().closed, 1);
    assert!(
        hci.initialize_with_provider(&cat, PlatformInputs::default())
            .is_err()
    );
    assert_eq!(trace.borrow().closed, 1);
}
#[test]
fn vendor_descriptor_admission_matches_source_and_requires_real_interface() {
    for vendor in [
        0x105b, 0x0bb4, 0x0489, 0x04ca, 0x0a5c, 0x0b05, 0x050d, 0x13d3, 0x413c, 0x0930,
    ] {
        let device = device(vendor, 0xabcd, 0xff);
        let interface = &xhci::interfaces(&device.configuration)[0];
        assert!(is_vendor_interface(&device, interface));
        assert!(Binding::new(&device, interface).is_ok());
        assert!(is_candidate(&device));
    }
    let unknown = device(0x1234, 0x5678, 0xff);
    assert!(Binding::new(&unknown, &xhci::interfaces(&unknown.configuration)[0]).is_err());
    let known = device(0x0a5c, 0x21e8, 0xff);
    let mut fabricated = xhci::interfaces(&known.configuration)[0].clone();
    fabricated.endpoints[0].address = 0x8f;
    assert!(Binding::new(&known, &fabricated).is_err());
}

#[test]
fn short_identity_and_finalize_responses_fail_with_partial_observations() {
    for index in [1, 2, 3, 4, 5, 10, 11, 12, 13] {
        let (mut hci, trace) = model(0x220e);
        let response = &mut hci.io.steps[index].responses[0].0;
        response.pop();
        response[1] -= 1;
        let error = initialize(&mut hci, &catalog(0x220e, false, image_bytes())).unwrap_err();
        let (cause, observed) = attempt(&error);
        assert!(matches!(cause, Error::Protocol { .. }));
        assert_eq!(trace.borrow().commands.len(), index + 1);
        assert_eq!(trace.borrow().closed, 1);
        if index >= 2 {
            assert!(observed.version.is_some());
        }
        if index >= 3 {
            assert!(observed.verbose.is_some());
        }
        if index >= 4 {
            assert!(observed.features.is_some());
        }
        if index >= 5 {
            assert!(observed.local_name.is_some());
        }
        if index >= 10 {
            assert_eq!(observed.patch_commands, 2);
            assert!(observed.firmware.is_some());
        }
    }
    let (mut hci, trace) = model(0x220e);
    hci.io.steps[1].responses[0].0[10] = 0xff; // Actual manufacturer low byte.
    let error = initialize(&mut hci, &catalog(0x220e, false, image_bytes())).unwrap_err();
    assert!(matches!(attempt(&error).0, Error::Protocol { .. }));
    assert_eq!(trace.borrow().commands.len(), 2);
}

#[test]
fn asynchronous_overflow_and_address_write_without_matching_readback_fail_closed() {
    let (mut hci, trace) = model(0x220e);
    let mut events = Vec::new();
    for byte in 0..65 {
        events.extend_from_slice(&[0xff, 1, byte]);
    }
    events.extend(cc(0xfc2e, &[0], 1));
    hci.io.steps[6].responses = vec![(events, Some(1))];
    let error = initialize(&mut hci, &catalog(0x220e, false, image_bytes())).unwrap_err();
    let (cause, observed) = attempt(&error);
    assert!(matches!(cause, Error::Protocol { observed, .. } if observed == &[0xff, 1, 64]));
    assert_eq!(observed.asynchronous.len(), 64);
    assert_eq!(trace.borrow().closed, 1);
    let (mut hci, trace) = model(0x220e);
    hci.io.steps[13].responses = vec![(cc(0x1009, &[0, 0, 0, 0, 0, 0, 0], 1), Some(1))];
    hci.io.steps.push_back(Step {
        command: wire(0xfc01, &[1, 2, 3, 4, 5, 6]),
        responses: vec![(cc(0xfc01, &[0], 1), Some(1))],
    });
    hci.io.steps.push_back(Step {
        command: wire(0x1009, &[]),
        responses: vec![(cc(0x1009, &[0, 6, 5, 4, 3, 2, 1], 1), Some(1))],
    });
    let error = initialize_with_address(
        &mut hci,
        &catalog(0x220e, false, image_bytes()),
        [1, 2, 3, 4, 5, 6],
    )
    .unwrap_err();
    assert!(matches!(attempt(&error).0, Error::Protocol { .. }));
    assert_eq!(attempt(&error).1.address, Some([6, 5, 4, 3, 2, 1]));
    assert_eq!(trace.borrow().closed, 1);
}
