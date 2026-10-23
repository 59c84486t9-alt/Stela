use super::*;
use crate::{
    block::BlockError,
    firmware::{Catalog, Image, Provider, Requirement},
    usb::{
        bluetooth::{Binding, InitializationReport, Pipe},
        xhci::{self, Device},
    },
};
use alloc::{collections::VecDeque, rc::Rc};
use core::cell::{Cell, RefCell};
#[derive(Clone, Debug)]
enum Step {
    Vendor(u8, Vec<u8>),
    Command(u16, Vec<Packet>),
    Quiesce,
}
#[derive(Default)]
struct Trace {
    operations: usize,
    closed: usize,
    requests: usize,
}
struct Model {
    steps: VecDeque<Step>,
    event: VecDeque<Vec<u8>>,
    acl: VecDeque<Vec<u8>>,
    trace: Rc<RefCell<Trace>>,
    time: Cell<u64>,
    fail: Option<usize>,
    close_error: bool,
    credits: u8,
}
impl Model {
    fn step(&mut self) -> core::result::Result<Step, BlockError> {
        assert_eq!(self.trace.borrow().closed, 0);
        self.trace.borrow_mut().operations += 1;
        if self.fail == Some(self.trace.borrow().operations) {
            return Err(BlockError::Device { status: 0x55 });
        }
        Ok(self
            .steps
            .pop_front()
            .expect("unexpected runtime operation"))
    }
}
impl Io for Model {
    fn control(&mut self, s: [u8; 8], b: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(s, xhci::setup(0x20, 0, 0, 0, 3));
        assert_eq!(b.len(), 3);
        assert_eq!(b[2], 0);
        assert_ne!(self.credits, 0, "HCI command without actual credits");
        self.credits -= 1;
        let Step::Command(op, packets) = self.step()? else {
            panic!("runtime expected different operation")
        };
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), op);
        for packet in packets {
            match packet {
                Packet::Event(b) => self.event.push_back(b),
                Packet::Acl(b) => self.acl.push_back(b),
                Packet::Diagnostic(_) => panic!(),
            }
        }
        Ok(())
    }
    fn control_read(&mut self, s: [u8; 8]) -> core::result::Result<Vec<u8>, BlockError> {
        let Step::Vendor(req, b) = self.step()? else {
            panic!("vendor identity not queried")
        };
        assert_eq!(
            s,
            xhci::setup(0xc0, req, 0, 0, if req == 9 { 20 } else { 1 })
        );
        Ok(b)
    }
    fn receive(&mut self, p: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        let b = match p {
            Pipe::Event => self.event.pop_front(),
            Pipe::Acl => self.acl.pop_front(),
        };
        if let Some(b) = &b
            && p == Pipe::Event
        {
            if b.first() == Some(&0x0e) && b.len() >= 5 {
                self.credits = b[2];
            }
            if b.first() == Some(&0x0f) && b.len() == 6 {
                self.credits = b[3];
            }
        }
        Ok(b)
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        panic!("no ordinary ACL transmitted during runtime setup")
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        assert!(matches!(self.step()?, Step::Quiesce));
        Ok(())
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
        let t = self.time.get();
        self.time.set(t.wrapping_add(100_000));
        t
    }
}
struct NoFirmware(Rc<RefCell<Trace>>);
impl Provider for NoFirmware {
    fn load(&self, _: Requirement<'_>) -> core::result::Result<Image<'_>, crate::firmware::Error> {
        self.0.borrow_mut().requests += 1;
        panic!("no image may be fabricated for a source unknown-high-ROM")
    }
}
fn device(vendor: u16, product: u16, revision: u16) -> Device {
    let config = vec![
        9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1, 7,
        5, 0x82, 2, 64, 0, 0, 7, 5, 2, 2, 64, 0, 0,
    ];
    let mut descriptor = [18, 1, 0, 2, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    descriptor[8..10].copy_from_slice(&vendor.to_le_bytes());
    descriptor[10..12].copy_from_slice(&product.to_le_bytes());
    descriptor[12..14].copy_from_slice(&revision.to_le_bytes());
    Device {
        vendor_ethernet_revision: None,
        vendor_ethernet_tcr: None,
        slot: 2,
        speed: xhci::FULL_SPEED,
        location: "fresh post-rebind AR3012 HCI model".into(),
        descriptor,
        configurations: vec![config.clone()],
        configuration: config,
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
    }
}
fn complete(opcode: u16, returned: &[u8], credits: u8) -> Packet {
    let mut b = vec![
        0x0e,
        (3 + returned.len()) as u8,
        credits,
        opcode as u8,
        (opcode >> 8) as u8,
    ];
    b.extend_from_slice(returned);
    Packet::Event(b)
}
fn version(rom: u32) -> qca::Version {
    let mut raw = [0; 20];
    raw[..4].copy_from_slice(&rom.to_le_bytes());
    raw[4..8].copy_from_slice(&10u32.to_le_bytes());
    qca::Version { raw }
}
fn model(rom: u32) -> (Hci<Model>, NoFirmware, Rc<RefCell<Trace>>) {
    let d = device(0x0489, 0xe04d, 2);
    let binding = Binding::new(&d, &xhci::interfaces(&d.configuration)[0]).unwrap();
    let steps = VecDeque::from([
        Step::Vendor(9, version(rom).raw.to_vec()),
        Step::Command(0x0c03, vec![complete(0x0c03, &[0], 1)]),
        Step::Command(
            0x1001,
            vec![complete(0x1001, &[0, 9, 1, 0, 9, 0x45, 0, 1, 0], 1)],
        ),
        Step::Command(0x1009, vec![complete(0x1009, &[0, 1, 2, 3, 4, 5, 6], 1)]),
    ]);
    let trace = Rc::new(RefCell::new(Trace::default()));
    (
        Hci::from_io(
            binding,
            Model {
                steps,
                event: VecDeque::new(),
                acl: VecDeque::new(),
                trace: trace.clone(),
                time: Cell::new(0),
                fail: None,
                close_error: false,
                credits: 1,
            },
        ),
        NoFirmware(trace.clone()),
        trace,
    )
}
fn attempt(error: &Error) -> (&Error, &Attempt) {
    match error {
        Error::Attempt { cause, observation } => (cause, observation),
        Error::Cleanup { cause, .. } => attempt(cause),
        other => panic!("missing runtime partial evidence {other:?}"),
    }
}
#[test]
fn all_52_actual_runtime_aliases_initialize_genuine_hci_and_cache_unknown_image_evidence() {
    for &(v, p, k) in super::super::SOURCE_USB_IDS {
        if k != super::super::Kind::Ar3012 {
            continue;
        }
        let (mut hci, provider, trace) = model(0x01020201);
        let d = device(v, p, 0x1234);
        hci.binding = Binding::new(&d, &xhci::interfaces(&d.configuration)[0]).unwrap();
        let report = hci
            .initialize_with_provider(
                &provider,
                crate::usb::bluetooth::intel::PlatformInputs::default(),
            )
            .unwrap();
        let InitializationReport::Atheros(report) = report else {
            panic!("runtime not dispatched")
        };
        assert_eq!(
            (report.usb.vendor, report.usb.product, report.usb.revision),
            (v, p, 0x1234)
        );
        assert_eq!(report.firmware, FirmwareEvidence::RunningUnknown);
        assert_eq!(report.completed_commands, [0x0c03, 0x1001, 0x1009]);
        assert_eq!(report.address, [1, 2, 3, 4, 5, 6]);
        assert_eq!(report.local_version, [9, 1, 0, 9, 0x45, 0, 1, 0]);
        assert!(report.policy.simultaneous_discovery && report.policy.strict_duplicate_filter);
        assert!(!report.policy.broken_enhanced_setup_sync_conn);
        assert_eq!(hci.state(), State::Open);
        assert!(hci.io.steps.is_empty());
        assert_eq!(trace.borrow().requests, 0);
        hci.initialize_with_provider(
            &provider,
            crate::usb::bluetooth::intel::PlatformInputs::default(),
        )
        .unwrap();
        assert_eq!(trace.borrow().operations, 4);
    }
}
#[test]
fn raw_old_revision_unlisted_ids_and_unknown_low_rom_do_not_become_runtime() {
    for (v, p, revision) in [
        (0x0489, 0xe04d, 1),
        (0x0cf3, 0x3000, 2),
        (0x0489, 0xffff, 2),
    ] {
        let (mut hci, provider, trace) = model(0x01020201);
        let d = device(v, p, revision);
        hci.binding = Binding::new(&d, &xhci::interfaces(&d.configuration)[0]).unwrap();
        assert!(matches!(
            initialize(&mut hci, &provider),
            Err(Error::Unsupported(_))
        ));
        assert_eq!(trace.borrow().operations, 0);
        assert!(qca::initialize_atheros(&mut hci, &provider, 0x01020201).is_err());
        assert_eq!(trace.borrow().operations, 0);
    }
    let (mut hci, provider, trace) = model(0x00007777);
    let e = initialize(&mut hci, &provider).unwrap_err();
    assert!(matches!(attempt(&e).0, Error::Unsupported(_)));
    assert_eq!(trace.borrow().operations, 1);
    assert_eq!(trace.borrow().closed, 1);
}
#[test]
fn known_rom_reuses_dfu_engine_with_real_before_after_and_atheros_policy() {
    for p in qca::PROFILES {
        let (mut hci, provider, trace) = model(p.rom);
        hci.io.steps.insert(1, Step::Quiesce);
        hci.io
            .steps
            .insert(2, Step::Vendor(9, version(p.rom).raw.to_vec()));
        hci.io.steps.insert(3, Step::Vendor(5, vec![0xc0]));
        hci.io
            .steps
            .insert(4, Step::Vendor(9, version(p.rom).raw.to_vec()));
        let report = initialize(&mut hci, &provider).unwrap();
        let FirmwareEvidence::Dfu(dfu) = report.firmware else {
            panic!()
        };
        assert_eq!(dfu.kind, qca::Kind::Ath3012);
        assert_eq!(dfu.before, version(p.rom));
        assert_eq!(dfu.after_patch, version(p.rom));
        assert!(!dfu.policy.wideband_speech);
        assert_eq!(dfu.policy.microsoft_opcode, None);
        assert!(report.policy.broken_enhanced_setup_sync_conn);
        assert_eq!(trace.borrow().requests, 0);
        assert!(hci.io.steps.is_empty());
    }
}
#[test]
fn every_real_io_failure_keeps_first_command_and_transport_cleanup_fault() {
    for failed in 1..=4 {
        let (mut hci, provider, trace) = model(0x01020201);
        hci.io.fail = Some(failed);
        hci.io.close_error = true;
        let e = initialize(&mut hci, &provider).unwrap_err();
        let (cause, obs) = attempt(&e);
        if failed == 1 {
            assert!(matches!(e, Error::Cleanup { .. }));
            assert!(matches!(cause, Error::Usb(_)));
        } else {
            let Error::Transport(transport) = cause else {
                panic!("missing transport fault")
            };
            assert_eq!(transport.cleanup, Some(BlockError::Timeout));
        }
        assert_eq!(
            obs.pending_command,
            match failed {
                2 => Some(0x0c03),
                3 => Some(0x1001),
                4 => Some(0x1009),
                _ => None,
            }
        );
        assert_eq!(hci.state(), State::Failed);
        assert_eq!(trace.borrow().closed, 1);
    }
}
#[test]
fn actual_statusless_credit_grants_gate_commands_and_asynchronous_frames_are_retained() {
    let (mut hci, provider, _) = model(0x01020201);
    hci.io.steps[1] = Step::Command(
        0x0c03,
        vec![
            complete(0x0c03, &[0], 0),
            Packet::Event(vec![0x0e, 3, 0, 0, 0]),
            Packet::Event(vec![0x0e, 3, 1, 0, 0]),
            Packet::Event(vec![0xff, 1, 9]),
            Packet::Acl(vec![1, 0, 1, 0, 0xaa]),
        ],
    );
    let report = initialize(&mut hci, &provider).unwrap();
    assert_eq!(
        report.asynchronous,
        [
            Packet::Acl(vec![1, 0, 1, 0, 0xaa]),
            Packet::Event(vec![0xff, 1, 9])
        ]
    );
}
#[test]
fn malformed_mismatched_missing_and_status_only_responses_never_count_as_completion() {
    for packet in [
        Packet::Event(vec![0x0e, 3, 1, 3, 0x0c]),
        complete(0x1009, &[0], 1),
        complete(0x0c03, &[0x0c], 1),
        Packet::Event(vec![0x0f, 4, 0, 1, 3, 0x0c]),
    ] {
        let (mut hci, provider, trace) = model(0x01020201);
        hci.io.steps[1] = Step::Command(0x0c03, vec![packet]);
        let e = initialize(&mut hci, &provider).unwrap_err();
        assert!(matches!(
            attempt(&e).0,
            Error::Protocol { .. } | Error::Controller { .. } | Error::Timeout
        ));
        assert_eq!(trace.borrow().operations, 2);
        assert_eq!(trace.borrow().closed, 1);
    }
    for index in [0, 2, 3] {
        let (mut hci, provider, _) = model(0x01020201);
        match &mut hci.io.steps[index] {
            Step::Vendor(_, b) => {
                b.pop();
            }
            Step::Command(_, packets) => {
                let Packet::Event(b) = &mut packets[0] else {
                    panic!()
                };
                b.pop();
                b[1] -= 1;
            }
            _ => panic!(),
        }
        let e = initialize(&mut hci, &provider).unwrap_err();
        assert!(matches!(attempt(&e).0, Error::Protocol { .. }));
    }
    for address in [[0; 6], [0xff; 6]] {
        let (mut hci, provider, _) = model(0x01020201);
        let mut returned = vec![0];
        returned.extend_from_slice(&address);
        hci.io.steps[3] = Step::Command(0x1009, vec![complete(0x1009, &returned, 1)]);
        let e = initialize(&mut hci, &provider).unwrap_err();
        assert_eq!(attempt(&e).1.address, Some(address));
    }
}

#[test]
fn known_rom_missing_image_retains_dfu_failure_without_hci_or_fake_cache_success() {
    let (mut hci, _, trace) = model(0x302);
    hci.io.steps.insert(1, Step::Quiesce);
    hci.io
        .steps
        .insert(2, Step::Vendor(9, version(0x302).raw.to_vec()));
    hci.io.steps.insert(3, Step::Vendor(5, vec![0]));
    let empty = Catalog::from_handoff(vec![]).unwrap();
    let error = hci
        .initialize_with_provider(
            &empty,
            crate::usb::bluetooth::intel::PlatformInputs::default(),
        )
        .unwrap_err();
    let crate::usb::bluetooth::InitializationError::Atheros(error) = error else {
        panic!()
    };
    assert!(matches!(attempt(error).0, Error::Dfu(_)));
    assert_eq!(attempt(error).1.vendor_version, Some(version(0x302)));
    assert!(attempt(error).1.completed_commands.is_empty());
    assert_eq!(trace.borrow().operations, 4);
    assert_eq!(trace.borrow().closed, 1);
    assert!(
        hci.initialize_with_provider(
            &empty,
            crate::usb::bluetooth::intel::PlatformInputs::default()
        )
        .is_err()
    );
    assert_eq!(trace.borrow().operations, 4);
}

struct RecordingCatalog {
    catalog: Catalog,
    requests: Cell<usize>,
}
impl Provider for RecordingCatalog {
    fn load(&self, r: Requirement<'_>) -> core::result::Result<Image<'_>, crate::firmware::Error> {
        self.requests.set(self.requests.get() + 1);
        self.catalog.load(r)
    }
}
#[test]
fn changed_rom_during_dfu_refuses_before_status_resource_or_any_download_write() {
    use crate::firmware::{Provenance, Resource};
    use sha2::{Digest, Sha256};
    let (mut hci, _, trace) = model(0x302);
    hci.io.steps.insert(1, Step::Quiesce);
    hci.io
        .steps
        .insert(2, Step::Vendor(9, version(0x300).raw.to_vec()));
    hci.io.steps.insert(3, Step::Vendor(5, vec![0]));
    let second = version(0x300);
    let profile = second.profile().unwrap();
    let mut patch = vec![0x5a; profile.rampatch_header + 1];
    patch[profile.version_offset..profile.version_offset + 2].copy_from_slice(&0u16.to_le_bytes());
    patch[profile.version_offset + 2..profile.version_offset + 4]
        .copy_from_slice(&0x300u16.to_le_bytes());
    patch[profile.version_offset + 4..profile.version_offset + 6]
        .copy_from_slice(&11u16.to_le_bytes());
    assert!(qca::RampatchVersion::parse(&patch, &second, profile).is_ok());
    let hardware = qca::UsbIdentity::read(hci.binding.device()).hardware_label();
    let revision = second.revision_label();
    let patch_name = second.rampatch_name();
    let nvm_name = second.nvm_name();
    let resource = |name, bytes: Vec<u8>| Resource {
        name,
        target: second.target(&hardware, &revision),
        provenance: Provenance {
            source: "independent second-ROM valid image model",
            revision: "atheros-runtime-v1",
            member: name,
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    };
    let provider = RecordingCatalog {
        catalog: Catalog::from_handoff(vec![
            resource(&patch_name, patch),
            resource(&nvm_name, vec![0xa5; 5]),
        ])
        .unwrap(),
        requests: Cell::new(0),
    };
    let error = initialize(&mut hci, &provider).unwrap_err();
    let (cause, obs) = attempt(&error);
    let Error::Dfu(dfu) = cause else {
        panic!("missing DFU failure")
    };
    let qca::Error::Attempt { cause, observation } = dfu.as_ref() else {
        panic!("missing both ROM observations")
    };
    assert!(matches!(**cause, qca::Error::Protocol { .. }));
    assert_eq!(obs.vendor_version, Some(version(0x302)));
    assert_eq!(observation.before, Some(second));
    assert!(
        observation.completed.is_empty()
            && observation.pending.is_none()
            && observation.status.is_none()
    );
    assert_eq!(provider.requests.get(), 0);
    assert_eq!(trace.borrow().operations, 3);
    assert_eq!(trace.borrow().closed, 1);
    assert!(obs.completed_commands.is_empty());
    assert!(matches!(hci.io.steps.front(),Some(Step::Vendor(5,b))if b==&[0]));
}
