use super::*;
use crate::{
    block::BlockError,
    firmware::{Catalog, Image, Provenance, Provider, Requirement, Resource},
    usb::{
        bluetooth::{
            Binding, Hci, InitializationError, InitializationReport, Io, Pipe, State,
            intel::PlatformInputs,
        },
        xhci::{self, Device},
    },
};
use alloc::{collections::VecDeque, rc::Rc, string::String, vec::Vec};
use core::cell::{Cell, RefCell};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
enum Step {
    Read(u8, Vec<u8>),
    Header(Vec<u8>),
    Body(Vec<u8>),
    Quiesce,
}
#[derive(Default)]
struct Trace {
    completed: Vec<(u64, Step)>,
    closed: usize,
}
struct Model {
    steps: VecDeque<Step>,
    time: Cell<u64>,
    trace: Rc<RefCell<Trace>>,
    fail: Option<usize>,
    close_error: bool,
    polling: bool,
    event_rx: VecDeque<Vec<u8>>,
    acl_rx: VecDeque<Vec<u8>>,
}
impl Model {
    fn step(&mut self, actual: Step) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        assert_eq!(self.trace.borrow().closed, 0);
        let expected = self.steps.pop_front().expect("unexpected USB transaction");
        let result = match (&actual, expected) {
            (Step::Read(a, _), Step::Read(e, r)) => {
                assert_eq!(*a, e);
                Some(r)
            }
            (Step::Header(a), Step::Header(e)) | (Step::Body(a), Step::Body(e)) => {
                assert_eq!(a, &e);
                None
            }
            (Step::Quiesce, Step::Quiesce) => None,
            other => panic!("wrong USB transaction {other:?}"),
        };
        self.trace
            .borrow_mut()
            .completed
            .push((self.time.get(), actual));
        if self.fail == Some(self.trace.borrow().completed.len()) {
            return Err(BlockError::Device { status: 0x55 });
        }
        Ok(result)
    }
}
impl Io for Model {
    fn validate(&self) -> core::result::Result<(), BlockError> {
        Ok(()) // This in-memory model has no physical device-generation owner.
    }
    fn control(&mut self, setup: [u8; 8], data: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(setup[..6], [0x40, 1, 0, 0, 0, 0]);
        assert_eq!(
            usize::from(u16::from_le_bytes([setup[6], setup[7]])),
            data.len()
        );
        self.step(Step::Header(data.to_vec())).map(|_| ())
    }
    fn control_read(&mut self, setup: [u8; 8]) -> core::result::Result<Vec<u8>, BlockError> {
        assert_eq!(setup[0], 0xc0);
        assert_eq!(setup[2..6], [0, 0, 0, 0]);
        let data = self.step(Step::Read(setup[1], Vec::new()))?.unwrap();
        assert!(usize::from(u16::from_le_bytes([setup[6], setup[7]])) <= 20);
        Ok(data)
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        panic!("QCA DFU must honor its own bulk deadline")
    }
    fn write_firmware(
        &mut self,
        data: &[u8],
        timeout: u64,
    ) -> core::result::Result<(), BlockError> {
        assert_eq!(timeout, 3_000_000);
        assert!(data.len() <= 4096);
        self.step(Step::Body(data.to_vec())).map(|_| ())
    }
    fn receive(&mut self, pipe: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        assert!(self.polling, "DFU occurs before HCI receive polling");
        Ok(match pipe {
            Pipe::Event => self.event_rx.pop_front(),
            Pipe::Acl => self.acl_rx.pop_front(),
        })
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        self.step(Step::Quiesce).map(|_| ())
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
        let now = self.time.get();
        self.time.set(now.wrapping_add(1000));
        now
    }
}
fn version(rom: u32, patch: u32, ram: u32, chip: u8, platform: u8, flags: u16) -> Version {
    let mut raw = [0; 20];
    raw[..4].copy_from_slice(&rom.to_le_bytes());
    raw[4..8].copy_from_slice(&patch.to_le_bytes());
    raw[8..12].copy_from_slice(&ram.to_le_bytes());
    raw[12] = chip;
    raw[13] = platform;
    raw[14..16].copy_from_slice(&flags.to_le_bytes());
    Version { raw }
}
fn binding(kind: Kind) -> Binding {
    let mut config = vec![
        9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1, 7,
        5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0,
    ];
    let length = config.len() as u16;
    config[2..4].copy_from_slice(&length.to_le_bytes());
    let product = if kind == Kind::Rome {
        0xe300u16
    } else {
        0xe600u16
    };
    let mut descriptor = [18, 1, 0, 2, 0, 0, 0, 64, 0xf3, 0x0c, 0, 0, 0, 1, 0, 0, 0, 1];
    descriptor[10..12].copy_from_slice(&product.to_le_bytes());
    let device = Device {
        id: crate::usb::xhci::SlotId::fixture(1),
        vendor_ethernet_revision: None,
        vendor_ethernet_tcr: None,
        slot: 1,
        speed: xhci::FULL_SPEED,
        location: "QCA USB model".into(),
        descriptor,
        configurations: vec![config.clone()],
        configuration: config,
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
    };
    Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap()
}
fn rampatch(v: &Version, body: usize) -> Vec<u8> {
    let p = v.profile().unwrap();
    let mut image = vec![0x5a; p.rampatch_header + body];
    let n = p.version_offset;
    image[n..n + 2].copy_from_slice(&((v.rom() >> 16) as u16).to_le_bytes());
    image[n + 2..n + 4].copy_from_slice(&(v.rom() as u16).to_le_bytes());
    image[n + 4..n + 6].copy_from_slice(&((v.patch() + 1) as u16).to_le_bytes());
    image
}
fn nvm(body: usize) -> Vec<u8> {
    vec![0xa5; 4 + body]
}
fn model(
    before: Version,
    after: Version,
    status: u8,
    patch_body: usize,
    nvm_body: usize,
) -> (Hci<Model>, Catalog, Rc<RefCell<Trace>>) {
    let kind = if before.rom() < 0x10000 {
        Kind::Rome
    } else {
        Kind::Wcn
    };
    let binding = binding(kind);
    let usb = UsbIdentity::read(binding.device());
    let hardware = usb.hardware_label();
    let rev_before = before.revision_label();
    let rev_after = after.revision_label();
    let fw = rampatch(&before, patch_body);
    let config = nvm(nvm_body);
    let patch_name = before.rampatch_name();
    let nvm_name = after.nvm_name();
    let resource = |name, version: &Version, revision, bytes: Vec<u8>| Resource {
        name,
        target: version.target(&hardware, revision),
        provenance: Provenance {
            source: "independent USB controller model",
            revision: "qca-model-v1",
            member: name,
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    };
    let catalog = Catalog::from_handoff(vec![
        resource(&patch_name, &before, &rev_before, fw.clone()),
        resource(&nvm_name, &after, &rev_after, config.clone()),
    ])
    .unwrap();
    let mut steps = VecDeque::from([
        Step::Quiesce,
        Step::Read(9, before.raw.to_vec()),
        Step::Read(5, vec![status]),
    ]);
    let profile = before.profile().unwrap();
    if status & 0x80 == 0 {
        steps.push_back(Step::Header(fw[..profile.rampatch_header].to_vec()));
        for chunk in fw[profile.rampatch_header..].chunks(4096) {
            steps.push_back(Step::Body(chunk.to_vec()));
        }
    }
    steps.push_back(Step::Read(9, after.raw.to_vec()));
    if status & 0x40 == 0 {
        steps.push_back(Step::Header(config[..4].to_vec()));
        for chunk in config[4..].chunks(4096) {
            steps.push_back(Step::Body(chunk.to_vec()));
        }
    }
    let trace = Rc::new(RefCell::new(Trace::default()));
    (
        Hci::from_io(
            binding,
            Model {
                steps,
                time: Cell::new(0),
                trace: trace.clone(),
                fail: None,
                close_error: false,
                polling: false,
                event_rx: VecDeque::new(),
                acl_rx: VecDeque::new(),
            },
        ),
        catalog,
        trace,
    )
}
pub(super) fn initialized_media_report(kind: Kind) -> OwnedReport {
    let rom = if kind == Kind::Rome {
        0x00000302
    } else {
        0x00130201
    };
    let before = version(rom, 1, 0x1234, 0, 0, 0);
    let mut after = before.clone();
    after.raw[4..8].copy_from_slice(&2u32.to_le_bytes());
    let (mut hci, catalog, _) = model(before, after, 0, 4, 4);
    initialize(&mut hci, &catalog).unwrap()
}
fn attempt(error: &Error) -> (&Error, &Attempt) {
    match error {
        Error::Attempt { cause, observation } => (cause, observation),
        Error::Cleanup { cause, .. } => attempt(cause),
        other => panic!("missing partial evidence {other:?}"),
    }
}
#[test]
fn every_known_rom_and_status_combination_uses_real_source_download_sequence() {
    for profile in PROFILES {
        for status in [0, 0x40, 0x80, 0xc0] {
            let before = version(profile.rom, 1, 0x1234, 0, 0, 0);
            let mut after = before.clone();
            if status & 0x80 == 0 {
                after.raw[4..8].copy_from_slice(&2u32.to_le_bytes());
            }
            let (mut hci, catalog, trace) =
                model(before.clone(), after.clone(), status, 4097, 4097);
            let report = initialize(&mut hci, &catalog).unwrap();
            assert_eq!(report.before, before);
            assert_eq!(report.after_patch, after);
            assert_eq!(report.status, status);
            assert_eq!(hci.state(), State::Open);
            assert!(hci.io.steps.is_empty());
            assert_eq!(
                matches!(report.rampatch, FirmwareEvidence::AlreadyPresent),
                status & 0x80 != 0
            );
            assert_eq!(
                matches!(report.nvm, FirmwareEvidence::AlreadyPresent),
                status & 0x40 != 0
            );
            assert!(
                report.policy.simultaneous_discovery
                    && report.policy.broken_enhanced_setup_sync_conn
            );
            let trace = trace.borrow();
            for pair in trace.completed.windows(2) {
                if matches!(pair[0].1, Step::Header(_)) {
                    assert!(pair[1].0 - pair[0].0 >= 20_000);
                }
            }
            if profile.rom >= 0x00130201 && status & 0x40 == 0 {
                assert!(hci.io.time.get() - trace.completed.last().unwrap().0 >= 100_000);
            }
            for component in [Component::Rampatch, Component::Nvm] {
                let transferred: usize = report
                    .completed
                    .iter()
                    .filter(|t| t.component == component)
                    .map(|t| t.bytes)
                    .sum();
                let expected = match component {
                    Component::Rampatch if status & 0x80 == 0 => profile.rampatch_header + 4097,
                    Component::Nvm if status & 0x40 == 0 => 4 + 4097,
                    _ => 0,
                };
                assert_eq!(transferred, expected);
            }
        }
    }
}
#[test]
fn exact_source_board_gf_and_custom_directory_rules_are_preserved() {
    for (rom, ram, chip, platform, flags, patch, nvm) in [
        (
            0x00130201,
            0x400c1211,
            3,
            10,
            0x8000,
            "qca/QCA2066/rampatch_usb_00130201.bin",
            "qca/QCA2066/nvm_usb_00130201_gf_030a.bin",
        ),
        (
            0x00130201,
            0,
            3,
            11,
            0x80ff,
            "qca/QCA2066/rampatch_usb_00130201.bin",
            "qca/QCA2066/nvm_usb_00130201_030b.bin",
        ),
        (
            0x00130200,
            0x400c1200,
            1,
            2,
            0x8000,
            "qca/rampatch_usb_00130200.bin",
            "qca/nvm_usb_00130200_gf_0102.bin",
        ),
        (
            0x00190200,
            0,
            0xff,
            0xff,
            0x8000,
            "qca/rampatch_usb_00190200.bin",
            "qca/nvm_usb_00190200.bin",
        ),
        (
            0x302,
            0,
            3,
            10,
            0x0080,
            "qca/rampatch_usb_00000302.bin",
            "qca/nvm_usb_00000302.bin",
        ),
    ] {
        let v = version(rom, 1, ram, chip, platform, flags);
        assert_eq!(v.rampatch_name(), patch);
        assert_eq!(v.nvm_name(), nvm);
    }
    // NVM selection must use the post-patch OTP/RAM/board response.
    let before = version(0x00130201, 1, 0, 0, 0, 0);
    let after = version(0x00130201, 2, 0x400c1211, 3, 10, 0x8000);
    let (mut hci, catalog, _) = model(before, after, 0, 1, 1);
    let report = initialize(&mut hci, &catalog).unwrap();
    let FirmwareEvidence::Uploaded(receipt) = report.nvm else {
        panic!()
    };
    assert_eq!(receipt.name, "qca/QCA2066/nvm_usb_00130201_gf_030a.bin");
}
#[test]
fn all_source_usb_aliases_are_candidates_without_inferring_rom_or_images() {
    assert_eq!(SOURCE_USB_IDS.len(), 75);
    for &(vendor, product, kind) in SOURCE_USB_IDS {
        assert_eq!(
            UsbIdentity {
                vendor,
                product,
                revision: 0xffff
            }
            .kind(),
            Some(kind)
        );
    }
    assert_eq!(
        UsbIdentity {
            vendor: 0x0cf3,
            product: 0xffff,
            revision: 0
        }
        .kind(),
        None
    );
    for bytes in [vec![], vec![0; 19], vec![0; 21]] {
        assert!(Version::parse(&bytes).is_err());
    }
    assert!(matches!(
        version(0x99990100, 0, 0, 0, 0, 0).profile(),
        Err(Error::UnsupportedRom(0x99990100))
    ));
}
#[test]
fn bulk_splitting_and_rom_patch_version_guards_cover_all_boundaries() {
    for body in [0, 1, 4095, 4096, 4097, 8192, 8193] {
        let before = version(0x302, 1, 0, 0, 0, 0);
        let after = version(0x302, 2, 0, 0, 0, 0);
        let (mut hci, catalog, _) = model(before, after, 0, body, body);
        let report = initialize(&mut hci, &catalog).unwrap();
        assert!(
            report
                .completed
                .iter()
                .all(|t| t.kind == TransferKind::Header || (1..=4096).contains(&t.bytes))
        );
    }
    let v = version(0x00130201, 10, 0, 0, 0, 0);
    let p = v.profile().unwrap();
    let mut bytes = rampatch(&v, 1);
    bytes[p.version_offset + 4..p.version_offset + 6].copy_from_slice(&10u16.to_le_bytes());
    assert_eq!(RampatchVersion::parse(&bytes, &v, p).unwrap().patch, 10);
    bytes[p.version_offset + 4..p.version_offset + 6].copy_from_slice(&9u16.to_le_bytes());
    assert!(RampatchVersion::parse(&bytes, &v, p).is_err());
    let mut bytes = rampatch(&v, 1);
    bytes[p.version_offset] ^= 1;
    assert!(RampatchVersion::parse(&bytes, &v, p).is_err());
    assert!(RampatchVersion::parse(&[0; 39], &v, p).is_err());
}
#[test]
fn every_usb_failure_keeps_pending_or_completed_ownership_and_closes_once() {
    let before = version(0x00130201, 1, 0, 0, 0, 0);
    let after = version(0x00130201, 2, 0, 0, 0, 0);
    let (probe, _, _) = model(before.clone(), after.clone(), 0, 4097, 4097);
    let count = probe.io.steps.len();
    for failed in 1..=count {
        let (mut hci, catalog, trace) = model(before.clone(), after.clone(), 0, 4097, 4097);
        hci.io.fail = Some(failed);
        let error = initialize(&mut hci, &catalog).unwrap_err();
        let (cause, observed) = attempt(&error);
        assert!(matches!(cause, Error::Usb(_)));
        assert_eq!(trace.borrow().completed.len(), failed);
        assert_eq!(trace.borrow().closed, 1);
        if matches!(
            trace.borrow().completed.last().unwrap().1,
            Step::Header(_) | Step::Body(_)
        ) {
            assert!(observed.pending.is_some());
        }
        assert!(initialize(&mut hci, &catalog).is_err());
        assert_eq!(trace.borrow().completed.len(), failed);
    }
}
struct Recording<'a> {
    catalog: &'a Catalog,
    requests: RefCell<Vec<String>>,
}
impl Provider for Recording<'_> {
    fn load(&self, r: Requirement<'_>) -> core::result::Result<Image<'_>, crate::firmware::Error> {
        self.requests.borrow_mut().push(r.name.into());
        self.catalog.load(r)
    }
}
#[test]
fn native_once_only_cache_already_present_unknown_images_and_missing_are_explicit() {
    let v = version(0x302, 1, 0, 0, 0, 0);
    let (mut hci, _, trace) = model(v.clone(), v.clone(), 0xc0, 1, 1);
    let empty = Catalog::from_handoff(vec![]).unwrap();
    let recording = Recording {
        catalog: &empty,
        requests: RefCell::new(Vec::new()),
    };
    let report = hci
        .initialize_with_provider(&recording, PlatformInputs::default())
        .unwrap();
    assert!(matches!(report, InitializationReport::Qualcomm(_)));
    assert!(recording.requests.borrow().is_empty());
    let count = trace.borrow().completed.len();
    assert!(
        hci.initialize_with_provider(&recording, PlatformInputs::default())
            .is_ok()
    );
    assert_eq!(trace.borrow().completed.len(), count);
    let (mut hci, _, trace) = model(v.clone(), version(0x302, 2, 0, 0, 0, 0), 0, 1, 1);
    hci.io.close_error = true;
    let error = hci
        .initialize_with_provider(&empty, PlatformInputs::default())
        .unwrap_err();
    assert!(matches!(
        error,
        InitializationError::Qualcomm(Error::Cleanup { .. })
    ));
    assert_eq!(hci.state(), State::Failed);
    assert_eq!(trace.borrow().completed.len(), 3);
}
#[test]
fn short_status_version_and_nonapplying_firmware_do_not_report_ready() {
    for index in [1, 2] {
        let (mut hci, catalog, trace) = model(
            version(0x302, 1, 0, 0, 0, 0),
            version(0x302, 2, 0, 0, 0, 0),
            0,
            1,
            1,
        );
        let Step::Read(_, data) = &mut hci.io.steps[index] else {
            panic!()
        };
        data.pop();
        let error = initialize(&mut hci, &catalog).unwrap_err();
        assert!(matches!(attempt(&error).0, Error::Protocol { .. }));
        assert_eq!(trace.borrow().completed.len(), index + 1);
    }
    let v = version(0x302, 1, 0, 0, 0, 0);
    let (mut hci, catalog, trace) = model(v.clone(), v, 0, 1, 1);
    let error = initialize(&mut hci, &catalog).unwrap_err();
    assert!(matches!(attempt(&error).0, Error::Protocol { .. }));
    assert!(
        trace
            .borrow()
            .completed
            .iter()
            .all(|(_, step)| !matches!(step,Step::Header(v)if v.len()==4))
    );
}

#[test]
fn wcn_debug_acl_is_reclassified_exactly_across_usb_fragment_boundaries() {
    let raw = vec![0xdc, 0x2e, 3, 0, 0xaa, 0xbb, 0xcc];
    for split in 0..=raw.len() {
        let v = version(0x00130201, 1, 0, 0, 0, 0);
        let (mut hci, catalog, _) = model(v.clone(), v, 0xc0, 1, 1);
        hci.initialize_with_provider(&catalog, PlatformInputs::default())
            .unwrap();
        hci.io.polling = true;
        hci.io.acl_rx.push_back(raw[..split].to_vec());
        hci.io.acl_rx.push_back(raw[split..].to_vec());
        let mut packets = hci.poll().unwrap();
        packets.extend(hci.poll().unwrap());
        assert_eq!(
            packets,
            [crate::usb::bluetooth::Packet::Diagnostic(raw.clone())]
        );
    }
    let v = version(0x302, 1, 0, 0, 0, 0);
    let (mut hci, catalog, _) = model(v.clone(), v, 0xc0, 1, 1);
    hci.initialize_with_provider(&catalog, PlatformInputs::default())
        .unwrap();
    hci.io.polling = true;
    hci.io.acl_rx.push_back(raw.clone());
    assert_eq!(
        hci.poll().unwrap(),
        [crate::usb::bluetooth::Packet::Acl(raw)]
    );
}

#[test]
fn dump_signatures_keep_first_fault_and_quarantine() {
    use crate::usb::bluetooth::{ErrorKind, Packet};
    let event = vec![0xff, 9, 1, 8, 0, 0, 0, 0x20, 0, 0, 0];
    let short_event = vec![0xff, 2, 1, 8];
    let mut acl = vec![0xdd, 0x2e, event.len() as u8, 0];
    acl.extend_from_slice(&event);
    for packet in [
        Packet::Event(event),
        Packet::Event(short_event),
        Packet::Acl(acl),
    ] {
        let v = version(0x00130201, 1, 0, 0, 0, 0);
        let (mut hci, catalog, trace) = model(v.clone(), v, 0xc0, 1, 1);
        hci.initialize_with_provider(&catalog, PlatformInputs::default())
            .unwrap();
        hci.io.polling = true;
        hci.io.close_error = true;
        match &packet {
            Packet::Event(raw) => hci.io.event_rx.push_back(raw.clone()),
            Packet::Acl(raw) => hci.io.acl_rx.push_back(raw.clone()),
            _ => unreachable!(),
        }
        let error = hci.poll().unwrap_err();
        assert_eq!(
            error.kind,
            ErrorKind::ControllerDump {
                driver: "qualcomm-usb",
                packet
            }
        );
        assert_eq!(error.cleanup, Some(BlockError::Timeout));
        assert_eq!(hci.state(), State::Failed);
        assert_eq!(trace.borrow().closed, 1);
        assert_eq!(hci.poll().unwrap_err().kind, ErrorKind::Failed);
        assert_eq!(trace.borrow().closed, 1);
    }
}

#[test]
fn exact_catalog_target_and_complete_patch_are_required_before_download_mode() {
    for case in 0..4 {
        let before = version(0x302, 1, 0, 0, 0, 0);
        let (mut hci, _, trace) = model(before.clone(), version(0x302, 2, 0, 0, 0, 0), 0, 1, 1);
        let usb = UsbIdentity::read(hci.binding.device());
        let hardware = usb.hardware_label();
        let revision = before.revision_label();
        let name = before.rampatch_name();
        let mut bytes = rampatch(&before, 1);
        let p = before.profile().unwrap();
        match case {
            1 => bytes.truncate(p.rampatch_header - 1),
            2 => bytes[p.version_offset + 2] ^= 1,
            3 => bytes[p.version_offset + 4..p.version_offset + 6]
                .copy_from_slice(&0u16.to_le_bytes()),
            _ => {}
        }
        let mut target = before.target(&hardware, &revision);
        if case == 0 {
            target.hardware = "usb:ffff:ffff:ffff";
        }
        let catalog = Catalog::from_handoff(vec![Resource {
            name: &name,
            target,
            provenance: Provenance {
                source: "independent rejected firmware model",
                revision: "qca-model-v1",
                member: &name,
                license: "MIT",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes,
        }])
        .unwrap();
        let error = initialize(&mut hci, &catalog).unwrap_err();
        let (cause, observed) = attempt(&error);
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
        assert!(observed.pending.is_none());
        assert!(observed.completed.is_empty());
        assert_eq!(trace.borrow().completed.len(), 3);
        assert_eq!(trace.borrow().closed, 1);
        assert!(matches!(hci.io.steps.front(), Some(Step::Header(_))));
    }
    let before = version(0x302, 1, 0, 0, 0, 0);
    let (mut hci, catalog, trace) = model(before.clone(), before, 0xc0, 1, 1);
    hci.binding.output.address = 3;
    let error = initialize(&mut hci, &catalog).unwrap_err();
    assert!(matches!(attempt(&error).0, Error::Unsupported(_)));
    assert!(trace.borrow().completed.is_empty());
    assert_eq!(trace.borrow().closed, 1);
}
