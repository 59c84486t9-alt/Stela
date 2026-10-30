use super::*;
use crate::{
    block::BlockError,
    firmware::{Catalog, Image, Provenance, Provider, Requirement, Resource, Target},
    usb::{
        bluetooth::{
            Binding, FirmwareStatus, InitializationError, InitializationReport, Pipe, State,
            intel::PlatformInputs,
        },
        xhci::{Device, FULL_SPEED},
    },
};
use alloc::{collections::VecDeque, rc::Rc, string::String};
use core::cell::{Cell, RefCell};
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Present,
    ProgressOnce,
    ProgressForever,
    FragmentProgress,
    InterruptOnly,
    AuxiliaryFailure,
    LateVendor,
    WrongVendorOp,
    VendorFragment,
    VendorLength,
    EnableFailure,
    ResetStatusOnly,
    ResetStatusFailure,
    ResetNoCredits,
    WrongManufacturer,
    ZeroAddress,
    TrailingEvent,
    VersionSilent,
}
#[derive(Default)]
struct Trace {
    commands: Vec<Vec<u8>>,
    closed: usize,
    reopened: usize,
    iso_starts: usize,
    option_writes: usize,
    reads: usize,
    /// Writes once btusb_mtk_reset's first uhw read arrived.
    uhw: Vec<(u32, u32)>,
    resetting: bool,
    usb_resets: usize,
}
struct Model {
    registers: [u32; 4],
    events: VecDeque<Vec<u8>>,
    vendor: Option<Vec<u8>>,
    trace: Rc<RefCell<Trace>>,
    fault: Fault,
    time: Cell<u64>,
    queries: usize,
    fail_read: Option<usize>,
    close_failure: bool,
}
fn cc(op: u16, p: &[u8]) -> Vec<u8> {
    let mut b = vec![14, (p.len() + 3) as u8, 1];
    b.extend_from_slice(&op.to_le_bytes());
    b.extend_from_slice(p);
    b
}
impl Io for Model {
    fn validate(&self) -> core::result::Result<(), BlockError> {
        Ok(()) // This in-memory model has no physical device-generation owner.
    }
    fn control(&mut self, setup: [u8; 8], p: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(self.trace.borrow().closed, 0);
        if setup[0] == 0x5e && self.trace.borrow().resetting {
            let address = u32::from(u16::from_le_bytes([setup[2], setup[3]])) << 16
                | u32::from(u16::from_le_bytes([setup[4], setup[5]]));
            let value = u32::from_le_bytes(p.try_into().unwrap());
            self.trace.borrow_mut().uhw.push((address, value));
            return Ok(());
        }
        if setup[0] == 0x5e {
            assert_eq!(setup, [0x5e, 2, 1, 0x74, 0x90, 0x18, 4, 0]);
            assert_eq!(p, [1, 0, 1, 0]);
            self.trace.borrow_mut().option_writes += 1;
            return Ok(());
        }
        assert_eq!(setup[..6], [0x20, 0, 0, 0, 0, 0]);
        assert_eq!(usize::from(p[2]) + 3, p.len());
        self.trace.borrow_mut().commands.push(p.to_vec());
        let op = u16::from_le_bytes([p[0], p[1]]);
        if op == 0xfc6f {
            assert_eq!(p[3], 1);
            assert_eq!(usize::from(u16::from_le_bytes([p[5], p[6]])) + 7, p.len());
            let mut flag = 0;
            if p[4] == 1 && p[7] == 0 {
                self.queries += 1;
                flag = match self.fault {
                    Fault::Present => 2,
                    Fault::ProgressForever => 1,
                    Fault::ProgressOnce if self.queries % 2 == 1 => 1,
                    _ => 0,
                };
            } else if p[4] == 1 && self.fault == Fault::FragmentProgress {
                flag = 1;
            }
            if p[4] == 6 && self.fault == Fault::EnableFailure {
                flag = 1;
            }
            let mut e = vec![0xe4, 5, 2, p[4], 1, 0, flag];
            match self.fault {
                Fault::InterruptOnly => e.clear(),
                Fault::WrongVendorOp => e[3] = 7,
                Fault::VendorFragment => {
                    e.pop();
                }
                Fault::VendorLength => e[4] = 2,
                _ => {}
            }
            self.vendor = Some(e);
            // A real interrupt CC still cannot substitute for EP0 WMT.
            self.events.push_back(cc(
                op,
                &[if self.fault == Fault::AuxiliaryFailure {
                    0x0c
                } else {
                    0
                }],
            ));
            return Ok(());
        }
        if op == 0x1001 && self.fault == Fault::VersionSilent {
            return Ok(());
        }
        let mut response = match op {
            0x0c03 => match self.fault {
                Fault::ResetStatusOnly => vec![15, 4, 0, 1, 3, 0x0c],
                Fault::ResetStatusFailure => cc(op, &[0x0c]),
                Fault::ResetNoCredits => {
                    let mut b = cc(op, &[0]);
                    b[2] = 0;
                    b
                }
                _ => cc(op, &[0]),
            },
            0x1001 => cc(
                op,
                &[
                    0,
                    11,
                    0x34,
                    0x12,
                    11,
                    if self.fault == Fault::WrongManufacturer {
                        2
                    } else {
                        70
                    },
                    0,
                    0x78,
                    0x56,
                ],
            ),
            0x1009 => {
                if self.fault == Fault::ZeroAddress {
                    cc(op, &[0; 7])
                } else {
                    cc(op, &[0, 1, 2, 3, 4, 5, 6])
                }
            }
            // btmtk_usb_isointf_init's vendor command.
            0xfd98 => cc(op, &[0]),
            _ => panic!("unexpected HCI command {op:x}"),
        };
        if op == 0x1009 && self.fault == Fault::TrailingEvent {
            response.extend_from_slice(&[0xff, 0]);
        }
        // Interrupt event framing still crosses USB transfers.
        self.events.push_back(response[..1].to_vec());
        self.events.push_back(response[1..].to_vec());
        Ok(())
    }
    fn control_read(&mut self, setup: [u8; 8]) -> core::result::Result<Vec<u8>, BlockError> {
        self.trace.borrow_mut().reads += 1;
        if self.fail_read == Some(self.trace.borrow().reads) {
            return Err(BlockError::Device { status: 0x55 });
        }
        if setup[0] == 0xde {
            // Every uhw register reads as MTK_BT_RST_DONE.
            self.trace.borrow_mut().resetting = true;
            return Ok(0x100u32.to_le_bytes().to_vec());
        }
        if setup[1] == 0x63 {
            assert_eq!(setup[0], 0xc0);
            assert_eq!(setup[6..], [4, 0]);
            let address = (u32::from(u16::from_le_bytes([setup[2], setup[3]])) << 16)
                | u32::from(u16::from_le_bytes([setup[4], setup[5]]));
            let i = match address {
                0x80000008 => 0,
                0x70010200 => 1,
                0x80021004 => 2,
                0x70010020 => 3,
                _ => panic!("unexpected register"),
            };
            return Ok(self.registers[i].to_le_bytes().to_vec());
        }
        assert_eq!(setup, [0xc0, 1, 48, 0, 0, 0, 64, 0]);
        let result = self.vendor.take().unwrap_or_default();
        if self.fault == Fault::LateVendor {
            self.time.set(self.time.get() + 6_000_000);
        }
        Ok(result)
    }
    fn receive(&mut self, p: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        Ok(if p == Pipe::Event {
            self.events.pop_front()
        } else {
            None
        })
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        panic!("MediaTek WMT must not use bulk")
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        panic!("no Intel mode transition")
    }
    fn close(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().closed += 1;
        if self.close_failure {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn reopen(&mut self) -> core::result::Result<(), BlockError> {
        let mut trace = self.trace.borrow_mut();
        trace.closed = 0;
        trace.reopened += 1;
        Ok(())
    }
    fn queue_reset(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().usb_resets += 1;
        Ok(())
    }
    fn now_us(&self) -> u64 {
        let t = self.time.get();
        self.time.set(t + 10000);
        t
    }
}
fn firmware() -> Vec<u8> {
    let mut b = vec![0; 802];
    b[16..20].copy_from_slice(b"ALPS");
    b[24..28].fill(0xff);
    b[44..48].copy_from_slice(&3u32.to_le_bytes());
    for (i, offset, size, download) in [
        (0, 288u32, 501u32, 501u32),
        (1, 789, 10, 10),
        (2, 799, 3, 0),
    ] {
        let at = 96 + i * 64;
        for (n, value) in [
            (0, 1u32),
            (4, offset),
            (8, size),
            (12, 0x900000),
            (16, download),
            (20, 0x01000000),
            (32, 0x101),
        ] {
            b[at + n..at + n + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    b[288..789].fill(0xa5);
    b[789..799].fill(0xb6);
    b[799..].copy_from_slice(b"MET");
    b
}
fn fixture(chip: Chip, fault: Fault) -> (Hci<Model>, Catalog, Rc<RefCell<Trace>>) {
    let (vid, pid, device, rom) = match chip {
        Chip::Mt7961 => (0x0e8du16, 0x0608u16, 0x7961u32, 1u32),
        Chip::Mt7922 => (0x13d3, 0x3585, 0x7922, 0),
        Chip::Mt7925 => (0x0489, 0xe111, 0x7925, 0),
    };
    let mut descriptor = [18, 1, 0, 2, 0xe0, 1, 1, 64, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1];
    descriptor[8..10].copy_from_slice(&vid.to_le_bytes());
    descriptor[10..12].copy_from_slice(&pid.to_le_bytes());
    let configuration = vec![
        9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1, 7,
        5, 0x82, 2, 64, 0, 0, 7, 5, 2, 2, 64, 0, 0,
    ];
    let d = Device {
        id: crate::usb::xhci::SlotId::fixture(1),
        vendor_ethernet_tcr: None,
        vendor_ethernet_revision: None,
        slot: 1,
        speed: FULL_SPEED,
        location: "MediaTek stateful original model".into(),
        descriptor,
        configurations: vec![configuration.clone()],
        configuration,
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
    };
    let usb = UsbIdentity {
        vendor: vid,
        product: pid,
        revision: 0x100,
    };
    let trace = Rc::new(RefCell::new(Trace::default()));
    let binding =
        Binding::new(&d, &crate::usb::descriptor::interfaces(&d.configuration)[0]).unwrap();
    (
        Hci::from_io(binding, model(device, rom, fault, &trace)),
        catalog(usb, device, rom),
        trace,
    )
}
fn catalog(usb: UsbIdentity, device: u32, rom: u32) -> Catalog {
    let identity = Identity::select(usb, 0, device, rom, 0).unwrap();
    let hardware = usb.hardware_label();
    let revision = identity.revision_label();
    let target = Target {
        driver: "mediatek-bluetooth-usb-mt79xx-v1",
        hardware: &hardware,
        revision: &revision,
        board: None,
    };
    let bytes = firmware();
    Catalog::from_handoff(vec![Resource {
        name: identity.firmware_name(),
        target,
        provenance: Provenance {
            source: "original model",
            revision: "model-v1",
            member: identity.firmware_name(),
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap()
}
fn model(device: u32, rom: u32, fault: Fault, trace: &Rc<RefCell<Trace>>) -> Model {
    Model {
        registers: [0, device, rom, 0],
        events: VecDeque::new(),
        vendor: None,
        trace: trace.clone(),
        fault,
        time: Cell::new(0),
        queries: 0,
        fail_read: None,
        close_failure: false,
    }
}
/// The interrupt-interface media owner; this model carries no SCO.
impl media::MediaIo for Model {
    fn start_iso(
        &mut self,
        _: media::Pair,
        _: &mut dyn crate::bus::dma::DmaAllocator,
    ) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().iso_starts += 1;
        Ok(())
    }
    fn replace_sco(
        &mut self,
        _: Option<media::Pair>,
        _: Option<media::Pair>,
        _: &mut dyn crate::bus::dma::DmaAllocator,
    ) -> core::result::Result<(), BlockError> {
        unreachable!()
    }
    fn read_media(
        &mut self,
        _: media::Kind,
    ) -> core::result::Result<Option<media::Read>, BlockError> {
        Ok(None)
    }
    fn write_media(&mut self, _: media::Kind, _: &[u8]) -> media::Result<()> {
        unreachable!()
    }
    fn quiesce_media(&mut self) -> core::result::Result<(), BlockError> {
        unreachable!()
    }
    fn reset_media_epoch(&mut self) -> core::result::Result<(), BlockError> {
        unreachable!()
    }
    fn resume_media(&mut self) -> core::result::Result<(), BlockError> {
        unreachable!()
    }
    fn close_media(&mut self) -> core::result::Result<(), BlockError> {
        Ok(())
    }
    fn reopen_media(&mut self) -> core::result::Result<(), BlockError> {
        Ok(())
    }
}
type Requests = Vec<(String, String, String, String)>;
struct Recording<'a> {
    catalog: &'a Catalog,
    requests: RefCell<Requests>,
}
impl Provider for Recording<'_> {
    fn load(&self, r: Requirement<'_>) -> core::result::Result<Image<'_>, crate::firmware::Error> {
        assert!(r.target.board.is_none());
        self.requests.borrow_mut().push((
            r.name.into(),
            r.target.driver.into(),
            r.target.hardware.into(),
            r.target.revision.into(),
        ));
        self.catalog.load(r)
    }
}
#[test]
fn power_on_after_shutdown_runs_setup_again_like_non_persistent_setup() {
    struct NoDma;
    impl crate::bus::dma::DmaAllocator for NoDma {
        fn allocate(
            &mut self,
            _: usize,
            _: usize,
        ) -> core::result::Result<crate::bus::dma::DmaBuffer, BlockError> {
            panic!("the model allocates no DMA")
        }
    }
    // This PC's MT7925, bound with its media interfaces.
    let usb = UsbIdentity {
        vendor: 0x13d3,
        product: 0x3602,
        revision: 0x100,
    };
    let trace = Rc::new(RefCell::new(Trace::default()));
    let catalog = catalog(usb, 0x7925, 0);
    let mut hci = Hci::from_io(
        media::tests::binding(),
        model(0x7925, 0, Fault::None, &trace),
    );
    hci.initialize_with_provider(&catalog, PlatformInputs::default())
        .unwrap();
    let credits = match hci.initialization() {
        Some(Ok(InitializationReport::MediaTek(r))) => r.command_credits,
        _ => panic!("MediaTek report expected"),
    };
    assert_eq!(credits, 1);
    let mut s = media::Session::start(hci, &mut NoDma, credits).unwrap();
    assert!(matches!(
        s.power_on(&catalog, &mut NoDma),
        Err(media::PowerOnError::Media(_))
    ));
    assert_eq!(s.lifecycle(), media::Lifecycle::Running);
    s.shutdown(1).unwrap();
    assert_eq!(s.lifecycle(), media::Lifecycle::Off);
    let resets = |trace: &Trace| {
        trace
            .commands
            .iter()
            .filter(|c| c[..2] == [3, 0x0c])
            .count()
    };
    assert_eq!(resets(&trace.borrow()), 1);
    // The function keeps its patch across power-off.
    s.hci.io.fault = Fault::Present;
    s.power_on(&catalog, &mut NoDma).unwrap();
    assert_eq!(s.lifecycle(), media::Lifecycle::Running);
    let trace = trace.borrow();
    assert_eq!((trace.reopened, trace.iso_starts), (1, 2));
    // Setup ran again through HCI Reset, then the ISO interface init.
    assert_eq!(resets(&trace), 2);
    assert_eq!(trace.commands.last().unwrap(), &[0x98, 0xfd, 2, 8, 1]);
    assert_eq!(s.setup_report().completion, cc(0xfd98, &[0]));
}
fn attempt(e: &Error) -> (&Error, &Attempt) {
    match e {
        Error::Attempt { cause, observation } => (cause, observation),
        Error::Cleanup { cause, .. } => attempt(cause),
        _ => panic!("missing partial attempt {e:?}"),
    }
}
#[test]
fn native_report_owns_evidence_preserves_present_unknown_and_never_retries() {
    for chip in [Chip::Mt7961, Chip::Mt7922, Chip::Mt7925] {
        for fault in [Fault::None, Fault::Present, Fault::ProgressOnce] {
            let (mut hci, catalog, trace) = fixture(chip, fault);
            let provider = Recording {
                catalog: &catalog,
                requests: RefCell::new(vec![]),
            };
            let InitializationReport::MediaTek(r) = hci
                .initialize_with_provider(&provider, PlatformInputs::default())
                .unwrap()
            else {
                panic!("MediaTek report expected")
            };
            assert_eq!(r.identity.chip, chip);
            assert_eq!(r.metadata.sections.len(), 3);
            assert_eq!(r.metadata.sections[2].size(), 3);
            assert_eq!(r.address, [1, 2, 3, 4, 5, 6]);
            assert_eq!(r.local_version, [0, 11, 0x34, 0x12, 11, 70, 0, 0x78, 0x56]);
            assert_eq!(r.reset_completion, cc(0x0c03, &[0]));
            assert_eq!(r.sections.len(), 2);
            assert_eq!(r.recovery, RecoveryPolicy::FreshRebindRequired);
            assert_eq!(
                r.policy,
                HostPolicy {
                    manufacturer: 70,
                    wideband_speech: r.identity.usb.vendor != 0x0e8d
                        || [0x0608, 0x223c, 0x8c38].contains(&r.identity.usb.product),
                    broken_enhanced_setup_sync_conn: true,
                    non_persistent_setup: true,
                    microsoft_opcode: Some(0xfd30),
                    aosp: true,
                }
            );
            for s in &r.sections {
                assert_eq!(
                    s.disposition,
                    Some(if fault == Fault::Present {
                        SectionDisposition::AlreadyPresentUnknown
                    } else {
                        SectionDisposition::Transferred
                    })
                );
                assert_eq!(
                    s.queries.len(),
                    if fault == Fault::ProgressOnce { 2 } else { 1 }
                );
            }
            assert_eq!(
                r.sections
                    .iter()
                    .map(|s| s.acknowledged_fragments)
                    .sum::<usize>(),
                if fault == Fault::Present { 0 } else { 4 }
            );
            assert_eq!(r.firmware.target_revision, r.identity.revision_label());
            assert!(r.firmware.target_revision.len() < 256);
            assert!(!r.auxiliary_hci_events.is_empty());
            assert_eq!(provider.requests.borrow().len(), 1);
            drop(provider);
            drop(catalog);
            // This reference still borrows Hci after both Provider and its
            // Catalog are gone; report fields cannot borrow image bytes.
            assert_eq!(r.identity.chip, chip);
            assert_eq!(r.firmware.sha256, r.metadata.sha256);
            let count = trace.borrow().commands.len();
            let empty = Catalog::from_handoff(vec![]).unwrap();
            assert!(
                hci.initialize_with_provider(&empty, PlatformInputs::default())
                    .is_ok()
            );
            assert_eq!(trace.borrow().commands.len(), count);
            assert_eq!(trace.borrow().option_writes, 1);
            assert_eq!(hci.state(), State::Open);
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            if fault != Fault::Present {
                let commands = &trace.borrow().commands;
                let flags: Vec<_> = commands
                    .iter()
                    .filter(|p| p[0..2] == [0x6f, 0xfc] && p[4] == 1 && p[7] != 0)
                    .map(|p| (p[7], p.len() - 8))
                    .collect();
                assert_eq!(flags, [(1, 250), (2, 250), (3, 1), (1, 10)]);
            }
        }
    }
}
#[test]
fn missing_exact_image_is_recorded_once_and_uncertain_candidate_is_quarantined() {
    let (mut hci, _, trace) = fixture(Chip::Mt7961, Fault::None);
    let empty = Catalog::from_handoff(vec![]).unwrap();
    let provider = Recording {
        catalog: &empty,
        requests: RefCell::new(vec![]),
    };
    let InitializationError::MediaTek(e) = hci
        .initialize_with_provider(&provider, PlatformInputs::default())
        .unwrap_err()
    else {
        panic!("MediaTek error expected")
    };
    let (cause, a) = attempt(e);
    assert!(matches!(cause,Error::Resource(e)if e.name=="mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin"));
    assert_eq!(a.registers.len(), 4);
    assert!(a.sections.is_empty());
    assert_eq!(
        provider.requests.borrow().as_slice(),
        [(
            "mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin".into(),
            "mediatek-bluetooth-usb-mt79xx-v1".into(),
            "usb:0e8d:0608:0100".into(),
            "mt79xx-v1:legacy-00000000:device-00007961:firmware-00000001:flavor-00000000".into()
        )]
    );
    assert!(trace.borrow().commands.is_empty());
    // request_firmware's failure is a failed firmware setup.
    assert_eq!(trace.borrow().usb_resets, 1);
    assert_eq!(hci.state(), State::Closed);
    assert!(
        hci.initialize_with_provider(&provider, PlatformInputs::default())
            .is_err()
    );
    assert_eq!(provider.requests.borrow().len(), 1);
    assert!(hci.submit_command(&[3, 0x0c, 0]).is_err());
}
#[test]
fn ep0_wmt_and_hci_reset_completions_cannot_be_substituted_or_guessed() {
    for fault in [
        Fault::ProgressForever,
        Fault::FragmentProgress,
        Fault::InterruptOnly,
        Fault::AuxiliaryFailure,
        Fault::LateVendor,
        Fault::WrongVendorOp,
        Fault::VendorFragment,
        Fault::VendorLength,
        Fault::EnableFailure,
        Fault::ResetStatusOnly,
        Fault::ResetStatusFailure,
        Fault::ResetNoCredits,
        Fault::WrongManufacturer,
        Fault::ZeroAddress,
        Fault::TrailingEvent,
        Fault::VersionSilent,
    ] {
        let (mut hci, catalog, trace) = fixture(Chip::Mt7925, fault);
        let e = initialize(&mut hci, &catalog).unwrap_err();
        let (_, a) = attempt(&e);
        assert!(a.metadata.is_some());
        assert!(a.firmware.is_some());
        assert_eq!(hci.state(), State::Closed);
        assert_eq!(trace.borrow().closed, 1);
        // A failed firmware setup and a timed-out command other than HCI
        // Reset run btusb_mtk_reset; later failures do not.
        let reset = matches!(
            fault,
            Fault::ProgressForever
                | Fault::FragmentProgress
                | Fault::InterruptOnly
                | Fault::AuxiliaryFailure
                | Fault::LateVendor
                | Fault::WrongVendorOp
                | Fault::VendorFragment
                | Fault::VendorLength
                | Fault::VersionSilent
        );
        assert_eq!(trace.borrow().usb_resets, usize::from(reset), "{fault:?}");
        if let Some(r) = &a.reset {
            assert_eq!((&r.subsystem, &r.usb), (&Ok(()), &Ok(())));
            assert_eq!(trace.borrow().uhw[0], (0x7002_8610, 0x120));
        }
        assert!(hci.submit_acl(&[1, 0, 0, 0]).is_err());
        if fault == Fault::ProgressForever {
            assert_eq!(a.sections[0].queries.len(), 20);
            assert_eq!(trace.borrow().option_writes, 0);
        }
        if fault == Fault::InterruptOnly {
            assert!(matches!(attempt(&e).0, Error::Timeout(_)));
            assert!(!a.auxiliary_hci_events.is_empty());
            assert!(a.pending_wmt.is_some());
        }
        if fault == Fault::AuxiliaryFailure || fault == Fault::LateVendor {
            assert!(a.last_wmt.is_some());
            assert!(a.pending_wmt.is_some());
            assert!(a.sections[0].queries.is_empty());
        }
        if fault == Fault::ResetStatusFailure || fault == Fault::ResetNoCredits {
            assert!(a.reset_completion.is_some());
        }
        if fault == Fault::WrongManufacturer {
            assert_eq!(a.local_version.as_ref().unwrap()[5], 2);
        }
        if fault == Fault::ZeroAddress {
            assert_eq!(a.address, Some([0; 6]));
        }
        if fault == Fault::TrailingEvent {
            assert_eq!(a.address, Some([1, 2, 3, 4, 5, 6]));
            assert!(matches!(attempt(&e).0,Error::Protocol {observed,..} if observed==&[0xff,0]));
        }
    }
}
#[test]
fn unqualified_rom_flavor_and_combo_id_never_trigger_load_or_reset() {
    for (register, value) in [(1, 0), (1, 0x6639), (2, 2), (3, 0x80)] {
        let (mut hci, catalog, trace) = fixture(Chip::Mt7961, Fault::None);
        hci.io.registers[register] = value;
        let provider = Recording {
            catalog: &catalog,
            requests: RefCell::new(vec![]),
        };
        let e = initialize(&mut hci, &provider).unwrap_err();
        assert!(matches!(attempt(&e).0, Error::Unsupported(_)));
        assert!(provider.requests.borrow().is_empty());
        assert!(trace.borrow().commands.is_empty());
        assert_eq!(trace.borrow().option_writes, 0);
        assert_eq!(hci.state(), State::Closed);
    }
}
#[test]
fn donor_own_vendor_match_requires_hci_class_and_observed_silicon_not_a_guessed_pid() {
    let (mut hci, _, trace) = fixture(Chip::Mt7922, Fault::None);
    hci.binding.device.descriptor[8..10].copy_from_slice(&0x0e8du16.to_le_bytes());
    hci.binding.device.descriptor[10..12].copy_from_slice(&0x0616u16.to_le_bytes());
    assert!(is_candidate(hci.binding.device()));
    let empty = Catalog::from_handoff(vec![]).unwrap();
    let provider = Recording {
        catalog: &empty,
        requests: RefCell::new(vec![]),
    };
    let error = initialize(&mut hci, &provider).unwrap_err();
    assert!(matches!(attempt(&error).0, Error::Resource(_)));
    let calls = provider.requests.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin");
    assert_eq!(calls[0].2, "usb:0e8d:0616:0100");
    assert!(trace.borrow().commands.is_empty());
    hci.binding.device.configuration[14] = 0xff;
    assert!(!is_candidate(hci.binding.device()));
}
#[test]
fn failed_control_read_keeps_typed_errors() {
    for read in [1, 5] {
        let (mut hci, catalog, trace) = fixture(Chip::Mt7922, Fault::None);
        hci.io.fail_read = Some(read);
        let e = initialize(&mut hci, &catalog).unwrap_err();
        assert!(
            matches!(attempt(&e).0,Error::Transport(e)if matches!(e.kind,crate::usb::bluetooth::ErrorKind::Usb(BlockError::Device {status:0x55})))
        );
        assert_eq!(hci.state(), State::Failed);
        assert_eq!(trace.borrow().closed, 1);
    }
    let (mut hci, catalog, _) = fixture(Chip::Mt7922, Fault::EnableFailure);
    hci.io.close_failure = true;
    let e = initialize(&mut hci, &catalog).unwrap_err();
    assert!(matches!(e, Error::Cleanup { .. }));
    assert_eq!(hci.state(), State::Failed);
}
