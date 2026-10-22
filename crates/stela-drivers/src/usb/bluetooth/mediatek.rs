// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Bounded MT79xx Bluetooth firmware parsing and WMT download framing adapted
//! from pinned Linux btmtk.c. The explicit native initializer requires observed
//! silicon/ROM/flavor, exact Provider input and genuine EP0 WMT events. Image
//! authenticity, physical/radio qualification and guest services remain separate.
mod firmware;
mod identity;
mod initialize;
mod wmt;
pub use firmware::{FirmwareMetadata, Fragment, Patch, Section, SectionMetadata};
pub use identity::{Chip, Identity, UsbIdentity};
pub use wmt::{WmtCommandReceipt, WmtEvent};

use super::{FirmwareReceipt, Hci, Io};
use alloc::{boxed::Box, vec::Vec};
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterObservation {
    pub address: u32,
    pub value: u32,
}
/// Already-present controller state is not proof that our candidate image was
/// uploaded, verified by the ROM, or is the active executable image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionDisposition {
    Transferred,
    AlreadyPresentUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionReceipt {
    pub index: usize,
    pub queries: Vec<WmtEvent>,
    pub acknowledged_fragments: usize,
    pub last_download_response: Option<WmtEvent>,
    pub disposition: Option<SectionDisposition>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub registers: Vec<RegisterObservation>,
    pub identity: Option<Identity>,
    pub firmware: Option<FirmwareReceipt>,
    pub metadata: Option<FirmwareMetadata>,
    pub sections: Vec<SectionReceipt>,
    pub pending_wmt: Option<WmtCommandReceipt>,
    /// Latest parsed actual EP0 observation, including a response rejected by
    /// subsequent timing/interrupt/status validation. It never credits success.
    pub last_wmt: Option<WmtEvent>,
    pub endpoint_reset_option_completed: bool,
    pub function_enable: Option<WmtEvent>,
    pub auxiliary_hci_events: Vec<Vec<u8>>,
    pub reset_completion: Option<Vec<u8>>,
    pub local_version: Option<[u8; 9]>,
    pub address: Option<[u8; 6]>,
}
/// No shared combo power/reset service has granted authority to retry a failed
/// firmware upload. Failure is terminal for this attachment and requires rebind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPolicy {
    FreshRebindRequired,
}
/// Owned historical execution evidence. Per-section dispositions preserve the
/// distinction between transferred bytes and unknown already-present firmware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub identity: Identity,
    pub firmware: Box<FirmwareReceipt>,
    pub metadata: FirmwareMetadata,
    pub sections: Vec<SectionReceipt>,
    pub function_enable: WmtEvent,
    pub auxiliary_hci_events: Vec<Vec<u8>>,
    pub reset_completion: Vec<u8>,
    pub local_version: [u8; 9],
    pub address: [u8; 6],
    pub recovery: RecoveryPolicy,
}
#[derive(Debug)]
pub enum Error {
    Unsupported(&'static str),
    Protocol {
        requirement: &'static str,
        observed: Vec<u8>,
    },
    Format(FormatError),
    Resource(crate::firmware::Error),
    Controller {
        opcode: u16,
        status: u8,
        parameters: Vec<u8>,
    },
    Timeout(&'static str),
    Transport(super::Error),
    Attempt {
        cause: Box<Error>,
        observation: Box<Attempt>,
    },
    Cleanup {
        cause: Box<Error>,
        cleanup: super::Error,
    },
}
impl Error {
    fn protocol(requirement: &'static str, observed: &[u8]) -> Self {
        Self::Protocol {
            requirement,
            observed: observed.to_vec(),
        }
    }
}
impl From<FormatError> for Error {
    fn from(e: FormatError) -> Self {
        Self::Format(e)
    }
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Transport(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek Bluetooth initialization {self:?}")
    }
}
impl core::error::Error for Error {}
pub fn is_candidate(device: &crate::usb::xhci::Device) -> bool {
    UsbIdentity::read(device).candidate()
        && crate::usb::xhci::interfaces(&device.configuration)
            .iter()
            .any(|i| i.alternate == 0 && (i.class, i.subclass, i.protocol) == (super::CLASS, 1, 1))
}
pub fn initialize<B: Io>(
    hci: &mut Hci<B>,
    provider: &dyn crate::firmware::Provider,
) -> Result<OwnedReport> {
    initialize::run(hci, provider)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    Size,
    Header,
    SectionTable,
    SectionBounds,
    DownloadBounds,
    OverlappingSections,
    NoDownload,
}
impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek firmware format {self:?}")
    }
}
impl core::error::Error for FormatError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::BlockError,
        firmware::{Catalog, Image, Provenance, Provider, Requirement, Resource, Target},
        usb::{
            bluetooth::{
                Binding, FirmwareStatus, InitializationError, InitializationReport, Pipe, State,
                intel::PlatformInputs,
            },
            xhci::{self, Device, FULL_SPEED},
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
    }
    #[derive(Default)]
    struct Trace {
        commands: Vec<Vec<u8>>,
        closed: usize,
        option_writes: usize,
        reads: usize,
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
        fn control(&mut self, setup: [u8; 8], p: &[u8]) -> core::result::Result<(), BlockError> {
            assert_eq!(self.trace.borrow().closed, 0);
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
                _ => panic!("unexpected HCI command {op:x}"),
            };
            if op == 0x1009 && self.fault == Fault::TrailingEvent {
                response.extend_from_slice(&[0xff, 0]);
            }
            // Genuine interrupt event framing still crosses USB transfers.
            self.events.push_back(response[..1].to_vec());
            self.events.push_back(response[1..].to_vec());
            Ok(())
        }
        fn control_read(&mut self, setup: [u8; 8]) -> core::result::Result<Vec<u8>, BlockError> {
            self.trace.borrow_mut().reads += 1;
            if self.fail_read == Some(self.trace.borrow().reads) {
                return Err(BlockError::Device { status: 0x55 });
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
            9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 2, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1,
            7, 5, 0x82, 2, 64, 0, 0, 7, 5, 2, 2, 64, 0, 0,
        ];
        let d = Device {
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
        };
        let usb = UsbIdentity {
            vendor: vid,
            product: pid,
            revision: 0x100,
        };
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
        let catalog = Catalog::from_handoff(vec![Resource {
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
        .unwrap();
        let trace = Rc::new(RefCell::new(Trace::default()));
        let binding = Binding::new(&d, &xhci::interfaces(&d.configuration)[0]).unwrap();
        (
            Hci::from_io(
                binding,
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
                },
            ),
            catalog,
            trace,
        )
    }
    type Requests = Vec<(String, String, String, String)>;
    struct Recording<'a> {
        catalog: &'a Catalog,
        requests: RefCell<Requests>,
    }
    impl Provider for Recording<'_> {
        fn load(
            &self,
            r: Requirement<'_>,
        ) -> core::result::Result<Image<'_>, crate::firmware::Error> {
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
    fn attempt(e: &Error) -> (&Error, &Attempt) {
        match e {
            Error::Attempt { cause, observation } => (cause, observation),
            Error::Cleanup { cause, .. } => attempt(cause),
            _ => panic!("missing partial attempt {e:?}"),
        }
    }
    #[test]
    fn exact_native_report_owns_evidence_preserves_present_unknown_and_never_retries() {
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
        assert!(
            matches!(cause,Error::Resource(e)if e.name=="mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin")
        );
        assert_eq!(a.registers.len(), 4);
        assert!(a.sections.is_empty());
        assert_eq!(
            provider.requests.borrow().as_slice(),
            [(
                "mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin".into(),
                "mediatek-bluetooth-usb-mt79xx-v1".into(),
                "usb:0e8d:0608:0100".into(),
                "mt79xx-v1:legacy-00000000:device-00007961:firmware-00000001:flavor-00000000"
                    .into()
            )]
        );
        assert!(trace.borrow().commands.is_empty());
        assert_eq!(hci.state(), State::Closed);
        assert!(
            hci.initialize_with_provider(&provider, PlatformInputs::default())
                .is_err()
        );
        assert_eq!(provider.requests.borrow().len(), 1);
        assert!(hci.submit_command(&[3, 0x0c, 0]).is_err());
    }
    #[test]
    fn genuine_ep0_wmt_and_hci_reset_completions_cannot_be_substituted_or_guessed() {
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
        ] {
            let (mut hci, catalog, trace) = fixture(Chip::Mt7925, fault);
            let e = initialize(&mut hci, &catalog).unwrap_err();
            let (_, a) = attempt(&e);
            assert!(a.metadata.is_some());
            assert!(a.firmware.is_some());
            assert_eq!(hci.state(), State::Closed);
            assert_eq!(trace.borrow().closed, 1);
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
                assert!(
                    matches!(attempt(&e).0,Error::Protocol {observed,..} if observed==&[0xff,0])
                );
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
    fn failed_control_read_and_failed_cleanup_preserve_typed_errors_and_terminal_state() {
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
}
