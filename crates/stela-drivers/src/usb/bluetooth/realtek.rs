// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Endless Mobile, Inc.
//! Realtek USB firmware staging adapted from pinned Linux `btrtl.c`/`btrtl.h`.
//! See THIRD_PARTY.md for exact provenance and limits. Explicit initialization
//! observes an exact USB/HCI/ROM/security profile, stages exact Provider images
//! and requires real download completions and post-upload version/address.
//! This establishes observed protocol execution, never vendor authentication,
//! radio qualification or guest services. Generic firmware status is unchanged.
mod firmware;
mod identity;
mod initialize;
pub mod media;
mod v2;
pub use firmware::{Configuration, Fragment, Patch, Project, Staged};
pub use identity::{Identity, LocalVersion, UsbIdentity};
pub use v2::{ExtensionRecord, SectionObservation, SubsectionObservation, V2Metadata, V2Patch};

/// Malformed or explicitly unsupported Realtek input. Parsing never emits a
/// partially selected download or silently substitutes another ROM/project.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    Size,
    Signature,
    Extension,
    Project,
    PatchTable,
    PatchBounds,
    OverlappingPatches,
    DuplicateChip,
    MissingRom,
    ConfigHeader,
    ConfigEntry,
    OverlappingConfig,
    Section,
    Subsection,
    Security,
}
impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Realtek firmware format {self:?}")
    }
}
impl core::error::Error for FormatError {}

use super::{FirmwareReceipt, Hci, Io};
use alloc::{boxed::Box, vec::Vec};
pub type Result<T> = core::result::Result<T, Error>;

/// Exact config image or a retained named Missing error permitted by this
/// profile. Malformed/integrity/target failures can never enter OptionalMissing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationEvidence {
    Supplied(FirmwareReceipt),
    OptionalMissing(crate::firmware::Error),
}
/// Genuine download return index retained without inventing an undocumented
/// echo rule. The pinned donor checks return shape, not index equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DownloadResponse {
    pub sent_index: u8,
    pub returned_index: u8,
}
/// Partial observed identity and immutable receipts survive every failure;
/// acknowledged commands never credit a ready or successfully booted image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub version: Option<LocalVersion>,
    pub register_subversion: Option<u16>,
    pub register_revision: Option<u16>,
    pub rom_version: Option<u8>,
    pub security: Option<[u8; 2]>,
    pub identity: Option<Identity>,
    pub firmware: Option<FirmwareReceipt>,
    pub configuration: Option<core::result::Result<FirmwareReceipt, crate::firmware::Error>>,
    pub container_version: Option<ContainerVersion>,
    pub v2: Option<V2Metadata>,
    pub download: Vec<DownloadResponse>,
    pub after: Option<LocalVersion>,
}
/// Container versions have different wire layouts. V2 retains all eight raw
/// bytes in their original order; no truncation or invented scalar endianness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerVersion {
    V1(u32),
    V2([u8; 8]),
}
/// Historical owned protocol/image evidence, not current transport/radio state
/// or vendor-signature authentication. No Image/provider/firmware-byte borrow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub before: Identity,
    pub after: LocalVersion,
    pub address: [u8; 6],
    pub firmware: Box<FirmwareReceipt>,
    pub configuration: ConfigurationEvidence,
    pub container_version: ContainerVersion,
    /// Validated v2 hierarchy/control observations, absent for a v1 container.
    pub v2: Option<V2Metadata>,
    pub download: Vec<DownloadResponse>,
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
        write!(f, "Realtek Bluetooth initialization {self:?}")
    }
}
impl core::error::Error for Error {}

pub(super) fn is_candidate(device: &crate::usb::xhci::Device) -> bool {
    UsbIdentity::read(device).project().is_some()
}
/// Initialize an exclusively owned attached candidate exactly once through the
/// native consumer wrapper. Any failed candidate attempt closes/quarantines its
/// transport and preserves typed failure/partial receipts; rebind is required.
/// Unsupported running variants are refused, never dropped or guessed ready.
pub fn initialize<B: Io>(
    hci: &mut Hci<B>,
    provider: &dyn crate::firmware::Provider,
) -> Result<OwnedReport> {
    initialize::run(hci, provider)
}

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
    pub(super) fn initialized_report(project: Project) -> OwnedReport {
        let (mut hci, catalog, _) = fixture(project, true);
        initialize(&mut hci, &catalog).unwrap()
    }
    struct Step {
        parameters: Vec<u8>,
        response: Vec<u8>,
    }
    #[derive(Default)]
    struct Trace {
        commands: usize,
        closed: usize,
    }
    struct Model {
        steps: VecDeque<Step>,
        events: VecDeque<Vec<u8>>,
        time: Cell<u64>,
        trace: Rc<RefCell<Trace>>,
        cleanup_error: bool,
        fail_command: Option<usize>,
    }
    impl Io for Model {
        fn validate(&self) -> core::result::Result<(), BlockError> {
            Ok(()) // This in-memory model has no physical device-generation owner.
        }
        fn control(&mut self, setup: [u8; 8], p: &[u8]) -> core::result::Result<(), BlockError> {
            assert_eq!(setup[..6], [0x20, 0, 0, 0, 0, 0]);
            assert_eq!(self.trace.borrow().closed, 0);
            let step = self.steps.pop_front().expect("unexpected command");
            assert_eq!(p, step.parameters);
            self.trace.borrow_mut().commands += 1;
            if self.fail_command == Some(self.trace.borrow().commands) {
                return Err(BlockError::Device { status: 0x55 });
            }
            // Exercise framing across two genuine transfer completions.
            if !step.response.is_empty() {
                self.events.push_back(step.response[..1].to_vec());
                self.events.push_back(step.response[1..].to_vec());
            }
            Ok(())
        }
        fn receive(&mut self, pipe: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
            Ok(if pipe == Pipe::Event {
                self.events.pop_front()
            } else {
                None
            })
        }
        fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
            panic!("firmware commands must use EP0")
        }
        fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
            panic!("Realtek must not enter Intel bulk boot mode")
        }
        fn close(&mut self) -> core::result::Result<(), BlockError> {
            self.trace.borrow_mut().closed += 1;
            if self.cleanup_error {
                Err(BlockError::Timeout)
            } else {
                Ok(())
            }
        }
        fn now_us(&self) -> u64 {
            let t = self.time.get();
            self.time.set(t + 100_000);
            t
        }
    }
    fn command(op: u16, p: &[u8]) -> Vec<u8> {
        let mut b = op.to_le_bytes().to_vec();
        b.push(p.len() as u8);
        b.extend_from_slice(p);
        b
    }
    fn cc(op: u16, p: &[u8]) -> Vec<u8> {
        let mut b = vec![0x0e, (p.len() + 3) as u8, 1];
        b.extend_from_slice(&op.to_le_bytes());
        b.extend_from_slice(p);
        b
    }
    fn version(project: Project, after: bool) -> Vec<u8> {
        let (hci, lmp) = match project {
            Project::Rtl8761Bu => (10, 0x8761u16),
            Project::Rtl8822B => (7, 0x8822),
            Project::Rtl8852Bu => (11, 0x8852),
        };
        let mut b = vec![0, hci, 11, 0, hci, 0x5d, 0];
        b.extend_from_slice(&(if after { 0x5678 } else { lmp }).to_le_bytes());
        b
    }
    fn firmware(project: Project) -> Vec<u8> {
        if project == Project::Rtl8852Bu {
            let mut b = b"RTBTCore".to_vec();
            b.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            b.extend_from_slice(&2u32.to_le_bytes());
            b.extend_from_slice(&1u32.to_le_bytes());
            b.extend_from_slice(&16u32.to_le_bytes());
            b.extend_from_slice(&[1, 0, 0, 0, 1, 15, 0, 0, 4, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef]);
            b.extend_from_slice(&8u32.to_le_bytes());
            b.extend_from_slice(&2u32.to_le_bytes());
            b.extend_from_slice(&[0x99, 0x98]);
            b.extend_from_slice(&[0xff, 2, 1, 1, 20, 1, 0, 0x51, 4, 0xfd, 0x77]);
            return b;
        }
        let mut b = vec![0; 36];
        b[..8].copy_from_slice(b"Realtech");
        b[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());
        b[12..14].copy_from_slice(&1u16.to_le_bytes());
        b[14..16].copy_from_slice(&1u16.to_le_bytes());
        b[16..18].copy_from_slice(&4u16.to_le_bytes());
        b[18..22].copy_from_slice(&24u32.to_le_bytes());
        b[28..].copy_from_slice(&[0xff, project.id(), 1, 0, 0x51, 4, 0xfd, 0x77]);
        b
    }
    fn fixture(project: Project, config: bool) -> (Hci<Model>, Catalog, Rc<RefCell<Trace>>) {
        let (vid, pid, sub, hci) = match project {
            Project::Rtl8761Bu => (0x0bdau16, 0x8771u16, 0x8761u16, 10),
            Project::Rtl8822B => (0x13d3, 0x3526, 0x8822, 7),
            Project::Rtl8852Bu => (0x0bda, 0xb85b, 0x8852, 11),
        };
        let mut descriptor = [18, 1, 0, 2, 0xe0, 1, 1, 64, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1];
        descriptor[8..10].copy_from_slice(&vid.to_le_bytes());
        descriptor[10..12].copy_from_slice(&pid.to_le_bytes());
        let configuration = vec![
            9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1,
            7, 5, 0x82, 2, 64, 0, 0, 7, 5, 2, 2, 64, 0, 0,
        ];
        let device = Device {
            id: crate::usb::xhci::SlotId::fixture(1),
            slot: 1,
            speed: FULL_SPEED,
            location: "Realtek stateful HCI model".into(),
            descriptor,
            configurations: vec![configuration.clone()],
            configuration,
            manufacturer: None,
            product: None,
            serial: None,
            language: None,
            vendor_ethernet_revision: None,
            vendor_ethernet_tcr: None,
        };
        let hardware = match project {
            Project::Rtl8761Bu => "usb:0bda:8771:0100",
            Project::Rtl8822B => "usb:13d3:3526:0100",
            Project::Rtl8852Bu => "usb:0bda:b85b:0100",
        };
        let revision = match project {
            Project::Rtl8761Bu => {
                "epatch-v1:hci-0a-000b:lmp-0a-8761:manufacturer-005d:register-8761-none:rom-00:security-00-00"
            }
            Project::Rtl8822B => {
                "epatch-v1:hci-07-000b:lmp-07-8822:manufacturer-005d:register-8822-000b:rom-00:security-00-00"
            }
            Project::Rtl8852Bu => {
                "epatch-v2:hci-0b-000b:lmp-0b-8852:manufacturer-005d:register-8852-none:rom-00:security-00-00"
            }
        };
        let target = Target {
            driver: if project == Project::Rtl8852Bu {
                "realtek-bluetooth-usb-epatch-v2"
            } else {
                "realtek-bluetooth-usb-epatch-v1"
            },
            hardware,
            revision,
            board: None,
        };
        let name = match project {
            Project::Rtl8761Bu => "rtl_bt/rtl8761bu_fw.bin",
            Project::Rtl8822B => "rtl_bt/rtl8822b_fw.bin",
            Project::Rtl8852Bu => "rtl_bt/rtl8852bu_fw.bin",
        };
        let cfgname = match project {
            Project::Rtl8761Bu => "rtl_bt/rtl8761bu_config.bin",
            Project::Rtl8822B => "rtl_bt/rtl8822b_config.bin",
            Project::Rtl8852Bu => "rtl_bt/rtl8852bu_config.bin",
        };
        let cfg = vec![0x55, 0xab, 0x23, 0x87, 0, 0];
        let fw = firmware(project);
        let resource = |name, bytes: Vec<u8>| Resource {
            name,
            target,
            provenance: Provenance {
                source: "original stateful fixture",
                revision: "model-v1",
                member: if project == Project::Rtl8852Bu && name == cfgname {
                    "rtl_bt/rtl8761bu_config.bin"
                } else {
                    name
                },
                license: "MIT",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes,
        };
        let mut resources = vec![resource(name, fw)];
        if config {
            resources.push(resource(cfgname, cfg.clone()));
        }
        let catalog = Catalog::from_handoff(resources).unwrap();
        let mut steps = VecDeque::new();
        let mut add = |op, p: &[u8], r: &[u8]| {
            steps.push_back(Step {
                parameters: command(op, p),
                response: cc(op, r),
            })
        };
        add(
            0xfc61,
            &[0x10, 0x38, 4, 0x28, 0x80],
            &[0, sub as u8, (sub >> 8) as u8],
        );
        if project == Project::Rtl8822B {
            add(0xfc61, &[0x10, 0x3a, 4, 0x28, 0x80], &[0, 11, 0]);
        }
        add(0x1001, &[], &version(project, false));
        add(0xfc6d, &[], &[0, 0]);
        add(0xfc61, &[0x10, 0xa4, 0xad, 0, 0xb0], &[0, 0, 0]);
        let mut data = if project == Project::Rtl8852Bu {
            vec![0x80, 0xde, 0xad, 0xbe, 0xef]
        } else {
            vec![0x80, 0x78, 0x56, 0x34, 0x12]
        };
        if config {
            data.extend_from_slice(&cfg);
        }
        add(0xfc20, &data, &[0, 0x42]);
        add(0x1001, &[], &version(project, true));
        add(0x1009, &[], &[0, 1, 2, 3, 4, 5, 6]);
        let trace = Rc::new(RefCell::new(Trace::default()));
        let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
        assert_eq!(hci, version(project, false)[1]);
        (
            Hci::from_io(
                binding,
                Model {
                    steps,
                    events: VecDeque::new(),
                    time: Cell::new(0),
                    trace: trace.clone(),
                    cleanup_error: false,
                    fail_command: None,
                },
            ),
            catalog,
            trace,
        )
    }
    struct Recording<'a> {
        catalog: &'a Catalog,
        requests: RefCell<Vec<(String, String, String, String)>>,
    }
    impl Provider for Recording<'_> {
        fn load(
            &self,
            r: Requirement<'_>,
        ) -> core::result::Result<Image<'_>, crate::firmware::Error> {
            self.requests.borrow_mut().push((
                r.name.into(),
                r.target.hardware.into(),
                r.target.revision.into(),
                r.target.driver.into(),
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
    fn native_report_retains_actual_identity_receipts_and_indices_after_provider_drop() {
        for project in [Project::Rtl8761Bu, Project::Rtl8822B, Project::Rtl8852Bu] {
            let (mut hci, catalog, trace) = fixture(project, true);
            {
                let provider = Recording {
                    catalog: &catalog,
                    requests: RefCell::new(vec![]),
                };
                let InitializationReport::Realtek(r) = hci
                    .initialize_with_provider(&provider, PlatformInputs::default())
                    .unwrap()
                else {
                    panic!("Realtek report expected")
                };
                assert_eq!(r.before.project, project);
                assert_eq!(r.before.security, [0, 0]);
                assert_eq!(r.after.raw, version(project, true)[..]);
                assert_eq!(r.address, [1, 2, 3, 4, 5, 6]);
                if project == Project::Rtl8852Bu {
                    assert_eq!(
                        r.container_version,
                        ContainerVersion::V2([1, 2, 3, 4, 5, 6, 7, 8])
                    );
                    let meta = r.v2.as_ref().unwrap();
                    assert_eq!(meta.project, Project::Rtl8852Bu);
                    assert_eq!(meta.sections[1].opcode, 8);
                    assert!(meta.sections[1].skipped);
                    let ConfigurationEvidence::Supplied(config) = &r.configuration else {
                        panic!("supplied config expected")
                    };
                    assert_eq!(config.name, "rtl_bt/rtl8852bu_config.bin");
                    assert_eq!(config.member, "rtl_bt/rtl8761bu_config.bin");
                } else {
                    assert_eq!(r.container_version, ContainerVersion::V1(0x12345678));
                    assert!(r.v2.is_none());
                }
                assert_eq!(
                    r.download,
                    vec![DownloadResponse {
                        sent_index: 0x80,
                        returned_index: 0x42
                    }]
                );
                assert_eq!(provider.requests.borrow().len(), 2);
                assert_eq!(r.firmware.target_revision, r.before.revision_label());
                assert!(r.firmware.target_revision.len() < 256);
                assert_eq!(r.firmware.target_hardware, r.before.usb.hardware_label());
            }
            drop(catalog);
            let commands = trace.borrow().commands;
            let empty = Catalog::from_handoff(vec![]).unwrap();
            assert!(
                hci.initialize_with_provider(&empty, PlatformInputs::default())
                    .is_ok()
            );
            assert_eq!(trace.borrow().commands, commands);
            assert_eq!(hci.state(), State::Open);
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            assert!(hci.io.steps.is_empty());
        }
    }
    #[test]
    fn missing_firmware_records_both_exact_companions_and_closes_without_upload() {
        let (mut hci, _, trace) = fixture(Project::Rtl8761Bu, true);
        let empty = Catalog::from_handoff(vec![]).unwrap();
        let provider = Recording {
            catalog: &empty,
            requests: RefCell::new(vec![]),
        };
        let InitializationError::Realtek(e) = hci
            .initialize_with_provider(&provider, PlatformInputs::default())
            .unwrap_err()
        else {
            panic!("Realtek error expected")
        };
        let (cause, a) = attempt(e);
        assert!(matches!(cause,Error::Resource(e)if e.name=="rtl_bt/rtl8761bu_fw.bin"));
        assert!(a.download.is_empty());
        assert_eq!(a.identity.as_ref().unwrap().rom_version, 0);
        assert!(a.configuration.as_ref().unwrap().is_err());
        let calls = provider.requests.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "rtl_bt/rtl8761bu_fw.bin");
        assert_eq!(calls[1].0, "rtl_bt/rtl8761bu_config.bin");
        assert_eq!(calls[0].1, "usb:0bda:8771:0100");
        assert_eq!(calls[0].2, calls[1].2);
        drop(calls);
        assert_eq!(trace.borrow().commands, 4);
        assert_eq!(hci.state(), State::Closed);
        let before = trace.borrow().commands;
        assert!(
            hci.initialize_with_provider(&provider, PlatformInputs::default())
                .is_err()
        );
        assert_eq!(trace.borrow().commands, before);
        assert_eq!(provider.requests.borrow().len(), 2);
        assert!(hci.submit_command(&[3, 0x0c, 0]).is_err());
        assert!(hci.submit_acl(&[1, 0, 0, 0]).is_err());
    }
    #[test]
    fn absent_config_is_retained_only_for_the_exact_optional_profile() {
        let (mut hci, catalog, _) = fixture(Project::Rtl8761Bu, false);
        let r = initialize(&mut hci, &catalog).unwrap();
        assert!(
            matches!(r.configuration,ConfigurationEvidence::OptionalMissing(e)if e.name=="rtl_bt/rtl8761bu_config.bin")
        );
        let (mut hci, catalog, trace) = fixture(Project::Rtl8822B, false);
        let e = initialize(&mut hci, &catalog).unwrap_err();
        assert!(matches!(attempt(&e).0,Error::Resource(e)if e.name=="rtl_bt/rtl8822b_config.bin"));
        assert_eq!(trace.borrow().commands, 5);
        assert_eq!(hci.state(), State::Closed);
    }
    #[test]
    fn genuine_completion_status_credits_shape_and_timeout_are_required() {
        for fault in 0..7 {
            let (mut hci, catalog, trace) = fixture(Project::Rtl8761Bu, true);
            let step = &mut hci.io.steps[4];
            match fault {
                0 => step.response[5] = 0x0c,
                1 => step.response[2] = 0,
                2 => step.response[3] = 0x21,
                3 => step.response = cc(0xfc20, &[0]),
                4 => step.response.clear(),
                5 => step.response = vec![0x0f, 4, 0, 1, 0x20, 0xfc], // delivery/Status without actual CC
                _ => {
                    step.response = vec![0x0f, 4, 0, 1, 0x20, 0xfc];
                    step.response.extend_from_slice(&cc(0xfc20, &[0, 0x42]));
                }
            }
            let result = initialize(&mut hci, &catalog);
            if fault == 6 {
                assert!(result.is_ok());
                continue;
            }
            let e = result.unwrap_err();
            let (error, a) = attempt(&e);
            if fault == 1 {
                // A completion may grant no credits; without a later grant
                // the next command never goes out.
                assert!(matches!(
                    error,
                    Error::Timeout("genuine HCI command credits")
                ));
                assert_eq!(trace.borrow().commands, 5);
                assert_eq!(hci.state(), State::Closed);
                continue;
            }
            assert!(a.firmware.is_some());
            assert!(a.download.is_empty());
            assert_eq!(trace.borrow().commands, 5);
            assert_eq!(hci.state(), State::Closed);
        }
    }
    #[test]
    fn rejected_identity_security_rom_and_postboot_observations_fail_closed() {
        for fault in 0..6 {
            let (mut hci, catalog, trace) = fixture(Project::Rtl8761Bu, true);
            match fault {
                0 => hci.io.steps[1].response[10] = 0,
                1 => hci.io.steps[2].response[6] = 7,
                2 => hci.io.steps[3].response[6] = 3,
                3 => hci.io.steps[5].response = cc(0x1001, &version(Project::Rtl8761Bu, false)),
                4 => hci.io.steps[5].response[10] = 0,
                _ => hci.io.steps[6].response = cc(0x1009, &[0, 0, 0, 0, 0, 0, 0]),
            }
            let e = initialize(&mut hci, &catalog).unwrap_err();
            let (_, a) = attempt(&e);
            if fault >= 3 {
                assert_eq!(a.download.len(), 1);
                assert!(a.after.is_some());
            } else {
                assert!(a.download.is_empty());
            }
            assert_eq!(hci.state(), State::Closed);
            assert_eq!(trace.borrow().closed, 1);
        }
    }
    #[test]
    fn cleanup_failure_is_separate_and_cannot_reopen_candidate() {
        let (mut hci, catalog, _) = fixture(Project::Rtl8761Bu, true);
        hci.io.steps[4].response[5] = 1;
        hci.io.cleanup_error = true;
        let e = initialize(&mut hci, &catalog).unwrap_err();
        assert!(matches!(e, Error::Cleanup { .. }));
        assert!(matches!(
            attempt(&e).0,
            Error::Controller {
                opcode: 0xfc20,
                status: 1,
                ..
            }
        ));
        assert_eq!(hci.state(), State::Failed);
        assert!(hci.submit_command(&[3, 0x0c, 0]).is_err());
    }
    #[test]
    fn optional_config_integrity_or_target_errors_never_become_absence() {
        struct RejectConfig<'a> {
            catalog: &'a Catalog,
            kind: crate::firmware::ErrorKind,
        }
        impl Provider for RejectConfig<'_> {
            fn load(
                &self,
                r: Requirement<'_>,
            ) -> core::result::Result<Image<'_>, crate::firmware::Error> {
                if r.name.ends_with("_config.bin") {
                    Err(crate::firmware::Error {
                        name: r.name.into(),
                        kind: self.kind.clone(),
                    })
                } else {
                    self.catalog.load(r)
                }
            }
        }
        for project in [Project::Rtl8761Bu, Project::Rtl8852Bu] {
            for kind in [
                crate::firmware::ErrorKind::WrongTarget,
                crate::firmware::ErrorKind::DigestMismatch {
                    expected: [1; 32],
                    actual: [2; 32],
                },
            ] {
                let (mut hci, catalog, trace) = fixture(project, true);
                let provider = RejectConfig {
                    catalog: &catalog,
                    kind: kind.clone(),
                };
                let e = initialize(&mut hci, &provider).unwrap_err();
                assert!(matches!(attempt(&e).0,Error::Resource(e)if e.kind==kind));
                assert!(attempt(&e).1.download.is_empty());
                assert_eq!(trace.borrow().commands, 4);
                assert_eq!(hci.state(), State::Closed);
            }
        }
    }
    #[test]
    fn usb_failures_retain_typed_error_and_native_attempt_never_reopens() {
        for command in 1..=7 {
            let (mut hci, catalog, trace) = fixture(Project::Rtl8761Bu, true);
            hci.io.fail_command = Some(command);
            let InitializationError::Realtek(e) = hci
                .initialize_with_provider(&catalog, PlatformInputs::default())
                .unwrap_err()
            else {
                panic!("Realtek error expected")
            };
            assert!(
                matches!(attempt(e).0,Error::Transport(e)if matches!(e.kind,crate::usb::bluetooth::ErrorKind::Usb(BlockError::Device{status:0x55})))
            );
            assert_eq!(hci.state(), State::Failed);
            let sent = trace.borrow().commands;
            assert!(
                hci.initialize_with_provider(&catalog, PlatformInputs::default())
                    .is_err()
            );
            assert_eq!(trace.borrow().commands, sent);
            assert_eq!(trace.borrow().closed, 1);
        }
    }
    #[test]
    fn v2_requires_exact_usb_stock_hci_register_rom_and_key_profile() {
        for (vendor, product) in [
            (0x0cb8, 0xc559),
            (0x0bda, 0x4853),
            (0x0bda, 0x887b),
            (0x0bda, 0xb85b),
            (0x13d3, 0x3570),
            (0x13d3, 0x3571),
            (0x13d3, 0x3572),
            (0x13d3, 0x3591),
            (0x0489, 0xe123),
            (0x0489, 0xe125),
        ] {
            let usb = UsbIdentity {
                vendor,
                product,
                revision: 0x1234,
            };
            let v = LocalVersion::parse(&version(Project::Rtl8852Bu, false)).unwrap();
            let identity = Identity::select(usb, v.clone(), 0x8852, None, 1, [0, 0x42]).unwrap();
            assert_eq!(identity.project, Project::Rtl8852Bu);
            assert!(identity.revision_label().ends_with("rom-01:security-00-42"));
            assert!(identity.usb.hardware_label().ends_with(":1234"));
            for wrong in [Project::Rtl8761Bu, Project::Rtl8822B] {
                assert!(
                    Identity::select(
                        usb,
                        LocalVersion::parse(&version(wrong, false)).unwrap(),
                        0x8852,
                        None,
                        1,
                        [0, 0]
                    )
                    .is_err()
                );
            }
            assert!(Identity::select(usb, v.clone(), 0x8851, None, 1, [0, 0]).is_err());
            assert!(Identity::select(usb, v, 0x8852, None, 1, [1, 0]).is_err());
        }
        for (vendor, product) in [
            (0x0bda, 0x8520),
            (0x0cb8, 0xc558),
            (0x13d3, 0x3573),
            (0x1209, 0xb85b),
        ] {
            assert!(
                UsbIdentity {
                    vendor,
                    product,
                    revision: 0x100
                }
                .project()
                .is_none()
            );
        }
    }
    #[test]
    fn v2_missing_companions_are_exact_and_only_named_optional_config_absence_is_permitted() {
        let (mut hci, _, trace) = fixture(Project::Rtl8852Bu, true);
        let empty = Catalog::from_handoff(vec![]).unwrap();
        let provider = Recording {
            catalog: &empty,
            requests: RefCell::new(vec![]),
        };
        let e = initialize(&mut hci, &provider).unwrap_err();
        let (cause, a) = attempt(&e);
        assert!(matches!(cause,Error::Resource(e)if e.name=="rtl_bt/rtl8852bu_fw.bin"));
        assert!(a.download.is_empty());
        assert!(a.v2.is_none());
        let requests = provider.requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].0, "rtl_bt/rtl8852bu_fw.bin");
        assert_eq!(requests[1].0, "rtl_bt/rtl8852bu_config.bin");
        for r in requests.iter() {
            assert_eq!(r.1, "usb:0bda:b85b:0100");
            assert_eq!(
                r.2,
                "epatch-v2:hci-0b-000b:lmp-0b-8852:manufacturer-005d:register-8852-none:rom-00:security-00-00"
            );
            assert_eq!(r.3, "realtek-bluetooth-usb-epatch-v2");
        }
        assert_eq!(trace.borrow().commands, 4);
        assert_eq!(hci.state(), State::Closed);
        let (mut hci, catalog, _) = fixture(Project::Rtl8852Bu, false);
        let r = initialize(&mut hci, &catalog).unwrap();
        assert!(
            matches!(r.configuration,ConfigurationEvidence::OptionalMissing(e)if e.name=="rtl_bt/rtl8852bu_config.bin")
        );
    }
    #[test]
    fn v2_validated_metadata_and_alias_receipt_survive_rejected_upload_or_boot() {
        for boot in [false, true] {
            let (mut hci, catalog, trace) = fixture(Project::Rtl8852Bu, true);
            if boot {
                hci.io.steps[5].response = cc(0x1001, &version(Project::Rtl8852Bu, false));
            } else {
                hci.io.steps[4].response = cc(0xfc20, &[0x0c, 0]);
            }
            let InitializationError::Realtek(e) = hci
                .initialize_with_provider(&catalog, PlatformInputs::default())
                .unwrap_err()
            else {
                panic!("Realtek error expected")
            };
            let (_, a) = attempt(e);
            assert_eq!(
                a.container_version,
                Some(ContainerVersion::V2([1, 2, 3, 4, 5, 6, 7, 8]))
            );
            let metadata = a.v2.as_ref().unwrap();
            assert_eq!(metadata.sections[0].subsections[0].control, [0, 0]);
            assert!(metadata.sections[1].skipped);
            assert_eq!(metadata.sections[1].length, 2);
            assert_eq!(
                metadata.sections[1].sha256,
                <[u8; 32]>::from(Sha256::digest([0x99, 0x98]))
            );
            let config = a.configuration.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(config.name, "rtl_bt/rtl8852bu_config.bin");
            assert_eq!(config.member, "rtl_bt/rtl8761bu_config.bin");
            assert_eq!(a.download.len(), usize::from(boot));
            assert_eq!(a.after.is_some(), boot);
            assert_eq!(hci.state(), State::Closed);
            let commands = trace.borrow().commands;
            assert!(
                hci.initialize_with_provider(&catalog, PlatformInputs::default())
                    .is_err()
            );
            assert_eq!(trace.borrow().commands, commands);
            assert!(hci.submit_command(&[3, 0x0c, 0]).is_err());
        }
    }
}
