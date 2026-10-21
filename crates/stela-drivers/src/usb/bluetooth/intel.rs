// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Intel USB legacy RSA initializer, adapted from Linux btintel.c/btusb.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//!
//! Supported: the exact USB IDs in identity.rs, platform 0x37 and legacy
//! variants 0x0b/0x0c/0x11–0x14 with secure boot and per-fragment completions.
//! Only RSA SFI files with a complete aligned command stream and explicit boot
//! parameters are accepted. TLV/ECDSA/hybrid/IML, legacy ROM patching and firmware
//! upgrades from an already operational image remain explicit unsupported paths.
//! Both exact-target SFI and DDC must be in the supplied Catalog before upload.
//! Signatures are authenticated by the controller's secure boot ROM, not by a
//! host trust store; a real secure-send result, boot notification, operational
//! identity/version and OTP address must all agree before this returns a report.
//! This report is firmware evidence, not physical/radio/profile qualification.
//!
//! Reset is never given a synthetic Command Complete. A disconnect fails closed;
//! controller re-enumeration/rebind requires future generic USB lifecycle work.
//! No automatic hard-reset/retry loop is attempted over a stale USB slot.
mod firmware;
mod identity;
pub use identity::{BootParameters, Identity};

use super::{Hci, Io, Packet, State};
use crate::firmware::{Image, Provider, Requirement};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::fmt;

pub(super) const SECURE_SEND: u16 = 0xfc09;
const READ_VERSION: u16 = 0xfc05;
const READ_BOOT_PARAMS: u16 = 0xfc0d;
const INTEL_RESET: u16 = 0xfc01;
const WRITE_DDC: u16 = 0xfc8b;
const READ_BD_ADDR: u16 = 0x1009;
const COMMAND_US: u64 = 10_000_000;
const VENDOR_US: u64 = 5_000_000;
const UPLOAD_US: u64 = 120_000_000;
const FRAGMENT_BYTES: usize = 252;

type Result<T> = core::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Transport(super::Error),
    Resource(crate::firmware::Error),
    Unsupported(&'static str),
    FirmwareFormat(&'static str),
    Protocol(&'static str),
    Controller {
        opcode: u16,
        status: u8,
    },
    Timeout(&'static str),
    Cleanup {
        cause: Box<Error>,
        cleanup: super::Error,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Intel Bluetooth {self:?}")
    }
}
impl core::error::Error for Error {}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Transport(e)
    }
}
impl From<crate::firmware::Error> for Error {
    fn from(e: crate::firmware::Error) -> Self {
        Self::Resource(e)
    }
}

/// Verified catalog inputs remain borrowed, keeping their hash/source/license
/// attached to the observed operational controller identity.
#[derive(Debug)]
pub struct Report<'a> {
    pub before: Identity,
    pub after: Identity,
    pub firmware: Image<'a>,
    pub configuration: Image<'a>,
    pub boot_notification: [u8; 6],
}

/// Initialize one exclusively owned raw controller. Any failure after USB
/// identity selection closes/quarantines the transport; callers must rebind to
/// retry. Success leaves ordinary command/event/ACL transport open. The raw
/// transport's generic firmware_status remains Unverified; retain this report.
pub fn initialize<'a, B: Io>(hci: &mut Hci<B>, provider: &'a dyn Provider) -> Result<Report<'a>> {
    Identity::usb(hci.binding.device())?;
    match Engine::new(hci).run(provider) {
        Ok(report) => Ok(report),
        Err(cause) => {
            if hci.state() == State::Open
                && let Err(cleanup) = hci.close()
            {
                return Err(Error::Cleanup {
                    cause: Box::new(cause),
                    cleanup,
                });
            }
            Err(cause)
        }
    }
}

struct Engine<'a, B: Io> {
    hci: &'a mut Hci<B>,
    events: VecDeque<Vec<u8>>,
    secure: bool,
    boot: Option<[u8; 6]>,
    allow_secure: bool,
    allow_boot: bool,
}
impl<'a, B: Io> Engine<'a, B> {
    fn new(hci: &'a mut Hci<B>) -> Self {
        Self {
            hci,
            events: VecDeque::new(),
            secure: false,
            boot: None,
            allow_secure: false,
            allow_boot: false,
        }
    }
    fn now(&self) -> u64 {
        self.hci.io.now_us()
    }
    fn submit(&mut self, opcode: u16, parameters: &[u8]) -> Result<()> {
        if parameters.len() > 255 {
            return Err(Error::Protocol("command parameters exceed HCI maximum"));
        }
        let mut packet = Vec::with_capacity(3 + parameters.len());
        packet.extend_from_slice(&opcode.to_le_bytes());
        packet.push(parameters.len() as u8);
        packet.extend_from_slice(parameters);
        self.hci.submit_command(&packet)?;
        Ok(())
    }
    fn pump(&mut self) -> Result<()> {
        for packet in self.hci.poll()? {
            let Packet::Event(event) = packet else {
                return Err(Error::Protocol("ACL during firmware initialization"));
            };
            if event[0] != 0xff {
                self.events.push_back(event);
                continue;
            }
            match event.get(2).copied() {
                Some(6) if self.allow_secure && event.len() == 7 && !self.secure => {
                    if event[3] != 0
                        || u16::from_le_bytes([event[4], event[5]]) != SECURE_SEND
                        || event[6] != 0
                    {
                        return Err(Error::Protocol(
                            "controller rejected secure image/signature",
                        ));
                    }
                    self.secure = true;
                }
                Some(2) if self.allow_boot && event.len() == 9 && self.boot.is_none() => {
                    let boot: [u8; 6] = event[3..].try_into().unwrap();
                    if boot[0] != 0 || boot[1] == 0 || boot[5] != 0 {
                        return Err(Error::Protocol("invalid Intel boot notification"));
                    }
                    self.boot = Some(boot);
                }
                _ => return Err(Error::Protocol("unexpected/malformed Intel vendor event")),
            }
        }
        if self.events.len() > 16 {
            return Err(Error::Protocol("excess initialization events"));
        }
        Ok(())
    }
    fn command(&mut self, opcode: u16, parameters: &[u8]) -> Result<Vec<u8>> {
        if !self.events.is_empty() {
            return Err(Error::Protocol("stale command response"));
        }
        self.submit(opcode, parameters)?;
        let deadline = self.now().saturating_add(COMMAND_US);
        loop {
            self.pump()?;
            if let Some(event) = self.events.pop_front() {
                match event[0] {
                    0x0e if event.len() >= 6 => {
                        if u16::from_le_bytes([event[3], event[4]]) != opcode {
                            return Err(Error::Protocol("wrong command completion opcode"));
                        }
                        if event[5] != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status: event[5],
                            });
                        }
                        if event[2] == 0 {
                            return Err(Error::Protocol("no command credits after completion"));
                        }
                        return Ok(event[5..].to_vec());
                    }
                    0x0f if event.len() == 6 => {
                        if u16::from_le_bytes([event[4], event[5]]) != opcode {
                            return Err(Error::Protocol("wrong command status opcode"));
                        }
                        if event[2] != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status: event[2],
                            });
                        }
                    }
                    _ => return Err(Error::Protocol("unexpected/malformed command event")),
                }
            }
            if self.now() >= deadline {
                return Err(Error::Timeout("command completion"));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn vendor(&mut self, boot: bool) -> Result<()> {
        let deadline = self.now().saturating_add(VENDOR_US);
        loop {
            if if boot {
                self.boot.is_some()
            } else {
                self.secure
            } {
                return Ok(());
            }
            self.pump()?;
            if !self.events.is_empty() {
                return Err(Error::Protocol(
                    "unexpected completion while awaiting vendor notification",
                ));
            }
            if self.now() >= deadline {
                return Err(Error::Timeout(if boot {
                    "boot notification; rebind may be required"
                } else {
                    "secure result"
                }));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn run<'p>(&mut self, provider: &'p dyn Provider) -> Result<Report<'p>> {
        let version = self.command(READ_VERSION, &[0xff])?;
        let before = Identity::parse(self.hci.binding.device(), &version)?;
        if before.firmware_variant != 6 {
            return Err(Error::Unsupported(
                "controller is already operational; upgrade/reset/rebind is separate",
            ));
        }
        self.hci.intel_mode(true)?;
        let boot = BootParameters::parse(&self.command(READ_BOOT_PARAMS, &[])?)?;
        let hardware = before.hardware_label();
        let revision = before.revision_label(&boot);
        let sfi_name = before.filename(&boot, "sfi");
        let ddc_name = before.filename(&boot, "ddc");
        let target = before.target(&hardware, &revision);
        let firmware = provider.load(Requirement {
            name: &sfi_name,
            target,
            minimum_bytes: firmware::RSA_BYTES + 1,
        })?;
        let configuration = provider.load(Requirement {
            name: &ddc_name,
            target,
            minimum_bytes: 3,
        })?;
        // Fully parse both immutable images before mutating the secure loader.
        let sfi = firmware::Sfi::parse(firmware.bytes(), boot.minimum_build)?;
        let ddc = firmware::ddc(configuration.bytes())?;
        let deadline = self.now().saturating_add(UPLOAD_US);
        for (section_index, (kind, bytes)) in sfi.sections.iter().enumerate() {
            let count = bytes.len().div_ceil(FRAGMENT_BYTES);
            for (index, fragment) in bytes.chunks(FRAGMENT_BYTES).enumerate() {
                if self.now() >= deadline {
                    return Err(Error::Timeout("overall firmware upload"));
                }
                self.allow_secure = section_index + 1 == sfi.sections.len() && index + 1 == count;
                let mut parameters = Vec::with_capacity(fragment.len() + 1);
                parameters.push(*kind);
                parameters.extend_from_slice(fragment);
                let complete = self.command(SECURE_SEND, &parameters)?;
                if complete.len() != 1 {
                    return Err(Error::Protocol("secure-send completion length"));
                }
            }
        }
        self.vendor(false)?;
        self.allow_secure = false;
        self.allow_boot = true;
        let mut reset = vec![0, 1, 0, 1];
        reset.extend_from_slice(&sfi.boot_address.to_le_bytes());
        // USB delivery is the only synchronous acknowledgment here. The ROM
        // does not issue a real HCI CC for this reset; await firmware boot.
        if !self.events.is_empty() {
            return Err(Error::Protocol("stale response before reset"));
        }
        self.submit(INTEL_RESET, &reset)?;
        self.vendor(true)?;
        self.allow_boot = false;
        self.hci.intel_mode(false)?;
        let operational_version = self.command(READ_VERSION, &[])?;
        let after = Identity::parse(self.hci.binding.device(), &operational_version)?;
        if !before.same_hardware(&after)
            || after.firmware_variant != 0x23
            || (before.hardware_variant >= 0x11 && after.build != sfi.build)
        {
            return Err(Error::Protocol("postboot identity/version mismatch"));
        }
        let address = self.command(READ_BD_ADDR, &[])?;
        if address.len() != 7 {
            return Err(Error::Protocol("Read BD_ADDR length"));
        }
        let address: [u8; 6] = address[1..].try_into().unwrap();
        identity::valid_address(address)?;
        if address != boot.address {
            return Err(Error::Protocol("postboot address differs from OTP"));
        }
        let deadline = self.now().saturating_add(COMMAND_US);
        for record in ddc {
            if self.now() >= deadline {
                return Err(Error::Timeout("DDC configuration"));
            }
            if self.command(WRITE_DDC, record)?.len() != 1 {
                return Err(Error::Protocol("DDC completion length"));
            }
        }
        let final_version = self.command(READ_VERSION, &[])?;
        if Identity::parse(self.hci.binding.device(), &final_version)? != after {
            return Err(Error::Protocol("identity changed during DDC configuration"));
        }
        if !self.events.is_empty() {
            return Err(Error::Protocol(
                "surplus command completions after initialization",
            ));
        }
        Ok(Report {
            before,
            after,
            firmware,
            configuration,
            boot_notification: self.boot.unwrap(),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        block::BlockError,
        firmware::{Catalog, Provenance, Resource, Target},
        usb::{
            bluetooth::{Binding, Pipe},
            xhci::{self, Device, FULL_SPEED},
        },
    };
    use alloc::{rc::Rc, vec};
    use core::cell::Cell;
    use sha2::{Digest, Sha256};

    // Original synthetic bytes exercise structure/protocol only. They contain
    // no vendor image/signature and do not prove real secure-ROM authentication.
    pub(crate) fn image() -> Vec<u8> {
        let mut bytes = vec![0; 644];
        bytes[..4].copy_from_slice(&6u32.to_le_bytes());
        for (at, value) in [
            (4, 161u32),
            (16, 0x8086),
            (24, 165),
            (28, 64),
            (32, 64),
            (36, 1),
        ] {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        bytes[128..384].fill(0x5a);
        bytes[384..388].copy_from_slice(&[1, 0, 1, 0]);
        bytes[388..644].fill(0x6b);
        bytes.extend_from_slice(&[0x0e, 0xfc, 7, 0, 0, 0x20, 0, 9, 30, 26, 0, 0xfc, 3, 0, 0, 0]);
        bytes
    }
    fn version(operational: bool) -> Vec<u8> {
        vec![
            0,
            0x37,
            0x14,
            1,
            if operational { 0x23 } else { 6 },
            if operational { 4 } else { 3 },
            if operational { 9 } else { 1 },
            30,
            26,
            0,
        ]
    }
    fn boot_parameters() -> Vec<u8> {
        let mut p = vec![0; 23];
        p[4] = 1;
        p[6] = 1;
        p[12..18].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        p[18..21].copy_from_slice(&[1, 1, 25]);
        p
    }
    fn complete(opcode: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x0e, (3 + payload.len()) as u8, 1];
        p.extend_from_slice(&opcode.to_le_bytes());
        p.extend_from_slice(payload);
        p
    }
    fn command_bytes(opcode: u16, params: &[u8]) -> Vec<u8> {
        let mut p = opcode.to_le_bytes().to_vec();
        p.push(params.len() as u8);
        p.extend_from_slice(params);
        p
    }
    pub(crate) struct Step {
        command: Vec<u8>,
        bulk: bool,
        events: Vec<(Pipe, Vec<u8>)>,
    }
    pub(crate) struct Script {
        pub steps: VecDeque<Step>,
    }
    impl Script {
        pub(crate) fn command(&mut self, bulk: bool, bytes: &[u8]) -> Vec<(Pipe, Vec<u8>)> {
            let step = self.steps.pop_front().expect("unexpected USB command");
            assert_eq!(bulk, step.bulk, "wrong USB command endpoint");
            assert_eq!(bytes, step.command, "wrong command bytes/sequence");
            step.events
        }
    }
    pub(crate) fn fixture() -> (Device, Catalog, Script) {
        let device = Device {
            slot: 1,
            speed: FULL_SPEED,
            location: "Intel model".into(),
            descriptor: [
                18, 1, 0, 2, 0xe0, 1, 1, 64, 0x87, 0x80, 0x29, 0, 0, 1, 0, 0, 0, 1,
            ],
            configuration: vec![
                9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 2, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0,
                1, 7, 5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0,
            ],
            manufacturer: None,
            product: None,
            serial: None,
        };
        let sfi = image();
        let mut steps = VecDeque::new();
        let mut add = |opcode, params: &[u8], bulk, pipe, payload: &[u8]| {
            steps.push_back(Step {
                command: command_bytes(opcode, params),
                bulk,
                events: vec![(pipe, complete(opcode, payload))],
            })
        };
        add(READ_VERSION, &[0xff], false, Pipe::Event, &version(false));
        add(
            READ_BOOT_PARAMS,
            &[],
            false,
            Pipe::Event,
            &boot_parameters(),
        );
        // Exact pinned RSA wire layout, independent of Sfi::sections/parser.
        for (kind, bytes) in [
            (0, &sfi[..128]),
            (3, &sfi[128..380]),
            (3, &sfi[380..384]),
            (2, &sfi[388..640]),
            (2, &sfi[640..644]),
            (1, &sfi[644..]),
        ] {
            let mut params = vec![kind];
            params.extend_from_slice(bytes);
            add(SECURE_SEND, &params, true, Pipe::Acl, &[0]);
        }
        // Coalesced final command completion + genuine secure result on bulk IN.
        steps.back_mut().unwrap().events[0]
            .1
            .extend_from_slice(&[0xff, 5, 6, 0, 9, 0xfc, 0]);
        // Genuine boot event deliberately split across bulk USB completions.
        steps.push_back(Step {
            command: command_bytes(INTEL_RESET, &[0, 1, 0, 1, 0, 0, 0x20, 0]),
            bulk: false,
            events: vec![
                (Pipe::Acl, vec![0xff, 7]),
                (Pipe::Acl, vec![2, 0, 1, 0, 0, 0, 0]),
            ],
        });
        let mut add = |opcode, params: &[u8], payload: &[u8]| {
            steps.push_back(Step {
                command: command_bytes(opcode, params),
                bulk: false,
                events: vec![(Pipe::Event, complete(opcode, payload))],
            })
        };
        add(READ_VERSION, &[], &version(true));
        add(READ_BD_ADDR, &[], &[0, 1, 2, 3, 4, 5, 6]);
        add(WRITE_DDC, &[3, 1, 2, 0xaa], &[0]);
        add(READ_VERSION, &[], &version(true));
        (device, catalog(sfi, vec![3, 1, 2, 0xaa]), Script { steps })
    }
    fn catalog(sfi: Vec<u8>, ddc: Vec<u8>) -> Catalog {
        let target = Target {
            driver: "intel-bluetooth-usb-rsa",
            hardware: "usb:8087:0029:0100",
            revision: "37:14:01:03:dev-0001:otp-00-00-00:key-00-00:locks-00-00-00:min-01-01-19:loader-01-1e-1a-00:unlock-00",
            board: None,
        };
        let provenance = Provenance {
            source: "Stela synthetic protocol model",
            revision: "1",
            member: "synthetic/intel-model",
            license: "MIT",
        };
        Catalog::from_handoff(vec![
            Resource {
                name: "intel/ibt-20-1-3.sfi",
                target,
                provenance,
                expected_length: sfi.len(),
                expected_sha256: Sha256::digest(&sfi).into(),
                bytes: sfi,
            },
            Resource {
                name: "intel/ibt-20-1-3.ddc",
                target,
                provenance,
                expected_length: ddc.len(),
                expected_sha256: Sha256::digest(&ddc).into(),
                bytes: ddc,
            },
        ])
        .unwrap()
    }
    struct Model {
        script: Script,
        event: VecDeque<Vec<u8>>,
        bulk: VecDeque<Vec<u8>>,
        time: Cell<u64>,
        closed: Rc<Cell<usize>>,
        quiesced: usize,
        fail_reset: bool,
        fail_quiesce: bool,
        submitted: usize,
    }
    impl Model {
        fn dispatch(&mut self, bulk: bool, packet: &[u8]) -> core::result::Result<(), BlockError> {
            self.submitted += 1;
            if self.fail_reset && packet[..2] == INTEL_RESET.to_le_bytes() {
                return Err(BlockError::Unsupported("disconnected; rebind required"));
            }
            for (pipe, event) in self.script.command(bulk, packet) {
                match pipe {
                    Pipe::Event => &mut self.event,
                    Pipe::Acl => &mut self.bulk,
                }
                .push_back(event);
            }
            Ok(())
        }
    }
    impl Io for Model {
        fn control(&mut self, setup: [u8; 8], p: &[u8]) -> core::result::Result<(), BlockError> {
            assert_eq!(setup[..6], [0x20, 0, 0, 0, 0, 0]);
            self.dispatch(false, p)
        }
        fn receive(&mut self, pipe: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
            Ok(match pipe {
                Pipe::Event => &mut self.event,
                Pipe::Acl => &mut self.bulk,
            }
            .pop_front())
        }
        fn write_acl(&mut self, p: &[u8]) -> core::result::Result<(), BlockError> {
            self.dispatch(true, p)
        }
        fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
            self.quiesced += 1;
            if self.fail_quiesce {
                Err(BlockError::Timeout)
            } else {
                Ok(())
            }
        }
        fn close(&mut self) -> core::result::Result<(), BlockError> {
            self.closed.set(self.closed.get() + 1);
            Ok(())
        }
        fn now_us(&self) -> u64 {
            let now = self.time.get();
            self.time.set(now + 100_000);
            now
        }
    }
    fn transport(device: Device, script: Script) -> Hci<Model> {
        let interface = xhci::interfaces(&device.configuration).remove(0);
        let binding = Binding::new(&device, &interface).unwrap();
        Hci::from_io(
            binding,
            Model {
                script,
                event: VecDeque::new(),
                bulk: VecDeque::new(),
                time: Cell::new(0),
                closed: Rc::new(Cell::new(0)),
                quiesced: 0,
                fail_reset: false,
                fail_quiesce: false,
                submitted: 0,
            },
        )
    }
    #[test]
    fn secure_boot_sequence_uses_real_completions_and_returns_catalog_provenance() {
        let (device, catalog, script) = fixture();
        let mut hci = transport(device, script);
        let report = initialize(&mut hci, &catalog).unwrap();
        assert_eq!(report.after.firmware_variant, 0x23);
        assert_eq!(report.after.build, [9, 30, 26]);
        assert_eq!(report.firmware.sha256(), Sha256::digest(image())[..]);
        assert_eq!(
            report.configuration.provenance().source,
            "Stela synthetic protocol model"
        );
        assert!(hci.io.script.steps.is_empty());
        assert_eq!(hci.io.quiesced, 2);
        assert_eq!(hci.state(), State::Open);
        assert!(!hci.intel_bootloader);
        assert_eq!(
            hci.firmware_status(),
            super::super::FirmwareStatus::Unverified
        );
    }
    #[test]
    fn every_sfi_truncation_and_malformed_ddc_fails_before_upload() {
        let valid = image();
        for end in 0..valid.len() {
            assert!(
                firmware::Sfi::parse(&valid[..end], [1, 1, 25]).is_err(),
                "prefix {end}"
            );
        }
        for bytes in [vec![], vec![0], vec![1, 0], vec![3, 1, 2], vec![255; 256]] {
            assert!(firmware::ddc(&bytes).is_err());
        }
        for corrupt in 0..5 {
            let (device, _, script) = fixture();
            let mut bytes = image();
            let mut ddc = vec![3, 1, 2, 0xaa];
            match corrupt {
                0 => bytes[8] = 1,
                1 => bytes[128..384].fill(0),
                2 => bytes[646] = 255,
                3 => bytes.push(0),
                _ => ddc.pop().map(|_| ()).unwrap(),
            };
            let catalog = catalog(bytes, ddc);
            let mut hci = transport(device, script);
            assert!(matches!(
                initialize(&mut hci, &catalog),
                Err(Error::FirmwareFormat(_))
            ));
            assert_eq!(hci.io.submitted, 2);
            assert_eq!(hci.state(), State::Closed);
        }
    }
    #[test]
    fn command_vendor_reset_identity_and_address_failures_never_report_ready() {
        for case in 0..16 {
            let (device, catalog, mut script) = fixture();
            match case {
                0 => script.steps[2].events.clear(), // USB delivery without HCI CC
                1 => script.steps[2].events[0].1[3] ^= 1,
                2 => script.steps[2].events[0].1[5] = 0x0c,
                3 => script.steps[7].events[0].1[9] = 1, // secure-result rejection
                4 => script.steps[7].events[0].1.truncate(6), // final CC only
                5 => script.steps[8].events.clear(),     // reset delivery without boot
                6 => script.steps[8].events = vec![(Pipe::Acl, complete(INTEL_RESET, &[0]))],
                7 => script.steps[9].events[0].1[7] ^= 1, // hardware variant
                8 => script.steps[9].events[0].1[11] ^= 1, // build
                9 => script.steps[10].events[0].1[6] ^= 1, // address
                10 => script.steps[2].events[0].1[2] = 0, // zero credits
                11 => script.steps[7].events[0].1[10] ^= 1, // secure result wrong opcode
                12 => script.steps[8].events[1].1[6] = 1, // boot DDC error
                13 => script.steps[2].events[0].1 = vec![0x0f, 4, 0, 1, 9, 0xfc], // Status is not Complete
                14 => {
                    let duplicate = script.steps[2].events[0].1.clone();
                    script.steps[2].events[0].1.extend(duplicate);
                }
                _ => {
                    let duplicate = script.steps[12].events[0].1.clone();
                    script.steps[12].events[0].1.extend(duplicate);
                }
            }
            let mut hci = transport(device, script);
            assert!(initialize(&mut hci, &catalog).is_err(), "case {case}");
            assert_ne!(hci.state(), State::Open);
            assert_eq!(
                hci.firmware_status(),
                super::super::FirmwareStatus::Unverified
            );
        }
    }
    #[test]
    fn usb_disconnect_quiescence_and_exact_target_errors_close_transport() {
        for case in 0..4 {
            let (device, catalog, script) = fixture();
            let mut hci = transport(device, script);
            hci.io.fail_reset = case == 0;
            hci.io.fail_quiesce = case == 1;
            let empty = Catalog::from_handoff(vec![]).unwrap();
            if case == 3 {
                hci.binding.device.descriptor[12] ^= 1;
            }
            let provider: &dyn Provider = if case == 2 { &empty } else { &catalog };
            assert!(initialize(&mut hci, provider).is_err());
            assert_ne!(hci.state(), State::Open);
            assert_eq!(hci.io.closed.get(), 1);
        }
    }
}
