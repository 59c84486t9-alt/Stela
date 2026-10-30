// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! btmtk USB register, WMT patch/status and protocol-enable sequence. Native
//! synchronization, standard post-enable HCI checks and quarantine are Stela glue.
use super::{
    Attempt, Error, Hci, HostPolicy, Identity, Io, OwnedReport, Patch, RecoveryPolicy,
    RegisterObservation, Result, SectionDisposition, SectionReceipt, UsbIdentity, WmtEvent, reset,
    wmt,
};
use crate::{
    firmware::{Provider, Requirement},
    usb::bluetooth::{
        ErrorKind, Packet, State,
        command::{self, Response},
    },
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
const LEGACY_ID: u32 = 0x80000008;
const DEVICE_ID: u32 = 0x70010200;
const FIRMWARE_VERSION: u32 = 0x80021004;
const FLAVOR: u32 = 0x70010020;
const EP_RESET_OPTION: u32 = 0x74011890;
const EP_RESET_IN_OUT: u32 = 0x00010001;
const RESET: u16 = 0x0c03;
const READ_VERSION: u16 = 0x1001;
const READ_ADDRESS: u16 = 0x1009;
const COMMAND_US: u64 = 5_000_000;
/// HCI_CMD_TIMEOUT: hci_cmd_timeout calls hdev->reset once a command other
/// than HCI Reset goes this long without its completion.
const CMD_TIMEOUT_US: u64 = 2_000_000;
const ATTEMPT_US: u64 = 180_000_000;
const MAX_AUXILIARY: usize = 32768;

pub(super) fn run<B: Io>(hci: &mut Hci<B>, provider: &dyn Provider) -> Result<OwnedReport> {
    let usb = UsbIdentity::read(hci.binding.device());
    if !usb.candidate() {
        return Err(Error::Unsupported("USB identity"));
    }
    hci.open()?;
    let deadline = hci.io.now_us().saturating_add(ATTEMPT_US);
    let mut engine = Engine {
        hci,
        deadline,
        credits: 1,
        pending: VecDeque::new(),
        attempt: Attempt::default(),
        firmware: false,
        command_timeout: false,
    };
    match engine.run(usb, provider) {
        Ok(r) => Ok(r),
        Err(cause) => {
            // btmtk_usb_setup resets after a failed firmware setup, and
            // hci_cmd_timeout after a command timeout; the rebound device
            // runs setup again, so each attempt repeats this as in Linux.
            if (engine.firmware || engine.command_timeout)
                && let Some(device_id) = engine.attempt.identity.as_ref().map(|i| i.device_id)
            {
                engine.attempt.reset = Some(reset::run(engine.hci, device_id, None));
            }
            let cause = Error::Attempt {
                cause: Box::new(cause),
                observation: Box::new(engine.attempt),
            };
            if engine.hci.state() == State::Open
                && let Err(cleanup) = engine.hci.close()
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
    deadline: u64,
    credits: u8,
    pending: VecDeque<Vec<u8>>,
    attempt: Attempt,
    /// Inside btmtk_setup_firmware_79xx, whose failure resets the device.
    firmware: bool,
    command_timeout: bool,
}
impl<B: Io> Engine<'_, B> {
    fn control_read(&mut self, setup: [u8; 8]) -> Result<Vec<u8>> {
        self.hci.open()?;
        if self.hci.io.now_us() >= self.deadline {
            return Err(Error::Timeout("complete initialization attempt"));
        }
        self.hci
            .io
            .control_read(setup)
            .map_err(|e| self.hci.fail(ErrorKind::Usb(e)).into())
    }
    fn register(&mut self, address: u32) -> Result<u32> {
        let request =
            crate::usb::descriptor::setup(0xc0, 0x63, (address >> 16) as u16, address as u16, 4);
        let bytes = self.control_read(request)?;
        if bytes.len() != 4 {
            return Err(Error::protocol("complete vendor register read", &bytes));
        }
        let value = u32::from_le_bytes(bytes.try_into().unwrap());
        self.attempt
            .registers
            .push(RegisterObservation { address, value });
        Ok(value)
    }
    fn poll(&mut self) -> Result<()> {
        for p in self.hci.poll()? {
            match p {
                Packet::Event(e) => self.pending.push_back(e),
                // Firmware debug logs have no consumer before the session;
                // a firmware dump means the controller failed.
                Packet::Diagnostic(d)
                    if d.len() >= 2
                        && u16::from_le_bytes([d[0], d[1]]) != super::packet::DUMP_HANDLE => {}
                Packet::Diagnostic(a) => {
                    return Err(Error::protocol(
                        "MT79xx firmware dump while initializing",
                        &a,
                    ));
                }
                Packet::Acl(a) => {
                    return Err(Error::protocol(
                        "unexpected ACL while initializing MT79xx",
                        &a,
                    ));
                }
            }
        }
        if self.pending.len() > 16 {
            return Err(Error::protocol(
                "excess pending HCI initialization events",
                &[],
            ));
        }
        Ok(())
    }
    fn auxiliary_event(&mut self, event: Vec<u8>) -> Result<()> {
        let (status, credits) = match command::response(&event, wmt::OPCODE) {
            Ok(Response::Complete { credits, returned }) => (returned[0], credits),
            Ok(Response::Status { credits, status }) => (status, credits),
            Ok(Response::Credits(credits)) => {
                self.credits = credits;
                return Ok(());
            }
            Ok(Response::Other) => {
                return Err(Error::protocol(
                    "unexpected interrupt event during WMT",
                    &event,
                ));
            }
            Err(_) => {
                return Err(Error::protocol(
                    "stale interrupt HCI completion during WMT",
                    &event,
                ));
            }
        };
        let opcode = wmt::OPCODE;
        self.credits = credits;
        if self.attempt.auxiliary_hci_events.len() >= MAX_AUXILIARY {
            return Err(Error::protocol("excess WMT auxiliary HCI events", &event));
        }
        self.attempt.auxiliary_hci_events.push(event.clone());
        if status != 0 {
            return Err(Error::Controller {
                opcode,
                status,
                parameters: event,
            });
        }
        Ok(())
    }
    fn drain_auxiliary(&mut self) -> Result<()> {
        self.poll()?;
        while let Some(e) = self.pending.pop_front() {
            self.auxiliary_event(e)?;
        }
        Ok(())
    }
    fn wait(&mut self, us: u64) -> Result<()> {
        let until = self.hci.io.now_us().saturating_add(us);
        loop {
            let now = self.hci.io.now_us();
            if now >= self.deadline {
                return Err(Error::Timeout("complete initialization attempt"));
            }
            if now >= until {
                return Ok(());
            }
            self.drain_auxiliary()?;
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn wmt(&mut self, operation: u8, flag: u8, data: &[u8]) -> Result<WmtEvent> {
        self.drain_auxiliary()?;
        let now = self.hci.io.now_us();
        if now >= self.deadline {
            return Err(Error::Timeout("complete initialization attempt"));
        }
        let deadline = core::cmp::min(self.deadline, now.saturating_add(COMMAND_US));
        let command = wmt::command(operation, flag, data)?;
        self.attempt.pending_wmt = Some(wmt::WmtCommandReceipt::new(operation, flag, &command));
        self.hci.submit_command(&command)?;
        loop {
            // Vendor EP0 is the only WMT completion source. Interrupt CC/Status
            // is held as auxiliary evidence, never synthesized into WMT.
            let bytes = self.control_read(crate::usb::descriptor::setup(0xc0, 1, 48, 0, 64))?;
            if !bytes.is_empty() {
                let event = WmtEvent::parse(bytes, operation)?;
                self.attempt.last_wmt = Some(event.clone());
                self.drain_auxiliary()?;
                if self.hci.io.now_us() >= deadline {
                    return Err(Error::protocol(
                        "WMT event after command deadline",
                        event.bytes(),
                    ));
                }
                self.attempt.pending_wmt = None;
                return Ok(event);
            }
            self.drain_auxiliary()?;
            if self.hci.io.now_us() >= deadline {
                return Err(Error::Timeout("genuine EP0 WMT vendor event"));
            }
            // The pinned USB driver explicitly relaxes 500us between empty INs.
            self.wait(500)?;
        }
    }
    fn command(&mut self, opcode: u16) -> Result<Vec<u8>> {
        self.drain_auxiliary()?;
        if self.hci.io.now_us() >= self.deadline {
            return Err(Error::Timeout("complete initialization attempt"));
        }
        let timeout = if opcode == RESET {
            COMMAND_US
        } else {
            CMD_TIMEOUT_US
        };
        let deadline = core::cmp::min(self.deadline, self.hci.io.now_us().saturating_add(timeout));
        while self.credits == 0 {
            if self.hci.io.now_us() >= deadline {
                return Err(Error::Timeout("genuine HCI command credits"));
            }
            self.drain_auxiliary()?;
            crate::waiting();
            core::hint::spin_loop();
        }
        let packet = command::packet(opcode, &[]).map_err(|why| Error::protocol(why, &[]))?;
        self.hci.submit_command(&packet)?;
        self.credits -= 1;
        loop {
            self.poll()?;
            while let Some(e) = self.pending.pop_front() {
                // WMT's own completions arrive on this pipe as auxiliary evidence.
                if command::response(&e, wmt::OPCODE)
                    .is_ok_and(|r| matches!(r, Response::Complete { .. } | Response::Status { .. }))
                {
                    self.auxiliary_event(e)?;
                    continue;
                }
                match command::response(&e, opcode).map_err(|why| Error::protocol(why, &e))? {
                    Response::Credits(credits) => self.credits = credits,
                    Response::Complete { credits, returned } => {
                        if opcode == RESET {
                            self.attempt.reset_completion = Some(e.clone());
                        }
                        if self.hci.io.now_us() >= deadline {
                            return Err(Error::protocol(
                                "HCI completion after command deadline",
                                &e,
                            ));
                        }
                        self.credits = credits;
                        if returned[0] != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status: returned[0],
                                parameters: returned.to_vec(),
                            });
                        }
                        return Ok(returned.to_vec());
                    }
                    Response::Status { credits, status } => {
                        self.credits = credits;
                        if status != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status,
                                parameters: e[2..].to_vec(),
                            });
                        }
                    }
                    Response::Other => {
                        return Err(Error::protocol("unexpected HCI initialization event", &e));
                    }
                }
            }
            if self.hci.io.now_us() >= deadline {
                // HCI Reset never arms the command timer.
                self.command_timeout = opcode != RESET;
                return Err(Error::Timeout("genuine HCI completion"));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn run(&mut self, usb: UsbIdentity, provider: &dyn Provider) -> Result<OwnedReport> {
        let legacy = self.register(LEGACY_ID)?;
        if legacy == 0x7663 {
            return Err(Error::Unsupported("legacy MT7663 path"));
        }
        let device = self.register(DEVICE_ID)?;
        let version = self.register(FIRMWARE_VERSION)?;
        let flavor = self.register(FLAVOR)?;
        let identity = Identity::select(usb, legacy, device, version, flavor)?;
        self.attempt.identity = Some(identity.clone());
        self.firmware = true;
        let hardware = usb.hardware_label();
        let revision = identity.revision_label();
        let image = provider
            .load(Requirement {
                name: identity.firmware_name(),
                target: identity.target(&hardware, &revision),
                minimum_bytes: 160,
            })
            .map_err(Error::Resource)?;
        self.attempt.firmware = Some(image.into());
        let patch = Patch::parse(image.bytes())?;
        self.attempt.metadata = Some(patch.metadata());
        for (index, section) in patch.sections.iter().enumerate() {
            if section.metadata.download_size() == 0 {
                continue;
            }
            self.attempt.sections.push(SectionReceipt {
                index,
                queries: Vec::new(),
                acknowledged_fragments: 0,
                last_download_response: None,
                disposition: None,
            });
            let receipt = self.attempt.sections.len() - 1;
            let mut ready = false;
            let mut present = false;
            for _ in 0..20 {
                let event = self.wmt(wmt::PATCH, 0, &section.metadata.request())?;
                self.attempt.sections[receipt].queries.push(event.clone());
                match event.patch_status()? {
                    wmt::PatchStatus::Undone => {
                        ready = true;
                        break;
                    }
                    wmt::PatchStatus::Done => {
                        present = true;
                        break;
                    }
                    wmt::PatchStatus::Progress => self.wait(100_000)?,
                }
            }
            if present {
                self.attempt.sections[receipt].disposition =
                    Some(SectionDisposition::AlreadyPresentUnknown);
                continue;
            }
            if !ready {
                return Err(Error::Timeout("bounded section query retries"));
            }
            for fragment in section.fragments() {
                let event = self.wmt(wmt::PATCH, fragment.flag, fragment.data)?;
                self.attempt.sections[receipt].last_download_response = Some(event.clone());
                if event.patch_status()? == wmt::PatchStatus::Progress {
                    return Err(Error::protocol(
                        "unexpected patch progress during fragment transfer",
                        event.bytes(),
                    ));
                }
                self.attempt.sections[receipt].acknowledged_fragments += 1;
            }
            self.attempt.sections[receipt].disposition = Some(SectionDisposition::Transferred);
        }
        self.wait(100_000)?;
        self.firmware = false;
        // Options only: this does not assert/reset the shared combo subsystem.
        let request = crate::usb::descriptor::setup(
            0x5e,
            2,
            (EP_RESET_OPTION >> 16) as u16,
            EP_RESET_OPTION as u16,
            4,
        );
        self.hci
            .io
            .control(request, &EP_RESET_IN_OUT.to_le_bytes())
            .map_err(|e| self.hci.fail(ErrorKind::Usb(e)))?;
        self.attempt.endpoint_reset_option_completed = true;
        let enabled = self.wmt(wmt::FUNCTION, 0, &[1])?;
        self.attempt.function_enable = Some(enabled.clone());
        if !enabled.enabled() {
            return Err(Error::protocol(
                "Bluetooth function enable acknowledgment",
                enabled.bytes(),
            ));
        }
        let reset = self.command(RESET)?;
        if reset != [0] {
            return Err(Error::protocol("HCI Reset response shape", &reset));
        }
        let version = self.command(READ_VERSION)?;
        let raw: [u8; 9] = version
            .as_slice()
            .try_into()
            .map_err(|_| Error::protocol("Read Local Version shape", &version))?;
        self.attempt.local_version = Some(raw);
        // Standard company identifier70 is MediaTek; revision fields are
        // without inventing an image-header-to-HCI version mapping.
        if u16::from_le_bytes([raw[5], raw[6]]) != 70 {
            return Err(Error::protocol("observed MediaTek HCI identity", &raw));
        }
        let address = self.command(READ_ADDRESS)?;
        if address.len() != 7 {
            return Err(Error::protocol("BD_ADDR response shape", &address));
        }
        let address: [u8; 6] = address[1..].try_into().unwrap();
        self.attempt.address = Some(address);
        if address == [0; 6] || address == [0xff; 6] {
            return Err(Error::protocol("nonempty controller address", &address));
        }
        // A coalesced event after the last desired CC must be held as
        // auxiliary evidence or rejected explicitly, never dropped with Engine.
        self.drain_auxiliary()?;
        let policy = HostPolicy::for_device(identity.usb);
        Ok(OwnedReport {
            identity,
            firmware: Box::new(self.attempt.firmware.take().unwrap()),
            metadata: self.attempt.metadata.take().unwrap(),
            sections: core::mem::take(&mut self.attempt.sections),
            function_enable: enabled,
            auxiliary_hci_events: core::mem::take(&mut self.attempt.auxiliary_hci_events),
            reset_completion: self.attempt.reset_completion.take().unwrap(),
            local_version: raw,
            address,
            command_credits: self.credits,
            recovery: RecoveryPolicy::FreshRebindRequired,
            policy,
        })
    }
}
