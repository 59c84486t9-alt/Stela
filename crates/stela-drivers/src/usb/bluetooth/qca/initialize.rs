// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Qualcomm USB Bluetooth initialization: version query, then rampatch and NVM download.
use super::{
    Attempt, Component, Error, FirmwareEvidence, HostPolicy, Kind, OwnedReport, Profile,
    RampatchVersion, Result, Transfer, TransferKind, UsbIdentity, Version,
};
use crate::{
    firmware::{Provider, Requirement},
    usb::bluetooth::{Hci, Io, State},
};
use alloc::boxed::Box;
const GET_VERSION: u8 = 0x09;
const CHECK_STATUS: u8 = 0x05;
const DOWNLOAD: u8 = 0x01;
const PATCH_UPDATED: u8 = 0x80;
const NVM_UPDATED: u8 = 0x40;
const BODY_BYTES: usize = 4096;
const BODY_TIMEOUT_US: u64 = 3_000_000;
const ATTEMPT_US: u64 = 120_000_000;

#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub(super) fn run<B: Io>(hci: &mut Hci<B>, provider: &dyn Provider) -> Result<OwnedReport> {
    let usb = UsbIdentity::read(hci.binding.device());
    let kind = usb.kind().ok_or(Error::Unsupported("source USB ID"))?;
    run_as(hci, provider, kind, None)
}
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub(super) fn run_as<B: Io>(
    hci: &mut Hci<B>,
    provider: &dyn Provider,
    kind: Kind,
    expected_rom: Option<u32>,
) -> Result<OwnedReport> {
    let usb = UsbIdentity::read(hci.binding.device());
    hci.open()?;
    let start = hci.io.now_us();
    let mut engine = Engine {
        hci,
        start,
        expected_rom,
        attempt: Attempt {
            usb: Some(usb),
            ..Attempt::default()
        },
    };
    match engine.run(provider, usb, kind) {
        Ok(report) => Ok(report),
        Err(cause) => {
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
    start: u64,
    expected_rom: Option<u32>,
    attempt: Attempt,
}
impl<B: Io> Engine<'_, B> {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn bounded(&self) -> Result<()> {
        if self.hci.io.now_us().wrapping_sub(self.start) >= ATTEMPT_US {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn delay(&self, microseconds: u64) -> Result<()> {
        let start = self.hci.io.now_us();
        while self.hci.io.now_us().wrapping_sub(start) < microseconds {
            self.bounded()?;
            crate::waiting();
            core::hint::spin_loop();
        }
        self.bounded()
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn read(&mut self, request: u8, bytes: u16) -> Result<alloc::vec::Vec<u8>> {
        self.bounded()?;
        let setup = crate::usb::descriptor::setup(0xc0, request, 0, 0, bytes);
        let data = self.hci.io.control_read(setup).map_err(Error::Usb)?;
        if data.len() != usize::from(bytes) {
            return Err(Error::protocol("vendor control IN exact length", &data));
        }
        self.bounded()?;
        Ok(data)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn version(&mut self) -> Result<Version> {
        Version::parse(&self.read(GET_VERSION, 20)?)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn resource<'a>(
        &self,
        provider: &'a dyn Provider,
        name: &str,
        version: &Version,
        usb: UsbIdentity,
        minimum_bytes: usize,
    ) -> Result<crate::firmware::Image<'a>> {
        let hardware = usb.hardware_label();
        let revision = version.revision_label();
        provider
            .load(Requirement {
                name,
                target: version.target(&hardware, &revision),
                minimum_bytes,
            })
            .map_err(Error::Resource)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn upload(&mut self, component: Component, bytes: &[u8], header: usize) -> Result<()> {
        if bytes.len() < header {
            return Err(Error::protocol("complete USB DFU header required", bytes));
        }
        self.bounded()?;
        let transfer = Transfer {
            component,
            kind: TransferKind::Header,
            offset: 0,
            bytes: header,
        };
        self.attempt.pending = Some(transfer);
        self.hci
            .io
            .control(
                crate::usb::descriptor::setup(0x40, DOWNLOAD, 0, 0, header as u16),
                &bytes[..header],
            )
            .map_err(Error::Usb)?;
        self.attempt.completed.push(transfer);
        self.attempt.pending = None;
        self.delay(20_000)?;
        let mut offset = header;
        while offset < bytes.len() {
            self.bounded()?;
            let end = (offset + BODY_BYTES).min(bytes.len());
            let transfer = Transfer {
                component,
                kind: TransferKind::Body,
                offset,
                bytes: end - offset,
            };
            self.attempt.pending = Some(transfer);
            self.hci
                .io
                .write_firmware(&bytes[offset..end], BODY_TIMEOUT_US)
                .map_err(Error::Usb)?;
            self.attempt.completed.push(transfer);
            self.attempt.pending = None;
            offset = end;
        }
        self.bounded()
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn rampatch(
        &mut self,
        provider: &dyn Provider,
        usb: UsbIdentity,
        version: &Version,
        profile: Profile,
    ) -> Result<FirmwareEvidence> {
        let image = self.resource(
            provider,
            &version.rampatch_name(),
            version,
            usb,
            profile.rampatch_header,
        )?;
        self.attempt.rampatch = Some(image.into());
        let observed = RampatchVersion::parse(image.bytes(), version, profile)?;
        self.attempt.rampatch_version = Some(observed);
        self.upload(Component::Rampatch, image.bytes(), profile.rampatch_header)?;
        Ok(FirmwareEvidence::Uploaded(Box::new(image.into())))
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn nvm(
        &mut self,
        provider: &dyn Provider,
        usb: UsbIdentity,
        version: &Version,
        profile: Profile,
    ) -> Result<FirmwareEvidence> {
        let image = self.resource(
            provider,
            &version.nvm_name(),
            version,
            usb,
            profile.nvm_header,
        )?;
        self.attempt.nvm = Some(image.into());
        self.upload(Component::Nvm, image.bytes(), profile.nvm_header)?;
        if profile.rom >= 0x00130201 {
            self.delay(100_000)?;
        }
        Ok(FirmwareEvidence::Uploaded(Box::new(image.into())))
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn run(
        &mut self,
        provider: &dyn Provider,
        usb: UsbIdentity,
        kind: Kind,
    ) -> Result<OwnedReport> {
        // Linux's ROM-DFU protocol uses fixed bulk OUT EP2, not HCI commands.
        // Do not redirect firmware into some other descriptor-selected pipe.
        if self.hci.binding.output.address != 2 || self.hci.binding.output.kind() != 2 {
            return Err(Error::Unsupported(
                "DFU requires source bulk OUT endpoint 2",
            ));
        }
        if self.hci.events.since.is_some() || self.hci.acl.since.is_some() {
            return Err(Error::Unsupported("partial HCI frame before USB DFU"));
        }
        self.hci.io.quiesce_bulk().map_err(Error::Usb)?;
        let before = self.version()?;
        self.attempt.before = Some(before.clone());
        if self.expected_rom.is_some_and(|rom| rom != before.rom()) {
            return Err(Error::protocol(
                "runtime ROM changed before DFU",
                &before.raw,
            ));
        }
        let profile = before.profile()?;
        let status = self.read(CHECK_STATUS, 1)?[0];
        self.attempt.status = Some(status);
        let rampatch = if status & PATCH_UPDATED == 0 {
            self.rampatch(provider, usb, &before, profile)?
        } else {
            FirmwareEvidence::AlreadyPresent
        };
        let after_patch = self.version()?;
        self.attempt.after_patch = Some(after_patch.clone());
        if after_patch.rom() != before.rom() {
            return Err(Error::protocol(
                "ROM identity changed during DFU",
                &after_patch.raw,
            ));
        }
        if let Some(downloaded) = self.attempt.rampatch_version
            && after_patch.patch() < u32::from(downloaded.patch)
        {
            return Err(Error::protocol(
                "controller did not report downloaded patch version",
                &after_patch.raw,
            ));
        }
        let nvm = if status & NVM_UPDATED == 0 {
            self.nvm(provider, usb, &after_patch, profile)?
        } else {
            FirmwareEvidence::AlreadyPresent
        };
        Ok(OwnedReport {
            usb,
            kind,
            before,
            status,
            after_patch,
            rampatch,
            nvm,
            rampatch_version: self.attempt.rampatch_version,
            completed: core::mem::take(&mut self.attempt.completed),
            policy: HostPolicy {
                simultaneous_discovery: true,
                wideband_speech: kind != Kind::Ath3012,
                broken_enhanced_setup_sync_conn: true,
                microsoft_opcode: if kind == Kind::Wcn {
                    Some(0xfd70)
                } else {
                    None
                },
            },
        })
    }
}
