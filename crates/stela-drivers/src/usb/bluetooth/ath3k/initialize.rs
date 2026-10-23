// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2008-2009 Atheros Communications Inc.
use super::{
    Attempt, Bootloader, Component, Error, Kind, Operation, OwnedReport, Result, State,
    UsbIdentity, Version, identity::target,
};
use crate::{
    firmware::{Provider, Requirement},
    usb::{
        bluetooth::{FirmwareReceipt, Io},
        xhci,
    },
};
use alloc::{boxed::Box, vec::Vec};
const ATTEMPT_US: u64 = 120_000_000;
pub(super) fn run<B: Io>(
    owner: &mut Bootloader<B>,
    provider: &dyn Provider,
) -> Result<OwnedReport> {
    let start = owner.io.now_us();
    let mut engine = Engine {
        io: &mut owner.io,
        start,
        attempt: Attempt {
            usb: Some(UsbIdentity::read(owner.binding.device())),
            ..Attempt::default()
        },
    };
    let result = engine.run(provider, owner.binding.kind);
    let observation = engine.attempt;
    let result = match result {
        Ok(()) => Ok(OwnedReport {
            kind: owner.binding.kind,
            observation,
        }),
        Err(cause) => Err(Error::Attempt {
            cause: Box::new(cause),
            observation: Box::new(observation),
        }),
    };
    // Always terminal. Even a successful upload cannot transfer this raw slot's
    // ownership into a runtime HCI. USB lifecycle observes real removal/rebind.
    owner.state = if result.is_ok() {
        State::AwaitingReenumeration
    } else {
        State::Failed
    };
    if let Err(cleanup) = engine.io.close() {
        owner.state = State::Failed;
        let cause = match result {
            Ok(report) => Error::Attempt {
                cause: Box::new(Error::Unsupported(
                    "download completed but raw transport retirement failed",
                )),
                observation: Box::new(report.observation),
            },
            Err(cause) => cause,
        };
        return Err(Error::Cleanup {
            cause: Box::new(cause),
            cleanup,
        });
    }
    result
}
struct Engine<'a, B: Io> {
    io: &'a mut B,
    start: u64,
    attempt: Attempt,
}
impl<B: Io> Engine<'_, B> {
    fn bounded(&self) -> Result<()> {
        if self.io.now_us().wrapping_sub(self.start) >= ATTEMPT_US {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
    fn delay(&self) -> Result<()> {
        let start = self.io.now_us();
        while self.io.now_us().wrapping_sub(start) < 50 {
            self.bounded()?;
            crate::waiting();
            core::hint::spin_loop();
        }
        self.bounded()
    }
    fn read(&mut self, request: u8, length: u16) -> Result<Vec<u8>> {
        self.bounded()?;
        let bytes = self
            .io
            .control_read(xhci::setup(0xc0, request, 0, 0, length))
            .map_err(Error::Usb)?;
        if bytes.len() != usize::from(length) {
            return Err(Error::protocol("ATH3K control IN exact length", &bytes));
        }
        self.bounded()?;
        Ok(bytes)
    }
    fn state(&mut self) -> Result<u8> {
        let state = self.read(5, 1)?[0];
        self.attempt.states.push(state);
        Ok(state)
    }
    fn version(&mut self) -> Result<Version> {
        Version::parse(&self.read(9, 20)?)
    }
    fn resource<'a>(
        &self,
        provider: &'a dyn Provider,
        name: &str,
        revision: &str,
    ) -> Result<crate::firmware::Image<'a>> {
        let hardware = self.attempt.usb.unwrap().hardware();
        provider
            .load(Requirement {
                name,
                target: target(&hardware, revision),
                minimum_bytes: 20,
            })
            .map_err(Error::Resource)
    }
    fn upload(&mut self, component: Component, bytes: &[u8]) -> Result<()> {
        if bytes.len() < 20 {
            return Err(Error::protocol(
                "ATH3K complete 20-byte firmware header",
                bytes,
            ));
        }
        self.bounded()?;
        let operation = Operation::Header {
            component,
            bytes: 20,
        };
        self.attempt.pending = Some(operation);
        self.io
            .control(xhci::setup(0x40, 1, 0, 0, 20), &bytes[..20])
            .map_err(Error::Usb)?;
        self.attempt.completed.push(operation);
        self.attempt.pending = None;
        let mut offset = 20;
        while offset < bytes.len() {
            self.delay()?;
            let end = (offset + 4096).min(bytes.len());
            let operation = Operation::Body {
                component,
                offset,
                bytes: end - offset,
            };
            self.attempt.pending = Some(operation);
            self.io
                .write_firmware(&bytes[offset..end], 3_000_000)
                .map_err(Error::Usb)?;
            self.attempt.completed.push(operation);
            self.attempt.pending = None;
            offset = end;
        }
        self.bounded()
    }
    fn command(&mut self, request: u8, operation: Operation) -> Result<()> {
        self.bounded()?;
        self.attempt.pending = Some(operation);
        self.io
            .control(xhci::setup(0x40, request, 0, 0, 0), &[])
            .map_err(Error::Usb)?;
        self.attempt.completed.push(operation);
        self.attempt.pending = None;
        self.bounded()
    }
    fn run(&mut self, provider: &dyn Provider, kind: Kind) -> Result<()> {
        if kind == Kind::Ar3011 {
            let image = self.resource(provider, "ath3k-1.fw", "ar3011-monolithic")?;
            self.attempt.monolithic = Some(FirmwareReceipt::from(image));
            return self.upload(Component::Monolithic, image.bytes());
        }
        if self.state()? & 0x80 == 0 {
            let version = self.version()?;
            self.attempt.patch_identity = Some(version.clone());
            let image = self.resource(provider, &version.patch_name(), &version.revision())?;
            self.attempt.patch = Some(image.into());
            let bytes = image.bytes();
            let rom =
                u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().unwrap());
            let build = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
            if rom != version.rom() || build <= version.build() {
                return Err(Error::protocol(
                    "ATH3K patch ROM mismatch or non-newer build",
                    &bytes[bytes.len() - 8..],
                ));
            }
            self.attempt.patch_build = Some(build);
            self.upload(Component::Patch, bytes)?;
        } else {
            self.attempt.patch_already_present = true;
        }
        // Donor always reads fresh state/version and uploads syscfg, even when
        // the SYSCFG_UPDATED bit is already set. Do not skip board configuration.
        self.state()?;
        let version = self.version()?;
        self.attempt.configuration_identity = Some(version.clone());
        if let Some(patch) = &self.attempt.patch_identity
            && (version.rom() != patch.rom() || version.build() < self.attempt.patch_build.unwrap())
        {
            return Err(Error::protocol(
                "ATH3K post-patch version did not apply",
                &version.raw,
            ));
        }
        let image = self.resource(provider, &version.config_name(), &version.revision())?;
        self.attempt.configuration = Some(image.into());
        self.upload(Component::Configuration, image.bytes())?;
        if self.state()? & 0x3f != 0x0e {
            self.command(7, Operation::NormalMode)?;
        }
        self.command(0x0a, Operation::SwitchIdentity)
    }
}
