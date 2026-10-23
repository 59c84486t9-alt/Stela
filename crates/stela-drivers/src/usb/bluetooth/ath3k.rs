// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2008-2009 Atheros Communications Inc.
//! AR3011/AR3012 raw USB firmware bootloader. This owner is never an HCI link:
//! completed download requests still require genuine USB reenumeration before
//! another, freshly inventoried runtime device can attach.
mod host;
mod identity;
mod initialize;
#[cfg(test)]
mod tests;
use super::{FirmwareReceipt, Io};
use crate::{
    block::BlockError,
    firmware::Provider,
    usb::xhci::{self, Device, Endpoint, Interface},
};
use alloc::{boxed::Box, vec::Vec};
pub use host::Host;
pub use identity::{Kind, SOURCE_USB_IDS, UsbIdentity, Version};
pub type UsbBootloader = Bootloader<Host>;
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Debug)]
pub struct Binding {
    device: Device,
    output: Endpoint,
    kind: Kind,
}
impl Binding {
    pub fn new(device: &Device, interface: &Interface) -> core::result::Result<Self, &'static str> {
        let kind = UsbIdentity::read(device)
            .kind()
            .ok_or("not an ATH3K bootloader USB identity/revision")?;
        if !matches!(device.speed, xhci::FULL_SPEED | xhci::HIGH_SPEED) {
            return Err("ATH3K supports full/high speed USB only");
        }
        if interface.number != 0
            || interface.alternate != 0
            || !xhci::interfaces(&device.configuration).contains(interface)
        {
            return Err("ATH3K requires actual interface-zero alternate-zero");
        }
        let output = interface
            .endpoints
            .iter()
            .find(|e| e.address == 2 && e.kind() == 2)
            .copied()
            .ok_or("ATH3K requires actual bulk OUT endpoint 2")?;
        Ok(Self {
            device: device.clone(),
            output,
            kind,
        })
    }
    pub fn device(&self) -> &Device {
        &self.device
    }
    pub(in crate::usb) fn endpoints(&self) -> Vec<Endpoint> {
        vec![self.output]
    }
}
pub fn is_candidate(device: &Device) -> bool {
    UsbIdentity::read(device).kind().is_some()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    AwaitingReenumeration,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Monolithic,
    Patch,
    Configuration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Header {
        component: Component,
        bytes: usize,
    },
    Body {
        component: Component,
        offset: usize,
        bytes: usize,
    },
    NormalMode,
    SwitchIdentity,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub usb: Option<UsbIdentity>,
    pub states: Vec<u8>,
    pub patch_identity: Option<Version>,
    pub configuration_identity: Option<Version>,
    pub monolithic: Option<FirmwareReceipt>,
    pub patch: Option<FirmwareReceipt>,
    pub configuration: Option<FirmwareReceipt>,
    pub patch_build: Option<u32>,
    pub patch_already_present: bool,
    pub completed: Vec<Operation>,
    pub pending: Option<Operation>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub kind: Kind,
    pub observation: Attempt,
}
#[derive(Debug)]
pub enum Error {
    Unsupported(&'static str),
    Protocol {
        requirement: &'static str,
        observed: Vec<u8>,
    },
    Usb(BlockError),
    Resource(crate::firmware::Error),
    Timeout,
    Attempt {
        cause: Box<Error>,
        observation: Box<Attempt>,
    },
    Cleanup {
        cause: Box<Error>,
        cleanup: BlockError,
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
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ATH3K USB bootloader {self:?}")
    }
}
impl core::error::Error for Error {}
/// Retained exactly-once raw uploader, including terminal failures and uncertain
/// DMA ownership. No operation can reinterpret this attachment as a runtime HCI.
pub struct Bootloader<B: Io> {
    binding: Binding,
    io: B,
    state: State,
    initialization: Option<Box<Result<OwnedReport>>>,
}
impl<B: Io> Bootloader<B> {
    pub fn from_io(binding: Binding, io: B) -> Self {
        Self {
            binding,
            io,
            state: State::Fresh,
            initialization: None,
        }
    }
    pub fn device(&self) -> &Device {
        self.binding.device()
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn initialization(&self) -> Option<core::result::Result<&OwnedReport, &Error>> {
        self.initialization.as_deref().map(Result::as_ref)
    }
    pub fn initialize_with_provider(
        &mut self,
        provider: &dyn Provider,
    ) -> core::result::Result<&OwnedReport, &Error> {
        if self.initialization.is_none() {
            self.initialization = Some(Box::new(initialize::run(self, provider)));
        }
        self.initialization().unwrap()
    }
}
