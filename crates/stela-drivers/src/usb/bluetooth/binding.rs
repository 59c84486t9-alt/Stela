// SPDX-License-Identifier: MIT
//! The legacy USB Bluetooth HCI interface and its endpoints. Endpoint numbers
//! are discovered, never assumed from the specification's suggested addresses.
use super::super::descriptor::{Endpoint, Interface};
use super::super::xhci::{Device, FULL_SPEED, HIGH_SPEED};
use alloc::vec::Vec;

pub const CLASS: u8 = 0xe0;
const SUBCLASS: u8 = 1;
const PROTOCOL: u8 = 1;
/// The Bluetooth specification fixes the HCI interface's number.
const HCI_INTERFACE: u8 = 0;
const BULK: u8 = 2;
const INTERRUPT: u8 = 3;

/// Exact device/interface selection and original descriptors for a raw HCI link.
#[derive(Clone, Debug)]
pub struct Binding {
    pub(super) device: Device,
    pub(super) interface: u8,
    pub(super) events: Endpoint,
    pub(super) input: Endpoint,
    pub(super) output: Endpoint,
}

impl Binding {
    /// Select legacy HCI on interface 0's alternate zero, as Linux
    /// `btusb_probe` does: the first interrupt IN, bulk IN and bulk OUT
    /// endpoints carry events, inbound and outbound ACL; other endpoints are
    /// left alone. The SCO interface stays at alternate zero.
    pub fn new(device: &Device, interface: &Interface) -> Result<Self, &'static str> {
        if !matches!(device.speed, FULL_SPEED | HIGH_SPEED) {
            return Err("Bluetooth transport supports USB full/high speed only");
        }
        if interface.alternate != 0
            || ((interface.class, interface.subclass, interface.protocol)
                != (CLASS, SUBCLASS, PROTOCOL)
                && !super::broadcom::is_vendor_interface(device, interface))
        {
            return Err("not a legacy Bluetooth HCI interface");
        }
        if interface.number != HCI_INTERFACE {
            return Err("Bluetooth HCI on an interface other than 0");
        }
        // Do not accept caller-invented interface data detached from the device.
        if !super::super::descriptor::interfaces(&device.configuration).contains(interface) {
            return Err("Bluetooth interface is not in configuration");
        }
        let first = |kind: u8, input: bool| {
            interface
                .endpoints
                .iter()
                .copied()
                .find(|endpoint| endpoint.kind() == kind && endpoint.is_in() == input)
        };
        match (
            first(INTERRUPT, true),
            first(BULK, true),
            first(BULK, false),
        ) {
            (Some(events), Some(input), Some(output)) => Ok(Self {
                device: device.clone(),
                interface: interface.number,
                events,
                input,
                output,
            }),
            _ => Err("Bluetooth HCI endpoints are missing"),
        }
    }

    pub fn device(&self) -> &Device {
        &self.device
    }
    pub fn interface(&self) -> u8 {
        self.interface
    }
    pub(in crate::usb) fn endpoints(&self) -> Vec<Endpoint> {
        vec![self.events, self.input, self.output]
    }
}
