//! Validated legacy USB Bluetooth descriptors. Endpoint numbers are discovered,
//! never assumed from the specification's suggested addresses.
use super::super::xhci::{Device, Endpoint, FULL_SPEED, HIGH_SPEED, Interface};
use alloc::vec::Vec;

pub const CLASS: u8 = 0xe0;
const SUBCLASS: u8 = 1;
const PROTOCOL: u8 = 1;

/// Exact device/interface selection and original descriptors for a raw HCI link.
#[derive(Clone, Debug)]
pub struct Binding {
    pub(super) device: Device,
    pub(super) interface: u8,
    pub(super) recipient: u8,
    pub(super) events: Endpoint,
    pub(super) input: Endpoint,
    pub(super) output: Endpoint,
}

impl Binding {
    /// Select legacy HCI on alternate zero. The separate SCO interface is left
    /// at alternate zero; bulk serialization and isochronous endpoints are not
    /// configured. Single-function E0/01/01 devices use device-recipient EP0;
    /// per-interface/composite devices use interface-recipient EP0, regardless
    /// of how many alternate settings/SCO interfaces the function exposes.
    pub fn new(device: &Device, interface: &Interface) -> Result<Self, &'static str> {
        if device.descriptor[0] != 18 || device.descriptor[1] != 1 {
            return Err("invalid Bluetooth device descriptor");
        }
        if !matches!(device.speed, FULL_SPEED | HIGH_SPEED) {
            return Err("Bluetooth transport supports USB full/high speed only");
        }
        validate_configuration(&device.configuration)?;
        if interface.alternate != 0
            || (interface.class, interface.subclass, interface.protocol)
                != (CLASS, SUBCLASS, PROTOCOL)
        {
            return Err("not a legacy Bluetooth HCI interface");
        }
        // Do not accept caller-fabricated interface data detached from the device.
        if !super::super::xhci::interfaces(&device.configuration).contains(interface) {
            return Err("Bluetooth interface is not in configuration");
        }
        if interface.endpoints.is_empty()
            || interface
                .endpoints
                .iter()
                .any(|endpoint| endpoint.kind() == 1)
        {
            return Err("SCO/isochronous Bluetooth interface unsupported");
        }
        let device_class = &device.descriptor[4..7];
        let recipient = if device_class == [CLASS, SUBCLASS, PROTOCOL] {
            0x20
        } else if device_class == [0, 0, 0] || device_class == [0xef, 2, 1] {
            0x21
        } else {
            return Err("unsupported Bluetooth device class context");
        };
        if device_class == [0xef, 2, 1] && !has_iad(&device.configuration, interface.number) {
            return Err("composite Bluetooth function lacks matching IAD");
        }
        if interface.endpoints.len() != 3 {
            return Err("Bluetooth HCI requires interrupt IN and bulk IN/OUT; SCO unsupported");
        }
        let (mut events, mut input, mut output) = (None, None, None);
        for endpoint in &interface.endpoints {
            validate_endpoint(endpoint, device.speed)?;
            let destination = match (endpoint.kind(), endpoint.is_in()) {
                (3, true) => &mut events,
                (2, true) => &mut input,
                (2, false) => &mut output,
                _ => return Err("SCO/isochronous or incompatible Bluetooth endpoint"),
            };
            if destination.replace(*endpoint).is_some() {
                return Err("duplicate Bluetooth endpoint role");
            }
        }
        match (events, input, output) {
            (Some(events), Some(input), Some(output)) => Ok(Self {
                device: device.clone(),
                interface: interface.number,
                recipient,
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

fn validate_endpoint(endpoint: &Endpoint, speed: u8) -> Result<(), &'static str> {
    if endpoint.address & 0x70 != 0 || endpoint.address & 0x0f == 0 || endpoint.attributes & !3 != 0
    {
        return Err("invalid Bluetooth endpoint address/attributes");
    }
    let packet = endpoint.max_packet;
    match (endpoint.kind(), speed) {
        (2, FULL_SPEED) if matches!(packet, 8 | 16 | 32 | 64) => {}
        (2, HIGH_SPEED) if packet == 512 => {}
        (3, FULL_SPEED) if (1..=64).contains(&packet) && endpoint.interval != 0 => {}
        (3, HIGH_SPEED)
            if (1..=1024).contains(&packet) && (1..=16).contains(&endpoint.interval) => {}
        _ => return Err("invalid Bluetooth endpoint packet size/interval"),
    }
    Ok(())
}

fn has_iad(configuration: &[u8], interface: u8) -> bool {
    let mut at = 0;
    while at < configuration.len() {
        let len = usize::from(configuration[at]); // configuration already validated.
        let d = &configuration[at..at + len];
        if d[1] == 11
            && len >= 8
            && d[2] == interface
            && d[3] >= 2
            && d[4..7] == [CLASS, SUBCLASS, PROTOCOL]
        {
            return true;
        }
        at += len;
    }
    false
}

/// xhci::interfaces is deliberately tolerant for inventory; attachment needs a
/// complete, internally consistent stream rather than its parsed prefix.
fn validate_configuration(configuration: &[u8]) -> Result<(), &'static str> {
    if configuration.len() < 9
        || configuration[0] != 9
        || configuration[1] != 2
        || usize::from(u16::from_le_bytes([configuration[2], configuration[3]]))
            != configuration.len()
        || configuration[5] == 0
    {
        return Err("invalid Bluetooth configuration header/length");
    }
    let mut seen = Vec::new();
    let mut numbers = Vec::new();
    let mut endpoints = Vec::new();
    let mut counts: Option<(u8, usize, usize)> = None;
    let mut at = 9;
    while at < configuration.len() {
        if at + 2 > configuration.len() {
            return Err("truncated Bluetooth descriptor");
        }
        let len = usize::from(configuration[at]);
        if len < 2 || at + len > configuration.len() {
            return Err("truncated Bluetooth descriptor");
        }
        let d = &configuration[at..at + len];
        match d[1] {
            4 => {
                if len < 9 {
                    return Err("short Bluetooth interface descriptor");
                }
                if counts.is_some_and(|(_, expected, actual)| expected != actual) {
                    return Err("Bluetooth endpoint descriptor count mismatch");
                }
                if seen.contains(&(d[2], d[3])) {
                    return Err("duplicate Bluetooth interface setting");
                }
                seen.push((d[2], d[3]));
                if !numbers.contains(&d[2]) {
                    numbers.push(d[2]);
                }
                counts = Some((d[3], usize::from(d[4]), 0));
            }
            5 => {
                if len < 7 {
                    return Err("short Bluetooth endpoint descriptor");
                }
                let Some((alternate, _, count)) = counts.as_mut() else {
                    return Err("orphan Bluetooth endpoint descriptor");
                };
                *count += 1;
                if *alternate == 0 {
                    if endpoints.contains(&d[2]) {
                        return Err("duplicate active USB endpoint address");
                    }
                    endpoints.push(d[2]);
                }
            }
            2 => return Err("nested USB configuration descriptor"),
            _ => {}
        }
        at += len;
    }
    if counts.is_some_and(|(_, expected, actual)| expected != actual)
        || numbers.len() != usize::from(configuration[4])
    {
        return Err("Bluetooth interface/endpoint descriptor count mismatch");
    }
    Ok(())
}
