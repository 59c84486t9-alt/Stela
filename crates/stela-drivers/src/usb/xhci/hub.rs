// SPDX-License-Identifier: GPL-2.0-only
// Hub sequencing follows pinned Linux usb/core/hub.c and hub.h.
// Copyright (C) 1999 Linus Torvalds, Johannes Erdfelt, Gregory P. Smith;
// Copyright (C) 2001 Brad Hards; 2012 Intel Corp.
//! Cold enumeration of owned USB2 and SuperSpeed hub trees.
use super::*;

pub(super) mod descriptor;
#[cfg(test)]
pub(super) mod model;
mod power;
mod superspeed;
#[cfg(test)]
pub(super) mod tests;
mod tt;
mod usb2;

pub(super) fn status_endpoint(device: &Device, interface: &Interface) -> Option<Endpoint> {
    if interface.class != HUB_CLASS || interface.alternate != 0 || interface.endpoints.len() != 1 {
        return None;
    }
    if matches!(device.speed, SUPER_SPEED | SUPER_SPEED_PLUS)
        && (device.descriptor[6] != 3 || interface.protocol != 0)
    {
        return None;
    }
    let endpoint = interface.endpoints[0];
    (matches!(
        device.speed,
        FULL_SPEED | HIGH_SPEED | SUPER_SPEED | SUPER_SPEED_PLUS
    ) && endpoint.kind() == 3
        && endpoint.is_in()
        && endpoint::Context::new(&endpoint, device.speed).is_ok())
    .then_some(endpoint)
}

/// Check the original bytes of the setting selected by interface-zero
/// SET_INTERFACE. Sanitization must not hide duplicate interfaces/endpoints or
/// manufacture a usable status endpoint for the acknowledged setting.
pub(super) fn usb2_status_endpoint(
    configuration: &[u8],
    speed: u8,
    alternate: u8,
    ports: u8,
) -> Result<Endpoint, BlockError> {
    if !(1..=MAX_HUB_PORTS).contains(&ports) {
        return Err(BlockError::Unsupported(
            "USB2 hub selected bitmap port count is invalid",
        ));
    }
    let mut at = 0;
    while at < configuration.len() {
        let length = usize::from(configuration[at]);
        if length < 2 || length > configuration.len() - at {
            return Err(BlockError::Unsupported(
                "USB2 hub original configuration is malformed",
            ));
        }
        let bytes = &configuration[at..at + length];
        if bytes[1] == INTERFACE_DESCRIPTOR
            && length >= 9
            && bytes[2] == 0
            && bytes[3] == alternate
            && bytes[4] != 1
        {
            return Err(BlockError::Unsupported(
                "USB2 hub selected interface must declare one status endpoint",
            ));
        }
        at += length;
    }
    let all = interfaces(configuration);
    let mut selected = all
        .iter()
        .filter(|interface| interface.number == 0 && interface.alternate == alternate);
    let interface = selected.next().ok_or(BlockError::Unsupported(
        "USB2 hub selected status interface absent",
    ))?;
    if selected.next().is_some()
        || interface.class != HUB_CLASS
        || interface.subclass != 0
        || interface.endpoints.len() != 1
    {
        return Err(BlockError::Unsupported(
            "USB2 hub selected status interface is ambiguous or malformed",
        ));
    }
    let endpoint = interface.endpoints[0];
    if !matches!(speed, FULL_SPEED | HIGH_SPEED)
        || endpoint.kind() != 3
        || !endpoint.is_in()
        || endpoint.address & 0x0f == 0
        || endpoint.address & 0x70 != 0
        || usize::from(endpoint.max_packet & 0x7ff) < usize::from(ports + 1).div_ceil(8)
    {
        return Err(BlockError::Unsupported(
            "USB2 hub selected status endpoint is not a usable bitmap interrupt IN",
        ));
    }
    endpoint::Context::new(&endpoint, speed)?;
    Ok(endpoint)
}

/// One shared validator for cold and kept external hub status reads.
/// A lifecycle bitmap never authorizes accepting reserved port-state fields.
pub(super) fn validate_port_status(bytes: &[u8], speed: u8) -> Result<(), BlockError> {
    if matches!(speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
        superspeed::Port::decode(bytes, false)?;
    } else {
        if bytes.len() != 4 {
            return Err(BlockError::Unsupported("short USB2 hub port status"));
        }
        let status = u16::from_le_bytes([bytes[0], bytes[1]]);
        let change = u16::from_le_bytes([bytes[2], bytes[3]]);
        if status & !0x1f3f != 0
            || status & (HUB_PORT_LOW_SPEED | HUB_PORT_HIGH_SPEED)
                == HUB_PORT_LOW_SPEED | HUB_PORT_HIGH_SPEED
            || change & !0x3f != 0
        {
            return Err(BlockError::Unsupported("reserved USB2 hub port status"));
        }
    }
    Ok(())
}
