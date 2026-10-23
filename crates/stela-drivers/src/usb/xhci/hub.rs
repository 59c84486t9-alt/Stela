// SPDX-License-Identifier: GPL-2.0-only
// Hub sequencing follows pinned Linux usb/core/hub.c and hub.h.
// Copyright (C) 1999 Linus Torvalds, Johannes Erdfelt, Gregory P. Smith;
// Copyright (C) 2001 Brad Hards; 2012 Intel Corp.
//! Cold enumeration of owned USB2 and SuperSpeed hub trees.
use super::*;

pub(super) mod descriptor;
#[cfg(test)]
mod model;
mod power;
#[cfg(test)]
mod runtime_tests;
mod superspeed;
#[cfg(test)]
mod tests;
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
