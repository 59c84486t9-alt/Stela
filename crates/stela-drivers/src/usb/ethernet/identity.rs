// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
// Copyright (c) 2020 Realtek Semiconductor Corp. All rights reserved.
//! Exact USB candidates and serial/bcdDevice policy from pinned r8152.
use super::{Device, rtl815x};

/// Exact entries in the pinned r8152 USB table (which has no driver_info
/// flags). These are read-only preflight candidates, never proof of silicon.
/// RTL8157/815A IDs may be inventoried, but their unimplemented TCR versions
/// cannot acquire a vendor plan or hide compatible CDC configurations.
pub(crate) const USB_IDS: &[(u16, u16)] = &[
    (0x0bda, 0x8050),
    (0x0bda, 0x8053),
    (0x0bda, 0x8152),
    (0x0bda, 0x8153),
    (0x0bda, 0x8155),
    (0x0bda, 0x8156),
    (0x0bda, 0x8157),
    (0x0bda, 0x815a),
    (0x045e, 0x07ab),
    (0x045e, 0x07c6),
    (0x045e, 0x0927),
    (0x045e, 0x0c5e),
    (0x04e8, 0xa101),
    (0x17ef, 0x304f),
    (0x17ef, 0x3054),
    (0x17ef, 0x3062),
    (0x17ef, 0x3069),
    (0x17ef, 0x3082),
    (0x17ef, 0x3098),
    (0x17ef, 0x7205),
    (0x17ef, 0x720c),
    (0x17ef, 0x7214),
    (0x17ef, 0x721e),
    (0x17ef, 0xa359),
    (0x17ef, 0xa387),
    (0x13b1, 0x0041),
    (0x0955, 0x09ff),
    (0x2357, 0x0601),
    (0x2357, 0x0602),
    (0x2001, 0xb301),
    (0x413c, 0xb097),
    (0x0b05, 0x1976),
    (0x20f4, 0xe02b),
    (0x20f4, 0xe02c),
];

pub fn matches(descriptor: &[u8; 18]) -> bool {
    USB_IDS.contains(&(
        u16::from_le_bytes([descriptor[8], descriptor[9]]),
        u16::from_le_bytes([descriptor[10], descriptor[11]]),
    ))
}

pub(super) fn policy(device: &Device) -> rtl815x::Policy {
    // Exact rtl8152_probe_once predicate. It is a hardware serial/bcdDevice
    // quirk, not a vendor/rebrand guess; TX already submits one frame per TD.
    rtl815x::Policy {
        disable_receive_aggregation: u16::from_le_bytes([
            device.descriptor[12],
            device.descriptor[13],
        ]) == 0x3011
            && matches!(
                device.serial.as_deref(),
                Some("000001000000" | "000002000000")
            ),
    }
}
