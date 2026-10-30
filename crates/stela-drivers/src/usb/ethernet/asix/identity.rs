// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2011-2013 ASIX
// Legacy identities: Copyright (C) 2003-2006 David Hollis;
// 2005 Phil Chang; 2006 James Painter; 2002-2003 TiVo Inc.
//! Exact ASIX donor USB/interface candidates; chip/PHY readiness is separate.
use crate::usb::descriptor::Interface;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::usb::ethernet) enum Identity {
    Ax88179,
    Ax88178a,
    Ax88772 { eeprom_mac: bool },
}

pub(in crate::usb::ethernet) const IDS: &[(u16, u16, Identity)] = &[
    (0x0b95, 0x1790, Identity::Ax88179),
    (0x0b95, 0x178a, Identity::Ax88178a),
    (0x04b4, 0x3610, Identity::Ax88179),
    (0x2001, 0x4a00, Identity::Ax88179),
    (0x0df6, 0x0072, Identity::Ax88179),
    (0x04e8, 0xa100, Identity::Ax88179),
    (0x17ef, 0x304b, Identity::Ax88179),
    (0x050d, 0x0128, Identity::Ax88179),
    (0x0930, 0x0a13, Identity::Ax88179),
    (0x0711, 0x0179, Identity::Ax88179),
    (0x07c9, 0x000e, Identity::Ax88179),
    (0x07c9, 0x000f, Identity::Ax88179),
    (0x07c9, 0x0010, Identity::Ax88179),
];

// asix_devices.c USB_DEVICE entries: no additional donor class predicate.
// Stela currently admits only vendor-class interfaces with a unique bulk pair;
// compatible class configurations keep their own planner and preference.
pub(in crate::usb::ethernet) const LEGACY_IDS: &[(u16, u16, Identity)] = &[
    (0x17ef, 0x7203, Identity::Ax88772 { eeprom_mac: true }),
    (0x0b95, 0x772b, Identity::Ax88772 { eeprom_mac: true }),
    (0x0b95, 0x7720, Identity::Ax88772 { eeprom_mac: false }),
    (0x13b1, 0x0018, Identity::Ax88772 { eeprom_mac: false }),
    (0x1557, 0x7720, Identity::Ax88772 { eeprom_mac: false }),
    (0x07d1, 0x3c05, Identity::Ax88772 { eeprom_mac: false }),
    (0x2001, 0x3c05, Identity::Ax88772 { eeprom_mac: false }),
    (0x2001, 0x1a02, Identity::Ax88772 { eeprom_mac: false }),
    (0x05ac, 0x1402, Identity::Ax88772 { eeprom_mac: false }),
    (0x0b95, 0x772a, Identity::Ax88772 { eeprom_mac: false }),
    (0x0db0, 0xa877, Identity::Ax88772 { eeprom_mac: false }),
    (0x0b95, 0x7e2b, Identity::Ax88772 { eeprom_mac: true }),
    (0x066b, 0x20f9, Identity::Ax88772 { eeprom_mac: true }),
    (0x33f7, 0x0004, Identity::Ax88772 { eeprom_mac: true }),
];

pub(in crate::usb::ethernet) fn identify(
    descriptor: &[u8; 18],
    interface: &Interface,
) -> Option<Identity> {
    let vid = u16::from_le_bytes([descriptor[8], descriptor[9]]);
    let pid = u16::from_le_bytes([descriptor[10], descriptor[11]]);
    let found = IDS
        .iter()
        .chain(LEGACY_IDS)
        .find(|entry| (entry.0, entry.1) == (vid, pid))
        .map(|entry| entry.2)?;
    match found {
        Identity::Ax88772 { .. } if interface.class == 0xff => Some(found),
        Identity::Ax88772 { .. } => None,
        _ if (interface.class, interface.subclass, interface.protocol) == (0xff, 0xff, 0) => {
            Some(found)
        }
        _ => None,
    }
}
