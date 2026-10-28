// SPDX-License-Identifier: GPL-2.0-only
// Exact source SPI PCI profiles: intel-lpss-pci.c at
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8. Copyright (C) 2015 Intel.
//! Intel LPSS SPI PCI profiles from intel-lpss-pci.c.
use super::{Error, Identity, pxa2xx};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    device: u16,
    root: u32,
    family: pxa2xx::Profile,
}
impl Profile {
    pub fn select(identity: Identity) -> Result<Self, Error> {
        if identity.vendor != 0x8086 {
            return Err(Error::Configuration);
        }
        let (root, family) = match identity.device {
            0x02aa | 0x02ab | 0x02fb | 0x06aa | 0x06ab | 0x06fb | 0x34aa | 0x34ab | 0x34fb
            | 0x4daa | 0x4dab | 0x4dfb | 0x9daa | 0x9dab | 0x9dfb | 0xa0aa | 0xa0ab | 0xa0de
            | 0xa0df | 0xa0fb | 0xa0fd | 0xa0fe | 0xa32a | 0xa32b | 0xa37b => {
                (120_000_000, pxa2xx::Profile::CannonLake)
            }
            0x0ac2 | 0x0ac4 | 0x0ac6 | 0x1ac2 | 0x1ac4 | 0x1ac6 | 0x31c2 | 0x31c4 | 0x31c6
            | 0x4b2a | 0x4b2b | 0x4b37 | 0x5ac2 | 0x5ac4 | 0x5ac6 | 0x98aa => {
                (100_000_000, pxa2xx::Profile::Broxton)
            }
            0x43aa | 0x43ab | 0x43fb | 0x43fd | 0x4d27 | 0x4d30 | 0x4d46 | 0x51aa | 0x51ab
            | 0x51fb | 0x54aa | 0x54ab | 0x54fb | 0x6e2a | 0x6e2b | 0x6e5e | 0x7727 | 0x7730
            | 0x7746 | 0x7a2a | 0x7a2b | 0x7a79 | 0x7a7b | 0x7aaa | 0x7aab | 0x7af9 | 0x7afb
            | 0x7e27 | 0x7e30 | 0x7e46 | 0x7f2a | 0x7f2b | 0x7f5e | 0x7f5f | 0xa827 | 0xa830
            | 0xa846 | 0xd327 | 0xd330 | 0xd347 | 0xe327 | 0xe330 | 0xe346 | 0xe427 | 0xe430
            | 0xe446 => (100_000_000, pxa2xx::Profile::CannonLake),
            0x9d29 | 0x9d2a | 0xa129 | 0xa12a | 0xa2a9 | 0xa2aa | 0xa3a9 | 0xa3aa => {
                (120_000_000, pxa2xx::Profile::Sunrisepoint)
            }
            _ => return Err(Error::Configuration),
        };
        Ok(Self {
            device: identity.device,
            root,
            family,
        })
    }
    pub fn device(self) -> u16 {
        self.device
    }
    pub fn root_clock_hz(self) -> u32 {
        self.root
    }
    pub fn family(self) -> pxa2xx::Profile {
        self.family
    }
}
