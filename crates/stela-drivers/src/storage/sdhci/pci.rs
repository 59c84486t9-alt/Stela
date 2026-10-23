// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of sdhci-pci-core.c, Copyright 2005-2008 Pierre Ossman.
//! Exact PCI identities select source-required host operating sequences.

const ENE: u16 = 0x1524;
const CB712_SD: u16 = 0x0550;
const CB712_SD_2: u16 = 0x0551;
const CB714_SD: u16 = 0x0750;
const CB714_SD_2: u16 = 0x0751;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Profile {
    Standard,
    Ene712,
    Ene714,
}
impl Profile {
    pub fn select(vendor: u16, device: u16) -> Self {
        match (vendor, device) {
            (ENE, CB712_SD | CB712_SD_2) => Self::Ene712,
            (ENE, CB714_SD | CB714_SD_2) => Self::Ene714,
            _ => Self::Standard,
        }
    }
    pub fn single_power_write(self) -> bool {
        self != Self::Standard
    }
    pub fn broken_dma(self) -> bool {
        self != Self::Standard
    }
    pub fn reset_after_ios(self) -> bool {
        self == Self::Ene714
    }
}
