// SPDX-License-Identifier: GPL-2.0-only
// Native adaptation of sdhci-pci-core.c, Copyright 2005-2008 Pierre Ossman.
//! Exact PCI identities select source-required host operating sequences.

const ENE: u16 = 0x1524;
const CB712_SD: u16 = 0x0550;
const CB712_SD_2: u16 = 0x0551;
const CB714_SD: u16 = 0x0750;
const CB714_SD_2: u16 = 0x0751;
const INTEL: u16 = 0x8086;
const QRK_SD: u16 = 0x08a7;
const MRST_SD0: u16 = 0x0807;
const MRST_SD1: u16 = 0x0808;
const MRST_SD2: u16 = 0x084f;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Profile {
    Standard,
    Ene712,
    Ene714,
    IntelQuark,
    IntelMrst0,
    IntelMrstOther,
}
impl Profile {
    pub fn select(vendor: u16, device: u16) -> Self {
        match (vendor, device) {
            (ENE, CB712_SD | CB712_SD_2) => Self::Ene712,
            (ENE, CB714_SD | CB714_SD_2) => Self::Ene714,
            (INTEL, QRK_SD) => Self::IntelQuark,
            (INTEL, MRST_SD0) => Self::IntelMrst0,
            (INTEL, MRST_SD1 | MRST_SD2) => Self::IntelMrstOther,
            _ => Self::Standard,
        }
    }
    pub fn single_power_write(self) -> bool {
        matches!(self, Self::Ene712 | Self::Ene714)
    }
    pub fn disable_adma(self) -> bool {
        matches!(
            self,
            Self::Ene712 | Self::Ene714 | Self::IntelMrst0 | Self::IntelMrstOther
        )
    }
    pub fn reset_after_ios(self) -> bool {
        self == Self::Ene714
    }
    pub fn no_high_speed_bit(self) -> bool {
        matches!(
            self,
            Self::IntelQuark | Self::IntelMrst0 | Self::IntelMrstOther
        )
    }
    pub fn slots(self, reported: u8) -> u8 {
        // MRST HC1/2 expose unused, broken SDIO3/5 slot entries.
        if self == Self::IntelMrstOther {
            1
        } else {
            reported
        }
    }
    pub fn mmc_width(self) -> u8 {
        // mrst_hc_probe_slot declares this platform's eight physical pins.
        // Controller CAP_8BIT alone is never wiring authority.
        if self == Self::IntelMrst0 { 8 } else { 4 }
    }
}
