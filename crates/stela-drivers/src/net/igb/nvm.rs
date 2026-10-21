// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2007 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Read-only NVM validation, alternate station addresses and iNVM PLL erratum.
use super::{
    Chip, Mac, RegisterIo, Timer,
    hardware::{Hardware, PciCapabilities},
    registers::*,
};
use crate::{block::BlockError, bus::pci::ConfigSpace};

pub(super) fn station(low: u32, high: u32) -> Option<Mac> {
    let [a, b, c, d] = low.to_le_bytes();
    let [e, f, _, _] = high.to_le_bytes();
    let mac = Mac([a, b, c, d, e, f]);
    (high & (1 << 31) != 0 && mac.0 != [0; 6] && !mac.is_multicast()).then_some(mac)
}

impl<R: RegisterIo, T: Timer> Hardware<'_, R, T> {
    fn eerd(&self, word: u16) -> Result<u16, BlockError> {
        let words = 1u32 << (6 + ((self.io.read(EECD) >> 11) & 15)).min(15);
        // EERD's address is 14 bits; larger EEPROM regions need SPI access.
        // Every checksum region and ordinary MAC lies below this boundary.
        if u32::from(word) >= words || word >= 0x4000 {
            return Err(BlockError::Unsupported(
                "igb NVM word outside EERD address space",
            ));
        }
        self.io.write(EERD, u32::from(word) << 2 | 1);
        if !self.clock.wait(100_000, || self.io.read(EERD) & 2 != 0) {
            return Err(BlockError::Timeout);
        }
        Ok((self.io.read(EERD) >> 16) as u16)
    }

    pub(super) fn invm_word(&self, word: u8) -> Option<u16> {
        let mut index = 0;
        while index < INVM_WORDS {
            let record = self.io.read(INVM + index * 4);
            match record & 7 {
                0 => return None,
                1 if ((record >> 9) & 0x7f) as u8 == word => return Some((record >> 16) as u16),
                2 => index += 1, // CSR autoload has one payload DWORD
                4 => index += 8, // RSA-key SHA-256 has eight payload DWORDs
                _ => {}
            }
            index += 1;
        }
        None
    }

    pub(super) fn check_nvm(&mut self) -> Result<(), BlockError> {
        if self.chip.modern() && self.io.read(EECD) & EECD_FLASH == 0 {
            for word in 0..3 {
                self.invm_word(word).ok_or(BlockError::Unsupported(
                    "igb iNVM has no programmed MAC address",
                ))?;
            }
            return Ok(());
        }
        if !self.chip.modern() && self.io.read(EECD) & EECD_PRESENT == 0 {
            // Linux's EEPROM-less board/IGP3 scripts are not a promise that
            // a controller with no board configuration has a usable MAC.
            return Err(BlockError::Unsupported("igb requires programmed EEPROM"));
        }
        self.synchronized(NVM_EEPROM_SYNC, |hardware| {
            let regions = match hardware.chip {
                Chip::I350 => 4,
                Chip::I82580 if hardware.eerd(3)? & 0x8000 != 0 => 4,
                _ => 1,
            };
            for port in 0..regions {
                let base = if port == 0 { 0 } else { 0x40 + 0x40 * port };
                let mut checksum = 0u16;
                for word in 0..=NVM_CHECKSUM {
                    checksum = checksum.wrapping_add(hardware.eerd(base + word)?);
                }
                if checksum != NVM_SUM {
                    return Err(BlockError::Device {
                        status: u32::from(checksum),
                    });
                }
            }
            Ok(())
        })
    }

    pub(super) fn station_address(&mut self) -> Result<Mac, BlockError> {
        if self.chip.modern() && self.io.read(EECD) & EECD_FLASH == 0 {
            let mut bytes = [0; 6];
            for word in 0..3 {
                bytes[word * 2..word * 2 + 2].copy_from_slice(
                    &self
                        .invm_word(word as u8)
                        .ok_or(BlockError::Unsupported("igb missing iNVM MAC word"))?
                        .to_le_bytes(),
                );
            }
            let [a, b, c, d, e, f] = bytes;
            return station(
                u32::from_le_bytes([a, b, c, d]),
                u32::from(u16::from_le_bytes([e, f])) | (1 << 31),
            )
            .ok_or(BlockError::Unsupported("igb invalid iNVM MAC address"));
        }
        if self.chip.old_reset() {
            let alternate = self.synchronized(NVM_EEPROM_SYNC, |hardware| {
                let pointer = hardware.eerd(0x37)?;
                if pointer == 0 || pointer == u16::MAX {
                    return Ok(None);
                }
                let pointer = pointer.checked_add(u16::from(hardware.port) * 3).ok_or(
                    BlockError::Unsupported("igb alternate MAC pointer overflow"),
                )?;
                let mut bytes = [0; 6];
                for index in 0..3 {
                    let offset =
                        pointer
                            .checked_add(index as u16)
                            .ok_or(BlockError::Unsupported(
                                "igb alternate MAC pointer overflow",
                            ))?;
                    bytes[index * 2..index * 2 + 2]
                        .copy_from_slice(&hardware.eerd(offset)?.to_le_bytes());
                }
                let mac = Mac(bytes);
                if mac.0 == [0; 6] {
                    return Err(BlockError::Unsupported("igb zero alternate MAC address"));
                }
                Ok((!mac.is_multicast()).then_some(mac))
            })?;
            if let Some(mac) = alternate {
                return Ok(mac);
            }
        }
        station(self.io.read(RAL), self.io.read(RAH)).ok_or(BlockError::Unsupported(
            "igb has no valid autoloaded station address",
        ))
    }

    pub(super) fn pll_workaround(
        &mut self,
        config: &mut impl ConfigSpace,
        capabilities: PciCapabilities,
    ) -> Result<(), BlockError> {
        let pmcsr = capabilities.power.ok_or(BlockError::Unsupported(
            "flashless igb PLL recovery requires PCI power management",
        ))? + 4;
        let power = config.read16(pmcsr) & !(3 | (1 << 15)); // do not acknowledge PME_Status (W1C)
        let mdio = self.io.read(MDICNFG);
        let wake = self.io.read(WUC);
        let control = self.io.read(CTRL);
        let extended = self.io.read(CTRL_EXT);
        self.io.write(MDICNFG, mdio & !(1 << 31));
        let autoload = self.invm_word(0x0a).unwrap_or(0x202f);
        let result = (|| {
            self.write_phy(PHY_PAGE_M88, 0xfc)?;
            for _ in 0..5 {
                if self.read_phy(14)? & 0xff != 0xff {
                    return Ok(());
                }
                self.io.write(CTRL, control | CTRL_PHY_RST);
                self.io.write(CTRL_EXT, extended | CTRL_EXT_PHY_POWER);
                self.io.write(WUC, 0);
                self.io
                    .write(EEARBC, (0x0a << 4) | u32::from(autoload | 0x10) << 16);
                config.write16(pmcsr, power | 3);
                if config.read16(pmcsr) & 3 != 3 {
                    return Err(BlockError::Unsupported("igb PLL D3 transition refused"));
                }
                self.clock.delay(1_000);
                config.write16(pmcsr, power);
                if config.read16(pmcsr) & 3 != 0 {
                    return Err(BlockError::Unsupported("igb PLL D0 transition refused"));
                }
                self.clock.delay(1_000);
                self.io
                    .write(EEARBC, (0x0a << 4) | u32::from(autoload) << 16);
                self.io.write(WUC, wake);
            }
            Err(BlockError::Unsupported(
                "igb iNVM PLL frequency did not lock",
            ))
        })();
        // Always attempt to leave D0 before restoring MMIO/MDIO state.
        config.write16(pmcsr, power);
        if config.read16(pmcsr) & 3 != 0 {
            return Err(BlockError::Unsupported(
                "igb PLL recovery left controller outside D0",
            ));
        }
        self.io.write(CTRL, control);
        self.io.write(CTRL_EXT, extended);
        self.io
            .write(EEARBC, (0x0a << 4) | u32::from(autoload) << 16);
        self.io.write(WUC, wake);
        let page = self.write_phy(PHY_PAGE_M88, 0);
        self.io.write(MDICNFG, mdio);
        result.and(page)
    }
}
