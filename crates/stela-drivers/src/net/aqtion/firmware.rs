// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014-2019 aQuantia Corporation
// Copyright (C) 2019-2020 Marvell International Ltd.
use super::{Error, Generation, Hardware, Mac, Profile, Registers, Result, Timer, registers as f};
const IN: usize = 0x12000;
const OUT: usize = 0x13000;
const LINK_DROP: u32 = 1 << 22;
#[derive(Clone, Copy)]
pub(super) struct Firmware {
    pub version: u32,
    pub mac: Mac,
    pub l2_base: u8,
    pub art_base: u8,
    pub art_count: u8,
}
impl<R: Registers, T: Timer> Hardware<R, T> {
    pub(super) fn reset(&self, profile: Profile) -> Result<()> {
        if profile.generation == Generation::Antigua {
            self.write(0xf08, 1)?;
            self.write(0x3040, 1)?;
            self.wait(0x3040, 10, 200000, |v| v & (1 << 24) != 0)?;
            let mut status = 0;
            for _ in 0..=200000 {
                status = self.read(0x3040)?;
                if status & 0xb8000000 != 0 || self.read(0xf00)? & 1 != 0 {
                    break;
                }
                self.timer.delay(10);
            }
            if status & 0x38000000 != 0 {
                return Err(Error::Firmware { status });
            }
            if self.read(0xf00)? & 1 != 0 {
                return Err(Error::Unsupported(
                    "AQtion Antigua has no NVM firmware; host download unsupported",
                ));
            }
            if status & (1 << 31) == 0 {
                return Err(Error::Timeout { register: 0x3040 });
            }
            return Ok(());
        }
        let ver = self.read(0x18)?;
        if ver >> 24 == 1 {
            return Err(Error::Unsupported("AQtion firmware 1.x MPI/RPC"));
        }
        // B1 register identity, independent of the PCI revision wildcard.
        if self.read(0x1c)? & 15 != 10 {
            return Err(Error::Unsupported(
                "AQtion non-B1 silicon requires its own reset/descriptor profile",
            ));
        }
        let mut boot = 0;
        let mut started = false;
        for _ in 0..1000 {
            let flb = self.read(0x704)?;
            boot = self.read(0x388)?;
            if flb != 0x06000000 || boot != 0 {
                started = true;
                break;
            }
        }
        if !started {
            return Err(Error::Unsupported("AQtion neither RBL nor FLB started"));
        }
        if ver >> 24 == 4 {
            let timeout = self.read(0x348)?.min(3000) as u64 * 1000;
            if timeout != 0 {
                // Donor logs timeout and continues; Stela requires actual lock
                // acquisition instead of claiming reset synchronization.
                self.wait(0x3ac, 1, timeout, |v| v == 1)?;
                self.wait(0x3b0, 1, timeout, |v| v == 1)?;
            }
        }
        self.write(0x404, 0x40e1)?;
        if boot != 0 {
            self.write(0x3a0, 1)?;
            self.write(0x32a8, 0)?;
            self.write(0x388, 0xdead)?;
            let spi = self.read(0x53c)?;
            self.write(0x53c, spi | 0x10)?;
            self.global_reset()?;
            self.write(0x404, 0x40e0)?;
            let status = self.wait(0x388, 10000, 10_000_000, |v| {
                v & 0xffff != 0 && v & 0xffff != 0xdead
            })? & 0xffff;
            if status == 0xf1a7 {
                return Err(Error::Unsupported(
                    "AQtion RBL has no NVM firmware; host download unsupported",
                ));
            }
        } else {
            self.timer.delay(50_000);
            let spi = self.read(0x53c)?;
            self.write(0x53c, spi | 0x10)?;
            self.write(0, (self.read(0)? & 0xbfff) | 0x8000)?;
            self.write(0x404, 0x80e0)?;
            self.write(0x32a8, 0)?;
            self.write(0x520, 1)?;
            let spi = self.read(0x53c)?;
            self.write(0x53c, spi | 0x10)?;
            self.timer.delay(10_000);
            self.write(0x53c, spi & !0x10)?;
            self.write(0x404, 0x180e0)?;
            self.wait(0x704, 10000, 10_000_000, |v| v & 0x10 != 0)?;
            self.write(0x404, 0x80e0)?;
            self.timer.delay(50_000);
            self.write(0x3a0, 1)?;
            self.global_reset()?;
        }
        self.wait(0x18, 10000, 10_000_000, |v| v != 0)?;
        self.timer.delay(15_000);
        Ok(())
    }
    fn global_reset(&self) -> Result<()> {
        self.set(f::RX_RX_REG_RES_DIS_SET, 0, 0)?;
        self.set(f::TX_TX_REG_RES_DIS_SET, 0, 0)?;
        self.write(0x4000, self.read(0x4000)? & !(1 << 29))?;
        self.write(0, (self.read(0)? & 0xffffbfff) | 0x8000)
    }
    fn ram_read(&self, address: u32, words: &mut [u32]) -> Result<()> {
        if address == 0
            || !address.is_multiple_of(4)
            || address.checked_add((words.len() * 4) as u32).is_none()
        {
            return Err(Error::Unsupported("AQtion firmware RAM span"));
        }
        // Semaphore is read-to-acquire. Never forcibly clear an unknown owner's
        // live lock when the bounded attempt fails.
        self.wait(0x3a8, 1, 10000, |v| v == 1)?;
        let result = (|| {
            self.write(0x208, address)?;
            let mut expected = address;
            for word in words {
                self.write(0x200, 0x8000)?;
                self.wait(0x208, 1, 1000, |v| v != expected)?;
                *word = self.read(0x20c)?;
                expected += 4;
            }
            Ok(())
        })();
        let release = self.write(0x3a8, 1);
        result.and(release)
    }
    fn snapshot(&self, offset: usize, words: &mut [u32]) -> Result<()> {
        for _ in 0..1000 {
            let before = self.read(OUT)?;
            if before as u16 != (before >> 16) as u16 {
                self.timer.delay(1000);
                continue;
            }
            for (i, w) in words.iter_mut().enumerate() {
                *w = self.read(OUT + offset + i * 4)?;
            }
            let after = self.read(OUT)?;
            if before == after && after as u16 == (after >> 16) as u16 {
                return Ok(());
            }
        }
        Err(Error::Timeout { register: OUT })
    }
    fn acknowledge(&self, timeout: u64) -> Result<()> {
        self.write(0xe00, self.read(0xe00)? | 1)?;
        self.wait(0xe04, 100, timeout, |v| v & 1 == 0)?;
        Ok(())
    }
    pub(super) fn firmware(&self, profile: Profile) -> Result<Firmware> {
        let mut fw = Firmware {
            version: 0,
            mac: Mac::default(),
            l2_base: 0,
            art_base: 0,
            art_count: 0,
        };
        if profile.generation == Generation::Antigua {
            let mut version = [0; 4];
            self.snapshot(4, &mut version)?;
            if version[0] & 0xff != 1 || version[3] & 15 > 1 {
                return Err(Error::Unsupported(
                    "AQtion Antigua firmware/interface version",
                ));
            }
            fw.version =
                ((version[0] & 0xff) << 24) | ((version[0] & 0xff00) << 8) | (version[0] >> 16);
            let mut caps = [0; 3];
            self.snapshot(0x774, &mut caps)?;
            fw.l2_base = (caps[0] & 0x3f) as u8;
            let l2_count = (caps[0] >> 8) & 255;
            let base = ((caps[2] >> 16) & 255) * 8;
            let count = if caps[2] >> 24 == 0 {
                128
            } else {
                (caps[2] >> 24) * 8
            };
            if fw.l2_base >= 38
                || l2_count == 0
                || u32::from(fw.l2_base) + l2_count > 38
                || base + count > 128
                || count < 10
            {
                return Err(Error::Unsupported(
                    "AQtion Antigua firmware filter allocation",
                ));
            }
            fw.art_base = base as u8;
            fw.art_count = count as u8;
            let low = self.read(IN + 8)?.to_le_bytes();
            let high = self.read(IN + 12)?.to_le_bytes();
            fw.mac = Mac([low[0], low[1], low[2], low[3], high[0], high[1]]);
            self.write(IN + 16, (self.read(IN + 16)? & !15) | 1)?;
            self.write(IN, 16352)?;
            self.acknowledge(5_000_000)?;
        } else {
            fw.version = self.read(0x18)?;
            if !(2..=4).contains(&(fw.version >> 24)) {
                return Err(Error::Unsupported("AQtion firmware 2.x/3.x/4.x required"));
            }
            self.wait(0x360, 1000, 10000, |v| v != 0)?;
            self.wait(0x334, 1000, 100000, |v| v != 0)?;
            let efuse = self.read(0x364)?;
            let address = efuse
                .checked_add(160)
                .filter(|_| efuse != 0)
                .ok_or(Error::Unsupported("AQtion no programmed efuse address"))?;
            let mut mac = [0; 2];
            self.ram_read(address, &mut mac)?;
            let low = mac[0].to_be_bytes();
            let high = mac[1].to_be_bytes();
            fw.mac = Mac([low[0], low[1], low[2], low[3], high[0], high[1]]);
        }
        if fw.mac.is_multicast() || fw.mac.0 == [0; 6] {
            return Err(Error::Unsupported(
                "AQtion invalid permanent station address",
            ));
        }
        Ok(fw)
    }
    pub(super) fn firmware_link(&self, profile: Profile, _fw: Firmware, up: bool) -> Result<()> {
        if profile.generation == Generation::Antigua {
            // Explicit full-duplex rates, EEE/pause/loopbacks disabled.
            self.write(IN + 24, if up { profile.rates | 1 } else { 0 })?;
            self.acknowledge(100000)?;
            if !up {
                self.write(IN + 16, (self.read(IN + 16)? & !15) | 4)?;
                self.acknowledge(100000)?;
            }
        } else {
            self.write(0x368, if up { profile.rates } else { 0 })?;
            let mut control = self.read(0x36c)?;
            control &= !((3 << 3) | (15 << 8) | (3 << 23) | (3 << 26));
            if up {
                control &= !LINK_DROP;
            } else {
                control |= LINK_DROP;
            }
            self.write(0x36c, control)?;
            // Donor's ordinary set-state is asynchronous; require actual
            // state acknowledgement before publishing/releasing the link.
            self.wait(0x374, 10, 100000, |v| v & LINK_DROP == control & LINK_DROP)?;
        }
        Ok(())
    }
    pub(super) fn link(&self, profile: Profile, _fw: Firmware) -> Result<bool> {
        self.read(0x10)?; // donor's alive-check register
        if profile.generation == Generation::Antigua {
            let status = self.read(OUT + 20)?;
            let rate = (status >> 4) & 15;
            if rate > 6 {
                return Err(Error::Firmware { status });
            }
            Ok(rate != 0 && status & (1 << 11) != 0)
        } else {
            let status = self.read(0x370)?;
            Ok(status & profile.rates != 0)
        }
    }
}
