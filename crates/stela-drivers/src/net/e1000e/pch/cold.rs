// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Cold, unmanaged PCH MAC/PHY/NVM composition. Linux e1000e at the pinned
//! revision is the register-sequencing reference; no Linux execution ABI is
//! used. LPT is restricted to the exact [`lpt`] cohort and ownership contract.
//! I219 is restricted to the exact [`i219`] and [`mtp`] PCI cohorts. Unlisted MACs, managed
//! firmware and unimplemented low-power variants remain refused.
use super::{Delay, Fault, Identity, Kind, Phy, Register, Registers, nvm};
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

pub mod i219;
pub mod lpt;
pub mod mtp;
pub mod queue;
pub mod spt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    I82579,
    Lpt(lpt::Limits),
    I219(lpt::Limits, i219::Family),
    Mtp(lpt::Limits, mtp::Family, bool),
}
impl Profile {
    fn is_lpt_or_newer(self) -> bool {
        matches!(self, Self::Lpt(_) | Self::I219(_, _) | Self::Mtp(_, _, _))
    }
}

const CTRL: u32 = 0;
const STATUS: u32 = 8;
const STRAP: u32 = 0xc;
const FEXTNVM: u32 = 0x28;
const FEXTNVM3: u32 = 0x3c;
const ICR: u32 = 0xc0;
const IMC: u32 = 0xd8;
const RCTL: u32 = 0x100;
const TCTL: u32 = 0x400;
const EXTCNF_SIZE: u32 = 0xf08;
const PHY_CTRL: u32 = 0xf10;
const KABGTXD: u32 = 0x3004;
const PBA: u32 = 0x1000;
const RX_ALLOCATION_KIB: u32 = 26;
const LEDCTL: u32 = 0xe00;
const MASTER_DISABLE: u32 = 1 << 2;
const MASTER_ENABLED: u32 = 1 << 19;
const RESET: u32 = 1 << 26;
const PHY_RESET: u32 = 1 << 31;
const INIT_DONE: u32 = 1 << 9;
const PHY_RESET_ASSERTED: u32 = 1 << 10;
const PAD_SHORT: u32 = 1 << 3;
const GATE_PHY: u32 = 1 << 7;
const CONFIG_COUNTER: u32 = 3 << 26;
const CONFIG_50MS: u32 = 2 << 26;
const SW_CONFIG: u32 = 1 << 27;
const CONFIG_BASE: u32 = 0x0fff_0000;
const CONFIG_COUNT: u32 = 0x00ff_0000;
const BGSQLBIAS: u32 = 0x50000;
const MDIO_SLOW: u16 = 1 << 10;
const HOST_WAKE: u16 = 1 << 4;
const SMB_ADDRESS: u16 = 0x7f;
const SMB_ENABLE: u16 = 0x280;
const OEM_LPLU: u16 = 4;
const OEM_GBE_DISABLE: u16 = 0x40;
const OEM_RESTART: u16 = 0x400;
const PHY_D0_LPLU: u32 = 2;
const PHY_GBE_DISABLE: u32 = 0x40;
const MSE_THRESHOLD: u16 = 0x084f;
const MSE_LINK_DOWN: u16 = 0x2411;
const LPI_UPDATE_TIMER: u16 = 0x4805;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedDevice(u16),
    Phy(super::Error),
    Nvm(nvm::Error),
    MasterTimeout,
    ResetStuck,
    InitTimeout,
    ResetNotObserved,
    Configuration,
    LtrLimit(u16),
    HostIdentityNotObserved,
    SmbusMode,
    PowerCycleTimeout,
    UlpState,
    DescriptorFlushRequired,
    Dma(crate::block::BlockError),
    QueueStalled,
    Stopped,
    Poisoned,
}

impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Phy(value)
    }
}
impl From<Fault> for Error {
    fn from(value: Fault) -> Self {
        Self::Phy(value.into())
    }
}
impl From<nvm::Error> for Error {
    fn from(value: nvm::Error) -> Self {
        Self::Nvm(value)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PCH Ethernet: {self:?}")
    }
}
impl core::error::Error for Error {}

/// One function, shared only by the two serialized private transports.
/// Neither adapter escapes the controller, so another user cannot reset it or
/// sequence flash while a PHY operation is in progress.
struct Bus<R>(Rc<RefCell<R>>);
impl<R> Clone for Bus<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
// SAFETY: the owning constructor requires one same-function owner and
// complete serialization. Each short borrow performs exactly one real access.
unsafe impl<R: Registers> Registers for Bus<R> {
    fn read32(&mut self, at: u32) -> Result<u32, Fault> {
        self.0.borrow_mut().read32(at)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        self.0.borrow_mut().write32(at, value)
    }
}
// SAFETY: the same owner implements both window contracts;
// private adapters never issue overlapping operations or expose another user.
unsafe impl<R: nvm::Registers> nvm::Registers for Bus<R> {
    fn read_mac32(&mut self, at: u32) -> Result<u32, nvm::Error> {
        self.0.borrow_mut().read_mac32(at)
    }
    fn read16(&mut self, at: u32) -> Result<u16, nvm::Error> {
        self.0.borrow_mut().read16(at)
    }
    fn read32(&mut self, at: u32) -> Result<u32, nvm::Error> {
        self.0.borrow_mut().read32(at)
    }
    fn write16(&mut self, at: u32, value: u16) -> Result<(), nvm::Error> {
        self.0.borrow_mut().write16(at, value)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), nvm::Error> {
        self.0.borrow_mut().write32(at, value)
    }
}

type ConfigRead<R> = fn(&mut R, u16) -> Result<u16, Fault>;

/// One stopped, initialized declared PCH profile. Packet queues are owned by
/// the network backend; this constructor never enables receive or transmit.
pub struct Controller<R: Registers + nvm::Registers, D: Delay + Clone> {
    phy: Phy<Bus<R>, D>,
    nvm: nvm::Nvm<Bus<R>, D>,
    station: crate::net::Mac,
    identity: Identity,
    poisoned: bool,
    profile: Profile,
    config_read: Option<ConfigRead<R>>,
}
impl<R: Registers + nvm::Registers, D: Delay + Clone> Controller<R, D> {
    /// # Safety
    /// `device` is the PCI device ID of an exclusively claimed Intel
    /// Ethernet function (vendor 8086, class 020000). Both register traits on
    /// `io` access the same powered MAC/flash function and keep its
    /// real reservation/mappings. Native DMA, IRQs, firmware/SMM and all other
    /// users are already excluded/drained. This is a new cold reset epoch;
    /// `delay` and its clones provide real minimum elapsed hardware delays.
    /// The initial PHY must be accessible; SMBus/LANPHYPC recovery is not yet
    /// admitted. This does not authorize LPT/SPT by PHY-ID similarity.
    pub unsafe fn new(device: u16, io: R, delay: D) -> Result<Self, Error> {
        if !matches!(device, 0x1502 | 0x1503) {
            return Err(Error::UnsupportedDevice(device));
        }
        let bus = Bus(Rc::new(RefCell::new(io)));
        // SAFETY: the constructor supplies one real same-function reset grant;
        // only these two private serialized adapters keep it.
        let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Pch2, bus.clone(), delay.clone()) }?;
        // SAFETY: exact PCI cohort and the same grant as the NVM.
        let phy = unsafe { Phy::new(Kind::I82579, bus, delay) };
        let mut this = Self {
            phy,
            nvm,
            station: crate::net::Mac([0; 6]),
            identity: Identity {
                kind: Kind::I82579,
                id: 0,
                revision: 0,
            },
            poisoned: false,
            profile: Profile::I82579,
            config_read: None,
        };
        if let Err(error) = this.initialize() {
            this.poisoned = true;
            this.phy.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
    pub fn station(&self) -> crate::net::Mac {
        self.station
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned || self.phy.is_poisoned() || self.nvm.is_poisoned()
    }

    fn read(&mut self, at: u32) -> Result<u32, Error> {
        Ok(self.phy.read_mac(at)?)
    }
    fn write(&mut self, at: u32, value: u32) -> Result<(), Error> {
        Ok(self.phy.write_mac(at, value)?)
    }
    fn qualify(&mut self) -> Result<(), Error> {
        let fw = self.read(super::FWSM)?;
        if fw & super::FW_VALID != 0 {
            return Err(Fault::FirmwareOwned.into());
        }
        if fw & super::RESET_PERMITTED == 0 {
            return Err(Fault::ResetBlocked.into());
        }
        Ok(())
    }
    fn gate(&mut self, enabled: bool) -> Result<(), Error> {
        let value = self.read(super::EXTCNF_CTRL)?;
        self.write(
            super::EXTCNF_CTRL,
            if enabled {
                value | GATE_PHY
            } else {
                value & !GATE_PHY
            },
        )
    }
    fn initialize(&mut self) -> Result<(), Error> {
        self.qualify()?;
        // Refuse inaccessible/foreign PHYs before any recovery pulse. Exact
        // identity is checked again after both reset kinds have completed.
        self.identity = self.phy.identify()?;
        self.validate_nvm()?;
        self.station = self.nvm.station()?;
        self.gate(true)?;
        self.phy_reset()?;
        self.configuration_done()?;
        self.qualify()?;
        self.phy.delay.delay(10_000);
        self.gate(false)?;
        self.identity = self.phy.identify()?;
        // e1000e_reset sets the ordinary-MTU PCH2 allocation before invoking
        // reset_hw. Hardware derives the complementary TX allocation.
        self.write(PBA, RX_ALLOCATION_KIB)?;
        self.global_reset()?;
        self.configuration_done()?;
        self.post_reset()?;
        self.write(IMC, u32::MAX)?;
        self.read(ICR)?;
        let bias = self.read(KABGTXD)?;
        self.write(KABGTXD, bias | BGSQLBIAS)?;
        self.identity = self.phy.identify()?;
        Ok(())
    }
    fn phy_reset(&mut self) -> Result<(), Error> {
        self.phy.transaction(|p| {
            let ctrl = p.read_mac(CTRL)?;
            p.write_mac(CTRL, ctrl | PHY_RESET)?;
            p.read_mac(STATUS)?;
            p.delay.delay(100);
            p.write_mac(CTRL, ctrl)?;
            p.read_mac(STATUS)?;
            p.delay.delay(150);
            Ok(())
        })?;
        Ok(())
    }
    fn global_reset(&mut self) -> Result<(), Error> {
        self.qualify()?;
        let ctrl = self.read(CTRL)?;
        self.write(CTRL, ctrl | MASTER_DISABLE)?;
        let mut drained = false;
        for _ in 0..800 {
            if self.read(STATUS)? & MASTER_ENABLED == 0 {
                drained = true;
                break;
            }
            self.phy.delay.delay(100);
        }
        if !drained {
            return Err(Error::MasterTimeout);
        }
        self.write(IMC, u32::MAX)?;
        self.write(RCTL, 0)?;
        self.write(TCTL, PAD_SHORT)?;
        self.read(STATUS)?;
        self.phy.delay.delay(10_000);
        let ctrl = self.read(CTRL)? | PHY_RESET;
        self.qualify()?;
        if !self.profile.is_lpt_or_newer() {
            self.gate(true)?;
        }
        self.phy.acquire()?;
        // Global reset invalidates SWFLAG. Do not call transaction/release:
        // it would access a reset-invalid semaphore. Even an uncertain failed
        // store must observe the full no-register-access quiet interval.
        let reset = self.phy.write_mac(CTRL, ctrl | RESET);
        self.phy.delay.delay(20_000);
        reset?;
        if self.read(CTRL)? & RESET != 0 {
            return Err(Error::ResetStuck);
        }
        if !self.profile.is_lpt_or_newer() {
            let value = self.read(FEXTNVM3)?;
            self.write(FEXTNVM3, (value & !CONFIG_COUNTER) | CONFIG_50MS)?;
        }
        Ok(())
    }
    fn validate_nvm(&mut self) -> Result<(), Error> {
        if self.mtp_family().is_some() {
            self.nvm.validate_i219(nvm::I219Validation::Adp)?;
            return Ok(());
        }
        match self.i219_family() {
            Some(i219::Family::Tgp) => self.nvm.validate_i219(nvm::I219Validation::Tgp)?,
            Some(i219::Family::Adp) => self.nvm.validate_i219(nvm::I219Validation::Adp)?,
            _ => self.nvm.validate()?,
        }
        Ok(())
    }
    fn configuration_done(&mut self) -> Result<(), Error> {
        self.phy.delay.delay(10_000);
        let mut ready = false;
        for _ in 0..1500 {
            let status = self.read(STATUS)?;
            self.phy.delay.delay(100);
            if status & INIT_DONE != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(Error::InitTimeout);
        }
        let status = self.read(STATUS)?;
        self.write(STATUS, status & !INIT_DONE)?;
        let status = self.read(STATUS)?;
        if status & PHY_RESET_ASSERTED == 0 {
            return Err(Error::ResetNotObserved);
        }
        self.write(STATUS, status & !PHY_RESET_ASSERTED)?;
        // The flash itself is immutable in this exclusive epoch. Validate its
        // selected bank/checksum again after reset; no erased-bank fallback.
        self.validate_nvm()?;
        Ok(())
    }
    fn modify(&mut self, page: u16, index: u16, clear: u16, set: u16) -> Result<(), Error> {
        let reg = Register::new(page, index)?;
        let value = self.phy.read(reg)?;
        Ok(self.phy.write(reg, (value & !clear) | set)?)
    }
    fn emi(p: &mut Phy<Bus<R>, D>, at: u16, data: u16) -> Result<(), Fault> {
        p.access(Register { page: 0, index: 16 }, Some(at))?;
        p.access(Register { page: 0, index: 17 }, Some(data))?;
        Ok(())
    }
    fn post_reset(&mut self) -> Result<(), Error> {
        self.qualify()?;
        self.phy.delay.delay(10_000);
        if !self.profile.is_lpt_or_newer() {
            self.modify(769, 16, 0, MDIO_SLOW)?;
            self.phy.transaction(|p| {
                Self::emi(p, MSE_THRESHOLD, 0x34)?;
                Self::emi(p, MSE_LINK_DOWN, 5)
            })?;
        }
        self.modify(769, 17, HOST_WAKE, 0)?;
        self.lcd()?;
        self.oem()?;
        if !self.profile.is_lpt_or_newer() {
            self.qualify()?;
            self.phy.delay.delay(10_000);
            self.gate(false)?;
            self.phy
                .transaction(|p| Self::emi(p, LPI_UPDATE_TIMER, 0x1387))?;
        }
        Ok(())
    }
    fn lcd(&mut self) -> Result<(), Error> {
        if self.read(FEXTNVM)? & SW_CONFIG == 0 {
            return Ok(());
        }
        let control = self.read(super::EXTCNF_CTRL)?;
        let count = (self.read(EXTCNF_SIZE)? & CONFIG_COUNT) >> 16;
        if count == 0 {
            return Ok(());
        }
        let base = ((control & CONFIG_BASE) >> 16) * 2;
        let length = count * 2;
        if base
            .checked_add(length)
            .is_none_or(|end| end > self.nvm.geometry().bank_words.min(2048))
        {
            return Err(Error::Configuration);
        }
        let mut words = Vec::new();
        words
            .try_reserve_exact(length as usize)
            .map_err(|_| nvm::Error::Allocation)?;
        words.resize(length as usize, 0);
        self.nvm.read(base as u16, &mut words)?;
        // Prevalidate the complete immutable LCD script before its first PHY
        // write. This strengthens donor streaming error behavior.
        let mut page = 0u16;
        for pair in words.as_chunks::<2>().0 {
            if pair[1] == 31 {
                if pair[0] & 31 != 0 {
                    return Err(Error::Configuration);
                }
                page = pair[0] >> 5;
            } else {
                Register::new(page, pair[1] & 31)?;
            }
        }
        let strap = self.read(STRAP)?;
        let led = self.read(LEDCTL)? as u16;
        let lpt = self.profile.is_lpt_or_newer();
        let frequency = ((strap >> 12) & 3) as u16;
        if lpt && frequency == 0 {
            return Err(Error::Configuration);
        }
        self.phy.transaction(|p| {
            let smb = Register {
                page: 768,
                index: 26,
            };
            let mut value = p.access(smb, None)?;
            if lpt {
                let frequency = frequency - 1;
                value = (value & !0x1100) | ((frequency & 1) << 8) | ((frequency & 2) << 11);
            }
            p.access(
                smb,
                Some((value & !SMB_ADDRESS) | ((strap >> 17) as u16 & SMB_ADDRESS) | SMB_ENABLE),
            )?;
            p.access(
                Register {
                    page: 768,
                    index: 30,
                },
                Some(led),
            )?;
            let mut page = 0;
            for pair in words.as_chunks::<2>().0 {
                if pair[1] == 31 {
                    page = pair[0] >> 5;
                } else {
                    p.access(
                        Register {
                            page,
                            index: pair[1] & 31,
                        },
                        Some(pair[0]),
                    )?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }
    fn oem(&mut self) -> Result<(), Error> {
        // Source D0 policy: apply MAC-strapped LPLU/Gbe-disable bits.
        // Never manufacture a faster mode by ignoring an OEM restriction.
        self.phy.transaction(|p| {
            if p.read_mac(FEXTNVM)? & SW_CONFIG == 0 {
                return Ok(());
            }
            let control = p.read_mac(PHY_CTRL)?;
            let reg = Register {
                page: 768,
                index: 25,
            };
            let mut value = p.access(reg, None)? & !(OEM_LPLU | OEM_GBE_DISABLE);
            if control & PHY_D0_LPLU != 0 {
                value |= OEM_LPLU;
            }
            if control & PHY_GBE_DISABLE != 0 {
                value |= OEM_GBE_DISABLE;
            }
            let fw = p.read_mac(super::FWSM)?;
            if fw & super::FW_VALID != 0 {
                return Err(Fault::FirmwareOwned);
            }
            if fw & super::RESET_PERMITTED == 0 {
                return Err(Fault::ResetBlocked);
            }
            p.access(reg, Some(value | OEM_RESTART))?;
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
