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

/// One actual function, shared only by the two serialized private transports.
/// Neither adapter escapes the controller, so another user cannot reset it or
/// sequence flash while a PHY operation is in progress.
struct Bus<R>(Rc<RefCell<R>>);
impl<R> Clone for Bus<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
// SAFETY: the owning constructor requires one actual same-function owner and
// complete serialization. Each short borrow performs exactly one real access.
unsafe impl<R: Registers> Registers for Bus<R> {
    fn read32(&mut self, at: u32) -> Result<u32, Fault> {
        self.0.borrow_mut().read32(at)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        self.0.borrow_mut().write32(at, value)
    }
}
// SAFETY: the same retained owner implements both actual window contracts;
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
    /// `device` is the actual PCI device ID of an exclusively claimed Intel
    /// Ethernet function (vendor 8086, class 020000). Both register traits on
    /// `io` access the same actual powered MAC/flash function and retain its
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
        // only these two private serialized adapters retain it.
        let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Pch2, bus.clone(), delay.clone()) }?;
        // SAFETY: exact PCI cohort and the same retained grant as the NVM.
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
        // write. This intentionally strengthens donor streaming error behavior.
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
        // Source D0 policy: apply actual MAC-strapped LPLU/Gbe-disable bits.
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
mod tests {
    extern crate std;
    use super::*;
    use alloc::{collections::BTreeMap, sync::Arc, vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    pub(super) struct Model {
        pub(super) mac: BTreeMap<u32, u32>,
        pub(super) config: BTreeMap<u16, u16>,
        pub(super) spt: bool,
        pub(super) power_busy: usize,
        pub(super) power_pending: bool,
        pub(super) power_stuck: bool,
        pub(super) smb_hidden_after_power: bool,
        pub(super) smb_hidden: bool,
        pub(super) smb_stuck: bool,
        pub(super) ulp_stuck: bool,
        pub(super) flush_after_tx: bool,
        pub(super) flush_after_rx: bool,
        pub(super) phy: BTreeMap<(u8, u16, u16), u16>,
        pub(super) emi: BTreeMap<u16, u16>,
        pub(super) kmrn: BTreeMap<u8, u16>,
        pub(super) words: Vec<u16>,
        pub(super) operations: Vec<[u32; 3]>,
        pub(super) accesses: usize,
        pub(super) fail_at: Option<usize>,
        pub(super) fail_with: Fault,
        pub(super) page: u16,
        pub(super) emi_address: u16,
        pub(super) flash_address: u32,
        pub(super) flash_control: u16,
        pub(super) time: u64,
        pub(super) quiet_until: u64,
        pub(super) master_busy: usize,
        pub(super) mdic_failures: usize,
        pub(super) mdic_attempts: usize,
        pub(super) mdic_kind: u8,
        pub(super) init_missing: bool,
        pub(super) reset_missing: bool,
        pub(super) reset_stuck: bool,
    }
    impl Model {
        fn ready() -> Self {
            let mut words = vec![0; 4096];
            words[0] = 0x1102;
            words[1] = 0x3322;
            words[2] = 0x5544;
            words[0x13] = 0x8000;
            words[0x19] = 0x40;
            let sum = words[..63].iter().copied().fold(0u16, u16::wrapping_add);
            words[63] = 0xbabau16.wrapping_sub(sum);
            // LCD: page769, indexed data; then page772 and another value.
            words[128..136].copy_from_slice(&[769 << 5, 31, 0x125a, 20, 772 << 5, 31, 0x5601, 21]);
            Self {
                mac: BTreeMap::from([
                    (super::super::FWSM, super::super::RESET_PERMITTED),
                    (super::super::EXTCNF_CTRL, 64 << 16),
                    (EXTCNF_SIZE, 4 << 16),
                    (FEXTNVM, SW_CONFIG),
                    (STRAP, 0x55 << 17),
                    (LEDCTL, 0xa5c7),
                    (PHY_CTRL, PHY_D0_LPLU),
                    (0x1000, (6 << 16) | 26),
                ]),
                config: BTreeMap::from([(0xa8, 0x1003), (0xaa, 0x1003), (0xe4, 0)]),
                spt: false,
                power_busy: 0,
                power_pending: false,
                power_stuck: false,
                smb_hidden_after_power: false,
                smb_hidden: false,
                smb_stuck: false,
                ulp_stuck: false,
                flush_after_tx: false,
                flush_after_rx: false,
                phy: BTreeMap::from([((2, 0, 2), 0x154), ((2, 0, 3), 0x93)]),
                emi: BTreeMap::new(),
                kmrn: BTreeMap::new(),
                words,
                operations: Vec::new(),
                accesses: 0,
                fail_at: None,
                fail_with: Fault::Access,
                page: 0,
                emi_address: 0,
                flash_address: 0,
                flash_control: 0,
                time: 0,
                quiet_until: 0,
                master_busy: 0,
                mdic_failures: 0,
                mdic_attempts: 0,
                mdic_kind: 0,
                init_missing: false,
                reset_missing: false,
                reset_stuck: false,
            }
        }
        fn enter(&mut self) -> Result<(), Fault> {
            assert!(
                self.time >= self.quiet_until,
                "forbidden access immediately after reset"
            );
            let at = self.accesses;
            self.accesses += 1;
            if self.fail_at == Some(at) {
                Err(self.fail_with)
            } else {
                Ok(())
            }
        }
        fn phy_load(&self, address: u8, index: u16) -> u16 {
            let page = if index <= 15 { 0 } else { self.page };
            if address == 2 && page == 0 && index == 17 {
                return self.emi.get(&self.emi_address).copied().unwrap_or(0);
            }
            self.phy.get(&(address, page, index)).copied().unwrap_or(0)
        }
        fn phy_store(&mut self, address: u8, index: u16, value: u16) {
            if index == 31 {
                self.page = value >> 5;
                return;
            }
            let page = if index <= 15 { 0 } else { self.page };
            if address == 2 && page == 0 && index == 16 {
                self.emi_address = value;
            } else if address == 2 && page == 0 && index == 17 {
                self.emi.insert(self.emi_address, value);
            } else {
                if self.spt
                    && ((self.ulp_stuck && page == 779 && index == 16)
                        || (self.smb_stuck && page == 769 && index == 23))
                {
                    return;
                }
                self.phy.insert((address, page, index), value);
            }
        }
        fn did_reset(&mut self) {
            let status = if self.init_missing { 0 } else { INIT_DONE }
                | if self.reset_missing {
                    0
                } else {
                    PHY_RESET_ASSERTED
                };
            self.mac.insert(STATUS, status);
            self.page = 0;
        }
    }
    pub(super) struct Io(Rc<RefCell<Model>>, Arc<AtomicUsize>);
    impl Drop for Io {
        fn drop(&mut self) {
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }
    // SAFETY: exclusively serialized model, no actual resources or hardware.
    unsafe impl Registers for Io {
        fn read32(&mut self, at: u32) -> Result<u32, Fault> {
            let mut m = self.0.borrow_mut();
            m.enter()?;
            let mut value = m.mac.get(&at).copied().unwrap_or(0);
            if at == STATUS && m.master_busy != 0 {
                m.master_busy -= 1;
                value |= MASTER_ENABLED;
            }
            if m.spt && at == 0x18 && m.power_pending {
                if m.power_busy == 0 && !m.power_stuck {
                    value |= 4;
                    m.mac.insert(at, value);
                    m.power_pending = false;
                } else {
                    m.power_busy = m.power_busy.saturating_sub(1);
                    value &= !4;
                }
            }
            m.operations.push([0, at, value]);
            if at == ICR {
                m.mac.insert(at, 0);
            }
            Ok(value)
        }
        fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
            let mut m = self.0.borrow_mut();
            m.enter()?;
            // The integrated PCH MAC has 32 MTA words, not the discrete MAC's
            // 128-word table. Reject the remaining pre-RAR register span so
            // packet initialization cannot silently write reserved addresses.
            if (0x5280..0x5400).contains(&at) {
                return Err(Fault::OutsideBar);
            }
            m.operations.push([1, at, value]);
            let previous = m.mac.get(&at).copied().unwrap_or(0);
            if at == CTRL && value & RESET != 0 {
                m.did_reset();
                let ext = m.mac.get(&super::super::EXTCNF_CTRL).copied().unwrap_or(0);
                m.mac
                    .insert(super::super::EXTCNF_CTRL, ext & !super::super::SWFLAG);
                let reset = if m.reset_stuck { RESET } else { 0 };
                m.mac.insert(CTRL, (value & !(RESET | PHY_RESET)) | reset);
                m.quiet_until = m.time + 20_000;
            } else if at == CTRL && previous & PHY_RESET != 0 && value & PHY_RESET == 0 {
                m.mac.insert(at, value);
                m.did_reset();
            } else if m.spt && at == CTRL && previous & (1 << 16) != 0 && value & (1 << 16) == 0 {
                m.power_pending = true;
                if m.smb_hidden_after_power {
                    m.smb_hidden = true;
                    let value = m.phy.get(&(1, 769, 23)).copied().unwrap_or(0) | 1;
                    m.phy.insert((1, 769, 23), value);
                }
                let ext = m.mac.get(&0x18).copied().unwrap_or(0) & !4;
                m.mac.insert(0x18, ext);
                m.mac.insert(at, value);
            } else if at == PBA {
                m.mac
                    .insert(at, (32 - (value & 0xffff)) << 16 | (value & 0xffff));
            } else if at == 0x34 {
                let index = ((value >> 16) & 31) as u8;
                if value & (1 << 21) != 0 {
                    let word = m.kmrn.get(&index).copied().unwrap_or(0);
                    m.mac.insert(at, (value & !0xffff) | u32::from(word));
                } else {
                    m.kmrn.insert(index, value as u16);
                    m.mac.insert(at, value);
                }
            } else if at == super::super::MDIC {
                let index = ((value >> 16) & 31) as u16;
                let address = ((value >> 21) & 31) as u8;
                let smb = m.spt && address == 1 && m.page == 769 && index == 23;
                let mut mdi_error = false;
                let data = if value & super::super::MDIC_WRITE != 0 {
                    let switching = smb && m.phy_load(address, index) & 1 != 0 && value & 1 == 0;
                    m.phy_store(address, index, value as u16);
                    if switching {
                        m.smb_hidden = false;
                        mdi_error = true;
                    }
                    value as u16
                } else {
                    mdi_error = smb
                        && m.smb_hidden
                        && m.mac.get(&0x18).copied().unwrap_or(0) & (1 << 11) == 0;
                    m.phy_load(address, index)
                };
                let failed = m.mdic_attempts < m.mdic_failures;
                m.mdic_attempts += 1;
                let response = (value & !0xffff)
                    | u32::from(data)
                    | super::super::MDIC_READY
                    | if mdi_error { 1 << 30 } else { 0 };
                let response = if failed {
                    match m.mdic_kind {
                        0 => response & !(1 << 28),
                        1 => response | (1 << 30),
                        _ => (response & !(31 << 16)) | (7 << 16),
                    }
                } else {
                    response
                };
                m.mac.insert(at, response);
            } else {
                m.mac.insert(at, value);
            }
            if m.spt && m.config[&0xe4] & 0x100 != 0 {
                if at == 0x3818 && value != previous && m.flush_after_tx {
                    let address = u64::from(m.mac[&0x3800]) | (u64::from(m.mac[&0x3804]) << 32);
                    assert_ne!(address, 0);
                    assert_eq!(
                        m.mac[&0x3808],
                        (crate::net::ring::DESCRIPTORS * crate::net::ring::DESCRIPTOR) as u32
                    );
                    let descriptor = (address as usize + previous as usize * 16) as *const u8;
                    // SAFETY: the queue model's actual published ring belongs
                    // to its live synchronous Memory owner, aligned and512B.
                    let buffer = unsafe { core::ptr::read_volatile(descriptor.cast::<u64>()) };
                    // SAFETY: same actual descriptor's aligned lower dword.
                    let lower =
                        unsafe { core::ptr::read_volatile(descriptor.add(8).cast::<u32>()) };
                    assert_eq!(buffer, address);
                    assert_eq!(lower, 512 | (1 << 25));
                    m.config.insert(0xe4, 0);
                }
                if at == RCTL && value & 2 != 0 && m.flush_after_rx {
                    let thresholds = m.mac.get(&0x2828).copied().unwrap_or(0);
                    if thresholds & 0x3fff == 0x11f && thresholds & (1 << 24) != 0 {
                        m.config.insert(0xe4, 0);
                    }
                }
            }
            Ok(())
        }
    }
    // SAFETY: actual config words in the same single Function/reset model as
    // the MAC/PHY/flash registers. No separate owner/token supplies values.
    unsafe impl super::lpt::LptRegisters for Io {
        fn read_config16(&mut self, at: u16) -> Result<u16, Fault> {
            let mut m = self.0.borrow_mut();
            m.enter()?;
            let value = *m.config.get(&at).expect("actual modeled config word");
            m.operations.push([7, u32::from(at), u32::from(value)]);
            Ok(value)
        }
    }
    // SAFETY: same single model as its MAC implementation; width-specific
    // operations implement the flash register engine, not driver algorithms.
    unsafe impl nvm::Registers for Io {
        fn read_mac32(&mut self, at: u32) -> Result<u32, nvm::Error> {
            Registers::read32(self, at).map_err(|_| nvm::Error::Access)
        }
        fn read16(&mut self, at: u32) -> Result<u16, nvm::Error> {
            let mut m = self.0.borrow_mut();
            m.enter().map_err(|_| nvm::Error::Access)?;
            let value = match at {
                4 => 0x4001,
                6 => {
                    assert!(!m.spt, "SPT control requires32-bit access");
                    m.flash_control
                }
                _ => panic!("invalid flash16"),
            };
            m.operations.push([3, at, u32::from(value)]);
            Ok(value)
        }
        fn read32(&mut self, at: u32) -> Result<u32, nvm::Error> {
            let mut m = self.0.borrow_mut();
            m.enter().map_err(|_| nvm::Error::Access)?;
            let value = match at {
                0 => {
                    assert!(!m.spt, "SPT has no GFPREG");
                    1 << 16
                }
                4 => {
                    assert!(m.spt);
                    0x4001 | (u32::from(m.flash_control) << 16)
                }
                16 => {
                    let index = m.flash_address as usize / 2;
                    if m.spt {
                        u32::from(m.words[index]) | (u32::from(m.words[index + 1]) << 16)
                    } else {
                        u32::from(m.words[index]) >> ((m.flash_address & 1) * 8)
                    }
                }
                _ => panic!("invalid flash32"),
            };
            m.operations.push([4, at, value]);
            Ok(value)
        }
        fn write16(&mut self, at: u32, value: u16) -> Result<(), nvm::Error> {
            let mut m = self.0.borrow_mut();
            m.enter().map_err(|_| nvm::Error::Access)?;
            m.operations.push([5, at, u32::from(value)]);
            match at {
                4 => {}
                6 => {
                    assert_eq!(value & 6, 0, "non-read flash cycle");
                    m.flash_control = value & !1;
                }
                _ => panic!("invalid flash16 store"),
            }
            Ok(())
        }
        fn write32(&mut self, at: u32, value: u32) -> Result<(), nvm::Error> {
            let mut m = self.0.borrow_mut();
            m.enter().map_err(|_| nvm::Error::Access)?;
            m.operations.push([6, at, value]);
            match at {
                4 if m.spt => {
                    let control = (value >> 16) as u16;
                    assert_eq!(control & 6, 0, "non-read SPT flash cycle");
                    m.flash_control = control & !1;
                }
                8 => m.flash_address = value,
                _ => panic!("non-address flash32 store"),
            }
            Ok(())
        }
    }
    #[derive(Clone)]
    pub(super) struct Timer(Rc<RefCell<Model>>);
    impl Delay for Timer {
        fn delay(&mut self, us: u64) {
            let mut m = self.0.borrow_mut();
            m.time += us;
            m.operations.push([2, us as u32, 0]);
        }
    }
    type Fixture = (Rc<RefCell<Model>>, Arc<AtomicUsize>, Io, Timer);
    pub(super) fn fixture() -> Fixture {
        let state = Rc::new(RefCell::new(Model::ready()));
        let released = Arc::new(AtomicUsize::new(0));
        (
            state.clone(),
            released.clone(),
            Io(state.clone(), released),
            Timer(state),
        )
    }
    pub(super) fn start(io: Io, timer: Timer) -> Result<Controller<Io, Timer>, Error> {
        // SAFETY: one fresh exclusive same-function model and real model timer.
        unsafe { Controller::new(0x1503, io, timer) }
    }
    pub(super) fn fixture_lpt() -> Fixture {
        let (state, released, io, timer) = fixture();
        {
            let mut m = state.borrow_mut();
            m.phy.insert((2, 0, 3), 0xa7);
            m.words[3] |= 1;
            let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
            m.words[63] = 0xbabau16.wrapping_sub(sum);
            let strap = m.mac[&STRAP] | (2 << 12);
            m.mac.insert(STRAP, strap);
        }
        (state, released, io, timer)
    }
    pub(super) fn start_lpt(
        device: u16,
        io: Io,
        timer: Timer,
    ) -> Result<Controller<Io, Timer>, Error> {
        // SAFETY: one fresh same-function config/MAC/flash/PHY model epoch.
        unsafe { Controller::new_lpt(device, io, timer) }
    }
    fn raw(io: Io, timer: Timer) -> Controller<Io, Timer> {
        let bus = Bus(Rc::new(RefCell::new(io)));
        // SAFETY: raw single-function model before any PHY/DMA operation.
        let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Pch2, bus.clone(), timer.clone()) }.unwrap();
        // SAFETY: the exact same isolated model reset epoch.
        let phy = unsafe { Phy::new(Kind::I82579, bus, timer) };
        Controller {
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
        }
    }
    #[test]
    fn cold_composition_uses_real_nvm_and_two_distinct_reset_lifecycles() {
        let (state, released, io, timer) = fixture();
        let controller = start(io, timer).unwrap();
        assert_eq!(controller.station().0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(
            controller.identity(),
            Identity {
                kind: Kind::I82579,
                id: 0x01540090,
                revision: 3
            }
        );
        assert!(!controller.is_poisoned());
        let m = state.borrow();
        assert_eq!(m.phy[&(1, 769, 20)], 0x125a);
        assert_eq!(m.phy[&(1, 772, 21)], 0x5601);
        assert_eq!(m.phy[&(1, 0, 26)] & 0x3ff, 0x2d5);
        assert_eq!(m.phy[&(1, 0, 30)], 0xa5c7);
        assert_eq!(m.phy[&(1, 0, 25)] & 0x444, OEM_LPLU | OEM_RESTART);
        assert_eq!(m.emi[&MSE_THRESHOLD], 0x34);
        assert_eq!(m.emi[&MSE_LINK_DOWN], 5);
        assert_eq!(m.emi[&LPI_UPDATE_TIMER], 0x1387);
        assert_eq!(m.mac[&RCTL], 0);
        assert_eq!(m.mac[&TCTL], PAD_SHORT);
        assert_eq!(
            m.mac[&super::super::EXTCNF_CTRL] & (GATE_PHY | super::super::SWFLAG),
            0
        );
        let at = m
            .operations
            .iter()
            .position(|o| o[0] == 1 && o[1] == CTRL && o[2] & RESET != 0)
            .unwrap();
        assert_eq!(m.operations[at + 1], [2, 20_000, 0]);
        drop(m);
        drop(controller);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn unmanaged_exact_cohort_and_readiness_are_required() {
        for failure in 0..6 {
            let (state, released, io, timer) = fixture();
            {
                let mut m = state.borrow_mut();
                match failure {
                    0 => {
                        m.mac.insert(
                            super::super::FWSM,
                            super::super::FW_VALID | super::super::RESET_PERMITTED,
                        );
                    }
                    1 => {
                        m.mac.insert(super::super::FWSM, 0);
                    }
                    2 => m.init_missing = true,
                    3 => m.reset_missing = true,
                    4 => m.reset_stuck = true,
                    5 => {
                        m.master_busy = 2000;
                    }
                    _ => unreachable!(),
                }
            }
            let error = match start(io, timer) {
                Ok(_) => panic!("accepted unready model"),
                Err(e) => e,
            };
            assert!(matches!(
                error,
                Error::Nvm(nvm::Error::FirmwareOwned)
                    | Error::Phy(super::super::Error {
                        primary: Fault::ResetBlocked,
                        ..
                    })
                    | Error::InitTimeout
                    | Error::ResetNotObserved
                    | Error::ResetStuck
                    | Error::MasterTimeout
            ));
            assert_eq!(
                released.load(Ordering::SeqCst),
                0,
                "uncertain real owner released"
            );
            assert!(
                state
                    .borrow()
                    .operations
                    .iter()
                    .all(|o| !(o[0] == 1 && matches!(o[1], RCTL | TCTL) && o[2] & 2 != 0))
            );
        }
        let (_, released, io, timer) = fixture();
        // SAFETY: deliberately test exact-cohort refusal with a fresh model.
        assert!(matches!(
            unsafe { Controller::new(0x153a, io, timer) },
            Err(Error::UnsupportedDevice(0x153a))
        ));
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn each_access_failure_retains_the_single_actual_function_without_packet_dma() {
        let (state, _, io, timer) = fixture();
        let ready = start(io, timer).unwrap();
        let count = state.borrow().accesses;
        drop(ready);
        for at in 0..count {
            let (state, released, io, timer) = fixture();
            state.borrow_mut().fail_at = Some(at);
            assert!(start(io, timer).is_err(), "lost access failure at {at}");
            assert_eq!(
                released.load(Ordering::SeqCst),
                0,
                "released owner after failure {at}"
            );
            let m = state.borrow();
            assert!(
                m.operations
                    .iter()
                    .all(|o| !(o[0] == 1 && matches!(o[1], RCTL | TCTL) && o[2] & 2 != 0))
            );
        }
    }
    #[test]
    fn malformed_lcd_never_writes_its_script_or_reports_initialized() {
        for out_of_bounds in [false, true] {
            let (state, released, io, timer) = fixture();
            if out_of_bounds {
                state
                    .borrow_mut()
                    .mac
                    .insert(super::super::EXTCNF_CTRL, 0xfff << 16);
            } else {
                state.borrow_mut().words[128] |= 1;
            }
            assert!(matches!(start(io, timer), Err(Error::Configuration)));
            let m = state.borrow();
            assert!(!m.phy.contains_key(&(1, 769, 20)));
            assert!(!m.phy.contains_key(&(1, 772, 21)));
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    #[ignore = "oracle: STELA_E1000E_PCH_RESET_ORACLE"]
    fn unchanged_linux_global_reset_prefix_register_effects() {
        let path = std::env::var_os("STELA_E1000E_PCH_RESET_ORACLE").expect("reset trace path");
        let bytes = std::fs::read(path).expect("read reset trace");
        assert_eq!(bytes.len() % 4, 0);
        let words: Vec<_> = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_le_bytes(*b))
            .collect();
        let mut cursor = 0;
        let mut cases = 0;
        while cursor < words.len() {
            let busy = words[cursor];
            let count = words[cursor + 1] as usize;
            cursor += 2;
            let expected: Vec<[u32; 3]> = words[cursor..cursor + count * 3]
                .as_chunks::<3>()
                .0
                .to_vec();
            cursor += count * 3;
            let (state, _, io, timer) = fixture();
            let mut controller = raw(io, timer);
            state.borrow_mut().operations.clear();
            state.borrow_mut().master_busy = busy as usize;
            controller.global_reset().unwrap();
            // The source oracle's declared reset prefix compares all actual
            // stores, STATUS observations and delays. Extra Stela read-only
            // qualification/CTRL-reset-clear checks are covered separately.
            let actual: Vec<_> = state
                .borrow()
                .operations
                .iter()
                .copied()
                .filter(|o| o[0] == 1 || o[0] == 2 || (o[0] == 0 && o[1] == STATUS))
                .collect();
            assert_eq!(actual, expected, "master-busy polls={busy}");
            cases += 1;
        }
        assert_eq!(cases, 3);
    }
    pub(super) fn post_effects(operations: &[[u32; 3]], initial_ext: u32) -> Vec<[u32; 3]> {
        let mut actual = Vec::new();
        let mut page = 0;
        let mut pending = None;
        let mut ext = initial_ext;
        for &[kind, at, value] in operations {
            if kind == 2 && at >= 10_000 {
                actual.push([2, at, 0]);
            }
            if kind == 1 && at == super::super::EXTCNF_CTRL {
                if (ext ^ value) & GATE_PHY != 0 {
                    actual.push([1, at, value & !super::super::SWFLAG]);
                }
                ext = value;
            }
            if at != super::super::MDIC {
                continue;
            }
            if kind == 1 {
                let index = (value >> 16) & 31;
                if index == 31 {
                    page = (value & 0xffff) >> 5;
                    continue;
                }
                let address = (value >> 21) & 31;
                let logical = if index <= 15 {
                    index
                } else {
                    ((if address == 1 && page == 0 { 768 } else { page }) << 5) | index
                };
                if value & super::super::MDIC_WRITE != 0 {
                    actual.push([11, logical, value & 0xffff]);
                } else {
                    pending = Some(logical);
                }
            } else if kind == 0
                && let Some(logical) = pending.take()
            {
                actual.push([10, logical, value & 0xffff]);
            }
        }
        actual
    }
    #[test]
    #[ignore = "oracle: STELA_E1000E_PCH_POST_ORACLE"]
    fn unchanged_linux_post_reset_lcd_and_oem_effects() {
        let path = std::env::var_os("STELA_E1000E_PCH_POST_ORACLE").expect("post-reset trace path");
        let bytes = std::fs::read(path).expect("read post-reset trace");
        assert_eq!(bytes.len() % 4, 0);
        let words: Vec<_> = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_le_bytes(*b))
            .collect();
        let mut cursor = 0;
        let mut cases = 0;
        while cursor < words.len() {
            let [sw, count, oem, strap, operations] =
                *words[cursor..cursor + 5].first_chunk::<5>().unwrap();
            cursor += 5;
            let expected = words[cursor..cursor + operations as usize * 3]
                .as_chunks::<3>()
                .0
                .to_vec();
            cursor += operations as usize * 3;
            let (state, _, io, timer) = fixture();
            let mut controller = raw(io, timer);
            let initial_ext = (64 << 16) | GATE_PHY;
            {
                let mut m = state.borrow_mut();
                m.operations.clear();
                m.mac.insert(super::super::EXTCNF_CTRL, initial_ext);
                m.mac.insert(FEXTNVM, if sw == 0 { 0 } else { SW_CONFIG });
                m.mac.insert(EXTCNF_SIZE, count << 16);
                m.mac.insert(
                    PHY_CTRL,
                    if oem & 1 == 0 { 0 } else { 2 } | if oem & 2 == 0 { 0 } else { 0x40 },
                );
                m.mac.insert(STRAP, if strap == 0 { 0 } else { 0x55 << 17 });
                m.mac
                    .insert(LEDCTL, if strap == 0 { 0x5a38 } else { 0xa5c7 });
                m.phy.clear();
                for (address, page, index, data) in [
                    (1, 769, 16, 0x5252),
                    (1, 769, 17, 0x77f7),
                    (1, 0, 26, 0xa511),
                    (1, 0, 30, 0x9632),
                    (1, 0, 25, 0xa09c),
                ] {
                    m.phy.insert((address, page, index), data);
                }
            }
            controller.post_reset().unwrap();
            let actual = post_effects(&state.borrow().operations, initial_ext);
            assert_eq!(
                actual, expected,
                "sw={sw} count={count} oem={oem} strap={strap}"
            );
            cases += 1;
        }
        assert_eq!(cases, 32);
    }
}
