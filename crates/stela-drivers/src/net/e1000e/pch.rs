// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Owned PCH PHY transport for the 82579 and I217/I218/I219 paths.
//!
//! SWFLAG, MDIC, HV paging, debug ports and host-wakeup access follow the
//! pinned Linux e1000e shared code. This component does not admit a PCH MAC
//! to the network probe. [`cold`] composes only its declared unmanaged 82579
//! reset/NVM/PHY/MAC/queue profile behind owned unsafe grants. Other
//! generations and canonical native admission remain separate. It never applies the
//! discrete 82574L's PHY page or RAR policy to an integrated PCH controller.

use crate::Clock;

pub mod cold;
pub mod io;
pub mod nvm;

const MDIC: u32 = 0x20;
const FWSM: u32 = 0x5b54;
const EXTCNF_CTRL: u32 = 0xf00;
const SWFLAG: u32 = 1 << 5;
const FW_VALID: u32 = 1 << 15;
const RESET_PERMITTED: u32 = 1 << 6;
const MDIC_READ: u32 = 1 << 27;
const MDIC_WRITE: u32 = 1 << 26;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const MDIC_REG_MASK: u32 = 0x1f << 16;
const MDIC_POLLS: usize = 640 * 3;
const PHY_PAGE: u16 = 31;
const PORT_PAGE: u16 = 769;
const WAKE_PAGE: u16 = 800;
const WAKE_ENABLE: u16 = 17;
const WAKE_ADDRESS: u16 = 17;
const WAKE_DATA: u16 = 18;
const WAKE_ACCESS: u16 = 1 << 2;
const WAKE_ME_HOST: u16 = (1 << 4) | (1 << 5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    I82579,
    I217,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Access,
    OutsideBar,
    Misaligned,
    Removed,
    FirmwareOwned,
    ResetBlocked,
    SemaphoreBusy,
    SemaphoreTimeout,
    SemaphoreLost,
    MdicTimeout,
    MdicResponse(u32),
    WrongPhy(u32),
    InvalidRegister,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub primary: Fault,
    pub cleanup: Option<Fault>,
}
impl From<Fault> for Error {
    fn from(primary: Fault) -> Self {
        Self {
            primary,
            cleanup: None,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PCH PHY: {:?}", self.primary)?;
        if let Some(cleanup) = self.cleanup {
            write!(f, "; cleanup: {cleanup:?}")?;
        }
        Ok(())
    }
}
impl core::error::Error for Error {}

/// Complete PCH MAC register accesses with the real reservation kept.
///
/// # Safety
/// The implementation owns the powered, exclusively claimed PCH MAC,
/// uncached mapping and PCI resource through its lifetime, with DMA/IRQ/work
/// already stopped. No SMM, firmware or other user accesses these registers or
/// resets the PHY concurrently. Accesses are bounded, aligned, little-endian,
/// volatile and ordered; an error never invents an observation or successful
/// write. Reads flush this function's posted writes. Resource release must not
/// abandon pending native CPU accesses. An unrelated token is insufficient.
pub unsafe trait Registers: 'static {
    fn read32(&mut self, offset: u32) -> Result<u32, Fault>;
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Fault>;
}

/// Minimum hardware delays; polling is additionally bounded by count.
pub trait Delay {
    fn delay(&mut self, microseconds: u64);
}
impl Delay for Clock {
    fn delay(&mut self, microseconds: u64) {
        Clock::delay(self, microseconds);
    }
}

/// A checked HV register. Wakeup registers use the source's extended u16 index;
/// all other pages expose only their 32 MDIO register lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Register {
    page: u16,
    index: u16,
}
impl Register {
    pub fn new(page: u16, index: u16) -> Result<Self, Fault> {
        if page > 2047 || (page != WAKE_PAGE && index > 31) {
            return Err(Fault::InvalidRegister);
        }
        Ok(Self { page, index })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub kind: Kind,
    pub id: u32,
    pub revision: u8,
}

/// One exclusive PHY-access epoch. Any hardware/control failure poisons it;
/// Drop keeps the register owner after an uncertain operation. A fresh
/// object requires the constructor's reset/quiescence ownership grant.
pub struct Phy<R: Registers, D: Delay> {
    io: Option<R>,
    delay: D,
    kind: Kind,
    poisoned: bool,
    retry_count: u8,
    retry_enabled: bool,
}
impl<R: Registers, D: Delay> Phy<R, D> {
    /// # Safety
    /// `kind` describes the observed PCH PCI cohort: 82579 (PCH2) or
    /// I217/I218/I219 using the I217 PHY. The caller owns the exact physical
    /// requester's reset epoch exclusively, has drained DMA/IRQ/work and has
    /// not reused a prior failed PHY access epoch without real reset/recovery.
    /// `delay` must provide the requested minimum elapsed hardware time.
    /// This grant neither proves full MAC initialization nor admits network I/O.
    pub unsafe fn new(kind: Kind, io: R, delay: D) -> Self {
        Self {
            io: Some(io),
            delay,
            kind,
            poisoned: false,
            retry_count: 0,
            retry_enabled: false,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn read_mac(&mut self, at: u32) -> Result<u32, Fault> {
        let value = self
            .io
            .as_mut()
            .expect("live PHY register owner")
            .read32(at)?;
        if value == u32::MAX {
            Err(Fault::Removed)
        } else {
            Ok(value)
        }
    }
    fn write_mac(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        self.io
            .as_mut()
            .expect("live PHY register owner")
            .write32(at, value)
    }

    fn acquire(&mut self) -> Result<(), Error> {
        // This first boot profile refuses ME-owned/reset-blocked
        // hardware before any write; it does not claim coexistence with ME.
        let fw = self.read_mac(FWSM)?;
        if fw & FW_VALID != 0 {
            return Err(Fault::FirmwareOwned.into());
        }
        if fw & RESET_PERMITTED == 0 {
            return Err(Fault::ResetBlocked.into());
        }
        let mut value = 0;
        let mut available = false;
        for _ in 0..100 {
            value = self.read_mac(EXTCNF_CTRL)?;
            if value & SWFLAG == 0 {
                available = true;
                break;
            }
            self.delay.delay(1000);
        }
        if !available {
            return Err(Fault::SemaphoreBusy.into());
        }
        self.write_mac(EXTCNF_CTRL, value | SWFLAG)?;
        for _ in 0..1000 {
            if self.read_mac(EXTCNF_CTRL)? & SWFLAG != 0 {
                return Ok(());
            }
            self.delay.delay(1000);
        }
        // An unacknowledged claim is uncertain. Try the source's clear, keep
        // the owner on the final failure, and never retry this access epoch.
        let cleanup = (|| {
            let value = self.read_mac(EXTCNF_CTRL)?;
            self.write_mac(EXTCNF_CTRL, value & !SWFLAG)
        })();
        Err(Error {
            primary: Fault::SemaphoreTimeout,
            cleanup: cleanup.err(),
        })
    }

    fn release(&mut self) -> Result<(), Fault> {
        let value = self.read_mac(EXTCNF_CTRL)?;
        if value & SWFLAG == 0 {
            return Err(Fault::SemaphoreLost);
        }
        self.write_mac(EXTCNF_CTRL, value & !SWFLAG)?;
        if self.read_mac(EXTCNF_CTRL)? & SWFLAG != 0 {
            return Err(Fault::SemaphoreLost);
        }
        Ok(())
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Fault>,
    ) -> Result<T, Error> {
        if self.poisoned {
            return Err(Fault::Poisoned.into());
        }
        if let Err(error) = self.acquire() {
            self.poisoned = true;
            return Err(error);
        }
        let result = operation(self);
        let cleanup = self.release();
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), cleanup) => {
                self.poisoned = true;
                Err(Error {
                    primary,
                    cleanup: cleanup.err(),
                })
            }
            (Ok(_), Err(primary)) => {
                self.poisoned = true;
                Err(primary.into())
            }
        }
    }

    fn mdic(&mut self, address: u8, index: u16, write: Option<u16>) -> Result<u16, Fault> {
        let retries = if self.retry_enabled {
            self.retry_count
        } else {
            0
        };
        for attempt in 0..=retries {
            match self.mdic_once(address, index, write) {
                Err(Fault::MdicTimeout | Fault::MdicResponse(_)) if attempt < retries => {
                    self.delay.delay(10_000);
                }
                result => return result,
            }
        }
        unreachable!("bounded MDIC loop returns its last actual outcome")
    }
    fn mdic_once(&mut self, address: u8, index: u16, write: Option<u16>) -> Result<u16, Fault> {
        if address > 31 || index > 31 {
            return Err(Fault::InvalidRegister);
        }
        let command = (u32::from(address) << 21)
            | (u32::from(index) << 16)
            | write.map_or(MDIC_READ, |value| MDIC_WRITE | u32::from(value));
        self.write_mac(MDIC, command)?;
        let mut response = 0;
        let mut ready = false;
        for _ in 0..MDIC_POLLS {
            self.delay.delay(50);
            response = self.read_mac(MDIC)?;
            if response & MDIC_READY != 0 {
                ready = true;
                break;
            }
        }
        // 82579 requires this quiet interval even when the transaction fails.
        if self.kind == Kind::I82579 {
            self.delay.delay(100);
        }
        if !ready {
            return Err(Fault::MdicTimeout);
        }
        if response & MDIC_ERROR != 0 || response & MDIC_REG_MASK != command & MDIC_REG_MASK {
            return Err(Fault::MdicResponse(response));
        }
        Ok(response as u16)
    }

    fn page(&mut self, page: u16) -> Result<(), Fault> {
        self.mdic(1, PHY_PAGE, Some(page << 5)).map(|_| ())
    }

    fn access(&mut self, register: Register, value: Option<u16>) -> Result<u16, Fault> {
        let Register { page, index } = register;
        if page == WAKE_PAGE {
            return self.wakeup(index, value);
        }
        if page > 0 && page < 768 {
            // All supported PHY types use I82577's debug address/data pair.
            self.mdic(2, 16, Some(((page << 5) | index) & 0x3f))?;
            return self.mdic(2, 17, value);
        }
        let address = if page >= 768 { 1 } else { 2 };
        if index > 15 {
            self.page(if page == 768 { 0 } else { page })?;
        }
        self.mdic(address, index, value)
    }

    fn wakeup(&mut self, index: u16, value: Option<u16>) -> Result<u16, Fault> {
        self.page(PORT_PAGE)?;
        let saved = self.mdic(1, WAKE_ENABLE, None)?;
        self.mdic(1, WAKE_ENABLE, Some((saved | WAKE_ACCESS) & !WAKE_ME_HOST))?;
        self.page(WAKE_PAGE)?;
        self.mdic(1, WAKE_ADDRESS, Some(index))?;
        let result = self.mdic(1, WAKE_DATA, value)?;
        self.page(PORT_PAGE)?;
        self.mdic(1, WAKE_ENABLE, Some(saved))?;
        Ok(result)
    }

    pub fn read(&mut self, register: Register) -> Result<u16, Error> {
        self.transaction(|this| this.access(register, None))
    }
    pub fn write(&mut self, register: Register, value: u16) -> Result<(), Error> {
        self.transaction(|this| this.access(register, Some(value)).map(|_| ()))
    }
    pub fn identify(&mut self) -> Result<Identity, Error> {
        self.transaction(|this| {
            let high = this.access(Register { page: 0, index: 2 }, None)?;
            let low = this.access(Register { page: 0, index: 3 }, None)?;
            let raw = (u32::from(high) << 16) | u32::from(low);
            let expected = match this.kind {
                Kind::I82579 => 0x0154_0090,
                Kind::I217 => 0x0154_00a0,
            };
            if raw & !0xf != expected {
                return Err(Fault::WrongPhy(raw));
            }
            Ok(Identity {
                kind: this.kind,
                id: raw & !0xf,
                revision: (raw & 0xf) as u8,
            })
        })
    }
}
impl<R: Registers, D: Delay> Drop for Phy<R, D> {
    fn drop(&mut self) {
        if self.poisoned {
            // Preserve the reservation/mapping, including an uncertain
            // semaphore/page state. Only an external real reset can recover it.
            if let Some(owner) = self.io.take() {
                core::mem::forget(owner);
            }
        }
    }
}

#[cfg(test)]
mod tests;
