// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Standalone AX200/AX210 ownership, persistence, reset and MAC-clock wake.
//! Adapted from pcie/gen1_2/trans.c, iwl-io.c and the pinned MAC configurations.
//! This leaves interrupts masked. It never starts ROM self-load, authenticates
//! firmware, calibrates a radio or claims station/carrier readiness.
use super::{firmware::Family, identity::Profile};
use crate::{
    Clock, Handoff,
    bus::{mmio::Mmio, pci::Bar},
};

const HW_IF: u32 = 0;
const INT: u32 = 8;
const INT_MASK: u32 = 12;
const FH_INT: u32 = 16;
const RESET: u32 = 0x20;
const GP: u32 = 0x24;
const HW_REV: u32 = 0x28;
const GIO: u32 = 0x3c;
const MAILBOX: u32 = 0x88;
const RF_ID: u32 = 0x9c;
const CHICKEN: u32 = 0x100;
const HPET: u32 = 0x240;
const LINK_PWR: u32 = 0x250;
const PRPH_WADDR: u32 = 0x444;
const PRPH_RADDR: u32 = 0x448;
const PRPH_WDATA: u32 = 0x44c;
const PRPH_RDATA: u32 = 0x450;
const OWN: u32 = 0x00400000;
const WAKE_ME: u32 = 0x08000000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    Unavailable,
    Bounds,
    Mapping,
    Clock,
}

/// Exclusive process-context CSR access and a real advancing delay source.
/// Native construction requires a checked MMIO/PCI ownership contract.
pub trait Csr {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError>;
    fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError>;
    fn delay_us(&mut self, microseconds: u32) -> Result<(), AccessError>;
}

/// Direct access to an already mapped BAR. This does not manufacture an
/// exclusive PCI claim or attach a DMA domain/interrupt route.
pub struct NativeCsr {
    registers: Mmio,
    clock: Clock,
}
impl NativeCsr {
    /// # Safety
    /// The caller owns this exact standalone Intel PCI function exclusively,
    /// including its BAR and reset/power state. All old DMA/submissions/IRQ work
    /// are stopped and drained, PCI MSI/MSI-X/legacy interrupt delivery is
    /// disabled, no firmware/AML/other driver accesses the BAR,
    /// and the real mapped uncached BAR stays reserved for this object's life.
    /// The supplied clock is calibrated and keeps advancing in this context.
    pub unsafe fn new(
        handoff: &Handoff,
        bar: Option<Bar>,
        clock: Clock,
    ) -> Result<Self, AccessError> {
        if clock.ticks_per_microsecond == 0 {
            return Err(AccessError::Clock);
        }
        let registers =
            crate::registers(handoff, bar, 0, 4096).map_err(|_| AccessError::Mapping)?;
        Ok(Self { registers, clock })
    }
}
impl Csr for NativeCsr {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
        if !register.is_multiple_of(4) || register > 4092 {
            return Err(AccessError::Bounds);
        }
        Ok(self.registers.read32(register as usize))
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError> {
        if !register.is_multiple_of(4) || register > 4092 {
            return Err(AccessError::Bounds);
        }
        self.registers.write32(register as usize, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u32) -> Result<(), AccessError> {
        self.clock.delay(u64::from(microseconds));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access(AccessError),
    FailedRead { register: u32, value: u32 },
    IdentityChanged,
    Timeout { register: u32, mask: u32 },
    Rejected { register: u32, mask: u32 },
    ManagementUnknown,
    ManagementConnected,
    PersistenceProtected,
    State,
}
impl From<AccessError> for Error {
    fn from(value: AccessError) -> Self {
        Self::Access(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementSession {
    NotConnected,
    Connected,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Awake {
    pub family: Family,
    pub rf_killed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Cold,
    Awake(Awake),
    Poisoned,
}

pub struct Power<C: Csr> {
    io: C,
    profile: Profile,
    state: State,
}
impl<C: Csr> Power<C> {
    pub fn new(io: C, profile: Profile) -> Self {
        Self {
            io,
            profile,
            state: State::Cold,
        }
    }
    fn read(&mut self, register: u32) -> Result<u32, Error> {
        let value = self.io.read32(register)?;
        if value == u32::MAX || matches!(value & !0xf, 0xa5a5a5a0 | 0x5a5a5a50) {
            return Err(Error::FailedRead { register, value });
        }
        Ok(value)
    }
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.io.write32(register, value)?;
        Ok(())
    }
    fn set(&mut self, register: u32, mask: u32) -> Result<(), Error> {
        let value = self.read(register)?;
        self.write(register, value | mask)
    }
    fn set_checked(&mut self, register: u32, mask: u32) -> Result<(), Error> {
        self.set(register, mask)?;
        if self.read(register)? & mask != mask {
            return Err(Error::Rejected { register, mask });
        }
        Ok(())
    }
    fn poll(&mut self, register: u32, mask: u32, microseconds: u32) -> Result<(), Error> {
        // Same 10us interval/strict deadline as iwl_poll_bits_mask. A failed
        // register read is never a successful set-bit observation.
        for _ in 0..microseconds.div_ceil(10) {
            if self.read(register)? & mask == mask {
                return Ok(());
            }
            self.io.delay_us(10)?;
        }
        Err(Error::Timeout { register, mask })
    }
    fn ready(&mut self) -> Result<(), Error> {
        self.set(HW_IF, OWN)?;
        self.poll(HW_IF, OWN, 50)?;
        self.set(MAILBOX, 1 << 5)
    }
    fn ownership(&mut self, management: ManagementSession) -> Result<(), Error> {
        match self.ready() {
            Ok(()) => return Ok(()),
            Err(Error::Timeout { .. }) => {}
            Err(e) => return Err(e),
        }
        self.set_checked(LINK_PWR, 1 << 31)?;
        self.io.delay_us(1000)?;
        for _ in 0..10 {
            self.set(HW_IF, WAKE_ME)?;
            for _ in 0..750 {
                match self.ready() {
                    Ok(()) => return Ok(()),
                    Err(Error::Timeout { .. }) => {}
                    Err(e) => return Err(e),
                }
                match management {
                    ManagementSession::Connected => return Err(Error::ManagementConnected),
                    ManagementSession::Unknown => return Err(Error::ManagementUnknown),
                    ManagementSession::NotConnected => {}
                }
                self.io.delay_us(200)?;
            }
            self.io.delay_us(25000)?;
        }
        Err(Error::Timeout {
            register: HW_IF,
            mask: OWN,
        })
    }
    fn read_prph(&mut self, address: u32) -> Result<u32, Error> {
        let mask = if self.profile.family() == Family::Ax210 {
            0x00ffffff
        } else {
            0x000fffff
        };
        self.write(PRPH_RADDR, (address & mask) | (3 << 24))?;
        self.read(PRPH_RDATA)
    }
    fn write_prph(&mut self, address: u32, value: u32) -> Result<(), Error> {
        let mask = if self.profile.family() == Family::Ax210 {
            0x00ffffff
        } else {
            0x000fffff
        };
        self.write(PRPH_WADDR, (address & mask) | (3 << 24))?;
        self.write(PRPH_WDATA, value)
    }
    fn clear_persistence(&mut self) -> Result<(), Error> {
        if self.profile.family() != Family::Ax200 {
            return Ok(());
        }
        // AX200's pinned MAC cfg has umac_prph_offset=0. AX210 uses
        // +0x300000, but has no persistence-clear step in this donor routine.
        let hpm = self.read_prph(0xa03440)?;
        if hpm & (1 << 12) != 0 {
            if self.read_prph(0xa04d00)? & (1 << 12) != 0 {
                return Err(Error::PersistenceProtected);
            }
            self.write_prph(0xa03440, hpm & !(1 << 12))?;
            if self.read_prph(0xa03440)? & (1 << 12) != 0 {
                return Err(Error::PersistenceProtected);
            }
        }
        Ok(())
    }
    fn run(&mut self, management: ManagementSession) -> Result<Awake, Error> {
        let observed = self.profile.observed();
        if self.read(HW_REV)? != observed.hardware_revision
            || self.read(RF_ID)? != observed.radio_id
        {
            return Err(Error::IdentityChanged);
        }
        // Registration/routing remains inactive. This is not a DMA quiescence
        // proof; the exclusive NativeCsr constructor requires old DMA stopped.
        self.write(INT_MASK, 0)?;
        if self.read(INT_MASK)? != 0 {
            return Err(Error::Rejected {
                register: INT_MASK,
                mask: u32::MAX,
            });
        }
        self.write(INT, u32::MAX)?;
        self.write(FH_INT, u32::MAX)?;
        self.ownership(management)?;
        self.clear_persistence()?;
        self.set(RESET, 0x80)?;
        self.io.delay_us(5000)?;
        self.ownership(management)?;
        self.set_checked(CHICKEN, 0x00800000)?;
        self.set_checked(HPET, 0xffff0000)?;
        self.set_checked(HW_IF, 0x00080000)?;
        self.set_checked(GIO, 2)?;
        let bisr = self.profile.family() == Family::Ax200;
        if bisr {
            self.io.delay_us(2000)?;
        }
        self.set_checked(GP, 4)?;
        let wake = self.poll(GP, 1, 25000);
        if bisr {
            self.io.delay_us(200)?;
        }
        wake?;
        Ok(Awake {
            family: self.profile.family(),
            rf_killed: self.read(GP)? & 0x08000000 == 0,
        })
    }
    /// Consume only a successful MAC-clock epoch, transferring its exclusive
    /// CSR owner to the firmware/ring transport. This is not radio readiness.
    pub fn into_awake(self) -> Result<(C, Profile, Awake), Error> {
        if let State::Awake(status) = self.state {
            Ok((self.io, self.profile, status))
        } else {
            Err(Error::State)
        }
    }
    /// Wake the MAC clock with interrupts masked. Retrying an uncertain reset
    /// requires a new checked ownership/reset epoch, never this used object.
    pub fn wake(&mut self, management: ManagementSession) -> Result<Awake, Error> {
        if self.state != State::Cold {
            return Err(Error::State);
        }
        self.state = State::Poisoned;
        let awake = self.run(management)?;
        self.state = State::Awake(awake);
        Ok(awake)
    }
}

#[cfg(test)]
mod tests;
