// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Native NHI controller preparation from Linux pci.c/nhi.c.
//!
//! Intel force-power/FW_READY/LTR, USB4v2 host reset and interrupt
//! masking, which `nhi_probe` runs before either connection manager starts.
//! This never claims CM ownership, enables PCI bus mastering, supplies
//! an identity DMA domain or starts rings/tunnels. Platform grants precede it.
use super::ring::{CAPABILITIES, Registers};
use crate::bus::pci::ConfigSpace;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
const RESET: usize = 0x39898;
const INTERRUPT: usize = 0x38200;
const MASK_CLEAR: usize = 0x38208;
const NOTIFY: usize = 0x37800;
const INT_CLEAR: usize = 0x37808;
const VS_FW_READY: u16 = 0xc8;
const VS_LTR: u16 = 0xe0;
const VS_MAX_LTR: u16 = 0xe4;
const VS_FORCE: u16 = 0xfc;
const FORCE: u32 = 1 << 1;
const DMA_DELAY: u32 = 0xff00_0000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_controllers() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    IntelDiscrete,
    IntelIntegrated,
    Usb4Compliant,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptStyle {
    IntelAutoClear,
    Usb4MaskClear,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    vendor: u16,
    device: u16,
    class: u32,
    family: Family,
}
impl Profile {
    pub fn vendor(self) -> u16 {
        self.vendor
    }
    pub fn device(self) -> u16 {
        self.device
    }
    pub fn class(self) -> u32 {
        self.class
    }
    pub fn family(self) -> Family {
        self.family
    }
    pub fn interrupt_style(self) -> InterruptStyle {
        if self.vendor == 0x8086 {
            InterruptStyle::IntelAutoClear
        } else {
            InterruptStyle::Usb4MaskClear
        }
    }
    /// The NHI profile `pci.c::nhi_ids` gives this identity, by its 24-bit
    /// class code.
    pub fn identify(vendor: u16, device: u16, class: u32) -> Result<Self, Error> {
        Self::select(vendor, device, class)
    }
    fn select(vendor: u16, device: u16, class: u32) -> Result<Self, Error> {
        if vendor == 0 || vendor == u16::MAX || device == u16::MAX || class == 0xff_ffff {
            return Err(Error::Identity);
        }
        if vendor == 0x8086 && matches!(device, 0x1513 | 0x151a | 0x1547 | 0x156a | 0x156c) {
            return Err(Error::LegacyUnsupported);
        }
        // pci.c::nhi_ids attaches icl_nhi_ops to these exact integrated IDs;
        // the generic USB4 class must not accidentally inherit vendor registers.
        let family = if vendor == 0x8086
            && matches!(
                device,
                0x8a0d
                    | 0x8a17
                    | 0x9a1b
                    | 0x9a1d
                    | 0x9a1f
                    | 0x9a21
                    | 0x463e
                    | 0x466d
                    | 0xa73e
                    | 0xa76d
                    | 0x7eb2
                    | 0x7ec2
                    | 0x7ec3
                    | 0xa833
                    | 0xa834
                    | 0xe333
                    | 0xe334
                    | 0xe433
                    | 0xe434
                    | 0x4d33
            ) {
            Family::IntelIntegrated
        } else if vendor == 0x8086
            && matches!(
                device,
                0x1575
                    | 0x1577
                    | 0x15dd
                    | 0x15bf
                    | 0x15dc
                    | 0x15d9
                    | 0x15d2
                    | 0x15de
                    | 0x15e8
                    | 0x15eb
                    | 0x5781
                    | 0x5784
            )
        {
            Family::IntelDiscrete
        } else if class == 0x0c0340 {
            Family::Usb4Compliant
        } else {
            return Err(Error::Unsupported);
        };
        if !matches!(class, 0x088000 | 0x0c0340) {
            return Err(Error::Identity);
        }
        Ok(Self {
            vendor,
            device,
            class,
            family,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub profile: Profile,
    pub capabilities: u32,
    pub hop_count: u16,
    pub version: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Unsupported,
    LegacyUnsupported,
    PciState,
    PciRead(u16),
    PciRejected(u16),
    Mapping,
    Capabilities,
    Busy,
    RegisterRead(usize),
    RegisterRejected(usize),
    ClockOverflow,
    ClockRegressed,
    FirmwareTimeout,
    ResetTimeout,
    Stopped,
    Poisoned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Firmware {
        next: u64,
        deadline: u64,
        reads: u16,
    },
    Reset {
        earliest: u64,
        deadline: u64,
    },
    Prepared,
    Fault,
}
/// Caller-serialized controller preparation. Clock observations use one
/// monotonic millisecond source; polls never sleep or invent timer progress.
pub struct Controller<'a, C: ConfigSpace, R: Registers> {
    configuration: &'a mut C,
    registers: Arc<R>,
    profile: Profile,
    capabilities: u32,
    phase: Phase,
    last_now: Option<u64>,
    mutated: bool,
}
impl<'a, C: ConfigSpace, R: Registers> Controller<'a, C, R> {
    /// # Safety
    /// ConfigSpace and Registers identify the same live physical NHI
    /// requester, ownership/reset epoch and BAR0. The kept Registers owns
    /// its PCI function/MMIO/power reservation, including quarantine.
    /// The platform selected the connection manager as Linux's
    /// `nhi_select_cm` does (firmware ICM, or a software CM), and no other
    /// host software controls this NHI or its rings. Shared power
    /// resources and PCI D0/memory decode are established and kept. The
    /// platform resolves the firmware IMR_VALID property and rejects invalid
    /// firmware instead of substituting an unknown/default-success result. All
    /// prior NHI DMA/posted writes and IRQ/deferred work are stopped/drained;
    /// no active ring or tunneled path may be reset. PCI bus mastering stays
    /// disabled until its requester-isolating domain has been attached.
    ///
    /// Safe code cannot pair independent physical PCI and MMIO capabilities:
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::{pci::ConfigSpace, thunderbolt::{
    ///     controller::Controller, ring::Registers,
    /// }};
    /// fn pair<C: ConfigSpace, R: Registers>(pci: &mut C, registers: Arc<R>) {
    ///     let _controller = Controller::new(pci, registers);
    /// }
    /// ```
    pub unsafe fn new(configuration: &'a mut C, registers: Arc<R>) -> Result<Self, Error> {
        let identity = configuration.read32(0);
        if identity == u32::MAX {
            return Err(Error::PciRead(0));
        }
        let class = configuration.read32(8);
        if class == u32::MAX {
            return Err(Error::PciRead(8));
        }
        let profile = Profile::select(identity as u16, (identity >> 16) as u16, class >> 8)?;
        let header = configuration.read8(0x0e);
        if header & 0x7f != 0 {
            return Err(Error::Identity);
        }
        Self::pci_state(configuration)?;
        if registers.bytes() < RESET + 4 {
            return Err(Error::Mapping);
        }
        let capabilities = registers.read32(CAPABILITIES);
        if capabilities == u32::MAX || capabilities & 0x3ff == 0 {
            return Err(Error::Capabilities);
        }
        Ok(Self {
            configuration,
            registers,
            profile,
            capabilities,
            phase: Phase::New,
            last_now: None,
            mutated: false,
        })
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn registers(&self) -> Arc<R> {
        self.registers.clone()
    }
    fn pci_state(configuration: &C) -> Result<(), Error> {
        let command = configuration.read16(4);
        if command == u16::MAX {
            return Err(Error::PciRead(4));
        }
        if command & 2 == 0 || command & 4 != 0 {
            return Err(Error::PciState);
        }
        Ok(())
    }
    fn identity(&self) -> Result<(), Error> {
        let expected = u32::from(self.profile.vendor) | (u32::from(self.profile.device) << 16);
        if self.configuration.read32(0) != expected
            || self.configuration.read32(8) >> 8 != self.profile.class
        {
            return Err(Error::Identity);
        }
        Self::pci_state(self.configuration)
    }
    fn read_pci(&self, offset: u16) -> Result<u32, Error> {
        let value = self.configuration.read32(offset);
        if value == u32::MAX {
            Err(Error::PciRead(offset))
        } else {
            Ok(value)
        }
    }
    fn write_pci(&mut self, offset: u16, value: u32, mask: u32) -> Result<(), Error> {
        self.identity()?;
        self.mutated = true;
        self.configuration.write32(offset, value);
        if self.configuration.read32(offset) & mask != value & mask {
            return Err(Error::PciRejected(offset));
        }
        self.identity()
    }
    fn read_register(&self, offset: usize) -> Result<u32, Error> {
        let value = self.registers.read32(offset);
        if value == u32::MAX {
            Err(Error::RegisterRead(offset))
        } else {
            Ok(value)
        }
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.phase = Phase::Fault;
        Err(error)
    }
    fn preflight(&self) -> Result<(), Error> {
        self.identity()?;
        if self.read_register(CAPABILITIES)? != self.capabilities {
            return Err(Error::Capabilities);
        }
        for hop in 0..usize::from((self.capabilities & 0x3ff) as u16) {
            for base in [0x19800, 0x29800] {
                if self.read_register(base + hop * 32)? & (1 << 31) != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
    fn force_power(&mut self, now: u64) -> Result<(), Error> {
        let deadline = now.checked_add(1050).ok_or(Error::ClockOverflow)?;
        let value = self.read_pci(VS_FORCE)?;
        let value = (value & !DMA_DELAY) | (0x22 << 24) | FORCE;
        self.write_pci(VS_FORCE, value, DMA_DELAY | FORCE)?;
        self.phase = Phase::Firmware {
            next: now,
            deadline,
            reads: 0,
        };
        Ok(())
    }
    fn reset_or_mask(&mut self, now: u64) -> Result<Option<Prepared>, Error> {
        if (self.capabilities >> 16) & 255 < 0x40 {
            return self.mask(now);
        }
        let earliest = now.checked_add(100).ok_or(Error::ClockOverflow)?;
        let deadline = earliest.checked_add(500).ok_or(Error::ClockOverflow)?;
        self.mutated = true;
        self.registers.write32(RESET, 1);
        // HRR can self-clear immediately; a zero read is not completion until
        // the source-required minimum 100 ms interval has elapsed.
        let _ = self.read_register(RESET)?;
        self.phase = Phase::Reset { earliest, deadline };
        Ok(None)
    }
    fn mask(&mut self, now: u64) -> Result<Option<Prepared>, Error> {
        self.identity()?;
        let hops = (self.capabilities & 0x3ff) as usize;
        for index in 0..(2 * hops).div_ceil(32) {
            let offset = index * 4;
            self.mutated = true;
            match self.profile.interrupt_style() {
                InterruptStyle::IntelAutoClear => {
                    // All-one interrupt enables are valid, not a bus-failure
                    // sentinel. Verify the zero write instead of rejecting it.
                    let _ = self.registers.read32(INTERRUPT + offset);
                    self.registers.write32(INTERRUPT + offset, 0);
                }
                InterruptStyle::Usb4MaskClear => {
                    self.registers.write32(MASK_CLEAR + offset, u32::MAX)
                }
            }
            if self.registers.read32(INTERRUPT + offset) != 0 {
                return Err(Error::RegisterRejected(INTERRUPT + offset));
            }
        }
        for index in 0..(3 * hops).div_ceil(32) {
            let offset = index * 4;
            match self.profile.interrupt_style() {
                InterruptStyle::IntelAutoClear => {
                    let _ = self.registers.read32(NOTIFY + offset);
                }
                InterruptStyle::Usb4MaskClear => {
                    self.registers.write32(INT_CLEAR + offset, u32::MAX)
                }
            }
        }
        // Same-function MMIO read flushes posted writes. These source-defined
        // mask/clear effects still do not drain platform IRQ/deferred handlers.
        if self.read_register(CAPABILITIES)? != self.capabilities {
            return Err(Error::Capabilities);
        }
        self.identity()?;
        if self.profile.family == Family::IntelIntegrated {
            self.force_power(now)?;
            return Ok(None);
        }
        self.prepared()
    }
    fn prepared(&mut self) -> Result<Option<Prepared>, Error> {
        self.identity()?;
        if self.read_register(CAPABILITIES)? != self.capabilities {
            return Err(Error::Capabilities);
        }
        self.phase = Phase::Prepared;
        Ok(Some(Prepared {
            profile: self.profile,
            capabilities: self.capabilities,
            hop_count: (self.capabilities & 0x3ff) as u16,
            version: (self.capabilities >> 16) as u8,
        }))
    }
    pub fn poll(&mut self, now_ms: u64) -> Result<Option<Prepared>, Error> {
        match self.phase {
            Phase::Prepared => return Err(Error::Stopped),
            Phase::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if self.last_now.is_some_and(|last| now_ms < last) {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = Some(now_ms);
        let result = (|| match self.phase {
            Phase::New => {
                self.preflight()?;
                let reset_budget = if (self.capabilities >> 16) & 255 >= 0x40 {
                    600
                } else {
                    0
                };
                let firmware_budget = if self.profile.family == Family::IntelIntegrated {
                    1050
                } else {
                    0
                };
                let _ = now_ms
                    .checked_add(reset_budget + firmware_budget)
                    .ok_or(Error::ClockOverflow)?;
                self.reset_or_mask(now_ms)
            }
            Phase::Firmware {
                next,
                deadline,
                reads,
            } => {
                if now_ms >= deadline {
                    return Err(Error::FirmwareTimeout);
                }
                if now_ms < next {
                    return Ok(None);
                }
                if reads >= 350 {
                    return Err(Error::FirmwareTimeout);
                }
                if self.read_pci(VS_FW_READY)? & (1 << 31) != 0 {
                    let ltr = self.read_pci(VS_MAX_LTR)? & 0xffff;
                    self.write_pci(VS_LTR, ltr | (ltr << 16), u32::MAX)?;
                    self.prepared()
                } else {
                    self.phase = Phase::Firmware {
                        next: now_ms.checked_add(3).ok_or(Error::ClockOverflow)?,
                        deadline,
                        reads: reads + 1,
                    };
                    Ok(None)
                }
            }
            Phase::Reset { earliest, deadline } => {
                if now_ms >= deadline {
                    return Err(Error::ResetTimeout);
                }
                if now_ms < earliest {
                    return Ok(None);
                }
                if self.read_register(RESET)? & 1 != 0 {
                    return Ok(None);
                }
                self.mask(now_ms)
            }
            _ => Err(Error::Stopped),
        })();
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
}
impl<C: ConfigSpace, R: Registers> Drop for Controller<'_, C, R> {
    fn drop(&mut self) {
        if self.mutated && self.phase != Phase::Prepared {
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
            core::mem::forget(self.registers.clone());
        }
    }
}

#[cfg(test)]
mod tests;
