// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2015 Intel Corporation.
// Fractional clock: Copyright (C) 2014 Intel Corporation.
// Clock gates: Copyright (C) 2010-2011 Canonical Ltd, Jeremy Kerr;
// Copyright (C) 2011-2012 Mike Turquette, Linaro Ltd.
// Intel LPSS PCI SPI resources adapted from intel-lpss.c/intel-lpss-pci.c;
// same source pin and notices as the parent LPSS owner. See ../THIRD_PARTY.md.
//! PCI LPSS reset/remap/clock resources composed with SSP PIO.
//! Source root clocks are distinct from the observed fractional SSP input.
use super::{Identity, NativeRegisters, NativeResources, Registers, Retired};
use crate::bus::{mmio::owned::Mapping, pci::requester::StoppedRequester, spi::pxa2xx};
use core::mem::ManuallyDrop;
use pxa2xx::Timer;
mod custody;
pub use custody::{AttachFailure, AttachStage, Failure};

mod profiles;
pub use profiles::Profile;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Platform(super::Error),
    Spi(pxa2xx::Error),
    Configuration,
    ProgressExhausted,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Unmodified,
    Touched,
    Ready,
    Retired,
}
struct Owner<R: Registers> {
    registers: Option<R>,
    description: Option<pxa2xx::Description>,
    phase: Phase,
    progress: pxa2xx::Progress,
}
impl<R: Registers> Owner<R> {
    fn new(registers: R) -> Self {
        Self {
            registers: Some(registers),
            description: None,
            phase: Phase::Unmodified,
            progress: pxa2xx::Progress::default(),
        }
    }
    fn prepare(&mut self, chip_selects: u8) -> Result<(), Error> {
        let profile = self
            .registers
            .as_mut()
            .unwrap()
            .identity()
            .map_err(Error::Platform)
            .and_then(Profile::select)?;
        let maximum = if profile.family() == pxa2xx::Profile::Sunrisepoint {
            1
        } else {
            4
        };
        if chip_selects == 0 || chip_selects > maximum {
            return Err(Error::Configuration);
        }
        self.description = Some(pxa2xx::Description {
            profile: profile.family(),
            input_clock_hz: 0,
            chip_selects,
        });
        (|| {
            let caps = self.read(0x2fc)?;
            if caps == u32::MAX || caps & (15 << 4) != 2 << 4 {
                return Err(Error::Configuration);
            }
            let base = self.registers.as_ref().unwrap().physical_base();
            if base == 0 || !base.is_multiple_of(4096) || base.checked_add(0x300).is_none() {
                return Err(Error::Configuration);
            }
            let clock = self.read(0x200)?;
            // All bits belong to gates or M/N: 0xffffffff is a valid unity
            // divider with both gates on, not an unavailable-register sentinel.
            let numerator = (clock >> 1) & 32767;
            let denominator = (clock >> 16) & 32767;
            let hz = if numerator == 0 || denominator == 0 {
                u64::from(profile.root_clock_hz())
            } else {
                u64::from(profile.root_clock_hz()) * u64::from(numerator) / u64::from(denominator)
            };
            self.description.as_mut().unwrap().input_clock_hz = u32::try_from(hz)
                .ok()
                .filter(|hz| *hz != 0)
                .ok_or(Error::Configuration)?;
            self.phase = Phase::Touched;
            self.verified(0x204, 0)?;
            self.verified(0x204, 7)?;
            // Linux lo_hi_writeq: physical BAR, never a CPU pointer.
            self.write(0x240, base as u32)?;
            self.write(0x244, (base >> 32) as u32)?;
            self.verify(0x240, base as u32)?;
            self.verify(0x244, (base >> 32) as u32)?;
            if caps & (1 << 8) == 0 {
                self.verified(0x220, 1)?;
            }
            // Same fractional M/N and source gate order as the Linux clock
            // tree. A zero numerator or denominator bypasses to the root.
            self.verified(0x200, clock | 1)?;
            self.verified(0x200, clock | 1 | (1 << 31))?;
            self.phase = Phase::Ready;
            Ok(())
        })()
    }
    fn read(&mut self, offset: usize) -> Result<u32, Error> {
        let access = pxa2xx::Access::Read { offset };
        let next = self.pending(access)?;
        let value = self
            .registers
            .as_mut()
            .unwrap()
            .read32(offset)
            .map_err(Error::Platform)?;
        self.accepted(next, access, Some(value));
        Ok(value)
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let access = pxa2xx::Access::Write { offset, value };
        let next = self.pending(access)?;
        self.registers
            .as_mut()
            .unwrap()
            .write32(offset, value)
            .map_err(Error::Platform)?;
        self.accepted(next, access, None);
        Ok(())
    }
    fn pending(&mut self, access: pxa2xx::Access) -> Result<u64, Error> {
        let next = self
            .progress
            .accepted
            .checked_add(1)
            .ok_or(Error::ProgressExhausted)?;
        self.progress.pending = Some(access);
        Ok(next)
    }
    fn accepted(&mut self, next: u64, access: pxa2xx::Access, read_value: Option<u32>) {
        self.progress.accepted = next;
        self.progress.pending = None;
        self.progress.last = Some(pxa2xx::AccessResult { access, read_value });
    }
    fn verify(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let observed = self.read(offset)?;
        if observed != value {
            return Err(Error::Platform(super::Error::Register {
                offset,
                expected: value,
                observed,
            }));
        }
        Ok(())
    }
    fn verified(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.write(offset, value)?;
        self.verify(offset, value)
    }
    fn retire(&mut self) -> Result<(), Error> {
        // The SSP core has acknowledged idle, inactive CS and SSE=0.
        // Reverse the source clock gates before asserting the private reset.
        self.phase = Phase::Touched;
        let clock = self.read(0x200)?;
        self.verified(0x200, clock & !(1 << 31))?;
        self.verified(0x200, clock & !((1 << 31) | 1))?;
        self.verified(0x204, 0)?;
        self.phase = Phase::Retired;
        Ok(())
    }
}
impl<R: Registers> Drop for Owner<R> {
    fn drop(&mut self) {
        if !matches!(self.phase, Phase::Unmodified | Phase::Retired)
            && let Some(r) = self.registers.take()
        {
            core::mem::forget(r);
        }
    }
}
// SAFETY: this same original LPSS provider keeps the stopped canonical
// Function/UC mapping/firmware epoch; prepare acknowledged private reset/remap
// and clock gates. The PIO core alone can access these child/private CS
// registers and it never enables a DMA/IRQ service. Quarantine leaks this Owner.
unsafe impl<R: Registers> pxa2xx::Registers for Owner<R> {
    fn description(&self) -> pxa2xx::Description {
        self.description.unwrap()
    }
    fn bytes(&self) -> usize {
        0x300
    }
    fn read32(&mut self, offset: usize) -> Result<u32, pxa2xx::IoError> {
        if offset >= 0x300 || !offset.is_multiple_of(4) {
            return Err(pxa2xx::IoError::InvalidRegister { offset });
        }
        self.registers
            .as_mut()
            .unwrap()
            .read32(offset)
            .map_err(pxa2xx::IoError::Lpss)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), pxa2xx::IoError> {
        if offset >= 0x300 || !offset.is_multiple_of(4) {
            return Err(pxa2xx::IoError::InvalidRegister { offset });
        }
        self.registers
            .as_mut()
            .unwrap()
            .write32(offset, value)
            .map_err(pxa2xx::IoError::Lpss)
    }
}
pub struct Spi<R: Registers, T: Timer> {
    engine: pxa2xx::Controller<Owner<R>, T>,
}
impl<R: Registers, T: Timer> Spi<R, T> {
    pub fn message(
        &mut self,
        device: pxa2xx::Device,
        transfers: &mut [pxa2xx::Transfer<'_>],
    ) -> Result<(), Error> {
        self.engine.message(device, transfers).map_err(Error::Spi)
    }
}

#[cfg(test)]
mod tests;
