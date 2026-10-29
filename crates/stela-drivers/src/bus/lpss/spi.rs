// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2015 Intel Corporation.
// Fractional clock: Copyright (C) 2014 Intel Corporation.
// Clock gates: Copyright (C) 2010-2011 Canonical Ltd, Jeremy Kerr;
// Copyright (C) 2011-2012 Mike Turquette, Linaro Ltd.
// Intel LPSS PCI SPI resources adapted from intel-lpss.c/intel-lpss-pci.c;
// same source pin and notices as the parent LPSS owner. See ../THIRD_PARTY.md.
//! Actual retained PCI LPSS reset/remap/clock resources composed with SSP PIO.
//! Source root clocks are distinct from the observed fractional SSP input.
use super::{Identity, NativeRegisters, NativeResources, Registers, Retired};
use crate::bus::{mmio::owned::Mapping, pci::requester::StoppedRequester, spi::pxa2xx};
use pxa2xx::Timer;

mod profiles;
pub use profiles::Profile;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Platform(super::Error),
    Spi(pxa2xx::Error),
    Configuration,
}
pub struct AttachFailure {
    pub error: Error,
    pub unmodified: Option<NativeResources>,
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
    description: pxa2xx::Description,
    phase: Phase,
}
impl<R: Registers> Owner<R> {
    fn prepare(mut registers: R, chip_selects: u8) -> Result<Self, (Error, Option<R>)> {
        let profile = match registers
            .identity()
            .map_err(Error::Platform)
            .and_then(Profile::select)
        {
            Ok(profile) => profile,
            Err(error) => return Err((error, Some(registers))),
        };
        let maximum = if profile.family() == pxa2xx::Profile::Sunrisepoint {
            1
        } else {
            4
        };
        if chip_selects == 0 || chip_selects > maximum {
            return Err((Error::Configuration, Some(registers)));
        }
        let mut owner = Self {
            registers: Some(registers),
            description: pxa2xx::Description {
                profile: profile.family(),
                input_clock_hz: 0,
                chip_selects,
            },
            phase: Phase::Unmodified,
        };
        let result = (|| {
            let caps = owner.read(0x2fc)?;
            if caps == u32::MAX || caps & (15 << 4) != 2 << 4 {
                return Err(Error::Configuration);
            }
            let base = owner.registers.as_ref().unwrap().physical_base();
            if base == 0 || !base.is_multiple_of(4096) || base.checked_add(0x300).is_none() {
                return Err(Error::Configuration);
            }
            let clock = owner.read(0x200)?;
            // All bits belong to gates or M/N: 0xffffffff is a valid unity
            // divider with both gates on, not an unavailable-register sentinel.
            let numerator = (clock >> 1) & 32767;
            let denominator = (clock >> 16) & 32767;
            let hz = if numerator == 0 || denominator == 0 {
                u64::from(profile.root_clock_hz())
            } else {
                u64::from(profile.root_clock_hz()) * u64::from(numerator) / u64::from(denominator)
            };
            owner.description.input_clock_hz = u32::try_from(hz)
                .ok()
                .filter(|hz| *hz != 0)
                .ok_or(Error::Configuration)?;
            owner.phase = Phase::Touched;
            owner.verified(0x204, 0)?;
            owner.verified(0x204, 7)?;
            // Linux lo_hi_writeq: actual physical BAR, never a CPU pointer.
            owner.write(0x240, base as u32)?;
            owner.write(0x244, (base >> 32) as u32)?;
            owner.verify(0x240, base as u32)?;
            owner.verify(0x244, (base >> 32) as u32)?;
            if caps & (1 << 8) == 0 {
                owner.verified(0x220, 1)?;
            }
            // Same fractional M/N and source gate order as the Linux clock
            // tree. A zero numerator or denominator bypasses to the root.
            owner.verified(0x200, clock | 1)?;
            owner.verified(0x200, clock | 1 | (1 << 31))?;
            owner.phase = Phase::Ready;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(owner),
            Err(error) if owner.phase == Phase::Unmodified => Err((error, owner.registers.take())),
            Err(error) => Err((error, None)),
        }
    }
    fn read(&mut self, offset: usize) -> Result<u32, Error> {
        self.registers
            .as_mut()
            .unwrap()
            .read32(offset)
            .map_err(Error::Platform)
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.registers
            .as_mut()
            .unwrap()
            .write32(offset, value)
            .map_err(Error::Platform)
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
    fn retire(mut self) -> Result<Retired<R>, Error> {
        // The actual SSP core has acknowledged idle, inactive CS and SSE=0.
        // Reverse the source clock gates before asserting the private reset.
        self.phase = Phase::Touched;
        let clock = self.read(0x200)?;
        self.verified(0x200, clock & !(1 << 31))?;
        self.verified(0x200, clock & !((1 << 31) | 1))?;
        self.verified(0x204, 0)?;
        self.phase = Phase::Retired;
        Ok(Retired {
            registers: self.registers.take().unwrap(),
        })
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
// SAFETY: this same original LPSS provider retains the actual stopped canonical
// Function/UC mapping/firmware epoch; prepare acknowledged private reset/remap
// and actual clock gates. The PIO core alone can access these child/private CS
// registers and it never enables a DMA/IRQ service. Quarantine leaks this Owner.
unsafe impl<R: Registers> pxa2xx::Registers for Owner<R> {
    fn description(&self) -> pxa2xx::Description {
        self.description
    }
    fn bytes(&self) -> usize {
        0x300
    }
    fn read32(&mut self, offset: usize) -> Result<u32, pxa2xx::IoError> {
        if offset >= 0x300 || !offset.is_multiple_of(4) {
            return Err(pxa2xx::IoError);
        }
        self.registers
            .as_mut()
            .unwrap()
            .read32(offset)
            .map_err(|_| pxa2xx::IoError)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), pxa2xx::IoError> {
        if offset >= 0x300 || !offset.is_multiple_of(4) {
            return Err(pxa2xx::IoError);
        }
        self.registers
            .as_mut()
            .unwrap()
            .write32(offset, value)
            .map_err(|_| pxa2xx::IoError)
    }
}
pub struct Spi<R: Registers, T: Timer> {
    engine: Option<pxa2xx::Controller<Owner<R>, T>>,
}
impl<R: Registers, T: Timer> Spi<R, T> {
    /// # Safety
    /// The original retained provider grants this exact source-listed PCI
    /// function's powered root clock, board native-CS pins and firmware/PUNIT
    /// arbitration. Source root frequency is an actual established platform
    /// clock, not authority inferred solely from its PCI ID. No IRQ/DMA child
    /// exists, and all prior traffic/callbacks were drained by this same owner.
    pub unsafe fn attach(
        registers: R,
        timer: T,
        chip_selects: u8,
        timeout_us: u64,
    ) -> Result<Self, (Error, Option<R>)> {
        if !timer.calibrated() || timeout_us == 0 || timer.check_duration(timeout_us).is_err() {
            return Err((Error::Configuration, Some(registers)));
        }
        let owner = Owner::prepare(registers, chip_selects)?;
        let mut engine = match pxa2xx::Controller::new(owner, timer, timeout_us) {
            Ok(engine) => engine,
            Err((_, owner, _)) => {
                drop(owner);
                return Err((Error::Configuration, None));
            }
        };
        engine
            .initialize()
            .map_err(|error| (Error::Spi(error), None))?;
        Ok(Self {
            engine: Some(engine),
        })
    }
    pub fn message(
        &mut self,
        device: pxa2xx::Device,
        transfers: &mut [pxa2xx::Transfer<'_>],
    ) -> Result<(), Error> {
        self.engine
            .as_mut()
            .unwrap()
            .message(device, transfers)
            .map_err(Error::Spi)
    }
    pub fn shutdown(mut self) -> Result<(Retired<R>, T), Error> {
        let engine = self.engine.take().unwrap();
        let (owner, timer) = match engine.release() {
            Ok(owners) => owners,
            Err(engine) => return Err(Error::Spi(engine.failure().unwrap())),
        };
        Ok((owner.retire()?, timer))
    }
}
impl<T: Timer> Spi<NativeRegisters, T> {
    /// # Safety
    /// The parent's NativeRegisters claim and this adapter's root-clock/board/
    /// arbitration contracts hold for the same actual original stopped function
    /// and its complete exclusive UC BAR0 mapping, including retained Drop.
    pub unsafe fn attach_native(
        requester: StoppedRequester,
        mapping: Mapping,
        timer: T,
        chip_selects: u8,
        timeout_us: u64,
    ) -> Result<Self, AttachFailure> {
        // SAFETY: caller supplies the actual original stopped function/UC grant.
        let registers = unsafe { NativeRegisters::claim(requester, mapping) }.map_err(
            |(error, resources)| AttachFailure {
                error: Error::Platform(error),
                unmodified: Some(resources),
            },
        )?;
        // SAFETY: same genuine source clock/board/native firmware owner.
        unsafe { Self::attach(registers, timer, chip_selects, timeout_us) }.map_err(
            |(error, registers)| AttachFailure {
                error,
                unmodified: registers.map(NativeRegisters::into_resources),
            },
        )
    }
}
impl<R: Registers, T: Timer> Drop for Spi<R, T> {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.take() {
            core::mem::forget(engine);
        }
    }
}

#[cfg(test)]
mod tests;
