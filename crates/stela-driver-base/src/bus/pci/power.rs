// SPDX-License-Identifier: GPL-2.0-only
// Copyright 1993 -- 1997 Drew Eckhardt, Frederic Potter, David Mosberger-Tang
// Copyright 1997 -- 2000 Martin Mares <mj@ucw.cz>
// Copyright (c) 2026 Stela contributors
//! Endpoint PCI PM, with stable main power supplied by the producer.
//! PMCSR sequences follow Linux pci.c at cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
//! This owns real configuration effects, not platform rails or a wake route.
use super::regs;
use super::{CapabilityError, ConfigSpace, Function, Layout, msi::MsiConfigSpace};

const STATE: u16 = 3;
const NO_SOFT_RESET: u16 = 8;
const PME_ENABLE: u16 = 0x100;
const PME_STATUS: u16 = 0x8000;
const DATA_SELECT: u16 = 0x1e00;
const D3_DELAY: u64 = 10_000;
const READY_TIMEOUT: u64 = 60_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity,
    Capability,
    Unsupported,
    Clock,
    Read(u16),
    Readback(u16),
    State,
    BusMaster,
    Bars,
    NotReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    D0,
    D3hot,
    /// An effect or lost configuration access prevents safe register use.
    Unknown,
}

/// The state in which the prepared source must be capable of waking. PME is
/// commonly armed in D0 for a subsequent D3hot transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeState {
    D0,
    D3hot,
}

/// Retained, calibrated process-context timing, or an explicit device model.
///
/// # Safety
/// Successful waits must consume at least the requested real microseconds.
/// `check` must refuse unavailable timing before any hardware effects. The
/// timer must remain usable under the original platform's power/context grant.
pub unsafe trait Timer {
    fn check(&self) -> Result<(), Error>;
    fn wait_us(&self, microseconds: u64) -> Result<(), Error>;
}
// SAFETY: a shared timer is the same timer.
unsafe impl<T: Timer + ?Sized> Timer for alloc::rc::Rc<T> {
    fn check(&self) -> Result<(), Error> {
        (**self).check()
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), Error> {
        (**self).wait_us(microseconds)
    }
}
// SAFETY: the canonical checked Clock supplies calibrated elapsed ticks
// and modular waits. No private timer or absolute counter deadline is used.
unsafe impl Timer for crate::Clock {
    fn check(&self) -> Result<(), Error> {
        self.check_duration(READY_TIMEOUT).map_err(|_| Error::Clock)
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), Error> {
        self.check()?;
        self.try_delay(microseconds).map_err(|_| Error::Clock)
    }
}

/// The original endpoint configuration, platform power/exclusion and timing
/// owners. Access is withheld throughout D3hot or an uncertain transition.
/// Unfinished Drop keeps all three, including the stable-rail grant.
pub struct Power<C: MsiConfigSpace, T: Timer, P> {
    function: Option<Function<C>>,
    timer: Option<T>,
    platform: Option<P>,
    capability: u16,
    pmc: u16,
    state: State,
    bars: [u32; 7],
    command: u16,
    d3_delay: u64,
}

fn word<C: ConfigSpace>(c: &C, offset: u16) -> Result<u16, Error> {
    match c.read16(offset) {
        u16::MAX => Err(Error::Read(offset)),
        value => Ok(value),
    }
}
fn identity<C: ConfigSpace>(f: &Function<C>) -> Result<(), Error> {
    if f.config.read32(0) != u32::from(f.vendor) | u32::from(f.device) << 16
        || f.vendor == u16::MAX
        || f.config.read8(0x0e) & 0x7f != 0
        || f.config.read32(8) >> 8 != u32::from_be_bytes([0, f.class[0], f.class[1], f.class[2]])
    {
        return Err(Error::Identity);
    }
    Ok(())
}

/// Validate every known capability's complete occupied extent before effects.
/// Unknown body layouts cannot authorize a PM header hidden inside their body.
fn discover<C: MsiConfigSpace>(c: &C) -> Result<(u16, u16), Error> {
    if word(c, 6)? & 0x10 == 0 {
        return Err(Error::Capability);
    }
    let mut pm = None;
    for entry in c.capabilities() {
        let entry = entry.map_err(|error| match error {
            CapabilityError::FailedRead { offset } => Error::Read(offset),
            _ => Error::Capability,
        })?;
        match entry.id {
            1 => {
                if pm.is_some() {
                    return Err(Error::Capability);
                }
                let pmc = word(c, entry.offset + 2)?;
                if !(1..=3).contains(&(pmc & 7)) {
                    return Err(Error::Unsupported);
                }
                pm = Some((entry.offset, pmc));
            }
            2 | 3 | 4 | 5 | 7 | 9 | 0x0d | 0x10 | 0x11 | 0x12 | 0x13 => {
                if entry.layout != Layout::Sized {
                    return Err(Error::Capability);
                }
            }
            _ => return Err(Error::Unsupported),
        }
    }
    pm.ok_or(Error::Capability)
}

impl<C: MsiConfigSpace, T: Timer, P> Power<C, T, P> {
    /// # Safety
    /// Transfer the original endpoint and its exclusive configuration/
    /// resource ownership. `platform` is the originating stable-rail,
    /// reset/removal/firmware/multifunction exclusion owner, kept until
    /// verified D0 release; a caller-created flag, number or unrelated object
    /// is never this permission. It keeps main/auxiliary rails and links valid for
    /// this entire lifetime, including D3hot; firmware, peers and multifunction
    /// siblings cannot revoke them. The device/board admits this PM sequence.
    /// These are producer grants, not facts inferred from PCI IDs. This
    /// does not obtain ACPI/platform wake, auxiliary-power or D3cold permission.
    /// All operations/final releases obey the original process-context rules.
    pub unsafe fn attach(
        function: Function<C>,
        timer: T,
        platform: P,
        d3_delay_us: u64,
    ) -> Result<Self, (Error, Function<C>, T, P)> {
        let validation = (|| {
            timer.check()?;
            if !(D3_DELAY..=READY_TIMEOUT).contains(&d3_delay_us) {
                return Err(Error::Clock);
            }
            identity(&function)?;
            let (offset, pmc) = discover(&function.config)?;
            if word(&function.config, offset + 4)? & STATE != 0 {
                return Err(Error::State);
            }
            Ok((offset, pmc))
        })();
        match validation {
            Ok((capability, pmc)) => Ok(Self {
                function: Some(function),
                timer: Some(timer),
                platform: Some(platform),
                capability,
                pmc,
                state: State::D0,
                bars: [0; 7],
                command: 0,
                d3_delay: d3_delay_us,
            }),
            Err(error) => Err((error, function, timer, platform)),
        }
    }
    pub fn state(&self) -> State {
        self.state
    }

    fn validate(&self, expected: State) -> Result<u16, Error> {
        if self.state != expected || expected == State::Unknown {
            return Err(Error::State);
        }
        let f = self.function.as_ref().expect("retained");
        identity(f)?;
        if discover(&f.config)? != (self.capability, self.pmc) {
            return Err(Error::Capability);
        }
        let csr = word(&f.config, self.capability + 4)?;
        if csr & STATE != if expected == State::D0 { 0 } else { 3 } {
            return Err(Error::State);
        }
        Ok(csr)
    }
    fn checked(&mut self, expected: State) -> Result<u16, Error> {
        if self.state != expected || expected == State::Unknown {
            return Err(Error::State);
        }
        match self.validate(expected) {
            Ok(csr) => Ok(csr),
            Err(error) => {
                self.state = State::Unknown;
                Err(error)
            }
        }
    }

    /// Access the original function only after D0 validation.
    ///
    /// # Safety
    /// Preserve the original function/config owner, address, resource and PM
    /// capability epoch. Never extract/replace it or return a raw access path.
    /// Do not alter PMCSR, rail/link power or resource assignments, or reenter
    /// this owner. The caller owns all device DMA/IRQ programming and ordering.
    pub unsafe fn with_d0<R>(
        &mut self,
        action: impl FnOnce(&mut Function<C>) -> R,
    ) -> Result<R, Error> {
        self.checked(State::D0)?;
        self.state = State::Unknown;
        let result = action(self.function.as_mut().expect("retained"));
        self.state = State::D0;
        self.checked(State::D0)?;
        Ok(result)
    }

    /// Configure PME generation and acknowledge its old status, as
    /// Linux __pci_pme_active does. This does not install a platform wake route.
    ///
    /// # Safety
    /// On enable, the caller owns this device's prepared wake source,
    /// platform route and auxiliary-power/board/multifunction coordination for
    /// the intended state. On disable, wake/IRQ users cannot race this change.
    pub unsafe fn configure_pme(&mut self, wake: WakeState, enable: bool) -> Result<(), Error> {
        let state = self.state;
        if state == State::Unknown {
            return Err(Error::State);
        }
        let csr = self.checked(state)?;
        let support = match wake {
            WakeState::D0 => 1 << 11,
            WakeState::D3hot => 1 << 14,
        };
        if enable && self.pmc & support == 0 {
            return Err(Error::Unsupported);
        }
        self.state = State::Unknown;
        let value =
            (csr & (STATE | DATA_SELECT)) | PME_STATUS | if enable { PME_ENABLE } else { 0 };
        let c = &mut self.function.as_mut().expect("retained").config;
        c.write16(self.capability + 4, value);
        let observed = word(c, self.capability + 4)?;
        if observed & (STATE | PME_ENABLE | DATA_SELECT)
            != value & (STATE | PME_ENABLE | DATA_SELECT)
        {
            return Err(Error::Readback(self.capability + 4));
        }
        self.state = state;
        Ok(())
    }

    /// Enter stable-rail D3hot. No MMIO or automatic engine restart follows.
    ///
    /// # Safety
    /// Submissions/engines are stopped, all translated/peer/bypass DMA
    /// and posted writes completed, and interrupts/callbacks/work are masked
    /// and drained. Keep their original owners and payloads through resume
    /// and full device reinitialization. BusMaster-clear below is a containment
    /// check, never this completion proof. Device-specific wake is already
    /// programmed under board/platform permission if PME is enabled.
    pub unsafe fn suspend(&mut self) -> Result<(), Error> {
        if self.state != State::D0 {
            return Err(Error::State);
        }
        self.timer.as_ref().expect("retained").check()?;
        let csr = self.checked(State::D0)?;
        if csr & PME_ENABLE != 0 && self.pmc & (1 << 14) == 0 {
            return Err(Error::Unsupported);
        }
        let c = &mut self.function.as_mut().expect("retained").config;
        let command = match word(c, 4) {
            Ok(command) => command,
            Err(error) => {
                self.state = State::Unknown;
                return Err(error);
            }
        };
        if command & regs::COMMAND_MASTER != 0 {
            return Err(Error::BusMaster);
        }
        let bars = core::array::from_fn(|i| c.read32(bar_offset(i)));
        if bars.contains(&u32::MAX) {
            self.state = State::Unknown;
            return Err(Error::Bars);
        }
        if bars[6] & 1 != 0 {
            return Err(Error::Bars);
        }
        self.bars = bars;
        self.command = command | regs::COMMAND_INTX_DISABLE;
        self.state = State::Unknown;
        c.write16(4, self.command & !3);
        if word(c, 4)? != self.command & !3 {
            return Err(Error::Readback(4));
        }
        // Do not replay a pending PME_Status W1C during an ordinary transition.
        c.write16(self.capability + 4, (csr & (DATA_SELECT | PME_ENABLE)) | 3);
        self.timer
            .as_ref()
            .expect("retained")
            .wait_us(self.d3_delay)?;
        if word(c, self.capability + 4)? & (STATE | PME_ENABLE) != 3 | (csr & PME_ENABLE) {
            return Err(Error::Readback(self.capability + 4));
        }
        self.state = State::D3hot;
        Ok(())
    }

    /// Leave D3hot, wait for configuration readiness, restore/verify original
    /// BARs with decoding off, then restore only stopped, INTx-masked decoding.
    /// The driver must reinitialize its engines, MSI/MSI-X and device state.
    pub fn resume(&mut self) -> Result<(), Error> {
        if self.state != State::D3hot {
            return Err(Error::State);
        }
        self.timer.as_ref().expect("retained").check()?;
        let csr = self.checked(State::D3hot)?;
        self.state = State::Unknown;
        let c = &mut self.function.as_mut().expect("retained").config;
        // Linux pci_power_up's whole-word zero preserves pending PME_Status
        // while disabling PME generation and selecting D0.
        c.write16(self.capability + 4, 0);
        let timer = self.timer.as_ref().expect("retained");
        timer.wait_us(self.d3_delay)?;
        let mut remaining = READY_TIMEOUT;
        let mut delay = 1_000;
        loop {
            if c.read32(0) != 0xffff_0001 && c.read16(4) != u16::MAX {
                break;
            }
            if remaining == 0 {
                return Err(Error::NotReady);
            }
            let wait = delay.min(remaining);
            timer.wait_us(wait)?;
            remaining -= wait;
            delay = (delay * 2).min(1_000_000);
        }
        let f = self.function.as_ref().expect("retained");
        identity(f)?;
        if discover(&f.config)? != (self.capability, self.pmc) {
            return Err(Error::Capability);
        }
        let c = &mut self.function.as_mut().expect("retained").config;
        if word(c, self.capability + 4)? & (STATE | PME_ENABLE) != 0 {
            return Err(Error::Readback(self.capability + 4));
        }
        let command = word(c, 4)?;
        if command & regs::COMMAND_MASTER != 0 {
            return Err(Error::BusMaster);
        }
        c.write16(4, (command & !3) | regs::COMMAND_INTX_DISABLE);
        if word(c, 4)? != (command & !3) | regs::COMMAND_INTX_DISABLE {
            return Err(Error::Readback(4));
        }
        if csr & NO_SOFT_RESET == 0 {
            for (i, value) in self.bars.iter().copied().enumerate() {
                c.write32(bar_offset(i), value);
            }
        }
        for (i, value) in self.bars.iter().copied().enumerate() {
            if c.read32(bar_offset(i)) != value {
                return Err(Error::Bars);
            }
        }
        c.write16(4, self.command);
        if word(c, 4)? != self.command {
            return Err(Error::Readback(4));
        }
        self.state = State::D0;
        Ok(())
    }

    /// Return the same original owners in verified D0. Their independent
    /// mapping retirement and device shutdown obligations still apply.
    pub fn release(mut self) -> Result<(Function<C>, T, P), Self> {
        if self.checked(State::D0).is_err() {
            return Err(self);
        }
        Ok((
            self.function.take().expect("retained"),
            self.timer.take().expect("retained"),
            self.platform.take().expect("retained"),
        ))
    }
}
fn bar_offset(index: usize) -> u16 {
    if index == 6 {
        0x30
    } else {
        0x10 + index as u16 * 4
    }
}
impl<C: MsiConfigSpace, T: Timer, P> Drop for Power<C, T, P> {
    fn drop(&mut self) {
        // Even D0 says nothing about live DMA/IRQ/work programmed through the
        // original function. Only explicit release transfers its independent
        // shutdown obligations back to the original caller; Drop cannot end
        // the platform/exclusion grant beneath those consumers.
        core::mem::forget(self.function.take());
        core::mem::forget(self.timer.take());
        core::mem::forget(self.platform.take());
    }
}

#[cfg(test)]
mod tests;
