// SPDX-License-Identifier: GPL-2.0-only
//! Shared ACP lifecycle admission, register sentinel and deadline polling.
//! I2S/PDM keep their hardware profiles, registers and ownership epochs.
use super::{Error, Phase, Registers, State};
use crate::bus::i2c::Timer;

#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    phase: Phase,
    start: u64,
    timeout: u64,
}
impl Deadline {
    pub(crate) fn new(phase: Phase, start: u64, timeout: u64) -> Self {
        Self {
            phase,
            start,
            timeout,
        }
    }
    pub(crate) fn check(self, timer: &impl Timer) -> Result<(), Error> {
        if timer.now_us().wrapping_sub(self.start) >= self.timeout {
            Err(Error::Timeout(self.phase))
        } else {
            Ok(())
        }
    }
}
pub(crate) fn usable(state: State) -> Result<(), Error> {
    match state {
        State::Claimed => Err(Error::NotInitialized),
        State::Faulted => Err(Error::NeedsReset),
        State::Shutdown => Err(Error::Shutdown),
        State::Suspended => Err(Error::Suspended),
        _ => Ok(()),
    }
}
pub(crate) fn read(registers: &mut impl Registers, offset: usize) -> Result<u32, Error> {
    let value = registers.read32(offset);
    if value == u32::MAX {
        Err(Error::RegisterUnavailable(offset))
    } else {
        Ok(value)
    }
}
pub(crate) fn phase_read(
    registers: &mut impl Registers,
    timer: &impl Timer,
    offset: usize,
    deadline: Deadline,
) -> Result<u32, Error> {
    deadline.check(timer)?;
    // An access failure wins over the clock after that access. A late
    // successful ready observation never grants phase completion.
    let value = read(registers, offset)?;
    deadline.check(timer)?;
    Ok(value)
}
pub(crate) fn wait(
    registers: &mut impl Registers,
    timer: &impl Timer,
    offset: usize,
    deadline: Deadline,
    ready: impl Fn(u32) -> bool,
) -> Result<(), Error> {
    loop {
        if ready(phase_read(registers, timer, offset, deadline)?) {
            return Ok(());
        }
        timer.relax();
    }
}
