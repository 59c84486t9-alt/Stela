// SPDX-License-Identifier: GPL-2.0-only
//! Original-root ISH DMA containment, derived from Linux `ish_disable_dma`.
//!
//! This register-only operation keeps all inherited buffers untouched. It is
//! neither a firmware-session reset nor an IRQ/work/root retirement receipt.
//! In particular, RMP2 must not be reopened under a different DMA root until
//! an independently acknowledged reset invalidates firmware's old addresses.
use super::{Registers, Result, Time, registers::*};
pub mod native;

const DMA_TIMEOUT_US: u64 = 20_000;
const HOST_READY: u32 = 1 << 7;

/// A one-shot containment attempt belongs to the complete original graph.
/// Failed or interrupted effects cannot be retried through this object.
pub struct StopAttempt {
    attempted: bool,
    failure: Option<super::Error>,
}
impl Default for StopAttempt {
    fn default() -> Self {
        Self::new()
    }
}
impl StopAttempt {
    pub const fn new() -> Self {
        Self {
            attempted: false,
            failure: None,
        }
    }
    /// Mask source IRQs, close host readiness and gate all firmware DMA, then
    /// observe every DMA-active bit idle. Configuration, the original root,
    /// firmware/control exclusion and old allocation custody remain the caller's
    /// independent obligations. This exposes no stopped-requester token.
    pub fn stop(&mut self, registers: &impl Registers, clock: &impl Time) -> Result<()> {
        if self.attempted {
            return Err(self.failure.unwrap_or(super::Error::Terminal));
        }
        self.attempted = true;
        // Installed before the first callback, so caught unwind remains closed.
        self.failure = Some(super::Error::Terminal);
        let result = stop(registers, clock);
        self.failure = result.as_ref().err().copied();
        result
    }
}
fn check_time(clock: &impl Time, previous: &mut u64, deadline: u64) -> Result<()> {
    let now = clock.now_us();
    if now < *previous {
        return Err(super::Error::Requirement("monotonic original ISH clock"));
    }
    *previous = now;
    if now >= deadline {
        return Err(super::Error::Timeout("inherited DMA inactive"));
    }
    Ok(())
}
fn stop(r: &impl Registers, t: &impl Time) -> Result<()> {
    let mut previous = t.now_us();
    let deadline = previous
        .checked_add(DMA_TIMEOUT_US)
        .ok_or(super::Error::Requirement("bounded original ISH clock"))?;
    let mask = read(r, PIMR)? & !(IRQ_ENABLE | BUSY_CLEAR);
    check_time(t, &mut previous, deadline)?;
    store(r, PIMR, mask)?;
    check_time(t, &mut previous, deadline)?;
    // The donor's clear-host-ready macro uses XOR. Explicit clear preserves
    // an already-unready inherited host rather than accidentally reopening it.
    let host = read(r, HOST_COMM)? & !HOST_READY;
    check_time(t, &mut previous, deadline)?;
    store(r, HOST_COMM, host)?;
    check_time(t, &mut previous, deadline)?;
    store(r, RMP2, 0)?;
    check_time(t, &mut previous, deadline)?;
    loop {
        let status = read(r, FWSTS)?;
        // Include backend access time: a late zero is not an in-bound ACK.
        check_time(t, &mut previous, deadline)?;
        if status & IN_DMA == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests;
