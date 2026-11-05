// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! Intel BT disconnect/reset shared by cold preparation and transport teardown.
use super::{Error, Platform, Result, Snapshot, registers::*};
use alloc::boxed::Box;

/// Actual same-function control registers and qualified timing, or an isolated
/// device peer. This interface supplies neither DMA nor IRQ admission.
/// # Safety
/// Reads/writes reach this exclusively owned powered function at exact native
/// widths, with errors propagated. The original configuration, BAR and DMA
/// backing remain kept throughout reset. Timing progresses in the owning
/// processor/root context and preserves each requested minimum delay.
pub(super) unsafe trait Io {
    fn read(&mut self, offset: usize) -> Result<u32>;
    fn write(&mut self, offset: usize, value: u32) -> Result<()>;
    fn delay(&mut self, microseconds: u64) -> Result<()>;
}

pub(super) struct PlatformIo<'a, P: Platform>(
    pub(super) &'a mut P,
    pub(super) &'a mut Option<Box<Error>>,
);

/// Keep the original owner closed if its external minimum callback fails or
/// unwinds. A successful callback alone clears the prearmed effect fence.
pub(super) fn wait<P: Platform>(
    platform: &mut P,
    failure: &mut Option<Box<Error>>,
    microseconds: u64,
) -> Result<()> {
    if let Some(error) = failure.as_deref() {
        return Err(error.clone());
    }
    *failure = Some(Box::new(Error::MinimumInterrupted));
    match platform.minimum_delay(microseconds) {
        Ok(()) => {
            *failure = None;
            Ok(())
        }
        Err(error) => {
            *failure = Some(Box::new(error.clone()));
            Err(error)
        }
    }
}
// SAFETY: Platform's original function/MMIO/timing ownership and serialized
// context are borrowed for this call. No reference escapes the reset pass.
unsafe impl<P: Platform> Io for PlatformIo<'_, P> {
    fn read(&mut self, offset: usize) -> Result<u32> {
        if let Some(error) = self.1.as_deref() {
            return Err(error.clone());
        }
        self.0.read32(offset)
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<()> {
        if let Some(error) = self.1.as_deref() {
            return Err(error.clone());
        }
        self.0.write32(offset, value)
    }
    fn delay(&mut self, microseconds: u64) -> Result<()> {
        wait(self.0, self.1, microseconds)
    }
}

pub(super) fn update_function<I: Io>(
    io: &mut I,
    snapshot: &mut Snapshot,
    clear: u32,
    set: u32,
) -> Result<u32> {
    let value = io.read(FUNC)?;
    snapshot.function = value;
    if value == u32::MAX {
        return Err(Error::Mmio("unreadable function control"));
    }
    let value = (value & !clear) | set;
    io.write(FUNC, value)?;
    Ok(value)
}

/// `btintel_pcie_reset_bt`, with explicit missing-disconnect acknowledgement
/// failure. IRQ/work exclusion and remapper completion remain separate proofs.
pub(super) fn reset<I: Io>(io: &mut I, snapshot: &mut Snapshot) -> Result<()> {
    update_function(
        io,
        snapshot,
        ENABLE | MAC_INIT | FUNC_INIT,
        MASTER_DISCONNECT,
    )?;
    let mut stopped = false;
    for _ in 0..3 {
        let value = io.read(FUNC)?;
        snapshot.function = value;
        if value != u32::MAX && value & MASTER_STOPPED != 0 {
            stopped = true;
            break;
        }
        io.delay(10_000)?;
    }
    if !stopped {
        return Err(Error::Timeout(
            "actual bus-master disconnect acknowledgment",
        ));
    }
    io.delay(10_000)?;
    update_function(io, snapshot, ENABLE | MAC_INIT | FUNC_INIT, RESET)?;
    io.delay(10_000)?;
    snapshot.function = io.read(FUNC)?;
    snapshot.boot_stage = io.read(BOOT)?;
    if snapshot.boot_stage != 0 {
        return Err(Error::Protocol {
            requirement: "actual reset boot stage zero",
            observed: u64::from(snapshot.boot_stage),
        });
    }
    Ok(())
}
