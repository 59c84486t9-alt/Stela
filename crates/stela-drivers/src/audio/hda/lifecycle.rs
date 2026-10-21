// SPDX-License-Identifier: GPL-2.0-only
//! Explicit controller reset boundaries. DMA remains allocated for the boot;
//! software reservations are released only after all engines acknowledge stop.
use super::{Controller, Registers};
use crate::{audio::Error, bus::i2c::Timer};

impl<R: Registers, T: Timer> Controller<R, T> {
    /// Stop all streams/command engines, then reset and restart command DMA.
    /// All stream IDs, codec graphs and routes from the old generation become
    /// invalid, even if descriptor indices/tags or codec node numbers recur.
    /// On failed quiescence, buffers/reservations remain pinned and ordinary
    /// operations fail with NeedsReset. A later explicit attempt may recover.
    /// This does not restore PCI/ACPI power, ownership, or codec/OEM routes.
    pub fn reinitialize(&mut self) -> Result<(), Error> {
        let generation = self
            .token
            .generation
            .checked_add(1)
            .ok_or(Error::NeedsReset)?;
        self.lifecycle_failed = true;
        self.shutdown()?;
        // Every RUN acknowledgement succeeded. It is now safe to retire the
        // old software maps; backing RAM itself is never returned to an allocator.
        self.token.generation = generation;
        for stream in &mut self.streams {
            *stream = None;
        }
        self.routes.clear();
        self.corb_wp = 0;
        self.rirb_rp = 0;
        self.codec_mask = 0;
        if let Err(error) = self.initialize() {
            let _ = self.shutdown();
            return Err(error);
        }
        self.command_poisoned = false;
        self.routing_failed = false;
        self.lifecycle_failed = false;
        self.stopped = false;
        Ok(())
    }
}
