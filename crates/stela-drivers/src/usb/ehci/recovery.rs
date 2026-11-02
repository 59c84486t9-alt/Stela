// SPDX-License-Identifier: GPL-2.0-only
//! Explicit controller reset under the original PCI/UC/requester/IRQ owner.
//! Linux ehci-hcd.c ehci_halt/ehci_reset supplies the engine boundary. Native
//! posted-write drain and real mapping retirement are additional requirements.
use super::*;

impl Controller {
    /// Abandon this controller epoch and perform contained recovery.
    /// Every old device, pipe, transfer and suspended capability becomes stale
    /// before the first register effect. Outstanding transfers have unknown
    /// completion/USB effects and are never credited or automatically replayed.
    ///
    /// HALT/ASS0/PSS0, original BME-clear and posted-write drain precede old DMA
    /// unmap. Full reset/fresh schedule allocation and PE0 isolation of
    /// every inherited root precede reuse. Callers must explicitly reset,
    /// enumerate/configure and resynchronize their real devices afterward.
    /// Failure keeps unresolved resources under this same original owner.
    /// Explicit shutdown/retirement cannot be reversed by this method.
    /// Privately suspended roots require their explicit resume first; this
    /// method supplies no reset-on-resume or platform power transition.
    pub fn recover(&mut self) -> Result<(), Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if matches!(self.state, State::Retiring | State::Stopped) || self.hardware.is_none() {
            return Err(Error::Quarantined);
        }
        if self.ports.iter().flatten().any(|device| device.suspended) {
            return Err(Error::Unsupported(
                "EHCI recovery requires explicit resume of retained roots",
            ));
        }
        self.state = State::Failed;
        // Keep pending TD and original arena through every stop/drain/unmap
        // failure. Revoking public identity alone cannot free their resources.
        self.ports.iter_mut().for_each(|port| *port = None);
        let result = (|| {
            if self.op(CMD)? & RESET != 0 {
                // A prior reset timeout does not authorize operational writes
                // while that real reset remains in progress.
                self.wait(self.operational + CMD, RESET, 0, RESET_US)?;
            }
            self.put(INTR, 0)?;
            let command = self.op(CMD)?;
            self.put(CMD, command & !(RUN | ASE | PSE | IAAD))?;
            self.wait(self.operational + STS, HALT | ASS | PSS, HALT, HALT_US)?;
            self.hw().bus_master(false)?;
            self.hw().drain()?;
            if let Some(arena) = self.arena.as_mut() {
                // SAFETY: full HALT, both engines stopped, original
                // BME clear and original requester payload drain. The native
                // resource producer keeps masked/drained IRQ exclusion.
                unsafe {
                    arena.dma.unmap()?;
                }
            }
            self.arena = None;
            self.pending = None;
            self.default_port = None;
            // This reuses the original native resources/domain. It
            // does not borrow a new domain to assert old-path retirement.
            // Generation and transfer counters never reset.
            self.initialize_inner()
        })();
        self.guard(result)?;
        self.state = State::Running;
        Ok(())
    }
}
