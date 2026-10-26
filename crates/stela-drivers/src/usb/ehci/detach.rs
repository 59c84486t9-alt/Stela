// SPDX-License-Identifier: GPL-2.0-only
//! Actual root PE-clear isolation before releasing a USB address lease.
//! Linux ehci_hub_control ClearPortFeature(ENABLE) supplies the neutral write;
//! native schedule/payload/cache ownership and acknowledgement are additional.
use super::*;

impl Controller {
    /// Disable this exact root and retire every device/endpoint handle.
    /// The physical device may retain its old address; actual PE0 isolates it
    /// before that bus address (including address0) can be assigned elsewhere.
    /// No TD is cancelled implicitly, port power is preserved, and a privately
    /// suspended root requires its explicit resume capability first.
    ///
    /// Complete schedule stop and original requester drain/cache ownership
    /// precede handle revocation and the port write. Failed isolation closes
    /// the attachment and retains all native/DMA resources; software retirement
    /// alone can never release a reachable physical bus address.
    pub fn disable_port(&mut self, id: &DeviceId) -> Result<(), Error> {
        let index = self.identity(id)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.live(id)?;
        let stopped = self.schedule_off();
        self.guard(stopped)?;
        let value = self.read(self.port_at(index));
        let value = self.guard(value)?;
        if value
            & (CONNECT
                | ENABLE
                | OWNER
                | OVERCURRENT
                | PORT_RESET
                | PORT_SUSPEND
                | PORT_RESUME
                | PORT_CHANGES)
            != CONNECT | ENABLE
        {
            return self.fail(Error::Stale);
        }
        self.ports[index] = None;
        let isolated = (|| {
            let at = self.port_at(index);
            // Never acknowledge unseen changes or replay a reset/resume. PE
            // clears by software; setting it requires an actual HS reset.
            self.write(at, value & !(ENABLE | PORT_CHANGES))?;
            self.wait(
                at,
                ENABLE | OWNER | PORT_RESET | PORT_SUSPEND | PORT_RESUME,
                0,
                TRANSITION_US,
            )?;
            self.health()
        })();
        self.guard(isolated)?;
        if self.default_port == Some(id.port) {
            self.default_port = None;
        }
        Ok(())
    }
}
