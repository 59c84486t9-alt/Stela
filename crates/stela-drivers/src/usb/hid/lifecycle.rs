// SPDX-License-Identifier: GPL-2.0-or-later
// Linux USB HID lifecycle/control reference and kept notices:
// usb/THIRD_PARTY.md and the parent HID module.
//! Acknowledged native HID endpoint stop/restart and kept diagnostics.
use super::*;

impl UsbInput {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn first_error(&self) -> Option<BlockError> {
        self.error.clone()
    }
    pub fn descriptor(&self) -> Option<&Descriptor> {
        self.translator.descriptor()
    }
    /// Descriptor bytes, even when boot fallback was selected.
    pub fn report_descriptor(&self) -> &[u8] {
        &self.report_descriptor
    }

    /// Stop/Set-Dequeue must acknowledge before discarding an outstanding TD.
    /// A failed stop keeps the old ticket, DMA and first error. This is endpoint
    /// lifecycle, not device/platform suspend or USB remote-wakeup management.
    pub fn stop(&mut self) -> Result<Vec<Input>, BlockError> {
        Ok(self.stop_hid()?.inputs)
    }

    /// Complete lifecycle result for richer HID consumers. Stop events are
    /// emitted only after hardware acknowledges abandonment of its old TD.
    pub fn stop_hid(&mut self) -> Result<Poll, BlockError> {
        self.invalidate_touch();
        self.invalidate_receiver(receiver::Error::Stopped);
        self.controller.borrow().validate_device_id(self.id)?;
        if self.state == State::Stopped {
            return Ok(core::mem::take(&mut self.pending.hid));
        }
        self.state = State::Faulted;
        let result = self
            .controller
            .borrow_mut()
            .device(self.id)
            .and_then(|mut device| device.cancel(self.endpoint.dci()));
        if let Err(error) = result {
            self.fault(error.clone());
            return Err(error);
        }
        self.queued = None;
        self.retry = None;
        self.state = State::Stopped;
        let (releases, events) = self.translator.release();
        self.pending.hid.inputs.extend(releases);
        self.pending.hid.events.extend(events);
        Ok(core::mem::take(&mut self.pending.hid))
    }

    /// Resume polling this same device after an acknowledged stop.
    /// Retired slot aliases and poisoned endpoints are rejected by the controller.
    pub fn restart(&mut self) -> Result<(), BlockError> {
        self.invalidate_touch();
        self.controller.borrow().validate_device_id(self.id)?;
        if self.state != State::Stopped {
            return Err(BlockError::Unsupported(
                "HID restart requires acknowledged stop",
            ));
        }
        self.invalidate_receiver(receiver::Error::Stopped);
        let result = self
            .controller
            .borrow_mut()
            .device(self.id)
            .and_then(|mut device| device.endpoint_ready(self.endpoint.dci()));
        if let Err(error) = result {
            self.fault(error.clone());
            return Err(error);
        }
        self.failed = false;
        self.state = State::Running;
        self.restart_receiver();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
