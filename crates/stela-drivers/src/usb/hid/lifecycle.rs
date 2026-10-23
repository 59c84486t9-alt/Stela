// SPDX-License-Identifier: GPL-2.0-or-later
// Linux USB HID lifecycle/control reference and retained notices:
// usb/THIRD_PARTY.md and the parent HID module.
//! Acknowledged native HID endpoint stop/restart and retained diagnostics.
use super::*;

impl UsbInput {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn first_error(&self) -> Option<BlockError> {
        self.error.clone()
    }
    pub fn descriptor(&self) -> Option<&Descriptor> {
        self.descriptor.as_ref()
    }
    /// Actual descriptor bytes, even when boot fallback was selected.
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
        if self.state == State::Stopped {
            return Ok(Poll::default());
        }
        self.state = State::Faulted;
        let result = self
            .controller
            .borrow_mut()
            .cancel(self.slot, self.endpoint.dci());
        if let Err(error) = result {
            self.fault(error.clone());
            return Err(error);
        }
        self.queued = None;
        self.retry = None;
        self.state = State::Stopped;
        let mut releases = Vec::new();
        for usage in self.held.drain(..) {
            releases.push(Input::Key {
                usage: usage as u8,
                pressed: false,
            });
        }
        if self.buttons != 0 {
            releases.push(
                if self
                    .reports
                    .pointer
                    .as_ref()
                    .is_some_and(|p| p.x.is_some_and(|f| f.relative))
                {
                    Input::MouseButtons(0)
                } else {
                    Input::Buttons(0)
                },
            );
        }
        self.buttons = 0;
        self.position = None;
        Ok(Poll {
            inputs: releases,
            events: self.events.stop(),
            reports: Vec::new(),
        })
    }

    /// Resume polling this same retained device after an acknowledged stop.
    /// Retired slot aliases and poisoned endpoints are rejected by the controller.
    pub fn restart(&mut self) -> Result<(), BlockError> {
        if self.state != State::Stopped {
            return Err(BlockError::Unsupported(
                "HID restart requires acknowledged stop",
            ));
        }
        let result = self
            .controller
            .borrow_mut()
            .endpoint_ready(self.slot, self.endpoint.dci());
        if let Err(error) = result {
            self.fault(error.clone());
            return Err(error);
        }
        self.failed = false;
        self.state = State::Running;
        Ok(())
    }
}
