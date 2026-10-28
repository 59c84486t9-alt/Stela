// SPDX-License-Identifier: GPL-2.0-or-later
// Linux USB HID lifecycle/control reference and retained notices:
// usb/THIRD_PARTY.md and the parent HID module.
//! Descriptor-qualified synchronous HID class controls through owned EP0.
use super::*;

impl UsbInput {
    fn control_ready(&self) -> Result<(), BlockError> {
        if self.state == State::Faulted {
            return Err(BlockError::Unsupported(
                "HID transport fault requires acknowledged stop",
            ));
        }
        Ok(())
    }

    /// GET_REPORT through the device's owned EP0. Only descriptor-declared
    /// reports and exact lengths are admitted; numbered reports include the ID.
    pub fn get_report(&mut self, kind: ReportType, id: u8) -> Result<Vec<u8>, BlockError> {
        self.control_ready()?;
        let length = self.control_length(kind, id)?;
        let request = setup(
            DEVICE_TO_HOST | TYPE_CLASS | RECIPIENT_INTERFACE,
            GET_REPORT,
            (kind as u16) << 8 | u16::from(id),
            u16::from(self.interface),
            length as u16,
        );
        let bytes = self
            .controller
            .borrow_mut()
            .device(self.id)?
            .control(request, &[])?;
        if bytes.len() != length || (id != 0 && bytes.first() != Some(&id)) {
            return Err(BlockError::Protocol(
                "invalid USB HID GET_REPORT length or ID",
            ));
        }
        Ok(bytes)
    }

    fn control_length(&self, kind: ReportType, id: u8) -> Result<usize, BlockError> {
        self.descriptor
            .as_ref()
            .and_then(|d| d.layout(kind, id))
            .map(|layout| layout.wire_bytes())
            .filter(|length| *length != 0)
            .ok_or(BlockError::Unsupported(
                "HID control report absent from active report descriptor",
            ))
    }

    /// Synchronous SET_REPORT on EP0 supports LED output, gamepad control and
    /// digitizer feature negotiation.
    /// Success means actual status-stage ACK. Errors preserve uncertain effects;
    /// this method never automatically retries a state-changing report.
    pub fn set_report(&mut self, kind: ReportType, id: u8, bytes: &[u8]) -> Result<(), BlockError> {
        self.control_ready()?;
        if kind == ReportType::Input {
            return Err(BlockError::Unsupported(
                "SET_REPORT requires output or feature",
            ));
        }
        let length = self.control_length(kind, id)?;
        if bytes.len() != length || (id != 0 && bytes.first() != Some(&id)) {
            return Err(BlockError::Protocol(
                "invalid USB HID SET_REPORT length or ID",
            ));
        }
        let request = setup(
            TYPE_CLASS | RECIPIENT_INTERFACE,
            SET_REPORT,
            (kind as u16) << 8 | u16::from(id),
            u16::from(self.interface),
            length as u16,
        );
        // Arbitrary feature/output writes may change digitizer mode/capacity.
        // Re-enable through a fresh acknowledged maximum query afterward.
        self.touch = None;
        self.invalidate_receiver(receiver::Error::ExternalControl);
        self.controller
            .borrow_mut()
            .device(self.id)?
            .control(request, bytes)?;
        Ok(())
    }

    /// Linux `usbhid_output_report`: an output report goes out on the
    /// interrupt OUT endpoint, waiting up to USB_CTRL_SET_TIMEOUT, and the
    /// bytes it moved are returned. Without the endpoint it takes SET_REPORT,
    /// as callers of `hid_hw_output_report` fall back to `hid_hw_raw_request`.
    /// Numbered reports carry their ID; report zero sends none.
    pub fn output_report(&mut self, id: u8, bytes: &[u8]) -> Result<usize, BlockError> {
        if self.output.is_none() {
            return self
                .set_report(ReportType::Output, id, bytes)
                .map(|()| bytes.len());
        }
        self.control_ready()?;
        let length = self.control_length(ReportType::Output, id)?;
        if bytes.len() != length || (id != 0 && bytes.first() != Some(&id)) {
            return Err(BlockError::Protocol(
                "invalid USB HID output report length or ID",
            ));
        }
        // As with SET_REPORT, an output report may change device modes.
        self.touch = None;
        self.invalidate_receiver(receiver::Error::ExternalControl);
        let (endpoint, buffer) = self.output.as_mut().unwrap();
        buffer.bytes_mut()[..length].copy_from_slice(bytes);
        self.controller.borrow_mut().device(self.id)?.transfer(
            endpoint.dci(),
            buffer.physical(),
            length,
            OUTPUT_TIMEOUT_US,
        )
    }

    /// Linux `hidinput_led_worker`. `leds` holds input LED codes as bits
    /// (LED_NUML is bit 0); each LED-page usage `hidinput_configure_usage`
    /// maps takes its bit. The output report holding the first such field
    /// is sent with those fields set and every other field zero, through
    /// `output_report`. A device without one has no LEDs to set.
    pub fn set_leds(&mut self, leds: u16) -> Result<(), BlockError> {
        let Some(descriptor) = &self.descriptor else {
            return Ok(());
        };
        let led = |usage: u32| {
            (usage >> 16 == LED_PAGE)
                .then(|| {
                    LED_USAGES
                        .iter()
                        .position(|&led| u32::from(led) == usage & 0xffff)
                })
                .flatten()
        };
        let Some(layout) = descriptor
            .reports
            .iter()
            .filter(|layout| layout.kind == ReportType::Output)
            .find(|layout| {
                layout
                    .fields
                    .iter()
                    .any(|field| field.usages.iter().any(|&usage| led(usage).is_some()))
            })
        else {
            return Ok(());
        };
        let id = layout.id;
        let mut report = alloc::vec![0u8; layout.wire_bytes()];
        let body = usize::from(id != 0);
        report[0] |= id;
        for field in layout.fields.iter().filter(|f| f.flags & VARIABLE != 0) {
            for element in 0..field.count {
                let usage = field.usages.get(element).or(field.usages.last());
                let Some(code) = usage.and_then(|&usage| led(usage)) else {
                    continue;
                };
                if leds & 1 << code != 0 {
                    let bit = field.offset + element * field.size;
                    report[body + bit / 8] |= 1 << (bit % 8);
                }
            }
        }
        self.output_report(id, &report).map(|_| ())
    }

    /// HID duration units are 4 ms; report zero addresses all input reports.
    /// Device STALL remains an explicit result for callers of this API.
    pub fn set_idle(&mut self, id: u8, duration: u8) -> Result<(), BlockError> {
        self.control_ready()?;
        if id != 0 {
            self.control_length(ReportType::Input, id)?;
        }
        let request = setup(
            TYPE_CLASS | RECIPIENT_INTERFACE,
            SET_IDLE,
            u16::from(duration) << 8 | u16::from(id),
            u16::from(self.interface),
            0,
        );
        self.controller
            .borrow_mut()
            .device(self.id)?
            .control(request, &[])?;
        Ok(())
    }
}
