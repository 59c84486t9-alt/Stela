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
    /// digitizer feature negotiation without fabricating an interrupt-OUT path.
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
        self.controller
            .borrow_mut()
            .device(self.id)?
            .control(request, bytes)?;
        Ok(())
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
