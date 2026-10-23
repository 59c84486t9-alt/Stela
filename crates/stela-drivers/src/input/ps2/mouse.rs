// SPDX-License-Identifier: GPL-2.0-only
//! Standard PS/2 and IntelliMouse packets, following Linux psmouse-base.c.
//! Copyright (c) 1999–2002 Vojtech Pavlik; 2003–2004 Dmitry Torokhov.
use super::{ErrorKind, Input, Port};
use alloc::vec::Vec;

#[derive(Default)]
pub(super) struct Mouse {
    packet: [u8; 4],
    position: usize,
    start: u64,
    wheel: bool,
    buttons: u8,
}
impl Mouse {
    pub(super) fn wheel(&self) -> bool {
        self.wheel
    }
    pub(super) fn set_wheel(&mut self, wheel: bool) {
        self.wheel = wheel;
        self.position = 0;
    }
    pub(super) fn expire(&mut self, now: u64, timeout: u64) -> Result<(), ErrorKind> {
        if self.position != 0 && now.wrapping_sub(self.start) >= timeout {
            self.position = 0;
            return Err(ErrorKind::PacketTimeout(Port::Mouse));
        }
        Ok(())
    }
    pub(super) fn feed(
        &mut self,
        data: u8,
        now: u64,
        timeout: u64,
        events: &mut Vec<Input>,
    ) -> Result<(), ErrorKind> {
        if self.position != 0 && now.wrapping_sub(self.start) >= timeout {
            self.position = 0;
            return Err(ErrorKind::PacketTimeout(Port::Mouse));
        }
        if self.position == 0 {
            if data & 8 == 0 {
                return Err(ErrorKind::MouseSync(data));
            }
            self.start = now;
        }
        self.packet[self.position] = data;
        self.position += 1;
        if self.position == 2 && self.packet[..2] == [0xaa, 0] {
            self.position = 0;
            return Err(ErrorKind::DeviceReset(Port::Mouse));
        }
        let length = if self.wheel { 4 } else { 3 };
        if self.position != length {
            return Ok(());
        }
        self.position = 0;
        let header = self.packet[0];
        let buttons = header & 7;
        if buttons != self.buttons {
            self.buttons = buttons;
            events.push(Input::MouseButtons(buttons));
        }
        // Match Linux's nine-bit sign conversion, including sign+zero (some
        // devices set a sign bit for a zero byte). PS/2 Y grows upward; Stela
        // mouse counts grow downward. Header overflow bits carry no extra data.
        let axis = |byte, negative| {
            if byte == 0 {
                0
            } else {
                i16::from(byte) - if negative { 256 } else { 0 }
            }
        };
        let dx = axis(self.packet[1], header & 0x10 != 0);
        let dy = -axis(self.packet[2], header & 0x20 != 0);
        if dx != 0 || dy != 0 {
            events.push(Input::Motion { dx, dy });
        }
        if self.wheel {
            let wheel = -i16::from(self.packet[3] as i8);
            // +128 detents cannot fit one Input; retain the exact sum.
            if wheel == 128 {
                events.push(Input::MouseWheel(127));
                events.push(Input::MouseWheel(1));
            } else if wheel != 0 {
                events.push(Input::MouseWheel(wheel as i8));
            }
        }
        Ok(())
    }
    pub(super) fn release(&mut self, events: &mut Vec<Input>) {
        self.position = 0;
        if self.buttons != 0 {
            self.buttons = 0;
            events.push(Input::MouseButtons(0));
        }
    }
}
