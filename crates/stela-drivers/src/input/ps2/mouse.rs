// SPDX-License-Identifier: GPL-2.0-only
//! Standard PS/2, IntelliMouse and Explorer packets from Linux psmouse-base.c.
//! Copyright (c) 1999–2002 Vojtech Pavlik; 2003–2004 Dmitry Torokhov.
use super::{ErrorKind, Input, MouseProtocol, Port};
use alloc::vec::Vec;

#[derive(Default)]
pub(super) struct Mouse {
    packet: [u8; 4],
    position: usize,
    start: u64,
    protocol: MouseProtocol,
    buttons: u8,
    extra_buttons: u8,
}
impl Mouse {
    pub(super) fn protocol(&self) -> MouseProtocol {
        self.protocol
    }
    pub(super) fn set_protocol(&mut self, protocol: MouseProtocol) {
        self.protocol = protocol;
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
        self.feed_with_scroll(data, now, timeout, events, None)
    }
    pub(super) fn feed_with_scroll(
        &mut self,
        data: u8,
        now: u64,
        timeout: u64,
        events: &mut Vec<Input>,
        mut horizontal: Option<&mut Vec<i8>>,
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
        let length = if self.protocol == MouseProtocol::Standard {
            3
        } else {
            4
        };
        if self.position != length {
            return Ok(());
        }
        self.position = 0;
        let header = self.packet[0];
        let extra = self.packet[3];
        let (mut buttons, wheel) = match self.protocol {
            MouseProtocol::Standard => (header & 7, 0),
            MouseProtocol::IntelliMouse => (header & 7, -i16::from(extra as i8)),
            MouseProtocol::Explorer => {
                // The pinned Linux handler treats mode0 and mode0xc0 as the
                // ordinary signed-nibble vertical wheel with side/extra keys.
                // 0x40/0x80 require the separately enabled Explorer4.0 mode.
                if matches!(extra & 0xc0, 0 | 0xc0) {
                    let signed = i16::from(extra & 15) - if extra & 8 != 0 { 16 } else { 0 };
                    ((header & 7) | ((extra & 0x30) >> 1), -signed)
                } else if let Some(horizontal) = &mut horizontal {
                    let signed = i16::from(extra & 63) - if extra & 32 != 0 { 64 } else { 0 };
                    if extra & 0xc0 == 0x40 && signed != 0 {
                        horizontal.push(-signed as i8);
                    }
                    (
                        (header & 7) | (self.buttons & 0x18),
                        if extra & 0xc0 == 0x80 { -signed } else { 0 },
                    )
                } else {
                    return Err(ErrorKind::MousePacketMode(extra));
                }
            }
        };
        buttons |= self.extra_buttons;
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
        {
            // +128 IntelliMouse detents cannot fit one Input; retain the sum.
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
        self.extra_buttons = 0;
        if self.buttons != 0 {
            self.buttons = 0;
            events.push(Input::MouseButtons(0));
        }
    }
    /// A source OOB extra-button payload reports the three standard buttons
    /// immediately and is ORed into subsequent physical packet buttons.
    pub(super) fn external_buttons(&mut self, buttons: u8, events: &mut Vec<Input>) {
        self.extra_buttons = buttons & 7;
        let next = (self.buttons & !7) | self.extra_buttons;
        if next != self.buttons {
            self.buttons = next;
            events.push(Input::MouseButtons(next));
        }
    }
}
