// SPDX-License-Identifier: GPL-2.0-only
//! Raw scan-set-2 framing and the Linux atkbd set-2 keycode table.
//! Copyright (c) 1999–2002 Vojtech Pavlik. See input/THIRD_PARTY.md.
use super::{ErrorKind, Input, Port};
use alloc::vec::Vec;

const EXTENDED: u8 = 0xe0;
const PAUSE: u8 = 0xe1;
const BREAK: u8 = 0xf0;
const PAUSE_TAIL: [u8; 7] = [0x14, 0x77, 0xe1, 0xf0, 0x14, 0xf0, 0x77];

#[derive(Default)]
pub(super) struct Keyboard {
    extended: bool,
    released: bool,
    pause: Option<usize>,
    prefix_at: u64,
    held: [u64; 4],
    observed: Vec<u8>,
}
impl Keyboard {
    pub(super) fn begin_observation(&mut self) {
        self.observed.clear();
    }
    pub(super) fn drain_observed(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.observed)
    }
    fn reset_prefix(&mut self) {
        self.extended = false;
        self.released = false;
        self.pause = None;
    }
    fn prefix(&self) -> bool {
        self.extended || self.released || self.pause.is_some()
    }
    fn key(&mut self, usage: u8, pressed: bool, events: &mut Vec<Input>) {
        let word = usize::from(usage / 64);
        let bit = 1 << (usage % 64);
        if (self.held[word] & bit != 0) == pressed {
            return;
        }
        if pressed {
            self.held[word] |= bit;
        } else {
            self.held[word] &= !bit;
        }
        events.push(Input::Key { usage, pressed });
    }
    pub(super) fn expire(&mut self, now: u64, timeout: u64) -> Result<(), ErrorKind> {
        if self.prefix() && now.wrapping_sub(self.prefix_at) >= timeout {
            self.reset_prefix();
            return Err(ErrorKind::PacketTimeout(Port::Keyboard));
        }
        Ok(())
    }
    pub(super) fn feed(
        &mut self,
        data: u8,
        now: u64,
        timeout: u64,
        events: &mut Vec<Input>,
        observe: bool,
    ) -> Result<(), ErrorKind> {
        // The actual owning Producer admission controls this byte tap only.
        // Guest parsing still runs after observation closes; no observer
        // buffer grows and no Linux Pause/repeat policy is manufactured.
        if observe {
            self.observed.push(data);
        }
        if self.prefix() && now.wrapping_sub(self.prefix_at) >= timeout {
            self.reset_prefix();
            return Err(ErrorKind::PacketTimeout(Port::Keyboard));
        }
        if let Some(position) = self.pause {
            if data != PAUSE_TAIL[position] {
                self.reset_prefix();
                return Err(ErrorKind::KeyboardSequence);
            }
            if position + 1 == PAUSE_TAIL.len() {
                self.reset_prefix();
                // Pause has no break sequence; publish the complete pulse.
                self.key(0x48, true, events);
                self.key(0x48, false, events);
            } else {
                self.pause = Some(position + 1);
            }
            return Ok(());
        }
        match data {
            EXTENDED if !self.extended && !self.released => {
                self.extended = true;
                self.prefix_at = now;
                return Ok(());
            }
            PAUSE if !self.prefix() => {
                self.pause = Some(0);
                self.prefix_at = now;
                return Ok(());
            }
            BREAK if !self.released => {
                if !self.prefix() {
                    self.prefix_at = now;
                }
                self.released = true;
                return Ok(());
            }
            0xaa => return Err(ErrorKind::DeviceReset(Port::Keyboard)),
            0 | 0xff | 0xfa | 0xfe | EXTENDED | PAUSE | BREAK => {
                self.reset_prefix();
                return Err(ErrorKind::KeyboardSequence);
            }
            _ => {}
        }
        let extended = self.extended;
        let released = self.released;
        self.reset_prefix();
        // Print Screen's fake shift is framing, not a real left shift.
        if extended && data == 0x12 {
            return Ok(());
        }
        let index = usize::from(data & 0x7f)
            | (usize::from(data & 0x80) << 1)
            | if extended { 0x80 } else { 0 };
        let code = SET2.get(index).copied().unwrap_or(0);
        let Some(usage) = super::super::virtio::usage(code) else {
            return Err(ErrorKind::UnsupportedScanCode(index as u16));
        };
        self.key(usage, !released, events);
        Ok(())
    }
    pub(super) fn release(&mut self, events: &mut Vec<Input>) {
        self.reset_prefix();
        for usage in 0..=u8::MAX {
            self.key(usage, false, events);
        }
    }
}

// The remaining zero-initialized upstream entries are handled by get().
const SET2: [u16; 261] = [
    0, 67, 65, 63, 61, 59, 60, 88, 183, 68, 66, 64, 62, 15, 41, 117, 184, 56, 42, 93, 29, 16, 2, 0,
    185, 0, 44, 31, 30, 17, 3, 0, 186, 46, 45, 32, 18, 5, 4, 95, 187, 57, 47, 33, 20, 19, 6, 183,
    188, 49, 48, 35, 34, 21, 7, 184, 189, 0, 50, 36, 22, 8, 9, 185, 190, 51, 37, 23, 24, 11, 10, 0,
    191, 52, 53, 38, 39, 25, 12, 0, 192, 89, 40, 0, 26, 13, 0, 193, 58, 54, 28, 27, 0, 43, 0, 194,
    0, 86, 91, 90, 92, 0, 14, 94, 0, 79, 124, 75, 71, 121, 0, 0, 82, 83, 80, 76, 77, 72, 1, 69, 87,
    78, 81, 74, 55, 73, 70, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 217, 100, 255, 0,
    97, 165, 0, 0, 156, 0, 0, 0, 0, 0, 0, 125, 173, 114, 0, 113, 0, 0, 0, 126, 128, 0, 0, 140, 0,
    0, 0, 127, 159, 0, 115, 0, 164, 0, 0, 116, 158, 0, 172, 166, 0, 0, 0, 142, 157, 0, 0, 0, 0, 0,
    0, 0, 155, 0, 98, 0, 0, 163, 0, 0, 226, 0, 0, 0, 0, 0, 0, 0, 0, 255, 96, 0, 0, 0, 143, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 107, 0, 105, 102, 0, 0, 112, 110, 111, 108, 112, 106, 103, 0, 119, 0, 118,
    109, 0, 99, 104, 119, 0, 0, 0, 0, 65, 99,
];
