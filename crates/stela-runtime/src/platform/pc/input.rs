//! Host keyboards and pointers that the mount reads itself after
//! ExitBootServices: virtio-input PCI devices (virtio 1.2 section 5.8), as
//! QEMU's `virtio-keyboard-pci` and `virtio-tablet-pci` present them.
//!
//! The driver keeps the event queue stocked with device-writable 8-byte
//! buffers and polls its used ring; it leaves the status queue (LED
//! feedback) disabled. Events carry Linux evdev types and codes, which
//! [`Translator`] turns into the native USB peripheral's HID inputs: key
//! codes through the HID Usage Tables' Keyboard/Keypad page, absolute axes
//! scaled from the device's advertised range to the pointer's, the three
//! main buttons and the vertical wheel. Position changes go out at each
//! SYN_REPORT, so one report carries both axes. Codes with no keyboard
//! usage (media keys beyond volume and mute, horizontal wheel, extra
//! buttons) are counted and dropped, never mapped to something else.
use super::{
    Handoff,
    block::BlockError,
    dma::{DmaAllocator, DmaBuffer},
    mmio::Mmio,
    pci::Function,
    virtio::{AVAIL, DESCRIPTOR_WRITE, Modern, USED, VENDOR},
};
use crate::platform::usb::hid::{Input, POINTER_MAX};
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const MODERN_INPUT: u16 = 0x1052;
/// The queue layout `Modern::queue` uses fits 16 descriptors.
const QUEUE_ENTRIES: u16 = 16;
const EVENT_BYTES: usize = 8;

const SELECT: usize = 0;
const SUBSELECT: usize = 1;
const SIZE: usize = 2;
const DATA: usize = 8;
const CONFIG_NAME: u8 = 0x01;
const CONFIG_EVENTS: u8 = 0x11;
const CONFIG_ABS: u8 = 0x12;

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const SYN_REPORT: u16 = 0;
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;
const REL_WHEEL: u16 = 8;
const BTN_LEFT: u16 = 0x110;

pub fn matches(function: &Function) -> bool {
    function.vendor == VENDOR && function.device == MODERN_INPUT
}

/// One evdev event as the device wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}

/// An absolute axis's advertised range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Axis {
    pub minimum: i32,
    pub maximum: i32,
}

pub struct VirtioInput {
    notify: Mmio,
    queue: DmaBuffer,
    events: DmaBuffer,
    entries: u16,
    /// The used ring index consumed so far, and the driver ring's index.
    used: u16,
    available: u16,
    pub name: String,
    pub translator: Translator,
}

impl VirtioInput {
    pub fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let transport = Modern::new(function, handoff)?;
        transport.negotiate(0)?;
        let device = transport.device;
        let config = |select: u8, subselect: u8| {
            device.write8(SELECT, select);
            device.write8(SUBSELECT, subselect);
            let size = usize::from(device.read8(SIZE)).min(128);
            (0..size)
                .map(|n| device.read8(DATA + n))
                .collect::<Vec<u8>>()
        };
        let name = String::from_utf8_lossy(&config(CONFIG_NAME, 0)).into_owned();
        let absolute = config(CONFIG_EVENTS, EV_ABS as u8);
        let axis = |code: u16| {
            let bytes = config(CONFIG_ABS, code as u8);
            let word = |n: usize| i32::from_le_bytes(bytes[n * 4..n * 4 + 4].try_into().unwrap());
            (bytes.len() >= 8).then(|| Axis {
                minimum: word(0),
                maximum: word(1),
            })
        };
        let has = |bits: &[u8], code: u16| {
            bits.get(usize::from(code / 8))
                .is_some_and(|byte| byte & 1 << (code % 8) != 0)
        };
        let axes = match (has(&absolute, ABS_X), has(&absolute, ABS_Y)) {
            (true, true) => match (axis(ABS_X), axis(ABS_Y)) {
                (Some(x), Some(y)) if x.maximum > x.minimum && y.maximum > y.minimum => {
                    Some((x, y))
                }
                _ => {
                    return Err(BlockError::Unsupported(
                        "virtio-input absolute axes without a range",
                    ));
                }
            },
            _ => None,
        };
        let queue = dma.allocate(4096, 4096)?;
        let events = dma.allocate(4096, 4096)?;
        let (entries, notify) = transport.queue(handoff, 0, QUEUE_ENTRIES, &queue)?;
        let mut input = Self {
            notify,
            queue,
            events,
            entries,
            used: 0,
            available: 0,
            name,
            translator: Translator::new(axes),
        };
        for id in 0..entries {
            let base = 16 * usize::from(id);
            let address = input.events.physical() + (usize::from(id) * EVENT_BYTES) as u64;
            input.queue.write(base, address);
            input.queue.write(base + 8, EVENT_BYTES as u32);
            input.queue.write(base + 12, DESCRIPTOR_WRITE);
            input.queue.write(base + 14, 0u16);
            input.offer(id);
        }
        transport.ready();
        input.publish();
        Ok(input)
    }

    fn offer(&mut self, id: u16) {
        let slot = AVAIL + 4 + 2 * usize::from(self.available % self.entries);
        self.queue.write(slot, id);
        self.available = self.available.wrapping_add(1);
    }

    fn publish(&mut self) {
        fence(Ordering::SeqCst);
        self.queue.write(AVAIL + 2, self.available);
        fence(Ordering::SeqCst);
        self.notify.write16(0, 0);
    }

    /// The events the device has written since the last poll, each buffer
    /// handed back to it.
    pub fn poll(&mut self) -> Vec<Event> {
        fence(Ordering::SeqCst);
        let produced: u16 = self.queue.read(USED + 2);
        let mut events = Vec::new();
        while self.used != produced {
            let slot = USED + 4 + 8 * usize::from(self.used % self.entries);
            let id = self.queue.read::<u32>(slot) as u16 % self.entries;
            let at = usize::from(id) * EVENT_BYTES;
            events.push(Event {
                kind: self.events.read(at),
                code: self.events.read(at + 2),
                value: self.events.read(at + 4),
            });
            self.used = self.used.wrapping_add(1);
            self.offer(id);
        }
        if !events.is_empty() {
            self.publish();
        }
        events
    }
}

/// Turns one device's evdev events into peripheral inputs.
#[derive(Debug, Clone)]
pub struct Translator {
    axes: Option<(Axis, Axis)>,
    position: (u16, u16),
    moved: bool,
    buttons: u8,
    pub dropped: u64,
}

impl Translator {
    pub fn new(axes: Option<(Axis, Axis)>) -> Self {
        Self {
            axes,
            position: (0, 0),
            moved: false,
            buttons: 0,
            dropped: 0,
        }
    }

    fn scale(axis: Axis, value: i32) -> u16 {
        let span = i64::from(axis.maximum) - i64::from(axis.minimum);
        let offset = (i64::from(value) - i64::from(axis.minimum)).clamp(0, span);
        (offset * i64::from(POINTER_MAX) / span) as u16
    }

    pub fn translate(&mut self, event: Event) -> Option<Input> {
        match (event.kind, event.code) {
            (EV_KEY, BTN_LEFT..=0x112) => {
                // Left, right, middle are HID buttons 1, 2, 3.
                let bit = 1 << (event.code - BTN_LEFT);
                self.buttons = if event.value != 0 {
                    self.buttons | bit
                } else {
                    self.buttons & !bit
                };
                Some(Input::Buttons(self.buttons))
            }
            // Autorepeat (value 2) is the host's; macOS repeats keys itself.
            (EV_KEY, code) if event.value != 2 => match usage(code) {
                Some(usage) => Some(Input::Key {
                    usage,
                    pressed: event.value != 0,
                }),
                None => self.drop(),
            },
            (EV_KEY, _) => None,
            (EV_ABS, ABS_X | ABS_Y) => {
                let Some((x, y)) = self.axes else {
                    return self.drop();
                };
                if event.code == ABS_X {
                    self.position.0 = Self::scale(x, event.value);
                } else {
                    self.position.1 = Self::scale(y, event.value);
                }
                self.moved = true;
                None
            }
            (EV_REL, REL_WHEEL) => Some(Input::Wheel(event.value.clamp(-127, 127) as i8)),
            (EV_SYN, SYN_REPORT) if self.moved => {
                self.moved = false;
                let (x, y) = self.position;
                Some(Input::Move { x, y })
            }
            (EV_SYN, _) => None,
            _ => self.drop(),
        }
    }

    fn drop(&mut self) -> Option<Input> {
        self.dropped += 1;
        None
    }
}

/// The Keyboard/Keypad page usage of Linux key code `code`
/// (`input-event-codes.h`), if it has one.
pub fn usage(code: u16) -> Option<u8> {
    const LOW: [u8; 128] = [
        0x00, 0x29, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, // 0-7: ESC, 1..6
        0x24, 0x25, 0x26, 0x27, 0x2d, 0x2e, 0x2a, 0x2b, // 7..0, -, =, BS, TAB
        0x14, 0x1a, 0x08, 0x15, 0x17, 0x1c, 0x18, 0x0c, // Q W E R T Y U I
        0x12, 0x13, 0x2f, 0x30, 0x28, 0xe0, 0x04, 0x16, // O P [ ] ENTER LCTRL A S
        0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0e, 0x0f, 0x33, // D F G H J K L ;
        0x34, 0x35, 0xe1, 0x31, 0x1d, 0x1b, 0x06, 0x19, // ' ` LSHIFT \ Z X C V
        0x05, 0x11, 0x10, 0x36, 0x37, 0x38, 0xe5, 0x55, // B N M , . / RSHIFT KP*
        0xe2, 0x2c, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, // LALT SPACE CAPS F1..F5
        0x3f, 0x40, 0x41, 0x42, 0x43, 0x53, 0x47, 0x5f, // F6..F10 NUM SCROLL KP7
        0x60, 0x61, 0x56, 0x5c, 0x5d, 0x5e, 0x57, 0x59, // KP8 KP9 KP- KP4..6 KP+ KP1
        0x5a, 0x5b, 0x62, 0x63, 0x00, 0x94, 0x64, 0x44, // KP2 KP3 KP0 KP. - ZENKAKU 102ND F11
        0x45, 0x87, 0x92, 0x93, 0x8a, 0x88, 0x8b,
        0x8c, // F12 RO KATA HIRA HENKAN K/H MUHENKAN KPJPCOMMA
        0x58, 0xe4, 0x54, 0x46, 0xe6, 0x00, 0x4a,
        0x52, // KPENTER RCTRL KP/ SYSRQ RALT - HOME UP
        0x4b, 0x50, 0x4f, 0x4d, 0x51, 0x4e, 0x49,
        0x4c, // PGUP LEFT RIGHT END DOWN PGDN INS DEL
        0x00, 0x7f, 0x81, 0x80, 0x66, 0x67, 0x00, 0x48, // - MUTE VOL- VOL+ POWER KP= - PAUSE
        0x00, 0x85, 0x90, 0x91, 0x89, 0xe3, 0xe7,
        0x65, // - KP, HANGEUL HANJA YEN LMETA RMETA COMPOSE
    ];
    let usage = match code {
        0..=127 => LOW[usize::from(code)],
        // F13..F24.
        183..=194 => 0x68 + (code - 183) as u8,
        _ => 0,
    };
    (usage != 0).then_some(usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u16, code: u16, value: i32) -> Event {
        Event { kind, code, value }
    }

    #[test]
    fn linux_key_codes_map_to_keyboard_page_usages() {
        assert_eq!(usage(30), Some(0x04)); // A
        assert_eq!(usage(44), Some(0x1d)); // Z
        assert_eq!(usage(2), Some(0x1e)); // 1
        assert_eq!(usage(11), Some(0x27)); // 0
        assert_eq!(usage(28), Some(0x28)); // Enter
        assert_eq!(usage(125), Some(0xe3)); // Left Meta: Command
        assert_eq!(usage(100), Some(0xe6)); // Right Alt: Option
        assert_eq!(usage(103), Some(0x52)); // Up
        assert_eq!(usage(88), Some(0x45)); // F12
        assert_eq!(usage(194), Some(0x73)); // F24
        assert_eq!(usage(84), None);
        assert_eq!(usage(0x110), None);
    }

    #[test]
    fn tablet_events_become_scaled_moves_buttons_and_wheel() {
        let axis = Axis {
            minimum: 0,
            maximum: 0x7fff,
        };
        let mut t = Translator::new(Some((axis, axis)));
        assert_eq!(t.translate(event(EV_ABS, ABS_X, 0x7fff)), None);
        assert_eq!(t.translate(event(EV_ABS, ABS_Y, 100)), None);
        assert_eq!(
            t.translate(event(EV_SYN, SYN_REPORT, 0)),
            Some(Input::Move { x: 0x7fff, y: 100 })
        );
        assert_eq!(t.translate(event(EV_SYN, SYN_REPORT, 0)), None);
        assert_eq!(
            t.translate(event(EV_KEY, 0x111, 1)),
            Some(Input::Buttons(2))
        );
        assert_eq!(
            t.translate(event(EV_REL, REL_WHEEL, -300)),
            Some(Input::Wheel(-127))
        );
        let wide = Axis {
            minimum: -100,
            maximum: 100,
        };
        let mut t = Translator::new(Some((wide, wide)));
        t.translate(event(EV_ABS, ABS_X, 0));
        t.translate(event(EV_ABS, ABS_Y, 500));
        assert_eq!(
            t.translate(event(EV_SYN, SYN_REPORT, 0)),
            Some(Input::Move {
                x: 0x3fff,
                y: 0x7fff
            })
        );
    }

    #[test]
    fn keyboards_drop_repeats_and_codes_without_usages() {
        let mut t = Translator::new(None);
        assert_eq!(
            t.translate(event(EV_KEY, 30, 1)),
            Some(Input::Key {
                usage: 4,
                pressed: true
            })
        );
        assert_eq!(t.translate(event(EV_KEY, 30, 2)), None);
        assert_eq!(t.translate(event(EV_KEY, 0x2c0, 1)), None);
        assert_eq!(t.translate(event(EV_ABS, ABS_X, 5)), None);
        assert_eq!(t.dropped, 2);
    }
}
