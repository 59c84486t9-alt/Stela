//! A native full-speed USB keyboard, absolute pointer and mouse: one
//! composite device with three HID 1.11 interfaces, as a host port's
//! [`Function`].
//!
//! Evidence: USB 2.0 chapter 9 (standard requests and device states) and
//! Device Class Definition for HID 1.11 (class descriptors, requests,
//! boot protocol, Appendix B.1 keyboard and B.2 mouse reports). Interface
//! 0 is a boot keyboard (subclass 1, protocol 1) whose report is the boot
//! format in both protocols: modifiers, a reserved byte and a six-key
//! array, with an output report of five LEDs. Interface 1 is a
//! report-protocol pointer with three buttons, X and Y absolute over
//! 0..=0x7fff and a relative wheel: host tablets, whose positions macOS
//! takes as they are. Interface 2 is a boot mouse (subclass 1, protocol 2)
//! with three buttons and relative X, Y and wheel over -127..=127: host
//! mice, whose counts macOS accelerates as it does a Mac's own mouse. Its
//! report protocol report is the boot report followed by the wheel byte;
//! in the boot protocol it sends the three boot bytes. Motion beyond one
//! report's range splits across reports, and queued motion of unchanged
//! buttons coalesces. Usage values are those of HID Usage Tables 1.4
//! (Keyboard/Keypad page 07h); host sources translate their own codes into
//! them.
//!
//! The device identifies itself with the pid.codes open-source vendor ID
//! 0x1209 and its test product ID 0x0001, as a self-powered device without
//! remote wakeup, so a host never suspends it waiting on a wake it cannot
//! signal. Requests a full-speed HID device need not support (device
//! qualifier, other-speed configuration, test mode, remote wakeup,
//! SYNCH_FRAME, alternate settings) answer with a request-error STALL.
//! Transactions to an endpoint of an unconfigured device also STALL: the
//! bus boundary has no no-response outcome.
//!
//! Each input change queues one report. Queues are bounded; when one is
//! full the newest report replaces its last entry, so the final state
//! always reaches the host. A nonzero SET_IDLE rate repeats the current
//! report at that rate while nothing changes (HID 1.11 7.2.4).
use super::{BusPeer, Function, Reply, Token};
use alloc::{collections::VecDeque, vec::Vec};
use stela_drivers::input::{Input, POINTER_MAX};

const EP0_PACKET: usize = 64;
const KEYBOARD_ENDPOINT: u8 = 0x81;
const POINTER_ENDPOINT: u8 = 0x82;
const MOUSE_ENDPOINT: u8 = 0x83;
const KEYBOARD_REPORT: usize = 8;
const POINTER_REPORT: usize = 7;
const MOUSE_REPORT: usize = 5;
/// The boot mouse report: buttons, X and Y (HID 1.11 B.2).
const BOOT_MOUSE_REPORT: usize = 3;
const INTERFACES: usize = 3;
const KEYBOARD: usize = 0;
const POINTER: usize = 1;
const MOUSE: usize = 2;
/// One relative report's range per axis.
const MOTION_MAX: i16 = 127;
const QUEUE: usize = 64;
/// Keys the boot report reports before it reports rollover.
const ROLLOVER: usize = 6;
const ERROR_ROLLOVER: u8 = 1;
/// Keys held at once that the device tracks.
const MAX_HELD: usize = 32;
/// The idle rate's unit, 4 ms, in 24 MHz system counts.
const IDLE_UNIT: u64 = 96_000;
/// HID 1.11 7.2.4's recommended keyboard default, 500 ms; pointers report
/// only on change.
const KEYBOARD_IDLE: u8 = 125;

const GET_STATUS: u8 = 0;
const CLEAR_FEATURE: u8 = 1;
const SET_FEATURE: u8 = 3;
const SET_ADDRESS: u8 = 5;
const GET_DESCRIPTOR: u8 = 6;
const GET_CONFIGURATION: u8 = 8;
const SET_CONFIGURATION: u8 = 9;
const GET_INTERFACE: u8 = 10;
const SET_INTERFACE: u8 = 11;
const GET_REPORT: u8 = 1;
const GET_IDLE: u8 = 2;
const GET_PROTOCOL: u8 = 3;
const SET_REPORT: u8 = 9;
const SET_IDLE: u8 = 0x0a;
const SET_PROTOCOL: u8 = 0x0b;
const ENDPOINT_HALT: u16 = 0;
const DEVICE: u8 = 1;
const CONFIGURATION: u8 = 2;
const STRING: u8 = 3;
const HID: u8 = 0x21;
const REPORT: u8 = 0x22;
const INPUT_REPORT: u8 = 1;
const OUTPUT_REPORT: u8 = 2;
const BOOT_PROTOCOL: u8 = 0;
const REPORT_PROTOCOL: u8 = 1;
const ENGLISH: u16 = 0x0409;

const DEVICE_DESCRIPTOR: [u8; 18] = [
    18,
    DEVICE,
    0x00,
    0x02, // USB 2.0
    0,
    0,
    0, // class per interface
    EP0_PACKET as u8,
    0x09,
    0x12, // vendor 0x1209
    0x01,
    0x00, // product 0x0001
    0x00,
    0x01, // release 1.00
    1,
    2,
    0, // manufacturer, product, no serial
    1,
];

const KEYBOARD_REPORT_DESCRIPTOR: [u8; 64] = [
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, // Generic Desktop, Keyboard, Application
    0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, // modifier usages E0h..E7h
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, // 8 bits
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01, // reserved byte
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, // five LEDs
    0x95, 0x01, 0x75, 0x03, 0x91, 0x01, // LED padding
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x26, 0xdd, 0x00, // six keys 0..DDh
    0x05, 0x07, 0x19, 0x00, 0x29, 0xdd, 0x81, 0x00, // key array
    0xc0,
];

const POINTER_REPORT_DESCRIPTOR: [u8; 89] = [
    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, // Generic Desktop, Mouse, Application
    0x09, 0x01, 0xa1, 0x00, // Pointer, Physical
    0x05, 0x09, 0x19, 0x01, 0x29, 0x03, // buttons 1..3
    0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, //
    0x95, 0x01, 0x75, 0x05, 0x81, 0x01, // padding
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, // X, Y
    0x15, 0x00, 0x26, 0xff, 0x7f, 0x35, 0x00, 0x46, 0xff, 0x7f, //
    0x75, 0x10, 0x95, 0x02, 0x81, 0x02, // absolute
    0x05, 0x01, 0x09, 0x38, // wheel
    0x15, 0x81, 0x25, 0x7f, 0x35, 0x00, 0x45, 0x00, //
    0x75, 0x08, 0x95, 0x01, 0x81, 0x06, // relative
    0x05, 0x0c, 0x0a, 0x38, 0x02, // AC Pan
    0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x01, 0x81, 0x06, // relative
    0xc0, 0xc0,
];

/// The boot mouse report (HID 1.11 B.2) with wheel and AC Pan bytes after it.
const MOUSE_REPORT_DESCRIPTOR: [u8; 61] = [
    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, // Generic Desktop, Mouse, Application
    0x09, 0x01, 0xa1, 0x00, // Pointer, Physical
    0x05, 0x09, 0x19, 0x01, 0x29, 0x03, // buttons 1..3
    0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, //
    0x95, 0x01, 0x75, 0x05, 0x81, 0x01, // padding
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, // X, Y, wheel
    0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, // relative
    0x05, 0x0c, 0x0a, 0x38, 0x02, // AC Pan
    0x95, 0x01, 0x81, 0x06, // relative
    0xc0, 0xc0,
];

const fn hid_descriptor(report: usize) -> [u8; 9] {
    [
        9,
        HID,
        0x11,
        0x01, // HID 1.11
        0,
        1,
        REPORT,
        report as u8,
        (report >> 8) as u8,
    ]
}

/// Each interface's interface, HID and endpoint descriptors.
const INTERFACE_BYTES: usize = 9 + 9 + 7;
const CONFIGURATION_BYTES: usize = 9 + INTERFACES * INTERFACE_BYTES;

fn configuration_descriptor() -> [u8; CONFIGURATION_BYTES] {
    let mut bytes = [0; CONFIGURATION_BYTES];
    let parts: [&[u8]; 10] = [
        &[
            9,
            CONFIGURATION,
            CONFIGURATION_BYTES as u8,
            0,
            INTERFACES as u8,
            1,    // bConfigurationValue
            0,    // no string
            0xc0, // self-powered, no remote wakeup
            0,
        ],
        &[9, 4, KEYBOARD as u8, 0, 1, 3, 1, 1, 0], // boot keyboard
        &hid_descriptor(KEYBOARD_REPORT_DESCRIPTOR.len()),
        &[7, 5, KEYBOARD_ENDPOINT, 3, KEYBOARD_REPORT as u8, 0, 1],
        &[9, 4, POINTER as u8, 0, 1, 3, 0, 0, 0], // report-protocol pointer
        &hid_descriptor(POINTER_REPORT_DESCRIPTOR.len()),
        &[7, 5, POINTER_ENDPOINT, 3, POINTER_REPORT as u8, 0, 1],
        &[9, 4, MOUSE as u8, 0, 1, 3, 1, 2, 0], // boot mouse
        &hid_descriptor(MOUSE_REPORT_DESCRIPTOR.len()),
        &[7, 5, MOUSE_ENDPOINT, 3, MOUSE_REPORT as u8, 0, 1],
    ];
    let mut at = 0;
    for part in parts {
        bytes[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    bytes
}

fn string(text: &str) -> Vec<u8> {
    let mut bytes = alloc::vec![0, STRING];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    bytes[0] = bytes.len() as u8;
    bytes
}

#[derive(Clone)]
struct Interface {
    protocol: u8,
    idle: u8,
    halted: bool,
    queue: VecDeque<Vec<u8>>,
    /// The system count the last report went out at.
    sent: u64,
}

impl Interface {
    fn new(idle: u8) -> Self {
        Self {
            protocol: REPORT_PROTOCOL,
            idle,
            halted: false,
            queue: VecDeque::new(),
            sent: 0,
        }
    }

    fn push(&mut self, report: Vec<u8>) {
        if self.queue.len() == QUEUE {
            self.queue.pop_back();
        }
        self.queue.push_back(report);
    }
}

#[derive(Clone)]
enum Control {
    Idle,
    /// IN data stage: the reply, the bytes sent and whether the final
    /// (short or zero-length) packet has gone.
    In {
        data: Vec<u8>,
        sent: usize,
        length: usize,
        done: bool,
    },
    Out {
        setup: [u8; 8],
        data: Vec<u8>,
    },
    /// The status stage of a request that succeeded, with its deferred
    /// effect (SET_ADDRESS takes effect after its status stage).
    Status(Option<u8>),
    Stalled,
}

/// The device's bus state and its host's view of keys and pointer.
#[derive(Clone)]
pub struct Peripheral {
    address: u8,
    configuration: u8,
    control: Control,
    interfaces: [Interface; INTERFACES],
    /// The LEDs the host last set: Num, Caps, Scroll, Compose, Kana lock
    /// as bits 0..4.
    leds: u8,
    now: u64,
    modifiers: u8,
    held: Vec<u8>,
    buttons: u8,
    x: u16,
    y: u16,
    mouse_buttons: u8,
}

/// Each interface's idle rate after configuration.
fn interfaces() -> [Interface; INTERFACES] {
    [
        Interface::new(KEYBOARD_IDLE),
        Interface::new(0),
        Interface::new(0),
    ]
}

impl Default for Peripheral {
    fn default() -> Self {
        Self::new()
    }
}

impl Peripheral {
    pub fn new() -> Self {
        Self {
            address: 0,
            configuration: 0,
            control: Control::Idle,
            interfaces: interfaces(),
            leds: 0,
            now: 0,
            modifiers: 0,
            held: Vec::new(),
            buttons: 0,
            x: 0,
            y: 0,
            mouse_buttons: 0,
        }
    }

    /// The keyboard LEDs the host last set, Num Lock in bit 0 through Kana
    /// in bit 4, as the boot keyboard's output report carries them.
    pub fn leds(&self) -> u8 {
        self.leds
    }

    /// Applies one input change, queuing the report it produces. Reports
    /// queue only while configured; a host that has not configured the
    /// device reads the current state with GET_REPORT.
    pub fn input(&mut self, input: Input) -> Result<(), &'static str> {
        match input {
            Input::Key { usage, pressed } => {
                if let 0xe0..=0xe7 = usage {
                    let bit = 1 << (usage - 0xe0);
                    self.modifiers = if pressed {
                        self.modifiers | bit
                    } else {
                        self.modifiers & !bit
                    };
                } else if (0x04..=0xdd).contains(&usage) {
                    let position = self.held.iter().position(|&held| held == usage);
                    match (pressed, position) {
                        (true, None) if self.held.len() == MAX_HELD => {
                            return Err("too many keys held at once");
                        }
                        (true, None) => self.held.push(usage),
                        (false, Some(n)) => {
                            self.held.remove(n);
                        }
                        _ => return Ok(()),
                    }
                } else {
                    return Err("not a Keyboard/Keypad usage this keyboard reports");
                }
                let report = self.keyboard_report().to_vec();
                self.queue(KEYBOARD, report);
            }
            Input::Move { x, y } => {
                if x > POINTER_MAX || y > POINTER_MAX {
                    return Err("pointer position outside its logical range");
                }
                (self.x, self.y) = (x, y);
                // Motion coalesces into a queued report of the same buttons.
                let report = self.pointer_report(0, 0);
                let queue = &mut self.interfaces[POINTER].queue;
                match queue.back_mut() {
                    Some(last) if last[0] == report[0] && last[5] == 0 && last[6] == 0 => {
                        last.copy_from_slice(&report)
                    }
                    _ => self.queue(POINTER, report.to_vec()),
                }
            }
            Input::Buttons(buttons) => {
                if buttons & !7 != 0 {
                    return Err("the pointer has three buttons");
                }
                self.buttons = buttons;
                let report = self.pointer_report(0, 0).to_vec();
                self.queue(POINTER, report);
            }
            Input::Wheel(detents) => {
                if detents == i8::MIN {
                    return Err("wheel motion outside its logical range");
                }
                let report = self.pointer_report(detents, 0).to_vec();
                self.queue(POINTER, report);
            }
            Input::HWheel(detents) => {
                if detents == i8::MIN {
                    return Err("wheel motion outside its logical range");
                }
                let report = self.pointer_report(0, detents).to_vec();
                self.queue(POINTER, report);
            }
            Input::Motion { dx, dy } => self.motion(dx, dy),
            Input::MouseButtons(buttons) => {
                if buttons & !7 != 0 {
                    return Err("the mouse has three buttons");
                }
                self.mouse_buttons = buttons;
                let report = self.mouse_report(0, 0, 0, 0).to_vec();
                self.queue(MOUSE, report);
            }
            Input::MouseWheel(detents) => {
                if detents == i8::MIN {
                    return Err("wheel motion outside its logical range");
                }
                let report = self.mouse_report(0, 0, detents, 0).to_vec();
                self.queue(MOUSE, report);
            }
            Input::MouseHWheel(detents) => {
                if detents == i8::MIN {
                    return Err("wheel motion outside its logical range");
                }
                let report = self.mouse_report(0, 0, 0, detents).to_vec();
                self.queue(MOUSE, report);
            }
        }
        Ok(())
    }

    /// Queues mouse motion: first into a queued report of the same
    /// buttons without wheel motion, as far as its range allows, then in
    /// reports of at most [`MOTION_MAX`] counts per axis.
    fn motion(&mut self, mut dx: i16, mut dy: i16) {
        if self.configuration == 0 {
            return;
        }
        let buttons = self.mouse_buttons;
        let queue = &mut self.interfaces[MOUSE].queue;
        if let Some(last) = queue.back_mut()
            && last[0] == buttons
            && last[3] == 0
            && last[4] == 0
        {
            for (byte, delta) in [(1, &mut dx), (2, &mut dy)] {
                let held = i16::from(last[byte] as i8);
                let merged = (held + *delta).clamp(-MOTION_MAX, MOTION_MAX);
                *delta -= merged - held;
                last[byte] = merged as i8 as u8;
            }
        }
        while dx != 0 || dy != 0 {
            let step_x = dx.clamp(-MOTION_MAX, MOTION_MAX);
            let step_y = dy.clamp(-MOTION_MAX, MOTION_MAX);
            (dx, dy) = (dx - step_x, dy - step_y);
            let report = self.mouse_report(step_x as i8, step_y as i8, 0, 0).to_vec();
            self.interfaces[MOUSE].push(report);
        }
    }

    fn queue(&mut self, interface: usize, report: Vec<u8>) {
        if self.configuration != 0 {
            self.interfaces[interface].push(report);
        }
    }

    fn keyboard_report(&self) -> [u8; KEYBOARD_REPORT] {
        let mut report = [0; KEYBOARD_REPORT];
        report[0] = self.modifiers;
        if self.held.len() > ROLLOVER {
            report[2..].fill(ERROR_ROLLOVER);
        } else {
            report[2..2 + self.held.len()].copy_from_slice(&self.held);
        }
        report
    }

    fn pointer_report(&self, wheel: i8, pan: i8) -> [u8; POINTER_REPORT] {
        let [x0, x1] = self.x.to_le_bytes();
        let [y0, y1] = self.y.to_le_bytes();
        [self.buttons, x0, x1, y0, y1, wheel as u8, pan as u8]
    }

    fn mouse_report(&self, dx: i8, dy: i8, wheel: i8, pan: i8) -> [u8; MOUSE_REPORT] {
        [
            self.mouse_buttons,
            dx as u8,
            dy as u8,
            wheel as u8,
            pan as u8,
        ]
    }

    /// The interface's report now: relative fields report no motion.
    fn current(&self, interface: usize) -> Vec<u8> {
        match interface {
            KEYBOARD => self.keyboard_report().to_vec(),
            POINTER => self.pointer_report(0, 0).to_vec(),
            _ => self.mouse_report(0, 0, 0, 0).to_vec(),
        }
    }

    fn interface_of(endpoint: u8) -> Option<usize> {
        match endpoint {
            KEYBOARD_ENDPOINT => Some(KEYBOARD),
            POINTER_ENDPOINT => Some(POINTER),
            MOUSE_ENDPOINT => Some(MOUSE),
            _ => None,
        }
    }

    /// The boot-subclass interfaces, which take GET/SET_PROTOCOL.
    fn boot(interface: usize) -> bool {
        matches!(interface, KEYBOARD | MOUSE)
    }

    fn idle_due(&self, interface: usize) -> Option<u64> {
        let i = &self.interfaces[interface];
        (i.idle != 0).then(|| i.sent.saturating_add(u64::from(i.idle) * IDLE_UNIT))
    }

    /// Evaluates a request whose data stage, if any, is complete. `Err`
    /// is a request error: the device STALLs the rest of the transfer.
    fn request(&mut self, setup: [u8; 8], data: &[u8]) -> Result<Outcome, ()> {
        let kind = setup[0];
        let request = setup[1];
        let value = u16::from_le_bytes([setup[2], setup[3]]);
        let index = u16::from_le_bytes([setup[4], setup[5]]);
        let configured = self.configuration != 0;
        let interface = usize::from(index as u8);
        let reply = |bytes: &[u8]| Ok(Outcome::Data(bytes.to_vec()));
        match (kind, request) {
            (0x80, GET_STATUS) => reply(&[1, 0]), // self-powered
            (0x81, GET_STATUS) if configured && interface < INTERFACES => reply(&[0, 0]),
            (0x82, GET_STATUS) => match index as u8 {
                0 | 0x80 => reply(&[0, 0]),
                ep if configured => {
                    let n = Self::interface_of(ep).ok_or(())?;
                    reply(&[u8::from(self.interfaces[n].halted), 0])
                }
                _ => Err(()),
            },
            (0x02, CLEAR_FEATURE | SET_FEATURE) if value == ENDPOINT_HALT => match index as u8 {
                0 | 0x80 => Ok(Outcome::Done(None)),
                ep if configured => {
                    let n = Self::interface_of(ep).ok_or(())?;
                    self.interfaces[n].halted = request == SET_FEATURE;
                    Ok(Outcome::Done(None))
                }
                _ => Err(()),
            },
            (0x00, SET_ADDRESS) if value <= 127 && index == 0 && !configured => {
                Ok(Outcome::Done(Some(value as u8)))
            }
            (0x80, GET_DESCRIPTOR) => match ((value >> 8) as u8, value as u8) {
                (DEVICE, 0) => reply(&DEVICE_DESCRIPTOR),
                (CONFIGURATION, 0) => reply(&configuration_descriptor()),
                (STRING, 0) => reply(&[4, STRING, 0x09, 0x04]),
                (STRING, 1) if index == ENGLISH => reply(&string("Stela")),
                (STRING, 2) if index == ENGLISH => reply(&string("Stela Keyboard and Pointers")),
                _ => Err(()),
            },
            (0x81, GET_DESCRIPTOR) if interface < INTERFACES => {
                match ((value >> 8) as u8, value as u8) {
                    (HID, 0) => {
                        let start = 9 + interface * INTERFACE_BYTES + 9;
                        reply(&configuration_descriptor()[start..start + 9])
                    }
                    (REPORT, 0) => reply(match interface {
                        KEYBOARD => &KEYBOARD_REPORT_DESCRIPTOR[..],
                        POINTER => &POINTER_REPORT_DESCRIPTOR[..],
                        _ => &MOUSE_REPORT_DESCRIPTOR[..],
                    }),
                    _ => Err(()),
                }
            }
            (0x80, GET_CONFIGURATION) => reply(&[self.configuration]),
            (0x00, SET_CONFIGURATION) if value <= 1 && self.address != 0 => {
                self.configuration = value as u8;
                self.interfaces = interfaces();
                Ok(Outcome::Done(None))
            }
            (0x81, GET_INTERFACE) if configured && interface < INTERFACES => reply(&[0]),
            (0x01, SET_INTERFACE) if configured && interface < INTERFACES && value == 0 => {
                self.interfaces[interface].halted = false;
                Ok(Outcome::Done(None))
            }
            (0xa1, GET_REPORT)
                if interface < INTERFACES && value == u16::from(INPUT_REPORT) << 8 =>
            {
                reply(&self.report(interface, self.current(interface)))
            }
            (0x21, SET_REPORT)
                if interface == 0 && value == u16::from(OUTPUT_REPORT) << 8 && data.len() == 1 =>
            {
                self.leds = data[0] & 0x1f;
                Ok(Outcome::Done(None))
            }
            (0xa1, GET_IDLE) if interface < INTERFACES && value == 0 => {
                reply(&[self.interfaces[interface].idle])
            }
            (0x21, SET_IDLE) if interface < INTERFACES && value as u8 == 0 => {
                let i = &mut self.interfaces[interface];
                i.idle = (value >> 8) as u8;
                i.sent = self.now;
                Ok(Outcome::Done(None))
            }
            (0xa1, GET_PROTOCOL) if Self::boot(interface) && value == 0 => {
                reply(&[self.interfaces[interface].protocol])
            }
            (0x21, SET_PROTOCOL)
                if Self::boot(interface)
                    && matches!(value as u8, BOOT_PROTOCOL | REPORT_PROTOCOL) =>
            {
                self.interfaces[interface].protocol = value as u8;
                Ok(Outcome::Done(None))
            }
            _ => Err(()),
        }
    }

    fn setup(&mut self, setup: [u8; 8]) {
        let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        self.control = if setup[0] & 0x80 == 0 && length != 0 {
            Control::Out {
                setup,
                data: Vec::new(),
            }
        } else {
            match self.request(setup, &[]) {
                Ok(Outcome::Data(data)) if setup[0] & 0x80 != 0 => Control::In {
                    data,
                    sent: 0,
                    length,
                    done: length == 0,
                },
                Ok(Outcome::Done(effect)) if length == 0 => Control::Status(effect),
                _ => Control::Stalled,
            }
        };
    }

    fn control_in(&mut self, buffer: &mut [u8]) -> Reply {
        match &mut self.control {
            Control::In {
                data,
                sent,
                length,
                done,
            } if !*done => {
                let end = data.len().min(*length);
                let n = (end - *sent).min(EP0_PACKET).min(buffer.len());
                buffer[..n].copy_from_slice(&data[*sent..*sent + n]);
                *sent += n;
                *done = n < EP0_PACKET || *sent == *length;
                Reply::Ack(n)
            }
            Control::Status(effect) => {
                if let Some(address) = *effect {
                    self.address = address;
                }
                self.control = Control::Idle;
                Reply::Ack(0)
            }
            _ => {
                self.control = Control::Stalled;
                Reply::Stall
            }
        }
    }

    fn control_out(&mut self, data: &[u8]) -> Reply {
        match &mut self.control {
            // The host's status stage, after all or part of the IN data.
            Control::In { .. } if data.is_empty() => {
                self.control = Control::Idle;
                Reply::Ack(0)
            }
            Control::Out {
                setup,
                data: so_far,
            } => {
                so_far.extend_from_slice(data);
                let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
                if so_far.len() < length && data.len() == EP0_PACKET {
                    return Reply::Ack(data.len());
                }
                let (setup, so_far) = (*setup, core::mem::take(so_far));
                self.control = match self.request(setup, &so_far) {
                    Ok(Outcome::Done(effect)) if so_far.len() == length => Control::Status(effect),
                    _ => Control::Stalled,
                };
                Reply::Ack(data.len())
            }
            _ => {
                self.control = Control::Stalled;
                Reply::Stall
            }
        }
    }

    fn interrupt_in(&mut self, endpoint: u8, buffer: &mut [u8]) -> Reply {
        let Some(n) = Self::interface_of(endpoint).filter(|_| self.configuration != 0) else {
            return Reply::Stall;
        };
        if self.interfaces[n].halted {
            return Reply::Stall;
        }
        let report = match self.interfaces[n].queue.pop_front() {
            Some(report) => report,
            None if self.idle_due(n).is_some_and(|due| self.now >= due) => self.current(n),
            None => return Reply::Nak,
        };
        let report = self.report(n, report);
        let length = report.len().min(buffer.len());
        buffer[..length].copy_from_slice(&report[..length]);
        self.interfaces[n].sent = self.now;
        Reply::Ack(length)
    }

    /// `report` as interface `n` sends it in its current protocol: the
    /// boot mouse report is the first three bytes.
    fn report(&self, n: usize, mut report: Vec<u8>) -> Vec<u8> {
        if n == MOUSE && self.interfaces[n].protocol == BOOT_PROTOCOL {
            report.truncate(BOOT_MOUSE_REPORT);
        }
        report
    }
}

/// A request's outcome before its status stage.
enum Outcome {
    Data(Vec<u8>),
    Done(Option<u8>),
}

impl BusPeer for Peripheral {
    /// A bus reset returns the device to its Default state; held keys and
    /// buttons remain held.
    fn reset(&mut self) -> Result<(), &'static str> {
        self.address = 0;
        self.configuration = 0;
        self.control = Control::Idle;
        self.interfaces = interfaces();
        Ok(())
    }

    fn packet(
        &mut self,
        endpoint: u8,
        token: Token,
        data: &mut [u8],
    ) -> Result<Reply, &'static str> {
        Ok(match (endpoint, token) {
            (0, Token::Setup) => {
                let setup = data.try_into().map_err(|_| "a SETUP packet is 8 bytes")?;
                self.setup(setup);
                Reply::Ack(8)
            }
            (_, Token::Setup) => return Err("SETUP to a non-control endpoint"),
            (0, Token::In) => self.control_in(data),
            (0, Token::Out) => self.control_out(data),
            (_, Token::In) => self.interrupt_in(endpoint, data),
            // No OUT endpoint: the LED report arrives through SET_REPORT.
            (_, Token::Out) => Reply::Stall,
        })
    }
}

impl Function for Peripheral {
    fn set_time(&mut self, now: u64) {
        self.now = now;
    }

    fn ready_at(&self, endpoint: u8) -> Option<u64> {
        let n = Self::interface_of(endpoint)?;
        if self.configuration == 0 || self.interfaces[n].halted {
            return None;
        }
        if self.interfaces[n].queue.is_empty() {
            self.idle_due(n)
        } else {
            Some(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::dwc3::xhci::tests::host,
        usb::{
            Speed,
            hub::{Hub, Ports},
        },
    };

    fn control(p: &mut Peripheral, setup: [u8; 8], out: &[u8]) -> Result<Vec<u8>, ()> {
        assert_eq!(
            p.packet(0, Token::Setup, &mut setup.clone()),
            Ok(Reply::Ack(8))
        );
        let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        let mut reply = Vec::new();
        if setup[0] & 0x80 != 0 {
            while reply.len() < length {
                let mut packet = [0; EP0_PACKET];
                match p.packet(0, Token::In, &mut packet).unwrap() {
                    Reply::Ack(n) => {
                        reply.extend_from_slice(&packet[..n]);
                        if n < EP0_PACKET {
                            break;
                        }
                    }
                    Reply::Stall => return Err(()),
                    Reply::Nak => panic!("control NAK"),
                }
            }
            match p.packet(0, Token::Out, &mut []).unwrap() {
                Reply::Ack(0) => Ok(reply),
                _ => Err(()),
            }
        } else {
            for chunk in out.chunks(EP0_PACKET) {
                if p.packet(0, Token::Out, &mut chunk.to_vec()).unwrap() == Reply::Stall {
                    return Err(());
                }
            }
            match p.packet(0, Token::In, &mut []).unwrap() {
                Reply::Ack(0) => Ok(reply),
                _ => Err(()),
            }
        }
    }

    fn setup(kind: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
        let [v0, v1] = value.to_le_bytes();
        let [i0, i1] = index.to_le_bytes();
        let [l0, l1] = length.to_le_bytes();
        [kind, request, v0, v1, i0, i1, l0, l1]
    }

    fn enumerate(p: &mut Peripheral) {
        p.reset().unwrap();
        let device = control(p, setup(0x80, GET_DESCRIPTOR, 0x100, 0, 64), &[]).unwrap();
        assert_eq!(device, DEVICE_DESCRIPTOR);
        control(p, setup(0, SET_ADDRESS, 3, 0, 0), &[]).unwrap();
        assert_eq!(p.address, 3);
        control(p, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        control(p, setup(0x21, SET_IDLE, 0, 0, 0), &[]).unwrap();
    }

    #[test]
    fn descriptors_describe_a_composite_keyboard_and_pointer() {
        let mut p = Peripheral::new();
        let config = control(&mut p, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 9), &[]).unwrap();
        assert_eq!(config[..5], [9, CONFIGURATION, 84, 0, 3]);
        let full = control(&mut p, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(full, configuration_descriptor());
        // The HID descriptors name each report descriptor's length.
        for (n, report) in [
            &KEYBOARD_REPORT_DESCRIPTOR[..],
            &POINTER_REPORT_DESCRIPTOR[..],
            &MOUSE_REPORT_DESCRIPTOR[..],
        ]
        .into_iter()
        .enumerate()
        {
            let hid = control(
                &mut p,
                setup(0x81, GET_DESCRIPTOR, 0x2100, n as u16, 9),
                &[],
            );
            assert_eq!(hid.unwrap()[7], report.len() as u8);
            let got = control(
                &mut p,
                setup(0x81, GET_DESCRIPTOR, 0x2200, n as u16, 255),
                &[],
            );
            assert_eq!(got.unwrap(), report);
        }
        let product = control(
            &mut p,
            setup(0x80, GET_DESCRIPTOR, 0x302, ENGLISH, 255),
            &[],
        );
        assert_eq!(product.unwrap()[0], 2 + 2 * 27);
        // The mouse is a boot mouse.
        assert_eq!(&full[59..68], &[9, 4, 2, 0, 1, 3, 1, 2, 0]);
        // A full-speed-only device STALLs the device qualifier.
        assert!(control(&mut p, setup(0x80, GET_DESCRIPTOR, 0x600, 0, 10), &[]).is_err());
        // A STALL clears at the next SETUP.
        assert!(control(&mut p, setup(0x80, GET_STATUS, 0, 0, 2), &[]).is_ok());
    }

    #[test]
    fn configuration_needs_an_address_and_unconfigured_endpoints_stall() {
        let mut p = Peripheral::new();
        assert!(control(&mut p, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).is_err());
        let mut report = [0; 8];
        assert_eq!(p.packet(0x81, Token::In, &mut report), Ok(Reply::Stall));
        enumerate(&mut p);
        assert_eq!(p.packet(0x81, Token::In, &mut report), Ok(Reply::Nak));
        assert!(control(&mut p, setup(0, SET_ADDRESS, 4, 0, 0), &[]).is_err());
        assert!(control(&mut p, setup(0, SET_CONFIGURATION, 2, 0, 0), &[]).is_err());
        assert!(p.packet(1, Token::Setup, &mut [0; 8]).is_err());
    }

    #[test]
    fn keys_and_pointer_motion_queue_boot_and_absolute_reports() {
        let mut p = Peripheral::new();
        enumerate(&mut p);
        p.input(Input::Key {
            usage: 0xe1,
            pressed: true,
        })
        .unwrap();
        p.input(Input::Key {
            usage: 0x04,
            pressed: true,
        })
        .unwrap();
        assert_eq!(p.ready_at(0x81), Some(0));
        let mut report = [0; 8];
        assert_eq!(p.packet(0x81, Token::In, &mut report), Ok(Reply::Ack(8)));
        assert_eq!(report, [2, 0, 0, 0, 0, 0, 0, 0]);
        p.packet(0x81, Token::In, &mut report).unwrap();
        assert_eq!(report, [2, 0, 4, 0, 0, 0, 0, 0]);
        assert_eq!(p.ready_at(0x81), None);
        // Seven keys report rollover.
        for usage in 5..11 {
            p.input(Input::Key {
                usage,
                pressed: true,
            })
            .unwrap();
        }
        let mut last = [0; 8];
        while let Ok(Reply::Ack(_)) = p.packet(0x81, Token::In, &mut last) {}
        assert_eq!(last[2..], [ERROR_ROLLOVER; 6]);
        assert!(
            p.input(Input::Key {
                usage: 0x02,
                pressed: true
            })
            .is_err()
        );
        // Motion coalesces; a button change does not.
        p.input(Input::Move { x: 1, y: 2 }).unwrap();
        p.input(Input::Move { x: 0x7fff, y: 3 }).unwrap();
        p.input(Input::Buttons(1)).unwrap();
        p.input(Input::Wheel(-2)).unwrap();
        p.input(Input::HWheel(5)).unwrap();
        let mut pointer = [0; POINTER_REPORT];
        p.packet(0x82, Token::In, &mut pointer).unwrap();
        assert_eq!(pointer, [0, 0xff, 0x7f, 3, 0, 0, 0]);
        p.packet(0x82, Token::In, &mut pointer).unwrap();
        assert_eq!(pointer, [1, 0xff, 0x7f, 3, 0, 0, 0]);
        p.packet(0x82, Token::In, &mut pointer).unwrap();
        assert_eq!(pointer[5..], [(-2i8) as u8, 0]);
        p.packet(0x82, Token::In, &mut pointer).unwrap();
        assert_eq!(pointer[5..], [0, 5]);
        assert!(p.input(Input::Move { x: 0x8000, y: 0 }).is_err());
    }

    #[test]
    fn mouse_motion_splits_coalesces_and_follows_the_protocol() {
        let mut p = Peripheral::new();
        enumerate(&mut p);
        let read = |p: &mut Peripheral| {
            let mut report = [0; MOUSE_REPORT];
            match p.packet(MOUSE_ENDPOINT, Token::In, &mut report).unwrap() {
                Reply::Ack(n) => Some(report[..n].to_vec()),
                _ => None,
            }
        };
        // 300 counts right split into 127 + 127 + 46; queued motion of the
        // same buttons coalesces.
        p.input(Input::Motion { dx: 300, dy: -5 }).unwrap();
        p.input(Input::Motion { dx: 10, dy: -5 }).unwrap();
        assert_eq!(p.ready_at(MOUSE_ENDPOINT), Some(0));
        assert_eq!(read(&mut p).unwrap(), [0, 127, (-5i8) as u8, 0, 0]);
        assert_eq!(read(&mut p).unwrap(), [0, 127, 0, 0, 0]);
        assert_eq!(read(&mut p).unwrap(), [0, 56, (-5i8) as u8, 0, 0]);
        assert_eq!(read(&mut p), None);
        // A button change and wheel motion each send a report.
        p.input(Input::MouseButtons(2)).unwrap();
        p.input(Input::Motion { dx: -1, dy: 1 }).unwrap();
        p.input(Input::MouseWheel(3)).unwrap();
        p.input(Input::MouseHWheel(-4)).unwrap();
        assert_eq!(read(&mut p).unwrap(), [2, (-1i8) as u8, 1, 0, 0]);
        assert_eq!(read(&mut p).unwrap(), [2, 0, 0, 3, 0]);
        assert_eq!(read(&mut p).unwrap(), [2, 0, 0, 0, (-4i8) as u8]);
        assert!(p.input(Input::MouseHWheel(i8::MIN)).is_err());
        assert!(p.input(Input::MouseButtons(8)).is_err());
        assert!(p.input(Input::MouseWheel(i8::MIN)).is_err());
        // The pointer's state is its own.
        assert_eq!(p.buttons, 0);
        // The boot protocol sends the three boot bytes.
        control(&mut p, setup(0x21, SET_PROTOCOL, 0, 2, 0), &[]).unwrap();
        p.input(Input::Motion { dx: 4, dy: 4 }).unwrap();
        assert_eq!(read(&mut p).unwrap(), [2, 4, 4]);
        let report = control(&mut p, setup(0xa1, GET_REPORT, 0x100, 2, 4), &[]).unwrap();
        assert_eq!(report, [2, 0, 0]);
        // The absolute pointer takes no protocol requests.
        assert!(control(&mut p, setup(0xa1, GET_PROTOCOL, 0, 1, 1), &[]).is_err());
    }

    #[test]
    fn class_requests_set_leds_protocol_idle_and_halt() {
        let mut p = Peripheral::new();
        enumerate(&mut p);
        control(&mut p, setup(0x21, SET_REPORT, 0x200, 0, 1), &[0x23]).unwrap();
        assert_eq!(p.leds(), 3);
        control(&mut p, setup(0x21, SET_PROTOCOL, 0, 0, 0), &[]).unwrap();
        let protocol = control(&mut p, setup(0xa1, GET_PROTOCOL, 0, 0, 1), &[]).unwrap();
        assert_eq!(protocol, [BOOT_PROTOCOL]);
        assert!(control(&mut p, setup(0x21, SET_PROTOCOL, 0, 1, 0), &[]).is_err());
        let report = control(&mut p, setup(0xa1, GET_REPORT, 0x100, 1, 7), &[]).unwrap();
        assert_eq!(report.len(), POINTER_REPORT);
        // A 40 ms idle rate repeats the unchanged report.
        p.set_time(1000);
        control(&mut p, setup(0x21, SET_IDLE, 10 << 8, 0, 0), &[]).unwrap();
        assert_eq!(p.ready_at(0x81), Some(1000 + 10 * IDLE_UNIT));
        let mut buffer = [0; 8];
        assert_eq!(p.packet(0x81, Token::In, &mut buffer), Ok(Reply::Nak));
        p.set_time(1000 + 10 * IDLE_UNIT);
        assert_eq!(p.packet(0x81, Token::In, &mut buffer), Ok(Reply::Ack(8)));
        // Halt and clear.
        control(&mut p, setup(0x02, SET_FEATURE, 0, 0x81, 0), &[]).unwrap();
        assert_eq!(p.packet(0x81, Token::In, &mut buffer), Ok(Reply::Stall));
        let status = control(&mut p, setup(0x82, GET_STATUS, 0, 0x81, 2), &[]).unwrap();
        assert_eq!(status, [1, 0]);
        control(&mut p, setup(0x02, CLEAR_FEATURE, 0, 0x81, 0), &[]).unwrap();
        assert_ne!(p.packet(0x81, Token::In, &mut buffer), Ok(Reply::Stall));
    }

    struct One(Peripheral);
    impl Ports for One {
        fn count(&self) -> usize {
            1
        }
        fn speed(&self, _: usize) -> Speed {
            Speed::Full
        }
        fn function(&mut self, _: usize) -> &mut dyn Function {
            &mut self.0
        }
        fn function_ref(&self, _: usize) -> &dyn Function {
            &self.0
        }
    }

    #[test]
    fn the_native_keyboard_and_pointer_reach_the_host_through_a_hub() {
        let hub = Hub::new(One(Peripheral::new()), "HUB").unwrap();
        let mut bench = host::bench(hub);
        let mut found = host::run(&mut bench);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.inputs.len(), 3);
        let mut keyboard = found.inputs.remove(0);
        let mut pointer = found.inputs.remove(0);
        let mut mouse = found.inputs.remove(0);
        assert!(keyboard.poll().is_empty());
        assert!(pointer.poll().is_empty());
        assert!(mouse.poll().is_empty());
        let feed = |input: Input| {
            bench
                .model
                .borrow_mut()
                .function
                .ports
                .0
                .input(input)
                .unwrap();
        };
        feed(Input::Key {
            usage: 0x04,
            pressed: true,
        });
        feed(Input::Key {
            usage: 0xe1,
            pressed: true,
        });
        feed(Input::Move { x: 100, y: 0x7000 });
        feed(Input::Buttons(1));
        let mut keys = Vec::new();
        let mut motion = Vec::new();
        for _ in 0..50 {
            keys.extend(keyboard.poll());
            motion.extend(pointer.poll());
        }
        assert_eq!(
            keys,
            [
                Input::Key {
                    usage: 0x04,
                    pressed: true
                },
                Input::Key {
                    usage: 0xe1,
                    pressed: true
                },
            ]
        );
        assert!(
            motion.contains(&Input::Move { x: 100, y: 0x7000 }),
            "{motion:?}"
        );
        assert_eq!(motion.last(), Some(&Input::Buttons(1)));
        feed(Input::Key {
            usage: 0x04,
            pressed: false,
        });
        let mut released = Vec::new();
        for _ in 0..50 {
            released.extend(keyboard.poll());
        }
        assert_eq!(
            released,
            [Input::Key {
                usage: 0x04,
                pressed: false
            }]
        );
        // The native mouse runs the report protocol: its counts and wheel
        // arrive as they were sent.
        feed(Input::Motion { dx: -20, dy: 7 });
        feed(Input::MouseButtons(4));
        feed(Input::MouseWheel(-1));
        let mut moved = Vec::new();
        for _ in 0..50 {
            moved.extend(mouse.poll());
        }
        assert_eq!(
            moved,
            [
                Input::Motion { dx: -20, dy: 7 },
                Input::MouseButtons(4),
                Input::MouseWheel(-1),
            ]
        );
        assert!(!keyboard.failed() && !pointer.failed() && !mouse.failed());
    }
}
