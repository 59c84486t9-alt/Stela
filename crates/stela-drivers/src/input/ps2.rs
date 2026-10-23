// SPDX-License-Identifier: GPL-2.0-only
//! Polled PC i8042, raw-set-2 AT keyboards and ordinary/IntelliMouse PS/2 mice.
//!
//! Linux `i8042.c`, `libps2.c`, `atkbd.c` and `psmouse-base.c` are the protocol
//! references; see [`../THIRD_PARTY.md`](../THIRD_PARTY.md). Vojtech Pavlik
//! (1999–2002) and Dmitry Torokhov (2003–2004) retain their upstream copyrights.
//!
//! The platform must establish ACPI/PnP presence, remove USB legacy emulation,
//! mask both IRQ routes and provide exclusive controller ownership. This engine
//! leaves IRQs and set-1 translation disabled. It does not probe unadvertised
//! ports, active multiplexers, DMI quirks or vendor touchpad protocols. Every
//! command is acknowledged; a failed/uncertain command quarantines this owner.
use super::Input;
use crate::{Clock, bus::i2c::Timer};
use alloc::{collections::VecDeque, vec::Vec};

mod keyboard;
mod mouse;

const DATA_PORT: u16 = 0x60;
const COMMAND_PORT: u16 = 0x64;
const OUTPUT_FULL: u8 = 1;
const INPUT_FULL: u8 = 1 << 1;
const AUX_DATA: u8 = 1 << 5;
const FRAME_ERRORS: u8 = 0xc0;
const IRQ_BITS: u8 = 3;
const KEYBOARD_DISABLED: u8 = 1 << 4;
const MOUSE_DISABLED: u8 = 1 << 5;
const TRANSLATION: u8 = 1 << 6;
const READ_CONFIG: u8 = 0x20;
const WRITE_CONFIG: u8 = 0x60;
const SELF_TEST: u8 = 0xaa;
const TEST_KEYBOARD: u8 = 0xab;
const DISABLE_KEYBOARD: u8 = 0xad;
const ENABLE_KEYBOARD: u8 = 0xae;
const TEST_MOUSE: u8 = 0xa9;
const DISABLE_MOUSE: u8 = 0xa7;
const ENABLE_MOUSE: u8 = 0xa8;
const SEND_MOUSE: u8 = 0xd4;
const ACK: u8 = 0xfa;
const RESEND: u8 = 0xfe;
const RESET: u8 = 0xff;
const BAT_OK: u8 = 0xaa;
const ENABLE_REPORTING: u8 = 0xf4;
const DISABLE_REPORTING: u8 = 0xf5;
const DEFAULTS: u8 = 0xf6;
const GET_ID: u8 = 0xf2;
const SET_RATE: u8 = 0xf3;
const SET_SCAN: u8 = 0xf0;
const SET_LEDS: u8 = 0xed;
const SCALE_ONE_TO_ONE: u8 = 0xe6;
const SET_RESOLUTION: u8 = 0xe8;
const QUEUE_LIMIT: usize = 64;
const MAX_ATTEMPTS: usize = 2;

/// Ordered, exclusively owned byte operations on the i8042 register pair.
pub trait Registers {
    fn status(&mut self) -> u8;
    fn read_data(&mut self) -> u8;
    fn write_command(&mut self, value: u8);
    fn write_data(&mut self, value: u8);
}

/// The native PC register pair. Construction performs no hardware access.
pub struct PortIo(());

impl PortIo {
    /// # Safety
    /// The platform established that these are the enabled i8042 data/status
    /// resources, not an EC or absent decoder. Caller has I/O privilege and
    /// exclusive ownership, with USB legacy/SMM interception removed and IRQ1/
    /// IRQ12 masked. No firmware, other driver or interrupt handler may access
    /// either register until this owner has been explicitly stopped.
    pub unsafe fn claim() -> Self {
        Self(())
    }

    fn read(port: u16) -> u8 {
        let value: u8;
        // SAFETY: claim establishes privilege and exclusive decoded resources.
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
        }
        value
    }
    fn write(port: u16, value: u8) {
        // SAFETY: claim establishes privilege and exclusive decoded resources.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
        }
    }
}
impl Registers for PortIo {
    fn status(&mut self) -> u8 {
        Self::read(COMMAND_PORT)
    }
    fn read_data(&mut self) -> u8 {
        Self::read(DATA_PORT)
    }
    fn write_command(&mut self, value: u8) {
        Self::write(COMMAND_PORT, value);
    }
    fn write_data(&mut self, value: u8) {
        Self::write(DATA_PORT, value);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub keyboard: bool,
    pub mouse: bool,
    /// Attempt the standard 200/100/80 IntelliMouse negotiation; an ordinary
    /// mouse returning ID 0 remains a three-byte mouse.
    pub wheel: bool,
    pub io_timeout_us: u64,
    pub command_timeout_us: u64,
    pub reset_timeout_us: u64,
    /// An incomplete keyboard prefix or mouse packet cannot retain framing
    /// indefinitely. Expiration is reported; no invented input is emitted.
    pub packet_timeout_us: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            keyboard: true,
            mouse: true,
            wheel: true,
            io_timeout_us: 500_000,
            command_timeout_us: 200_000,
            reset_timeout_us: 1_000_000,
            packet_timeout_us: 500_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Port {
    Keyboard,
    Mouse,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    InputReady,
    Response,
    Drain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidConfiguration,
    NotInitialized,
    AlreadyInitialized,
    NeedsReset,
    NoController,
    Timeout(Phase),
    ControllerReply { command: u8, received: u8 },
    Frame { port: Port, status: u8 },
    DeviceReply { port: Port, received: u8 },
    ResendLimit { port: Port, byte: u8 },
    UnsupportedMouseId(u8),
    UnsupportedScanSet(u8),
    QueueFull,
    UnsupportedScanCode(u16),
    KeyboardSequence,
    PacketTimeout(Port),
    MouseSync(u8),
    DeviceReset(Port),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    NotAttempted,
    PortsDisabled,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub recovery: Recovery,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PS/2 {:?} (recovery {:?})", self.kind, self.recovery)
    }
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            recovery: Recovery::NotAttempted,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Fresh,
    Initializing,
    Ready,
    Stopped,
    Faulted,
}
#[derive(Clone, Copy)]
struct Byte {
    port: Port,
    data: u8,
    received_us: u64,
}

/// Owns the controller for both ports, including cross-port bytes received
/// while the sibling executes a command. No IRQ worker or firmware user runs
/// concurrently with this polled engine.
pub struct Controller<R = PortIo, T = Clock> {
    registers: R,
    timer: T,
    config: Config,
    state: State,
    controller_config: Option<u8>,
    input_known: bool,
    discarded_before_start: u64,
    pending: VecDeque<Byte>,
    events: Vec<Input>,
    keyboard: keyboard::Keyboard,
    mouse: mouse::Mouse,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Validates configuration only; call `initialize` to touch the hardware.
    pub fn new(registers: R, timer: T, config: Config) -> Result<Self, Error> {
        if (!config.keyboard && !config.mouse)
            || config.io_timeout_us == 0
            || config.command_timeout_us == 0
            || config.reset_timeout_us == 0
            || config.packet_timeout_us == 0
        {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        Ok(Self {
            registers,
            timer,
            config,
            state: State::Fresh,
            controller_config: None,
            input_known: false,
            discarded_before_start: 0,
            pending: VecDeque::new(),
            events: Vec::new(),
            keyboard: keyboard::Keyboard::default(),
            mouse: mouse::Mouse::default(),
        })
    }
    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }
    pub fn needs_reset(&self) -> bool {
        self.state == State::Faulted
    }
    /// Pre-reset bytes have unknown protocol/scan-set provenance and are not
    /// guest input. Count them rather than decoding them under the new mode.
    pub fn discarded_before_start(&self) -> u64 {
        self.discarded_before_start
    }
    pub fn has_wheel(&self) -> bool {
        self.mouse.wheel()
    }

    fn expired(&self, start: u64, limit: u64) -> bool {
        self.timer.now_us().wrapping_sub(start) >= limit
    }
    fn status(&mut self) -> Result<u8, ErrorKind> {
        let status = self.registers.status();
        if status == u8::MAX {
            Err(ErrorKind::NoController)
        } else {
            Ok(status)
        }
    }
    fn write_ready(&mut self) -> Result<(), ErrorKind> {
        let start = self.timer.now_us();
        loop {
            if self.status()? & INPUT_FULL == 0 {
                return Ok(());
            }
            if self.expired(start, self.config.io_timeout_us) {
                return Err(ErrorKind::Timeout(Phase::InputReady));
            }
            self.timer.relax();
        }
    }
    fn command(&mut self, command: u8) -> Result<(), ErrorKind> {
        self.write_ready()?;
        self.registers.write_command(command);
        Ok(())
    }
    fn write_data(&mut self, value: u8) -> Result<(), ErrorKind> {
        self.write_ready()?;
        self.registers.write_data(value);
        Ok(())
    }
    fn read_byte(&mut self) -> Result<Option<Byte>, ErrorKind> {
        let status = self.status()?;
        if status & OUTPUT_FULL == 0 {
            return Ok(None);
        }
        let port = if status & AUX_DATA == 0 {
            Port::Keyboard
        } else {
            Port::Mouse
        };
        let data = self.registers.read_data();
        if status & FRAME_ERRORS != 0 {
            return Err(ErrorKind::Frame { port, status });
        }
        Ok(Some(Byte {
            port,
            data,
            received_us: self.timer.now_us(),
        }))
    }
    fn queue(&mut self, byte: Byte) -> Result<(), ErrorKind> {
        if !self.input_known {
            self.discarded_before_start = self.discarded_before_start.saturating_add(1);
            return Ok(());
        }
        if self.pending.len() == QUEUE_LIMIT {
            return Err(ErrorKind::QueueFull);
        }
        self.pending.push_back(byte);
        Ok(())
    }
    fn response(&mut self, port: Port, start: u64, timeout: u64) -> Result<u8, ErrorKind> {
        loop {
            if let Some(byte) = self.read_byte()? {
                if byte.port == port {
                    return Ok(byte.data);
                }
                self.queue(byte)?;
            }
            if self.expired(start, timeout) {
                return Err(ErrorKind::Timeout(Phase::Response));
            }
            self.timer.relax();
        }
    }
    fn controller_response(&mut self, command: u8) -> Result<u8, ErrorKind> {
        self.command(command)?;
        self.response(
            Port::Keyboard,
            self.timer.now_us(),
            self.config.io_timeout_us,
        )
    }
    fn set_config(&mut self, value: u8) -> Result<(), ErrorKind> {
        self.command(WRITE_CONFIG)?;
        self.write_data(value)?;
        self.write_ready()?;
        // Inhibited keyboards cannot produce another byte; remove any older
        // pre-handoff data before a controller response uses the same lane.
        if value & KEYBOARD_DISABLED != 0 {
            self.collect_output()?;
        }
        let actual = self.controller_response(READ_CONFIG)?;
        let mask = IRQ_BITS | KEYBOARD_DISABLED | MOUSE_DISABLED | TRANSLATION;
        if actual & mask != value & mask {
            return Err(ErrorKind::ControllerReply {
                command: WRITE_CONFIG,
                received: actual,
            });
        }
        self.controller_config = Some(actual);
        Ok(())
    }
    fn expect_controller(&mut self, command: u8, expected: u8) -> Result<(), ErrorKind> {
        let actual = self.controller_response(command)?;
        if actual != expected {
            return Err(ErrorKind::ControllerReply {
                command,
                received: actual,
            });
        }
        Ok(())
    }
    fn send_byte(
        &mut self,
        port: Port,
        value: u8,
        timeout: u64,
        id_without_ack: bool,
    ) -> Result<Option<u8>, ErrorKind> {
        let start = self.timer.now_us();
        for _ in 0..MAX_ATTEMPTS {
            if port == Port::Mouse {
                self.command(SEND_MOUSE)?;
            }
            self.write_data(value)?;
            loop {
                let received = self.response(port, start, timeout)?;
                match received {
                    ACK => return Ok(None),
                    RESEND => break,
                    0xfc | 0xfd => return Err(ErrorKind::DeviceReply { port, received }),
                    0 | 3 | 4 if id_without_ack => return Ok(Some(received)),
                    BAT_OK if port == Port::Keyboard => return Err(ErrorKind::DeviceReset(port)),
                    _ => self.queue(Byte {
                        port,
                        data: received,
                        received_us: self.timer.now_us(),
                    })?,
                }
                if self.expired(start, timeout) {
                    return Err(ErrorKind::Timeout(Phase::Response));
                }
                self.timer.relax();
            }
        }
        Err(ErrorKind::ResendLimit { port, byte: value })
    }
    fn device_command(&mut self, port: Port, value: u8, arguments: &[u8]) -> Result<(), ErrorKind> {
        self.send_byte(port, value, self.config.command_timeout_us, false)?;
        for &argument in arguments {
            self.send_byte(port, argument, self.config.command_timeout_us, false)?;
        }
        Ok(())
    }
    fn reset_device(&mut self, port: Port) -> Result<(), ErrorKind> {
        self.send_byte(port, RESET, self.config.reset_timeout_us, false)?;
        let received = self.response(port, self.timer.now_us(), self.config.reset_timeout_us)?;
        if received != BAT_OK {
            return Err(ErrorKind::DeviceReply { port, received });
        }
        Ok(())
    }
    fn initialize_inner(&mut self) -> Result<(), ErrorKind> {
        self.command(DISABLE_KEYBOARD)?;
        self.command(DISABLE_MOUSE)?;
        // Discard only pre-handoff bytes while both ports are disabled. A
        // perpetually asserted OBF is a failure, not a successful flush.
        let start = self.timer.now_us();
        let mut drained = 0;
        while self.read_byte()?.is_some() {
            drained += 1;
            self.discarded_before_start = self.discarded_before_start.saturating_add(1);
            if drained == QUEUE_LIMIT || self.expired(start, self.config.io_timeout_us) {
                return Err(ErrorKind::Timeout(Phase::Drain));
            }
            self.timer.relax();
        }
        let config = self.controller_response(READ_CONFIG)?;
        self.controller_config = Some(config);
        self.set_config((config & !(IRQ_BITS | TRANSLATION)) | KEYBOARD_DISABLED | MOUSE_DISABLED)?;
        self.expect_controller(SELF_TEST, 0x55)?;
        // Self-test can reset CTR on real controllers; reapply/read it back.
        self.set_config((config & !(IRQ_BITS | TRANSLATION)) | KEYBOARD_DISABLED | MOUSE_DISABLED)?;
        if self.config.keyboard {
            self.expect_controller(TEST_KEYBOARD, 0)?;
        }
        if self.config.mouse {
            self.expect_controller(TEST_MOUSE, 0)?;
        }
        let enabled = (config & !(IRQ_BITS | TRANSLATION | KEYBOARD_DISABLED | MOUSE_DISABLED))
            | if self.config.keyboard {
                0
            } else {
                KEYBOARD_DISABLED
            }
            | if self.config.mouse { 0 } else { MOUSE_DISABLED };
        if self.config.keyboard {
            self.command(ENABLE_KEYBOARD)?;
            // Firmware may have left this keyboard reporting an unknown scan
            // set. Quiesce it before RESET, and never interpret those bytes.
            self.device_command(Port::Keyboard, DISABLE_REPORTING, &[])?;
            self.reset_device(Port::Keyboard)?;
            self.device_command(Port::Keyboard, DISABLE_REPORTING, &[])?;
            self.device_command(Port::Keyboard, SET_SCAN, &[2])?;
            self.device_command(Port::Keyboard, SET_SCAN, &[0])?;
            let scan = self.response(
                Port::Keyboard,
                self.timer.now_us(),
                self.config.command_timeout_us,
            )?;
            if scan != 2 {
                return Err(ErrorKind::UnsupportedScanSet(scan));
            }
            self.device_command(Port::Keyboard, SET_LEDS, &[0])?;
        }
        if self.config.mouse {
            self.command(ENABLE_MOUSE)?;
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            self.reset_device(Port::Mouse)?;
            let id = self.response(
                Port::Mouse,
                self.timer.now_us(),
                self.config.command_timeout_us,
            )?;
            if id != 0 {
                return Err(ErrorKind::UnsupportedMouseId(id));
            }
            self.device_command(Port::Mouse, DEFAULTS, &[])?;
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            self.device_command(Port::Mouse, SCALE_ONE_TO_ONE, &[])?;
            self.device_command(Port::Mouse, SET_RESOLUTION, &[2])?;
            if self.config.wheel {
                for rate in [200, 100, 80] {
                    self.device_command(Port::Mouse, SET_RATE, &[rate])?;
                }
                let id = match self.send_byte(
                    Port::Mouse,
                    GET_ID,
                    self.config.command_timeout_us,
                    true,
                )? {
                    Some(id) => id,
                    None => self.response(
                        Port::Mouse,
                        self.timer.now_us(),
                        self.config.command_timeout_us,
                    )?,
                };
                if !matches!(id, 0 | 3) {
                    return Err(ErrorKind::UnsupportedMouseId(id));
                }
                self.mouse.set_wheel(id == 3);
            }
            self.device_command(Port::Mouse, SET_RATE, &[100])?;
        }
        // Both configured devices have now acknowledged reporting disable and
        // their new protocol is known. Only now is the keyboard response lane
        // safe for final CTR readback with the keyboard clock running.
        self.set_config(enabled)?;
        self.input_known = true;
        if self.config.mouse {
            self.device_command(Port::Mouse, ENABLE_REPORTING, &[])?;
        }
        if self.config.keyboard {
            self.device_command(Port::Keyboard, ENABLE_REPORTING, &[])?;
        }
        Ok(())
    }
    /// Reset, test, initialize and enable only the configured attached ports.
    /// Ownership remains in this object on failure; a faulted object cannot
    /// retry without a platform-established reset and fresh ownership claim.
    pub fn initialize(&mut self) -> Result<(), Error> {
        if self.state == State::Ready {
            return Err(ErrorKind::AlreadyInitialized.into());
        }
        if !matches!(self.state, State::Fresh | State::Stopped) {
            return Err(ErrorKind::NeedsReset.into());
        }
        self.state = State::Initializing;
        self.input_known = false;
        match self.initialize_inner() {
            Ok(()) => {
                self.state = State::Ready;
                Ok(())
            }
            Err(kind) => Err(self.fail(kind)),
        }
    }
    fn collect_output(&mut self) -> Result<(), ErrorKind> {
        // Controller replies share the keyboard data lane. Retain all older
        // input before asking for CTR; otherwise a key byte could be mistaken
        // for a successful controller acknowledgement.
        for _ in 0..QUEUE_LIMIT {
            match self.read_byte()? {
                Some(byte) => self.queue(byte)?,
                None => break,
            }
        }
        if self.status()? & OUTPUT_FULL != 0 {
            return Err(ErrorKind::QueueFull);
        }
        Ok(())
    }
    fn disable_ports(&mut self) -> Result<(), ErrorKind> {
        self.command(DISABLE_KEYBOARD)?;
        self.command(DISABLE_MOUSE)?;
        self.write_ready()?;
        self.collect_output()?;
        let config = match self.controller_config {
            Some(value) => value,
            None => self.controller_response(READ_CONFIG)?,
        };
        self.set_config((config & !(IRQ_BITS | TRANSLATION)) | KEYBOARD_DISABLED | MOUSE_DISABLED)
    }
    fn fail(&mut self, kind: ErrorKind) -> Error {
        self.state = State::Faulted;
        let recovery = if self.disable_ports().is_ok() {
            Recovery::PortsDisabled
        } else {
            Recovery::Failed
        };
        Error { kind, recovery }
    }
    fn ready(&self) -> Result<(), Error> {
        match self.state {
            State::Ready => Ok(()),
            State::Faulted => Err(ErrorKind::NeedsReset.into()),
            _ => Err(ErrorKind::NotInitialized.into()),
        }
    }
    /// Set Scroll/Num/Caps LEDs (bits 0/1/2). Interleaved input is retained.
    pub fn set_leds(&mut self, leds: u8) -> Result<(), Error> {
        self.ready()?;
        if leds & !7 != 0 {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        if !self.config.keyboard {
            return Err(ErrorKind::NotInitialized.into());
        }
        self.device_command(Port::Keyboard, SET_LEDS, &[leds])
            .map_err(|kind| self.fail(kind))
    }
    fn decode(&mut self, byte: Byte) -> Result<(), ErrorKind> {
        match byte.port {
            Port::Keyboard if self.config.keyboard => self.keyboard.feed(
                byte.data,
                byte.received_us,
                self.config.packet_timeout_us,
                &mut self.events,
            ),
            Port::Mouse if self.config.mouse => self.mouse.feed(
                byte.data,
                byte.received_us,
                self.config.packet_timeout_us,
                &mut self.events,
            ),
            _ => Err(ErrorKind::DeviceReply {
                port: byte.port,
                received: byte.data,
            }),
        }
    }
    /// Decode at most 64 hardware bytes per poll. Prefixes/partial packets stay
    /// with their actual port. On error, already decoded input remains available
    /// through `drain_events`; it is never silently discarded with the error.
    pub fn poll(&mut self) -> Result<Vec<Input>, Error> {
        self.ready()?;
        for _ in 0..QUEUE_LIMIT {
            let byte = match self.pending.pop_front() {
                Some(byte) => Some(byte),
                None => self.read_byte().map_err(|kind| self.fail(kind))?,
            };
            let Some(byte) = byte else {
                break;
            };
            if let Err(kind) = self.decode(byte) {
                // A key outside the declared HID usage map is explicit but
                // does not corrupt either port's framing or stop known keys.
                if matches!(kind, ErrorKind::UnsupportedScanCode(_)) {
                    return Err(kind.into());
                }
                return Err(self.fail(kind));
            }
        }
        // A silent device must not retain an incomplete prefix indefinitely.
        // Do not expire a frame while complete bytes remain queued to decode.
        if self.pending.is_empty()
            && self.status().map_err(|kind| self.fail(kind))? & OUTPUT_FULL == 0
        {
            let now = self.timer.now_us();
            let result = self
                .keyboard
                .expire(now, self.config.packet_timeout_us)
                .and_then(|()| self.mouse.expire(now, self.config.packet_timeout_us));
            if let Err(kind) = result {
                return Err(self.fail(kind));
            }
        }
        Ok(self.drain_events())
    }
    pub fn drain_events(&mut self) -> Vec<Input> {
        core::mem::take(&mut self.events)
    }
    /// Release every published held key/button without inventing motion. Also
    /// used after an explicit fault so consumers can retire stale held input.
    pub fn release_inputs(&mut self) -> Vec<Input> {
        self.keyboard.release(&mut self.events);
        self.mouse.release(&mut self.events);
        self.drain_events()
    }
    /// Acknowledge reporting disable on both configured devices, then prove
    /// clock/IRQ disable by reading CTR. Failure quarantines this owner.
    pub fn stop(&mut self) -> Result<Vec<Input>, Error> {
        self.ready()?;
        let result = (|| {
            if self.config.keyboard {
                self.device_command(Port::Keyboard, DISABLE_REPORTING, &[])?;
            }
            if self.config.mouse {
                self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            }
            self.disable_ports()?;
            while let Some(byte) = self.pending.pop_front() {
                self.decode(byte)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.state = State::Stopped;
                Ok(self.release_inputs())
            }
            Err(kind) => Err(self.fail(kind)),
        }
    }
}

#[cfg(test)]
mod tests;
