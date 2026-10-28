// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017-2018 NVIDIA Corporation. All rights reserved.
// Copyright (c) 2026 Stela contributors
//! Cypress CCGx HPI transport, adapted from pinned Linux ucsi_ccg.c.
//!
//! The platform supplies the actual powered I²C adapter/target and exclusive
//! HPI ownership. Polling drains the same real interrupt-status register as
//! Linux's threaded handler, copying CCI and MESSAGE_IN before W1C. No cached
//! notification can complete a newly submitted command. CCG's fixed 16-byte
//! operation region supports UCSI 1.x; larger layouts are explicitly refused.
//! Firmware flashing, NVIDIA alternate-mode rewriting and runtime PM policy
//! are separate; raw firmware/alternate-mode data is retained.

use super::{Cci, Timer, Transport, TransportError};
use crate::bus::i2c::{Address, Bus, Operation};
use core::num::NonZeroU16;

const INTERRUPT: u16 = 6;
const CONTROL: u16 = 0x39;
const UCSI_INTERRUPT: u8 = 0x80;
const DEVICE_INTERRUPT: u8 = 1;
const UCSI_BASE: u16 = 0xf000;

pub const DEVICE_TREE_COMPATIBLE: &str = "cypress,cypd4226";
pub const ACPI_HID: &str = "AMDI0042";
pub const I2C_DRIVER_ID: &str = "ucsi_ccg";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareInfo {
    pub device: [u8; 6],
    /// Bootloader, FW1 and FW2 base/app version pairs, unchanged wire bytes.
    pub versions: [u8; 24],
}
impl FirmwareInfo {
    pub fn mode(self) -> u8 {
        self.device[0] & 3
    }
    pub fn silicon_id(self) -> u16 {
        u16::from_le_bytes([self.device[2], self.device[3]])
    }
    pub fn ports(self) -> u8 {
        1 + u8::from(self.device[0] & 0x0c != 0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    TimerBudget { microseconds: u64 },
    Transport(TransportError),
    InterruptDrainTimeout { last: u8 },
    FirmwareUnavailable(FirmwareInfo),
}
impl From<TransportError> for StartError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

pub struct Ccg<B: Bus> {
    bus: B,
    address: Address,
    max_read: NonZeroU16,
    firmware: FirmwareInfo,
    cci: Cci,
    message: [u8; 16],
    message_bytes: usize,
    last_interrupt: u8,
}
impl<B: Bus> Ccg<B> {
    /// Start the real HPI UCSI interface. `max_read` comes from the actual
    /// adapter capability; chunking preserves repeated START and advances RAB.
    /// This does not discover or power NVIDIA GPU/DesignWare I²C hardware.
    pub fn start(
        bus: B,
        address: Address,
        max_read: NonZeroU16,
        timer: &impl Timer,
    ) -> Result<Self, StartError> {
        if !timer.supports_duration(100_000) {
            return Err(StartError::TimerBudget {
                microseconds: 100_000,
            });
        }
        let mut this = Self {
            bus,
            address,
            max_read,
            firmware: FirmwareInfo {
                device: [0; 6],
                versions: [0; 24],
            },
            cci: Cci(0),
            message: [0; 16],
            message_bytes: 0,
            last_interrupt: 0,
        };
        this.write(CONTROL, &[2])?;
        this.write(CONTROL, &[1])?;
        let mut interrupts = [0];
        let mut drained = false;
        for _ in 0..10 {
            this.read(INTERRUPT, &mut interrupts)?;
            if interrupts[0] & DEVICE_INTERRUPT == 0 {
                drained = true;
                break;
            }
            this.write(INTERRUPT, &interrupts)?;
            timer.delay_us(10_000);
        }
        if !drained {
            return Err(StartError::InterruptDrainTimeout {
                last: interrupts[0],
            });
        }
        let mut versions = [0; 24];
        this.read(0x10, &mut versions)?;
        let mut device = [0; 6];
        this.read(0, &mut device)?;
        this.firmware = FirmwareInfo { device, versions };
        if !matches!(this.firmware.mode(), 1 | 2) {
            return Err(StartError::FirmwareUnavailable(this.firmware));
        }
        Ok(this)
    }
    pub fn firmware(&self) -> FirmwareInfo {
        self.firmware
    }
    pub fn last_interrupt(&self) -> u8 {
        self.last_interrupt
    }
    fn read(&mut self, register: u16, bytes: &mut [u8]) -> Result<(), TransportError> {
        if usize::from(register) + bytes.len() > 65536 {
            return Err(TransportError::Bounds {
                offset: usize::from(register),
                bytes: bytes.len(),
            });
        }
        for (index, chunk) in bytes
            .chunks_mut(usize::from(self.max_read.get()))
            .enumerate()
        {
            let offset = index * usize::from(self.max_read.get());
            let address = (register + offset as u16).to_le_bytes();
            self.bus
                .transaction(
                    self.address,
                    &mut [Operation::Write(&address), Operation::Read(chunk)],
                )
                .map_err(TransportError::I2c)?;
        }
        Ok(())
    }
    fn write(&mut self, register: u16, bytes: &[u8]) -> Result<(), TransportError> {
        if usize::from(register) + bytes.len() > 65536 {
            return Err(TransportError::Bounds {
                offset: usize::from(register),
                bytes: bytes.len(),
            });
        }
        let mut buffer = alloc::vec::Vec::with_capacity(bytes.len() + 2);
        buffer.extend_from_slice(&register.to_le_bytes());
        buffer.extend_from_slice(bytes);
        self.bus
            .transaction(self.address, &mut [Operation::Write(&buffer)])
            .map_err(TransportError::I2c)
    }
    /// Deferred interrupt work, or the equivalent real hardware poll. Cache
    /// publication follows a complete snapshot and successful interrupt ACK.
    pub fn service_interrupt(&mut self) -> Result<Cci, TransportError> {
        let mut interrupt = [0];
        self.read(INTERRUPT, &mut interrupt)?;
        self.last_interrupt = interrupt[0];
        if interrupt[0] == 0 {
            return Ok(self.cci);
        }
        let mut cci = self.cci;
        let mut message = self.message;
        let mut bytes = self.message_bytes;
        if interrupt[0] & UCSI_INTERRUPT != 0 {
            let mut raw = [0; 4];
            self.read(UCSI_BASE + 4, &mut raw)?;
            cci = Cci(u32::from_le_bytes(raw));
            bytes = 0;
            if !cci.busy() && cci.0 != u32::MAX && cci.length() != 0 {
                if cci.length() > message.len() {
                    return Err(TransportError::Bounds {
                        offset: 16,
                        bytes: cci.length(),
                    });
                }
                // CCG HPI requires the full region copied before clearing IRQ.
                self.read(UCSI_BASE + 16, &mut message)?;
                bytes = cci.length();
            }
        }
        self.write(INTERRUPT, &interrupt)?;
        self.cci = cci;
        self.message = message;
        self.message_bytes = bytes;
        Ok(cci)
    }
}
impl<B: Bus> Transport for Ccg<B> {
    fn read_version(&mut self) -> Result<u16, TransportError> {
        let mut raw = [0; 2];
        self.read(UCSI_BASE, &mut raw)?;
        let version = u16::from_le_bytes(raw);
        if version > 0x0120 {
            return Err(TransportError::UnsupportedTransportVersion(version));
        }
        Ok(version)
    }
    fn poll_cci(&mut self) -> Result<u32, TransportError> {
        self.service_interrupt().map(|cci| cci.0)
    }
    fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
        if bytes.len() > self.message_bytes {
            return Err(TransportError::Bounds {
                offset: 16,
                bytes: bytes.len(),
            });
        }
        bytes.copy_from_slice(&self.message[..bytes.len()]);
        Ok(())
    }
    fn write_message_out(&mut self, _bytes: &[u8]) -> Result<(), TransportError> {
        // Linux's CCG transport has no write_message_out operation.
        Err(TransportError::Unavailable)
    }
    fn write_control(&mut self, control: u64) -> Result<(), TransportError> {
        self.cci = Cci(0);
        self.message_bytes = 0;
        self.write(UCSI_BASE + 8, &control.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bus::i2c::{Error, ErrorKind};
    use crate::usb::typec::ucsi::{Command, ConnectorNumber, Controller};
    use alloc::{boxed::Box, rc::Rc, vec::Vec};
    use core::cell::{Cell, RefCell};

    struct Model {
        memory: Box<[u8]>,
        log: Vec<(bool, u16, usize)>,
        calls: usize,
        fail_at: usize,
        sticky: bool,
        drain_count: usize,
        control_bits: u32,
    }
    impl Model {
        fn new() -> Self {
            let mut memory = vec![0; 65536].into_boxed_slice();
            memory[0] = 6;
            memory[2..4].copy_from_slice(&0x1400u16.to_le_bytes());
            memory[0xf000..0xf002].copy_from_slice(&0x0120u16.to_le_bytes());
            Self {
                memory,
                log: Vec::new(),
                calls: 0,
                fail_at: usize::MAX,
                sticky: false,
                drain_count: 1,
                control_bits: 0,
            }
        }
        fn control(&mut self, control: u64) {
            let mut message = [0; 16];
            let (flags, bytes) = match control as u8 {
                1 => (1 << 27, 0),
                4 => (1 << 29, 0),
                5 | 0x0f => (1 << 31, 0),
                6 => {
                    message[4] = 2;
                    message[5] = 0xff;
                    (1 << 31, 16)
                }
                7 => {
                    message[0] = 0xff;
                    (1 << 31, 2)
                }
                0x12 => {
                    message[2] = 0x38;
                    (1 << 31, 9)
                }
                0x0e => {
                    message[0] = 3;
                    (1 << 31, 1)
                }
                _ => ((1 << 31) | (1 << 25), 0),
            };
            let cci = flags | (bytes << 8);
            self.memory[0xf004..0xf008].copy_from_slice(&u32::to_le_bytes(cci));
            self.memory[0xf010..0xf020].copy_from_slice(&message);
            self.memory[6] |= 0x80;
        }
    }
    #[derive(Clone)]
    struct Device(Rc<RefCell<Model>>);
    impl Bus for Device {
        fn transaction(
            &mut self,
            address: Address,
            operations: &mut [Operation<'_>],
        ) -> Result<(), Error> {
            assert_eq!(address, Address::SevenBit(0x08));
            let mut model = self.0.borrow_mut();
            model.calls += 1;
            if model.calls == model.fail_at {
                return Err(ErrorKind::Aborted {
                    kind: crate::bus::i2c::AbortKind::DataNack,
                    source: 0x1234,
                }
                .into());
            }
            match operations {
                [Operation::Write(bytes)] => {
                    assert!(bytes.len() >= 3);
                    let register = u16::from_le_bytes([bytes[0], bytes[1]]);
                    let payload = &bytes[2..];
                    model.log.push((false, register, payload.len()));
                    match register {
                        6 => {
                            if !model.sticky {
                                model.memory[6] &= !payload[0];
                                if payload[0] & 1 != 0 && model.drain_count > 0 {
                                    model.drain_count -= 1;
                                }
                                if model.drain_count > 0 {
                                    model.memory[6] |= 1;
                                }
                            }
                        }
                        0x39 => {
                            model.control_bits = (model.control_bits << 4) | u32::from(payload[0]);
                            if payload[0] == 1 && model.drain_count > 0 {
                                model.memory[6] |= 1;
                            }
                        }
                        0xf008 => model.control(u64::from_le_bytes(payload.try_into().unwrap())),
                        _ => model.memory
                            [usize::from(register)..usize::from(register) + payload.len()]
                            .copy_from_slice(payload),
                    }
                }
                [Operation::Write(bytes), Operation::Read(output)] => {
                    assert_eq!(bytes.len(), 2);
                    let register = u16::from_le_bytes([bytes[0], bytes[1]]);
                    model.log.push((true, register, output.len()));
                    output.copy_from_slice(
                        &model.memory[usize::from(register)..usize::from(register) + output.len()],
                    );
                }
                _ => panic!("CCG requires one write or atomic write/read transaction"),
            }
            Ok(())
        }
    }
    #[derive(Default)]
    struct Time(Cell<u64>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn delay_us(&self, us: u64) {
            self.0.set(self.0.get() + us);
        }
    }
    fn make_device() -> (Device, Rc<RefCell<Model>>) {
        let model = Rc::new(RefCell::new(Model::new()));
        (Device(model.clone()), model)
    }
    fn start(device: Device, chunk: u16) -> Result<Ccg<Device>, StartError> {
        Ccg::start(
            device,
            Address::SevenBit(8),
            NonZeroU16::new(chunk).unwrap(),
            &Time::default(),
        )
    }

    #[test]
    fn real_hpi_transactions_initialize_two_port_ucsi_and_copy_before_w1c() {
        for chunk in [1, 3, 4, 16, 32] {
            let (device, model) = make_device();
            let ccg = start(device, chunk).unwrap();
            assert_eq!(ccg.firmware().mode(), 2);
            assert_eq!(ccg.firmware().silicon_id(), 0x1400);
            assert_eq!(ccg.firmware().ports(), 2);
            let mut controller = Controller::new(ccg, Time::default()).unwrap();
            controller.initialize().unwrap();
            assert!(controller.initialized());
            assert_eq!(controller.connectors().len(), 2);
            assert!(controller.connectors()[0].status.connected());
            let log = &model.borrow().log;
            assert_eq!(
                &log[..4],
                &[
                    (false, 0x39, 1),
                    (false, 0x39, 1),
                    (true, 6, 1),
                    (false, 6, 1)
                ]
            );
            for (index, entry) in log.iter().enumerate() {
                if entry.0 && entry.1 == 0xf010 {
                    let tail = &log[index..];
                    let clear = tail
                        .iter()
                        .position(|entry| *entry == (false, 6, 1))
                        .unwrap();
                    assert_eq!(
                        tail[..clear]
                            .iter()
                            .filter(|entry| entry.0 && (0xf010..0xf020).contains(&entry.1))
                            .map(|entry| entry.2)
                            .sum::<usize>(),
                        16
                    );
                }
            }
        }
    }
    #[test]
    fn cached_completion_is_invalidated_before_new_control_publication() {
        let (device, model) = make_device();
        let mut ccg = start(device, 16).unwrap();
        ccg.read_version().unwrap();
        let command = Command::current_cam(ConnectorNumber::new(1).unwrap()).control();
        ccg.write_control(command).unwrap();
        assert_ne!(ccg.poll_cci().unwrap() & (1 << 31), 0);
        let mut message = [0];
        ccg.read_message_in(&mut message).unwrap();
        assert_eq!(message, [3]);
        let calls = model.borrow().calls;
        model.borrow_mut().fail_at = calls + 1;
        assert!(matches!(
            ccg.write_control(command),
            Err(TransportError::I2c(_))
        ));
        model.borrow_mut().fail_at = usize::MAX;
        assert_eq!(ccg.poll_cci().unwrap(), 0);
        assert!(ccg.read_message_in(&mut message).is_err());
    }
    #[test]
    fn failed_snapshot_does_not_clear_interrupt_or_publish_partial_message() {
        let (device, model) = make_device();
        let mut ccg = start(device, 16).unwrap();
        ccg.read_version().unwrap();
        ccg.write_control(Command::current_cam(ConnectorNumber::new(1).unwrap()).control())
            .unwrap();
        let calls = model.borrow().calls;
        model.borrow_mut().fail_at = calls + 3;
        assert!(matches!(
            ccg.service_interrupt(),
            Err(TransportError::I2c(_))
        ));
        assert_eq!(model.borrow().memory[6], 0x80);
        assert_eq!(ccg.cci, Cci(0));
        assert_eq!(ccg.message_bytes, 0);
        model.borrow_mut().fail_at = usize::MAX;
        assert_ne!(ccg.service_interrupt().unwrap().0 & (1 << 31), 0);
        assert_eq!(model.borrow().memory[6], 0);
    }
    #[test]
    fn missing_application_firmware_stuck_interrupt_and_new_layout_are_refused() {
        let (device, model) = make_device();
        model.borrow_mut().memory[0] = 0;
        assert!(matches!(
            start(device, 16),
            Err(StartError::FirmwareUnavailable(_))
        ));
        let (device, model) = make_device();
        model.borrow_mut().sticky = true;
        assert!(matches!(
            start(device, 16),
            Err(StartError::InterruptDrainTimeout { last: 1 })
        ));
        let (device, model) = make_device();
        let mut ccg = start(device, 16).unwrap();
        model.borrow_mut().memory[0xf000..0xf002].copy_from_slice(&0x0200u16.to_le_bytes());
        assert_eq!(
            ccg.read_version(),
            Err(TransportError::UnsupportedTransportVersion(0x0200))
        );
        assert_eq!(
            ccg.write_message_out(&[1]),
            Err(TransportError::Unavailable)
        );
    }
    #[test]
    #[ignore = "oracle: STELA_TYPEC_DISCRETE_ORACLE"]
    fn unchanged_linux_ccg_start_oracle() {
        let path = std::env::var("STELA_TYPEC_DISCRETE_ORACLE")
            .expect("STELA_TYPEC_DISCRETE_ORACLE trace path");
        let trace = std::fs::read_to_string(path).unwrap();
        let mut cases = 0;
        for line in trace.lines().filter(|line| line.starts_with("C ")) {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let remaining: usize = fields[1].parse().unwrap();
            let expected: i32 = fields[2].parse().unwrap();
            let reads: usize = fields[3].parse().unwrap();
            let writes: usize = fields[4].parse().unwrap();
            let delay: u64 = fields[5].parse().unwrap();
            let control = u32::from_str_radix(fields[6], 16).unwrap();
            let (device, model) = make_device();
            model.borrow_mut().drain_count = remaining;
            let timer = Time::default();
            let result = Ccg::start(
                device,
                Address::SevenBit(8),
                NonZeroU16::new(32).unwrap(),
                &timer,
            );
            match (expected, result) {
                (0, Ok(_)) | (-110, Err(StartError::InterruptDrainTimeout { .. })) => {}
                _ => panic!("CCG start differs from donor"),
            }
            let model = model.borrow();
            assert_eq!(
                model
                    .log
                    .iter()
                    .filter(|entry| **entry == (true, 6, 1))
                    .count(),
                reads
            );
            assert_eq!(
                model
                    .log
                    .iter()
                    .filter(|entry| !entry.0 && (entry.1 == 6 || entry.1 == 0x39))
                    .count(),
                writes
            );
            assert_eq!(timer.now_us(), delay);
            assert_eq!(model.control_bits, control);
            cases += 1;
        }
        assert_eq!(cases, 12);
    }
}
