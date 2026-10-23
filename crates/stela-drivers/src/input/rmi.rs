// SPDX-License-Identifier: GPL-2.0-only
//! Native RMI4 transport, function discovery and F01 device-control substrate.
//! Based on Linux rmi4; retained notices are in input/THIRD_PARTY.md.
//!
//! Control readiness is deliberately distinct from a usable touchpad. F11/F12
//! contacts, buttons, passthrough and other function engines must configure their
//! own discovered registers before their interrupts/input can be published.
use crate::bus::{i2c, smbus};
use alloc::vec::Vec;

pub mod descriptor;
pub mod f03;
mod f03_device;
pub mod f11;
mod f11_device;
pub mod f12;
mod f12_device;
pub mod f1a;
mod f1a_device;
mod input_device;
pub mod transport;
use transport::{Transport, buffer};

const PDT_START: u16 = 0xe9;
const PDT_END: u16 = 5;
const PDT_ENTRY_BYTES: u16 = 6;
const MAX_FUNCTIONS: usize = 256;
const MAX_IRQ_BYTES: usize = 32;
const CONFIGURED: u8 = 0x80;
const SLEEP_MASK: u8 = 3;
const NOSLEEP: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedPassthroughDevices(u8),
    InvalidF03QueueLength,
    InvalidButtonCount(u8),
    UnsupportedFormat { function: u8, format: u8 },
    UnsupportedF11Extension { query: u8, flags: u8 },
    InputConsumerActive,
    RegisterDescriptor,
    MissingRegister(u16),
    MissingFunction(u8),
    InvalidAddress,
    InvalidConfiguration,
    AddressRange { address: u16, length: usize },
    I2c(i2c::Error),
    Smbus(smbus::Error),
    Companion(transport::CompanionError),
    Attention(AttentionError),
    SmbusVersion(u16),
    BlockLength { expected: usize, actual: usize },
    NotActive,
    AlreadyActive,
    NeedsReset,
    Allocation,
    MissingF01,
    DuplicateF01,
    FunctionLimit,
    InterruptLimit,
    DeviceStatus(u8),
    ConfigurationRejected,
    UnsupportedPowerControl,
    UnsupportedControl(u16),
    IdentityChanged,
    UnexpectedReset,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RMI {self:?}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Fresh,
    Active,
    Stopped,
    Faulted,
}

/// The actual exclusively owned attention source: a physical active GPIO level
/// for I2C, or source/address-qualified SMBus Host Notify captured by the native
/// controller. CPU route masking/draining must preserve hardware attention.
/// `acknowledge` retires the captured source only after peripheral status read.
pub trait Attention {
    fn mask_and_drain(&mut self) -> Result<(), AttentionError>;
    fn pending(&mut self) -> Result<bool, AttentionError>;
    fn acknowledge(&mut self) -> Result<(), AttentionError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttentionError {
    Unavailable,
    Hardware(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quarantine {
    NotAttempted,
    Masked,
    Failed(AttentionError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub number: u8,
    pub version: u8,
    pub query: u16,
    pub command: u16,
    pub control: u16,
    pub data: u16,
    pub interrupt_start: u16,
    pub interrupt_count: u8,
}
impl Function {
    fn parse(address: u16, bytes: [u8; 6], interrupt_start: u16) -> Self {
        let page = address & 0xff00;
        Self {
            number: bytes[5],
            version: (bytes[4] >> 5) & 3,
            query: page | u16::from(bytes[0]),
            command: page | u16::from(bytes[1]),
            control: page | u16::from(bytes[2]),
            data: page | u16::from(bytes[3]),
            interrupt_start,
            interrupt_count: bytes[4] & 7,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Properties {
    /// Exact basic query00..20; unknown flags remain observable.
    pub basic_query: [u8; 21],
    pub pdt_properties: u8,
}
impl Properties {
    pub fn manufacturer(&self) -> u8 {
        self.basic_query[0]
    }
    pub fn product_id(&self) -> &[u8] {
        &self.basic_query[11..21]
    }
    pub fn product_info(&self) -> u16 {
        (u16::from(self.basic_query[2] & 0x7f) << 7) | u16::from(self.basic_query[3] & 0x7f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configuration {
    /// Actual reset settling interval, in microseconds; Linux default is 100ms.
    pub reset_delay_us: u64,
    pub no_sleep: Option<bool>,
    pub doze_interval: Option<u8>,
    pub wakeup_threshold: Option<u8>,
    pub doze_holdoff: Option<u8>,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            reset_delay_us: 100_000,
            no_sleep: None,
            doze_interval: None,
            wakeup_threshold: None,
            doze_holdoff: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlState {
    Uninitialized,
    Configured,
    Sleeping,
    Stopped,
    Uncertain,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttentionReport {
    pub device_status: u8,
    pub interrupts: Vec<u8>,
}

#[must_use = "inspect errors and any completed frames"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F12Poll {
    pub control: Option<AttentionReport>,
    pub frames: Vec<f12::Frame>,
    pub error: Option<Error>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FunctionReport {
    F03(f03::Frame),
    F11(f11::Frame),
    F12(f12::Frame),
    F1A(f1a::Frame),
}
#[must_use = "inspect errors and all completed function reports"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputPoll {
    pub control: Option<AttentionReport>,
    pub reports: Vec<FunctionReport>,
    pub error: Option<Error>,
}

pub struct Device<X, A, T> {
    transport: X,
    attention: A,
    timer: T,
    configuration: Configuration,
    state: ControlState,
    functions: Vec<Function>,
    properties: Option<Properties>,
    f01: Option<Function>,
    irq_mask: Vec<u8>,
    awake_control: u8,
    quarantine: Quarantine,
    f12: Vec<f12::Engine>,
    f11: Vec<f11::Engine>,
    f1a: Vec<f1a::Engine>,
    f03: Vec<f03::Engine>,
}
impl<X: Transport, A: Attention, T: i2c::Timer> Device<X, A, T> {
    pub fn new(
        transport: X,
        attention: A,
        timer: T,
        configuration: Configuration,
    ) -> Result<Self, Error> {
        if configuration.reset_delay_us == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            transport,
            attention,
            timer,
            configuration,
            state: ControlState::Uninitialized,
            functions: Vec::new(),
            properties: None,
            f01: None,
            irq_mask: Vec::new(),
            awake_control: 0,
            quarantine: Quarantine::NotAttempted,
            f12: Vec::new(),
            f11: Vec::new(),
            f1a: Vec::new(),
            f03: Vec::new(),
        })
    }
    pub fn control_state(&self) -> ControlState {
        self.state
    }
    pub fn quarantine(&self) -> Quarantine {
        self.quarantine
    }
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }
    pub fn properties(&self) -> Option<&Properties> {
        self.properties.as_ref()
    }
    fn fault<R>(&mut self, result: Result<R, Error>) -> Result<R, Error> {
        if result.is_err() {
            self.state = ControlState::Uncertain;
            // The original error remains primary. Keep source ownership even if
            // masking fails; no route/bus owner is handed to another consumer.
            self.quarantine = match self.attention.mask_and_drain() {
                Ok(()) => Quarantine::Masked,
                Err(error) => Quarantine::Failed(error),
            };
        }
        result
    }
    fn configured(&self) -> Result<(), Error> {
        match self.state {
            ControlState::Configured => Ok(()),
            ControlState::Uncertain => Err(Error::NeedsReset),
            _ => Err(Error::NotActive),
        }
    }
    fn register(base: u16, offset: usize) -> Result<u16, Error> {
        let address = usize::from(base) + offset;
        u16::try_from(address).map_err(|_| Error::AddressRange {
            address: base,
            length: offset + 1,
        })
    }
    fn byte(&mut self, address: u16) -> Result<u8, Error> {
        let mut byte = [0];
        self.transport.read(address, &mut byte)?;
        Ok(byte[0])
    }
    fn write_control(&mut self, f01: Function, value: u8) -> Result<(), Error> {
        self.transport.write(f01.control, &[value])?;
        if self.byte(f01.control)? != value {
            return Err(Error::ConfigurationRejected);
        }
        Ok(())
    }
    fn delay(&self) {
        let start = self.timer.now_us();
        while self.timer.now_us().wrapping_sub(start) < self.configuration.reset_delay_us {
            self.timer.relax();
        }
    }
    fn initial_f01(&mut self) -> Result<Function, Error> {
        for address in (PDT_END..=PDT_START)
            .rev()
            .step_by(PDT_ENTRY_BYTES as usize)
        {
            let mut bytes = [0; 6];
            self.transport.read(address, &mut bytes)?;
            if matches!(bytes[5], 0 | 255) {
                break;
            }
            if bytes[5] == 1 {
                return Ok(Function::parse(address, bytes, 0));
            }
        }
        Err(Error::MissingF01)
    }
    fn scan(&mut self) -> Result<(Vec<Function>, usize), Error> {
        let mut functions = Vec::new();
        let mut empty_pages = 0;
        let mut irq_count = 0u16;
        for page in 0u16..=255 {
            let mut found = false;
            for offset in (PDT_END..=PDT_START)
                .rev()
                .step_by(PDT_ENTRY_BYTES as usize)
            {
                let address = (page << 8) | offset;
                let mut bytes = [0; 6];
                self.transport.read(address, &mut bytes)?;
                if matches!(bytes[5], 0 | 255) {
                    break;
                }
                found = true;
                if functions.len() == MAX_FUNCTIONS {
                    return Err(Error::FunctionLimit);
                }
                functions.try_reserve(1).map_err(|_| Error::Allocation)?;
                let function = Function::parse(address, bytes, irq_count);
                irq_count += u16::from(function.interrupt_count);
                if usize::from(irq_count).div_ceil(8) > MAX_IRQ_BYTES {
                    return Err(Error::InterruptLimit);
                }
                functions.push(function);
            }
            empty_pages = if found { 0 } else { empty_pages + 1 };
            if empty_pages >= 2 {
                break;
            }
        }
        Ok((functions, usize::from(irq_count).div_ceil(8)))
    }
    fn check_status(&mut self, f01: Function) -> Result<u8, Error> {
        let status = self.byte(f01.data)?;
        if status & 0x40 != 0 || status & 0xf > 1 {
            return Err(Error::DeviceStatus(status));
        }
        if status & 0x80 != 0 {
            return Err(Error::UnexpectedReset);
        }
        Ok(status)
    }
    pub fn initialize_control(&mut self) -> Result<(), Error> {
        if !matches!(
            self.state,
            ControlState::Uninitialized | ControlState::Stopped
        ) {
            return Err(if self.state == ControlState::Uncertain {
                Error::NeedsReset
            } else {
                Error::AlreadyActive
            });
        }
        let result = self.initialize_inner();
        self.fault(result)?;
        self.f12.clear();
        self.f11.clear();
        self.f1a.clear();
        self.f03.clear();
        self.state = ControlState::Configured;
        Ok(())
    }
    fn initialize_inner(&mut self) -> Result<(), Error> {
        self.attention.mask_and_drain().map_err(Error::Attention)?;
        self.transport.activate()?;
        let before_reset = self.initial_f01()?;
        self.transport.reset(before_reset.command)?;
        self.delay();
        let (functions, irq_bytes) = self.scan()?;
        if !self.functions.is_empty() && self.functions != functions {
            return Err(Error::IdentityChanged);
        }
        let mut f01s = functions.iter().filter(|function| function.number == 1);
        let f01 = *f01s.next().ok_or(Error::MissingF01)?;
        if f01s.next().is_some() {
            return Err(Error::DuplicateF01);
        }
        let mut properties = Properties {
            basic_query: [0; 21],
            pdt_properties: self.byte(0xef)?,
        };
        self.transport
            .read(f01.query, &mut properties.basic_query)?;
        if self.properties.is_some_and(|old| old != properties) {
            return Err(Error::IdentityChanged);
        }
        let capabilities = properties.basic_query[1];
        if ((self.configuration.doze_interval.is_some()
            || self.configuration.wakeup_threshold.is_some())
            && capabilities & 0x20 == 0)
            || (self.configuration.doze_holdoff.is_some() && capabilities & 0x40 == 0)
        {
            return Err(Error::UnsupportedPowerControl);
        }
        // Own every discovered IRQ bit, but only enable the implemented F01
        // control function. Other function engines will enable their own bits.
        let mut irq_mask = buffer(irq_bytes)?;
        if irq_bytes != 0 {
            self.transport
                .write(Self::register(f01.control, 1)?, &irq_mask)?;
        }
        for bit in f01.interrupt_start..f01.interrupt_start + u16::from(f01.interrupt_count) {
            irq_mask[usize::from(bit / 8)] |= 1 << (bit % 8);
        }
        let mut control = self.byte(f01.control)? & !SLEEP_MASK;
        if let Some(no_sleep) = self.configuration.no_sleep {
            control = if no_sleep {
                control | NOSLEEP
            } else {
                control & !NOSLEEP
            };
        }
        control |= CONFIGURED;
        self.write_control(f01, control)?;
        let mut address = Self::register(f01.control, 1 + irq_bytes)?;
        if capabilities & 0x20 != 0 {
            for setting in [
                self.configuration.doze_interval,
                self.configuration.wakeup_threshold,
            ] {
                if let Some(value) = setting {
                    self.transport.write(address, &[value])?;
                    if self.byte(address)? != value {
                        return Err(Error::ConfigurationRejected);
                    }
                } else {
                    self.byte(address)?;
                }
                address = Self::register(address, 1)?;
            }
        }
        if capabilities & 4 != 0 {
            address = Self::register(address, 1)?;
        }
        if capabilities & 0x40 != 0 {
            if let Some(value) = self.configuration.doze_holdoff {
                self.transport.write(address, &[value])?;
                if self.byte(address)? != value {
                    return Err(Error::ConfigurationRejected);
                }
            } else {
                self.byte(address)?;
            }
        }
        if irq_bytes != 0 {
            let mut discard = buffer(irq_bytes)?;
            self.transport
                .read(Self::register(f01.data, 1)?, &mut discard)?;
            self.transport
                .write(Self::register(f01.control, 1)?, &irq_mask)?;
        }
        self.check_status(f01)?;
        self.attention.acknowledge().map_err(Error::Attention)?;
        self.functions = functions;
        self.properties = Some(properties);
        self.f01 = Some(f01);
        self.irq_mask = irq_mask;
        self.awake_control = control;
        Ok(())
    }
    /// Service actual peripheral attention. Unknown-function bits remain in the
    /// returned exact status bytes; this substrate does not fabricate events.
    pub fn poll_control(&mut self) -> Result<Option<AttentionReport>, Error> {
        self.configured()?;
        if !self.f12.is_empty()
            || !self.f11.is_empty()
            || !self.f1a.is_empty()
            || !self.f03.is_empty()
        {
            return Err(Error::InputConsumerActive);
        }
        self.poll_attention()
    }
    fn poll_attention(&mut self) -> Result<Option<AttentionReport>, Error> {
        self.configured()?;
        let result = (|| {
            if !self.attention.pending().map_err(Error::Attention)? {
                return Ok(None);
            }
            let f01 = self.f01.ok_or(Error::MissingF01)?;
            let device_status = self.check_status(f01)?;
            let mut interrupts = buffer(self.irq_mask.len())?;
            if !interrupts.is_empty() {
                self.transport
                    .read(Self::register(f01.data, 1)?, &mut interrupts)?;
            }
            self.attention.acknowledge().map_err(Error::Attention)?;
            Ok(Some(AttentionReport {
                device_status,
                interrupts,
            }))
        })();
        self.fault(result)
    }
    pub fn sleep(&mut self) -> Result<(), Error> {
        self.configured()?;
        let result = (|| {
            self.attention.mask_and_drain().map_err(Error::Attention)?;
            let f01 = self.f01.ok_or(Error::MissingF01)?;
            self.write_control(f01, (self.awake_control & !(NOSLEEP | SLEEP_MASK)) | 1)
        })();
        self.fault(result)?;
        self.state = ControlState::Sleeping;
        Ok(())
    }
    pub fn wake(&mut self) -> Result<(), Error> {
        if self.state != ControlState::Sleeping {
            return Err(if self.state == ControlState::Uncertain {
                Error::NeedsReset
            } else {
                Error::NotActive
            });
        }
        let result = (|| {
            let f01 = self.f01.ok_or(Error::MissingF01)?;
            self.write_control(f01, self.awake_control)?;
            self.check_status(f01)?;
            for engine in &self.f11 {
                engine.resume(&mut self.transport, &self.timer)?;
            }
            Ok(())
        })();
        self.fault(result)?;
        self.state = ControlState::Configured;
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        if self.state == ControlState::Configured {
            self.sleep()?;
        }
        if self.state != ControlState::Sleeping {
            return Err(if self.state == ControlState::Uncertain {
                Error::NeedsReset
            } else {
                Error::NotActive
            });
        }
        let result = self.transport.deactivate();
        self.fault(result)?;
        self.state = ControlState::Stopped;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
