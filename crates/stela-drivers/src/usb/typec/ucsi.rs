// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Serialized UCSI PPM command, reset and connector observation engine.
//!
//! Adapted from Linux ucsi.c/ucsi.h at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md for source
//! hashes. Polling uses the actual transport, including ACPI _DSM refreshes;
//! an interrupt notification is not treated as command completion by itself.
//! Platform ACPI discovery, SCI/EC service, mux/retimer programming and policy
//! remain separate. No guest Apple transport is implemented here.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

pub mod acpi;
pub mod altmode;
pub mod ccg;
mod wire;
use wire::*;
pub use wire::{Capability, Cci, ConnectorNumber, ConnectorStatus, Version};

const COMMAND_TIMEOUT_US: u64 = 10_000_000;
const RESET_POLL_US: u64 = 20_000;
const COMMAND_POLL_US: u64 = 1_000;

/// Process/deferred-context monotonic timer. A positive delay must advance
/// time by at least the requested duration; no scheduler sleeps are assumed.
pub trait Timer {
    fn now_us(&self) -> u64;
    fn delay_us(&self, microseconds: u64);
}
impl Timer for crate::Clock {
    fn now_us(&self) -> u64 {
        crate::Clock::now_us(self)
    }
    fn delay_us(&self, microseconds: u64) {
        self.delay(microseconds);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Unavailable,
    Mapping,
    Bounds { offset: usize, bytes: usize },
    Dsm { function: u64, status: u64 },
    DsmNoResult { function: u64 },
    I2c(crate::bus::i2c::Error),
    UnsupportedTransportVersion(u16),
    Io(u64),
}

/// One exclusively owned PPM transport. Calls must preserve real firmware
/// side effects and return failure when synchronization cannot be established.
/// `poll_cci` refreshes transport state even with notifications disabled.
pub trait Transport {
    fn read_version(&mut self) -> Result<u16, TransportError>;
    fn poll_cci(&mut self) -> Result<u32, TransportError>;
    fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError>;
    fn write_message_out(&mut self, bytes: &[u8]) -> Result<(), TransportError>;
    fn write_control(&mut self, control: u64) -> Result<(), TransportError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Version,
    Poll,
    Submit,
    MessageOut,
    MessageIn,
    Command,
    Acknowledge,
    Cancel,
    Reset,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Transport {
        phase: Phase,
        error: TransportError,
    },
    Timeout {
        phase: Phase,
        cci: u32,
    },
    InvalidCci(u32),
    UnexpectedCompletion {
        phase: Phase,
        cci: u32,
    },
    UnsupportedVersion(u16),
    InvalidConnector {
        number: u8,
        count: u8,
    },
    InvalidArgument,
    InvalidResponseLength {
        command: u8,
        bytes: usize,
    },
    NotSupported {
        command: u64,
        cci: u32,
    },
    Ppm {
        command: u64,
        cci: u32,
        status: u16,
    },
    /// PPM error flag without a successfully retrieved error-status payload.
    PpmRejected {
        command: u64,
        cci: u32,
    },
    ErrorStatus {
        command: u64,
        cci: u32,
        failure: Box<Error>,
    },
    /// Cancellation was acknowledged. The original request did not complete;
    /// a caller must decide whether issuing a new request is appropriate.
    Cancelled {
        command: u64,
        cci: u32,
    },
    NeedsReset,
    NotInitialized,
    GenerationExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UCSI {self:?}")
    }
}
impl core::error::Error for Error {}

/// A reviewed wire command. Its constructors retain all requested effects;
/// neither completion nor an accepted role request proves a role transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command {
    control: u64,
    connector: Option<ConnectorNumber>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Connector,
    Partner,
    CablePlug,
    CablePlugOther,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRole {
    Host,
    Device,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerRole {
    Source,
    Sink,
}

impl Command {
    fn global(control: u64) -> Self {
        Self {
            control,
            connector: None,
        }
    }
    fn connector(control: u64, connector: ConnectorNumber) -> Self {
        Self {
            control: control | connector.control(),
            connector: Some(connector),
        }
    }
    pub fn control(self) -> u64 {
        self.control
    }
    pub fn capability() -> Self {
        Self::global(CAPABILITY)
    }
    pub fn connector_capability(connector: ConnectorNumber) -> Self {
        Self::connector(CONNECTOR_CAPABILITY, connector)
    }
    pub fn connector_status(connector: ConnectorNumber) -> Self {
        Self::connector(STATUS, connector)
    }
    pub fn cable_property(connector: ConnectorNumber) -> Self {
        Self::connector(CABLE_PROPERTY, connector)
    }
    pub fn current_cam(connector: ConnectorNumber) -> Self {
        Self::connector(CURRENT_CAM, connector)
    }
    pub fn cam_supported(connector: ConnectorNumber) -> Self {
        Self::connector(CAM_SUPPORTED, connector)
    }
    pub fn new_cam(connector: ConnectorNumber, mode: u8, enter: bool) -> Self {
        Self::new_cam_configuration(connector, mode, enter, 0)
    }
    pub fn new_cam_configuration(
        connector: ConnectorNumber,
        mode: u8,
        enter: bool,
        configuration: u32,
    ) -> Self {
        Self::connector(
            NEW_CAM
                | (u64::from(enter) << 23)
                | (u64::from(mode) << 24)
                | (u64::from(configuration) << 32),
            connector,
        )
    }
    pub fn alternate_mode(connector: ConnectorNumber, recipient: Recipient, offset: u8) -> Self {
        let recipient = match recipient {
            Recipient::Connector => 0,
            Recipient::Partner => 1,
            Recipient::CablePlug => 2,
            Recipient::CablePlugOther => 3,
        };
        Self {
            control: ALTERNATE_MODES
                | (recipient << 16)
                | (u64::from(connector.get()) << 24)
                | (u64::from(offset) << 32),
            connector: Some(connector),
        }
    }
    pub fn pdos(
        connector: ConnectorNumber,
        partner: bool,
        source: bool,
        offset: u8,
        count: u8,
    ) -> Result<Self, Error> {
        if !(1..=4).contains(&count) {
            return Err(Error::InvalidArgument);
        }
        Ok(Self::connector(
            PDOS | (u64::from(partner) << 23)
                | (u64::from(offset) << 24)
                | (u64::from(count - 1) << 32)
                | (u64::from(source) << 34),
            connector,
        ))
    }
    pub fn request_data_role(
        connector: ConnectorNumber,
        role: DataRole,
        accept_swaps: bool,
    ) -> Self {
        Self::connector(
            SET_DATA_ROLE
                | (match role {
                    DataRole::Host => 1,
                    DataRole::Device => 2,
                } << 23)
                | (u64::from(accept_swaps) << 25),
            connector,
        )
    }
    pub fn request_power_role(
        connector: ConnectorNumber,
        role: PowerRole,
        accept_swaps: bool,
    ) -> Self {
        Self::connector(
            SET_POWER_ROLE
                | (match role {
                    PowerRole::Source => 1,
                    PowerRole::Sink => 2,
                } << 23)
                | (u64::from(accept_swaps) << 25),
            connector,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub command: u64,
    pub cci: Cci,
    pub bytes: usize,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorSnapshot {
    pub number: ConnectorNumber,
    pub generation: u64,
    pub capability: [u8; 4],
    pub capability_bytes: u8,
    pub status: ConnectorStatus,
}

/// All operations, including notification delivery, are serialized through
/// `&mut self` in process/deferred context. There is one in-flight command and
/// at most one firmware-latched connector change. No asynchronous work or
/// unacknowledged hardware is released by Drop.
pub struct Controller<T: Transport, C: Timer> {
    transport: T,
    timer: C,
    version: Version,
    generation: u64,
    ready: bool,
    initialized: bool,
    fault: Option<Error>,
    pending: Option<ConnectorNumber>,
    capability: Option<Capability>,
    connectors: Vec<ConnectorSnapshot>,
    last_cci: Cci,
    last_completion: Option<Completion>,
}

impl<T: Transport, C: Timer> Controller<T, C> {
    pub fn new(mut transport: T, timer: C) -> Result<Self, Error> {
        let raw = transport.read_version().map_err(|error| Error::Transport {
            phase: Phase::Version,
            error,
        })?;
        Ok(Self {
            transport,
            timer,
            version: Version::new(raw)?,
            generation: 0,
            ready: false,
            initialized: false,
            fault: None,
            pending: None,
            capability: None,
            connectors: Vec::new(),
            last_cci: Cci(0),
            last_completion: None,
        })
    }
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn initialized(&self) -> bool {
        self.initialized
    }
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_ref()
    }
    pub fn capability(&self) -> Option<Capability> {
        self.capability
    }
    pub fn connectors(&self) -> &[ConnectorSnapshot] {
        &self.connectors
    }
    pub fn pending_change(&self) -> Option<ConnectorNumber> {
        self.pending
    }
    pub fn last_cci(&self) -> Cci {
        self.last_cci
    }
    pub fn last_completion(&self) -> Option<Completion> {
        self.last_completion
    }

    fn poison(&mut self, error: Error) -> Error {
        self.ready = false;
        self.initialized = false;
        self.fault = Some(error.clone());
        error
    }
    fn check_ready(&self) -> Result<(), Error> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if !self.ready {
            return Err(Error::NeedsReset);
        }
        Ok(())
    }
    fn io<U>(&mut self, phase: Phase, result: Result<U, TransportError>) -> Result<U, Error> {
        result.map_err(|error| self.poison(Error::Transport { phase, error }))
    }
    fn cci(&mut self) -> Result<Cci, Error> {
        let read = self.transport.poll_cci();
        let cci = Cci(self.io(Phase::Poll, read)?);
        self.last_cci = cci;
        cci.validate().map_err(|e| self.poison(e))?;
        Ok(cci)
    }
    fn observe(&mut self, cci: Cci) -> Result<(), Error> {
        if cci.busy() {
            return Ok(());
        }
        if let Some(number) = cci.connector() {
            let count = self.capability.map_or(127, |cap| cap.connectors);
            if number.get() > count {
                return Err(self.poison(Error::InvalidConnector {
                    number: number.get(),
                    count,
                }));
            }
            if self.pending.is_some_and(|old| old != number) {
                return Err(self.poison(Error::UnexpectedCompletion {
                    phase: Phase::Poll,
                    cci: cci.0,
                }));
            }
            self.pending = Some(number);
        }
        Ok(())
    }
    /// Deliver a real cached CCI read from a platform notification. Busy CCI
    /// fields are ignored, and no command/ACK is completed on this path.
    pub fn observe_notification(&mut self, raw: u32) -> Result<(), Error> {
        self.check_ready()?;
        let cci = Cci(raw);
        cci.validate().map_err(|e| self.poison(e))?;
        self.observe(cci)
    }
    fn submit(&mut self, control: u64) -> Result<(), Error> {
        let write = self.transport.write_control(control);
        self.io(Phase::Submit, write)
    }
    fn expired(&self, start: u64) -> bool {
        self.timer.now_us().wrapping_sub(start) >= COMMAND_TIMEOUT_US
    }

    fn await_command(&mut self, phase: Phase) -> Result<Cci, Error> {
        let start = self.timer.now_us();
        loop {
            let cci = self.cci()?;
            if !cci.busy() {
                if phase != Phase::Acknowledge || cci.0 & ACK_COMPLETE != 0 {
                    self.observe(cci)?;
                }
                let complete = match phase {
                    Phase::Acknowledge => ACK_COMPLETE,
                    Phase::Cancel => CANCEL_COMPLETE | COMMAND_COMPLETE,
                    _ => COMMAND_COMPLETE,
                };
                if cci.0 & complete == complete {
                    let forbidden = match phase {
                        Phase::Acknowledge => {
                            COMMAND_COMPLETE
                                | ERROR
                                | NOT_SUPPORTED
                                | RESET_COMPLETE
                                | CANCEL_COMPLETE
                        }
                        Phase::Cancel => ACK_COMPLETE | ERROR | NOT_SUPPORTED | RESET_COMPLETE,
                        _ => ACK_COMPLETE | RESET_COMPLETE | CANCEL_COMPLETE,
                    };
                    if cci.0 & forbidden != 0 || (phase == Phase::Acknowledge && cci.length() != 0)
                    {
                        return Err(self.poison(Error::UnexpectedCompletion { phase, cci: cci.0 }));
                    }
                    return Ok(cci);
                }
            }
            if self.expired(start) {
                return Err(Error::Timeout { phase, cci: cci.0 });
            }
            self.timer.delay_us(COMMAND_POLL_US);
        }
    }
    fn acknowledge(&mut self, connector: Option<ConnectorNumber>) -> Result<(), Error> {
        // Clear the old software latch before observing ACK_COMPLETE. A new
        // firmware event, including the same connector again, is then retained.
        if let Some(number) = connector {
            if self.pending != Some(number) {
                return Err(self.poison(Error::UnexpectedCompletion {
                    phase: Phase::Acknowledge,
                    cci: self.last_cci.0,
                }));
            }
            self.pending = None;
        }
        let result = self
            .submit(
                ACK | ACK_COMMAND
                    | if connector.is_some() {
                        ACK_CONNECTOR
                    } else {
                        0
                    },
            )
            .and_then(|()| self.await_command(Phase::Acknowledge));
        if let Err(error) = result {
            if self.pending.is_none() {
                self.pending = connector;
            }
            return Err(self.poison(error));
        }
        Ok(())
    }

    /// An explicit reset invalidates all old snapshots, even if reset fails.
    /// Reset is the only operation permitted to recover an unresolved command.
    pub fn reset(&mut self) -> Result<(), Error> {
        self.generation = match self.generation.checked_add(1) {
            Some(value) => value,
            None => return Err(self.poison(Error::GenerationExhausted)),
        };
        self.ready = false;
        self.initialized = false;
        self.capability = None;
        self.connectors.clear();
        self.pending = None;
        self.last_completion = None;
        let initial = self.cci()?;
        if initial.0 & RESET_COMPLETE != 0 {
            // Source workaround: a new ordinary command clears an old reset
            // completion. A timeout here does not prove the following reset.
            self.submit(NOTIFY)?;
            let start = self.timer.now_us();
            while self.cci()?.0 & COMMAND_COMPLETE == 0 {
                if self.expired(start) {
                    break;
                }
                self.timer.delay_us(RESET_POLL_US);
            }
        }
        self.submit(RESET)?;
        // Linux ucsi_reset_ppm: done once the reset bit is set, resetting
        // again whenever the PPM still reports other work.
        let start = self.timer.now_us();
        let mut cci = initial;
        loop {
            if self.expired(start) {
                return Err(self.poison(Error::Timeout {
                    phase: Phase::Reset,
                    cci: cci.0,
                }));
            }
            self.timer.delay_us(RESET_POLL_US);
            cci = self.cci()?;
            if cci.0 & !RESET_COMPLETE != 0 {
                self.submit(RESET)?;
            }
            if cci.0 & RESET_COMPLETE != 0 {
                self.fault = None;
                self.ready = true;
                return Ok(());
            }
        }
    }

    fn run(
        &mut self,
        command: Command,
        input: &mut [u8],
        output: &[u8],
        connector_ack: bool,
    ) -> Result<Completion, Error> {
        self.check_ready()?;
        if input.len() > self.version.message_in_bytes()
            || output.len() > self.version.message_out_bytes()
        {
            return Err(Error::InvalidArgument);
        }
        if let (Some(number), Some(cap)) = (command.connector, self.capability)
            && number.get() > cap.connectors
        {
            return Err(Error::InvalidConnector {
                number: number.get(),
                count: cap.connectors,
            });
        }
        if !output.is_empty() {
            let result = self.transport.write_message_out(output);
            self.io(Phase::MessageOut, result)?;
        }
        self.submit(command.control)?;
        let cci = match self.await_command(Phase::Command) {
            Ok(cci) => cci,
            Err(Error::Timeout { cci, .. }) if cci & BUSY != 0 => {
                self.submit(CANCEL)?;
                if let Err(error) = self.await_command(Phase::Cancel) {
                    return Err(self.poison(error));
                }
                self.acknowledge(None)?;
                return Err(Error::Cancelled {
                    command: command.control,
                    cci,
                });
            }
            Err(error) => return Err(self.poison(error)),
        };
        let bytes = cci.length();
        let mut staged = [0u8; 255];
        let minimum = match command.control & 0xff {
            CAPABILITY => 16,
            CONNECTOR_CAPABILITY => 2,
            CURRENT_CAM => 1,
            CABLE_PROPERTY => 5,
            STATUS => 9,
            ERROR_STATUS => 2,
            _ => 0,
        };
        let protocol_length =
            bytes > input.len() || bytes > self.version.message_in_bytes() || bytes < minimum;
        if !protocol_length && cci.0 & (ERROR | NOT_SUPPORTED) == 0 && bytes != 0 {
            let result = self.transport.read_message_in(&mut staged[..bytes]);
            self.io(Phase::MessageIn, result)?;
        }
        // Error responses acknowledge only command completion; a connector
        // change remains latched until its own successful status observation.
        let ack = (connector_ack && cci.0 & (ERROR | NOT_SUPPORTED) == 0 && !protocol_length)
            .then_some(command.connector)
            .flatten();
        self.acknowledge(ack)?;
        let completion = Completion {
            command: command.control,
            cci,
            bytes,
            generation: self.generation,
        };
        self.last_completion = Some(completion);
        if cci.0 & NOT_SUPPORTED != 0 {
            return Err(Error::NotSupported {
                command: command.control,
                cci: cci.0,
            });
        }
        if cci.0 & ERROR != 0 {
            return Err(Error::PpmRejected {
                command: command.control,
                cci: cci.0,
            });
        }
        if protocol_length {
            return Err(Error::InvalidResponseLength {
                command: command.control as u8,
                bytes,
            });
        }
        input[..bytes].copy_from_slice(&staged[..bytes]);
        Ok(completion)
    }

    fn execute_inner(
        &mut self,
        command: Command,
        input: &mut [u8],
        output: &[u8],
        connector_ack: bool,
    ) -> Result<Completion, Error> {
        match self.run(command, input, output, connector_ack) {
            Err(Error::PpmRejected { cci, .. }) => {
                let target = if self.version.raw() > 0x0120 {
                    command.connector.map_or(0, ConnectorNumber::control)
                } else {
                    0
                };
                let mut bytes = [0u8; 2];
                let detail = self.run(
                    Command::global(ERROR_STATUS | target),
                    &mut bytes,
                    &[],
                    false,
                );
                match detail {
                    Ok(receipt) if receipt.bytes == 2 => Err(Error::Ppm {
                        command: command.control,
                        cci,
                        status: u16::from_le_bytes(bytes),
                    }),
                    Ok(receipt) => Err(Error::ErrorStatus {
                        command: command.control,
                        cci,
                        failure: Box::new(Error::InvalidResponseLength {
                            command: ERROR_STATUS as u8,
                            bytes: receipt.bytes,
                        }),
                    }),
                    Err(error) => Err(Error::ErrorStatus {
                        command: command.control,
                        cci,
                        failure: Box::new(error),
                    }),
                }
            }
            result => result,
        }
    }
    pub fn execute(
        &mut self,
        command: Command,
        input: &mut [u8],
        output: &[u8],
    ) -> Result<Completion, Error> {
        self.execute_inner(command, input, output, false)
    }

    pub fn initialize(&mut self) -> Result<(), Error> {
        let result = self.initialize_inner();
        result.map_err(|error| self.poison(error))
    }
    fn initialize_inner(&mut self) -> Result<(), Error> {
        self.reset()?;
        self.execute(Command::global(NOTIFY | NOTIFY_BASIC), &mut [], &[])?;
        let mut capability = [0; 16];
        let receipt = self.execute(Command::capability(), &mut capability, &[])?;
        let capability = Capability::parse(&capability[..receipt.bytes])?;
        self.capability = Some(capability);
        if let Some(number) = self.pending
            && number.get() > capability.connectors
        {
            return Err(Error::InvalidConnector {
                number: number.get(),
                count: capability.connectors,
            });
        }
        for number in 1..=capability.connectors {
            let number = ConnectorNumber::new(number)?;
            let mut cap = [0; 4];
            let receipt = self.execute(Command::connector_capability(number), &mut cap, &[])?;
            if !(2..=4).contains(&receipt.bytes) {
                return Err(Error::InvalidResponseLength {
                    command: CONNECTOR_CAPABILITY as u8,
                    bytes: receipt.bytes,
                });
            }
            let status = self.read_status(number, false)?;
            self.connectors.push(ConnectorSnapshot {
                number,
                generation: self.generation,
                capability: cap,
                capability_bytes: receipt.bytes as u8,
                status,
            });
        }
        self.execute(
            Command::global(NOTIFY | capability.notifications(self.version)),
            &mut [],
            &[],
        )?;
        self.initialized = true;
        Ok(())
    }
    fn read_status(
        &mut self,
        number: ConnectorNumber,
        acknowledge: bool,
    ) -> Result<ConnectorStatus, Error> {
        let mut bytes = [0; 19];
        let len = bytes.len().min(self.version.message_in_bytes());
        let receipt = self.execute_inner(
            Command::connector_status(number),
            &mut bytes[..len],
            &[],
            acknowledge,
        )?;
        ConnectorStatus::parse(self.version, &bytes[..receipt.bytes])
    }
    pub fn connector_status(&mut self, number: ConnectorNumber) -> Result<ConnectorStatus, Error> {
        self.read_status(number, false)
    }
    pub fn poll_change(&mut self) -> Result<Option<ConnectorNumber>, Error> {
        self.check_ready()?;
        let cci = self.cci()?;
        self.observe(cci)?;
        if !cci.busy() && cci.0 & COMMAND_COMPLETE != 0 {
            return Err(self.poison(Error::UnexpectedCompletion {
                phase: Phase::Poll,
                cci: cci.0,
            }));
        }
        Ok(self.pending)
    }
    /// Return only after the actual status and connector-change ACK complete.
    /// A role command's completion alone never updates this snapshot.
    pub fn service_change(&mut self) -> Result<Option<ConnectorSnapshot>, Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }
        self.check_ready()?;
        let Some(number) = self.pending else {
            return Ok(None);
        };
        let status = self.read_status(number, true)?;
        let snapshot = &mut self.connectors[usize::from(number.get() - 1)];
        snapshot.status = status;
        Ok(Some(*snapshot))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::{collections::VecDeque, rc::Rc};
    use core::cell::Cell;

    #[derive(Clone, Copy, Default)]
    enum Wait {
        #[default]
        Complete,
        Busy,
        Quiet,
    }
    struct Reply {
        command: u64,
        bytes: Vec<u8>,
        flags: u32,
        wait: Wait,
    }
    impl Reply {
        fn new(command: Command, bytes: &[u8]) -> Self {
            Self {
                command: command.control,
                bytes: bytes.to_vec(),
                flags: 0,
                wait: Wait::Complete,
            }
        }
    }
    #[derive(Clone, Copy)]
    enum State {
        Idle,
        Reset,
        Command(Wait),
        Ack(bool),
        Cancel,
    }
    struct Ppm {
        version: u16,
        state: State,
        cci: u32,
        replies: VecDeque<Reply>,
        payload: Vec<u8>,
        flags: u32,
        connector: u8,
        next_connector: u8,
        controls: Vec<u64>,
        outgoing: Vec<u8>,
        reads: usize,
        calls: usize,
        fail_at: usize,
        fail_after_control: Option<u8>,
        cancel_complete: bool,
        reset_complete: bool,
        /// CCI bits reported once alongside the next reset completion.
        reset_extra: u32,
    }
    impl Ppm {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                version: 0x0200,
                state: State::Idle,
                cci: 0,
                replies: replies.into(),
                payload: Vec::new(),
                flags: 0,
                connector: 0,
                next_connector: 0,
                controls: Vec::new(),
                outgoing: Vec::new(),
                reads: 0,
                calls: 0,
                fail_at: usize::MAX,
                fail_after_control: None,
                cancel_complete: true,
                reset_complete: true,
                reset_extra: 0,
            }
        }
        fn io(&mut self) -> Result<(), TransportError> {
            self.calls += 1;
            if self.calls == self.fail_at {
                Err(TransportError::Io(self.calls as u64))
            } else {
                Ok(())
            }
        }
    }
    impl Transport for Ppm {
        fn read_version(&mut self) -> Result<u16, TransportError> {
            self.io()?;
            Ok(self.version)
        }
        fn poll_cci(&mut self) -> Result<u32, TransportError> {
            self.io()?;
            self.cci = match self.state {
                State::Idle => u32::from(self.connector) << 1,
                State::Reset if self.reset_complete => {
                    RESET_COMPLETE | core::mem::take(&mut self.reset_extra)
                }
                State::Reset => 0,
                State::Command(Wait::Complete) => {
                    COMMAND_COMPLETE
                        | self.flags
                        | ((self.payload.len() as u32) << 8)
                        | (u32::from(self.connector) << 1)
                }
                State::Command(Wait::Busy) => BUSY | 0x01ff_ffff,
                State::Command(Wait::Quiet) => 0,
                State::Ack(true) => {
                    self.state = State::Ack(false);
                    return Ok(self.cci);
                }
                State::Ack(false) => {
                    self.state = State::Idle;
                    ACK_COMPLETE | (u32::from(self.connector) << 1)
                }
                State::Cancel if self.cancel_complete => CANCEL_COMPLETE | COMMAND_COMPLETE,
                State::Cancel => CANCEL_COMPLETE,
            };
            Ok(self.cci)
        }
        fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
            self.io()?;
            assert!(matches!(self.state, State::Command(Wait::Complete)));
            assert_eq!(self.cci & COMMAND_COMPLETE, COMMAND_COMPLETE);
            bytes.copy_from_slice(&self.payload[..bytes.len()]);
            self.reads += 1;
            Ok(())
        }
        fn write_message_out(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            self.io()?;
            self.outgoing = bytes.to_vec();
            Ok(())
        }
        fn write_control(&mut self, control: u64) -> Result<(), TransportError> {
            self.io()?;
            self.controls.push(control);
            match control as u8 {
                1 => {
                    self.state = State::Reset;
                    self.connector = 0;
                }
                2 => {
                    assert!(matches!(self.state, State::Command(Wait::Busy)));
                    self.state = State::Cancel;
                }
                4 => {
                    assert_eq!(control & ACK_COMMAND, ACK_COMMAND);
                    if control & ACK_CONNECTOR != 0 {
                        assert_ne!(self.connector, 0);
                        self.connector = self.next_connector;
                        self.next_connector = 0;
                    }
                    self.state = State::Ack(true);
                }
                _ => {
                    assert!(matches!(self.state, State::Idle | State::Reset));
                    let reply = self.replies.pop_front().expect("unplanned PPM command");
                    assert_eq!(control, reply.command);
                    self.payload = reply.bytes;
                    self.flags = reply.flags;
                    self.state = State::Command(reply.wait);
                }
            }
            if self.fail_after_control == Some(control as u8) {
                return Err(TransportError::Io(0xdead));
            }
            Ok(())
        }
    }
    #[derive(Clone)]
    struct Time(Rc<Cell<u64>>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn delay_us(&self, us: u64) {
            self.0.set(self.0.get().wrapping_add(us));
        }
    }
    fn make_controller(replies: Vec<Reply>) -> Controller<Ppm, Time> {
        Controller::new(Ppm::new(replies), Time(Rc::new(Cell::new(0)))).unwrap()
    }
    fn port() -> ConnectorNumber {
        ConnectorNumber::new(1).unwrap()
    }
    fn status() -> [u8; 19] {
        let mut bytes = [0; 19];
        bytes[2] = 0x78;
        bytes[3] = 0x20;
        bytes[10] = 0x40;
        bytes
    }
    fn initialized() -> Controller<Ppm, Time> {
        let mut cap = [0; 16];
        cap[4] = 0x81;
        cap[5] = 0xff;
        cap[6] = 0x3f;
        let capability = Capability::parse(&cap).unwrap();
        let mut controller = make_controller(vec![
            Reply::new(Command::global(NOTIFY | NOTIFY_BASIC), &[]),
            Reply::new(Command::capability(), &cap),
            Reply::new(
                Command::connector_capability(port()),
                &[0xff, 0xff, 0x0f, 0],
            ),
            Reply::new(Command::connector_status(port()), &status()),
            Reply::new(
                Command::global(NOTIFY | capability.notifications(Version::new(0x0200).unwrap())),
                &[],
            ),
        ]);
        controller.initialize().unwrap();
        controller
    }

    #[test]
    fn initialization_drives_real_commands_and_retains_wire_observations() {
        let controller = initialized();
        assert!(controller.initialized());
        assert_eq!(controller.generation(), 1);
        assert_eq!(controller.capability().unwrap().reported_connectors, 0x81);
        let snapshot = controller.connectors()[0];
        assert!(snapshot.status.connected());
        assert!(snapshot.status.power_source());
        assert!(snapshot.status.usb_data());
        assert!(snapshot.status.alternate_mode());
        assert_eq!(snapshot.status.orientation_reversed(), Some(true));
        assert_eq!(
            controller
                .transport
                .controls
                .iter()
                .filter(|c| **c as u8 == 4)
                .count(),
            5
        );
        assert!(controller.transport.replies.is_empty());
    }
    #[test]
    fn reset_required_and_stale_reset_completion_cleared_before_new_epoch() {
        let mut controller = make_controller(vec![Reply::new(Command::global(NOTIFY), &[])]);
        assert_eq!(
            controller.execute(Command::current_cam(port()), &mut [0; 1], &[]),
            Err(Error::NeedsReset)
        );
        controller.transport.state = State::Reset;
        controller.reset().unwrap();
        assert_eq!(controller.transport.controls, vec![NOTIFY, RESET]);
        assert_eq!(controller.timer.now_us(), RESET_POLL_US);
    }
    #[test]
    fn reset_completes_on_its_bit_and_resets_again_while_the_ppm_reports_other_work() {
        let mut controller = make_controller(Vec::new());
        controller.transport.reset_extra = BUSY;
        controller.reset().unwrap();
        assert_eq!(controller.transport.controls, vec![RESET, RESET]);
    }
    #[test]
    fn busy_timeout_cancels_acknowledges_and_never_claims_command_success() {
        let mut hanging = Reply::new(Command::current_cam(port()), &[]);
        hanging.wait = Wait::Busy;
        let mut controller = make_controller(vec![
            hanging,
            Reply::new(Command::current_cam(port()), &[7]),
        ]);
        controller.reset().unwrap();
        assert!(matches!(
            controller.execute(Command::current_cam(port()), &mut [0; 1], &[]),
            Err(Error::Cancelled { .. })
        ));
        assert_eq!(
            &controller.transport.controls[2..],
            &[CANCEL, ACK | ACK_COMMAND]
        );
        assert!(controller.fault().is_none());
        let mut result = [0];
        controller
            .execute(Command::current_cam(port()), &mut result, &[])
            .unwrap();
        assert_eq!(result, [7]);
    }
    #[test]
    fn incomplete_cancel_and_quiet_timeouts_require_explicit_reset() {
        for wait in [Wait::Busy, Wait::Quiet] {
            let mut hanging = Reply::new(Command::current_cam(port()), &[]);
            hanging.wait = wait;
            let mut controller = make_controller(vec![hanging]);
            controller.reset().unwrap();
            controller.transport.cancel_complete = false;
            let error = controller
                .execute(Command::current_cam(port()), &mut [0; 1], &[])
                .unwrap_err();
            assert!(matches!(error, Error::Timeout { .. }));
            let calls = controller.transport.calls;
            assert_eq!(
                controller.execute(Command::current_cam(port()), &mut [0; 1], &[]),
                Err(error)
            );
            assert_eq!(calls, controller.transport.calls);
            controller.reset().unwrap();
            assert!(controller.fault().is_none());
            assert_eq!(controller.generation(), 2);
        }
    }
    #[test]
    fn ppm_error_reads_actual_error_status_with_version_correct_connector() {
        for version in [0x0120, 0x0200] {
            let command = Command::alternate_mode(port(), Recipient::Partner, 3);
            let mut failed = Reply::new(command, &[]);
            failed.flags = ERROR;
            let target = if version > 0x0120 {
                port().control()
            } else {
                0
            };
            let mut controller = make_controller(vec![
                failed,
                Reply::new(Command::global(ERROR_STATUS | target), &[0x10, 0x80]),
            ]);
            controller.transport.version = version;
            controller.version = Version::new(version).unwrap();
            controller.reset().unwrap();
            assert!(matches!(
                controller.execute(command, &mut [0; 6], &[]),
                Err(Error::Ppm { status: 0x8010, .. })
            ));
            assert!(controller.fault().is_none());
            assert_eq!(controller.transport.reads, 1);
        }
    }
    #[test]
    fn unsupported_does_not_read_payload_or_poison_the_controller() {
        let mut reply = Reply::new(Command::current_cam(port()), &[9]);
        reply.flags = NOT_SUPPORTED;
        let mut controller = make_controller(vec![reply]);
        controller.reset().unwrap();
        let mut bytes = [0xaa];
        assert!(matches!(
            controller.execute(Command::current_cam(port()), &mut bytes, &[]),
            Err(Error::NotSupported { .. })
        ));
        assert_eq!(bytes, [0xaa]);
        assert_eq!(controller.transport.reads, 0);
        assert!(controller.fault().is_none());
    }
    #[test]
    fn malformed_status_keeps_connector_latched_and_does_not_publish_partial_state() {
        for bytes in [vec![1; 8], vec![1; 20]] {
            let mut controller = initialized();
            let old = controller.connectors()[0];
            controller.transport.connector = 1;
            controller.poll_change().unwrap();
            controller
                .transport
                .replies
                .push_back(Reply::new(Command::connector_status(port()), &bytes));
            assert!(matches!(
                controller.service_change(),
                Err(Error::InvalidResponseLength { .. })
            ));
            assert_eq!(controller.pending_change(), Some(port()));
            assert_eq!(controller.connectors()[0], old);
            assert_eq!(
                controller.transport.controls.last(),
                Some(&(ACK | ACK_COMMAND))
            );
            controller
                .transport
                .replies
                .push_back(Reply::new(Command::connector_status(port()), &status()));
            assert!(controller.service_change().unwrap().is_some());
            assert_eq!(controller.pending_change(), None);
        }
    }
    #[test]
    fn same_connector_relatched_during_ack_is_not_lost() {
        let mut controller = initialized();
        controller.transport.connector = 1;
        controller.transport.next_connector = 1;
        controller.poll_change().unwrap();
        controller
            .transport
            .replies
            .push_back(Reply::new(Command::connector_status(port()), &status()));
        controller.service_change().unwrap();
        assert_eq!(controller.pending_change(), Some(port()));
        assert_eq!(
            controller.transport.controls.last(),
            Some(&(ACK | ACK_COMMAND | ACK_CONNECTOR))
        );
    }
    #[test]
    fn contradictory_connector_and_failed_read_never_look_like_success() {
        let mut controller = initialized();
        controller.observe_notification(2).unwrap();
        assert!(matches!(
            controller.observe_notification(4),
            Err(Error::InvalidConnector {
                number: 2,
                count: 1
            })
        ));
        let mut controller = make_controller(vec![]);
        controller.reset().unwrap();
        assert_eq!(
            controller.observe_notification(u32::MAX),
            Err(Error::InvalidCci(u32::MAX))
        );
        assert!(controller.fault().is_some());
    }
    #[test]
    fn initialization_failure_and_failed_reset_invalidate_public_metadata() {
        let mut controller = initialized();
        controller.transport.reset_complete = false;
        assert!(matches!(
            controller.reset(),
            Err(Error::Timeout {
                phase: Phase::Reset,
                ..
            })
        ));
        assert!(!controller.initialized());
        assert!(controller.capability().is_none());
        assert!(controller.connectors().is_empty());
        let mut controller = make_controller(vec![
            Reply::new(Command::global(NOTIFY | NOTIFY_BASIC), &[]),
            Reply::new(Command::capability(), &[0; 16]),
        ]);
        assert!(controller.initialize().is_err());
        assert!(controller.fault().is_some());
        assert!(!controller.initialized());
    }
    #[test]
    fn transport_failures_at_every_command_io_boundary_block_replay() {
        let command = Command::current_cam(port());
        let mut baseline = make_controller(vec![Reply::new(command, &[7])]);
        baseline.reset().unwrap();
        let first = baseline.transport.calls + 1;
        baseline.execute(command, &mut [0; 1], &[0x55]).unwrap();
        let last = baseline.transport.calls;
        for fail_at in first..=last {
            let mut controller = make_controller(vec![Reply::new(command, &[7])]);
            controller.reset().unwrap();
            controller.transport.fail_at = fail_at;
            let mut output = [0xaa];
            let error = controller
                .execute(command, &mut output, &[0x55])
                .unwrap_err();
            assert!(matches!(error, Error::Transport { .. }));
            assert_eq!(output, [0xaa]);
            let calls = controller.transport.calls;
            assert_eq!(
                controller.execute(command, &mut output, &[0x55]),
                Err(error)
            );
            assert_eq!(calls, controller.transport.calls);
        }
    }
    #[test]
    fn response_and_output_bounds_are_checked_without_exposing_partial_data() {
        let command = Command::current_cam(port());
        let mut controller = make_controller(vec![Reply::new(command, &[7, 8])]);
        controller.reset().unwrap();
        let mut output = [0xaa];
        assert!(matches!(
            controller.execute(command, &mut output, &[]),
            Err(Error::InvalidResponseLength { bytes: 2, .. })
        ));
        assert_eq!(output, [0xaa]);
        assert_eq!(controller.transport.reads, 0);
        let calls = controller.transport.calls;
        assert_eq!(
            controller.execute(command, &mut [0; 256], &[]),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            controller.execute(command, &mut [], &[0; 257]),
            Err(Error::InvalidArgument)
        );
        assert_eq!(calls, controller.transport.calls);
    }

    #[test]
    fn uncertain_publication_retains_pending_event_and_requires_reset() {
        for fail in [0x12, 4] {
            let mut controller = initialized();
            controller.transport.connector = 1;
            controller.poll_change().unwrap();
            controller
                .transport
                .replies
                .push_back(Reply::new(Command::connector_status(port()), &status()));
            controller.transport.fail_after_control = Some(fail);
            let old = controller.connectors()[0];
            assert!(matches!(
                controller.service_change(),
                Err(Error::Transport { .. })
            ));
            assert_eq!(controller.pending_change(), Some(port()));
            assert_eq!(controller.connectors()[0], old);
            let calls = controller.transport.calls;
            assert!(
                controller
                    .execute(Command::current_cam(port()), &mut [0; 1], &[])
                    .is_err()
            );
            assert_eq!(controller.transport.calls, calls);
        }
    }
    #[test]
    fn role_command_completion_does_not_manufacture_a_role_transition() {
        let mut controller = initialized();
        let old = controller.connectors()[0];
        for command in [
            Command::request_data_role(port(), DataRole::Device, true),
            Command::request_power_role(port(), PowerRole::Sink, false),
            Command::new_cam(port(), 3, true),
        ] {
            controller
                .transport
                .replies
                .push_back(Reply::new(command, &[]));
            controller.execute(command, &mut [], &[]).unwrap();
            assert_eq!(controller.connectors()[0], old);
        }
        assert_eq!(
            Command::alternate_mode(port(), Recipient::CablePlugOther, 0x12).control(),
            0x12_0103_000c
        );
        assert_eq!(
            Command::pdos(port(), true, true, 5, 4).unwrap().control(),
            0x7_0581_0010
        );
        assert!(Command::pdos(port(), false, false, 0, 0).is_err());
        assert!(Command::pdos(port(), false, false, 0, 5).is_err());
    }

    #[test]
    fn failure_to_read_error_status_is_explicit_and_does_not_recurse() {
        let command = Command::current_cam(port());
        let mut failed = Reply::new(command, &[]);
        failed.flags = ERROR;
        let mut detail = Reply::new(Command::global(ERROR_STATUS | port().control()), &[]);
        detail.flags = ERROR;
        let mut controller = make_controller(vec![failed, detail]);
        controller.reset().unwrap();
        match controller.execute(command, &mut [0; 1], &[]) {
            Err(Error::ErrorStatus { failure, .. }) => {
                assert!(matches!(*failure, Error::PpmRejected { .. }))
            }
            other => panic!("unexpected error-status result {other:?}"),
        }
        assert_eq!(controller.transport.reads, 0);
        assert!(controller.transport.replies.is_empty());
    }
    /// Runs only with the immutable generated trace from ucsi_oracle.py.
    #[test]
    #[ignore = "requires unchanged pinned Linux C source oracle trace"]
    fn unchanged_linux_notifications_and_command_ack_oracle() {
        let path = std::env::var("STELA_UCSI_ORACLE").expect("STELA_UCSI_ORACLE trace path");
        let trace = std::fs::read_to_string(path).unwrap();
        let mut notifications = 0;
        let mut commands = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            match fields[0] {
                "N" => {
                    let version = u16::from_str_radix(fields[1], 16).unwrap();
                    let features = u16::from_str_radix(fields[2], 16).unwrap();
                    let expected = u64::from_str_radix(fields[3], 16).unwrap();
                    let mut bytes = [0; 16];
                    bytes[4] = 1;
                    bytes[5..7].copy_from_slice(&features.to_le_bytes());
                    assert_eq!(
                        Capability::parse(&bytes)
                            .unwrap()
                            .notifications(Version::new(version).unwrap()),
                        expected,
                        "version {version:x} features {features:x}"
                    );
                    notifications += 1;
                }
                "C" => {
                    let kind: u8 = fields[1].parse().unwrap();
                    let acknowledge = fields[2] == "1";
                    let expected: i32 = fields[3].parse().unwrap();
                    let count: usize = fields[4].parse().unwrap();
                    let expected_controls: Vec<_> = fields[5..]
                        .iter()
                        .map(|value| u64::from_str_radix(value, 16).unwrap())
                        .collect();
                    assert_eq!(count, expected_controls.len());
                    let command = Command::current_cam(port());
                    let mut reply = Reply::new(command, &[0x5a; 3]);
                    match kind {
                        0 => {}
                        1 => reply.flags = NOT_SUPPORTED,
                        2 => reply.flags = ERROR,
                        3 => reply.wait = Wait::Busy,
                        _ => panic!("unknown oracle scenario"),
                    }
                    let mut controller = make_controller(vec![reply]);
                    controller.reset().unwrap();
                    controller.transport.connector = 1;
                    controller.pending = Some(port());
                    let mut bytes = [0; 4];
                    let receipt = controller.run(command, &mut bytes, &[], acknowledge);
                    match (expected, receipt) {
                        (3, Ok(receipt)) => {
                            assert_eq!(receipt.bytes, 3);
                            assert_eq!(&bytes[..3], &[0x5a; 3]);
                        }
                        (-95, Err(Error::NotSupported { .. }))
                        | (-5, Err(Error::PpmRejected { .. }))
                        | (-16, Err(Error::Cancelled { .. })) => {}
                        (_, other) => panic!("Linux result {expected}, Stela result {other:?}"),
                    }
                    assert_eq!(&controller.transport.controls[1..], expected_controls);
                    commands += 1;
                }
                _ => panic!("unknown oracle trace record"),
            }
        }
        assert_eq!(notifications, 393216);
        assert_eq!(commands, 8);
    }
}
