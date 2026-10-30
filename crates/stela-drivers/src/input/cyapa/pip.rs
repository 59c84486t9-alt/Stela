// SPDX-License-Identifier: GPL-2.0-only
//! Cypress Gen5/6 PIP I2C FIFO, serialized command replies and physical reports.
use super::{Interrupt, InterruptError, Recovery};
use crate::bus::i2c::{self, Address, Bus, Operation, Timer};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
mod device;
mod report;
pub use report::{Contact, ContactType, Event, Frame, Record, Touches};

const MAX_PACKET: usize = 256;
const MAX_PENDING: usize = 16;
/// Complete FIFO read, including the little-endian length field.
/// A two-byte reset notice advertises zero, without manufacturing missing bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    bytes: [u8; MAX_PACKET],
    received: u16,
}
impl Packet {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.received)]
    }
    pub fn declared_length(&self) -> u16 {
        u16::from_le_bytes([self.bytes[0], self.bytes[1]])
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    Starting,
    Ready,
    DeepSleep,
    ButtonsOnly,
    /// Scanning remains enabled at the acknowledged device interval.
    LowPower {
        interval_ms: u16,
    },
    Stopped,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Clock(crate::ClockError),
    InvalidAddress,
    NotReady,
    AlreadyActive,
    NeedsReset,
    Bus(i2c::Error),
    Interrupt(InterruptError),
    Length(u16),
    ChangedLength {
        peek: u16,
        actual: u16,
    },
    QueueFull,
    DrainLimit,
    Timeout,
    UnexpectedReset,
    Descriptor,
    FirmwareLaunch,
    UnsupportedGeneration {
        family: u8,
        silicon_high: u8,
    },
    CommandStatus {
        command: u8,
        status: u8,
    },
    UnsupportedCommand(u8),
    UnsupportedReport(u8),
    ReportLength {
        id: u8,
        actual: u16,
    },
    ContactCount(u8),
    ContactType(u8),
    DuplicateId(u8),
    Coordinate {
        id: u8,
        x: u16,
        y: u16,
    },
    InvalidGeometry,
    ProductFamily(u16),
    UnsupportedProduct,
    IdentityChanged,
    Orientation(u8),
    InvalidScanInterval(u16),
    ParameterReply {
        id: u8,
        size: u8,
    },
    IntervalReadback {
        expected: (u16, u16, u16),
        actual: (u16, u16, u16),
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub recovery: Recovery,
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            recovery: Recovery::NotAttempted,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cypress PIP {:?} ({:?})", self.kind, self.recovery)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    Gen5,
    Gen6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalibrationPhase {
    SuspendScanning,
    MutualCapacitance,
    SelfCapacitance,
    ResumeScanning,
}
/// The original failure survives a separately acknowledged resume attempt.
/// Resume is attempted only after a complete calibration rejection, never after
/// an uncertain transfer or timeout that could still own a delayed reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationError {
    pub phase: CalibrationPhase,
    pub error: Error,
    pub response: Option<Box<Packet>>,
    pub resume_error: Option<Error>,
}
/// Observations from the most recent explicit Gen6 interval SET attempt.
/// `applied` survives a later GET failure; only matching SET/GET observations
/// check publication in `Capabilities::power_intervals`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntervalUpdate {
    pub requested: (u16, u16, u16),
    pub applied: Option<(u16, u16, u16)>,
    pub readback: Option<(u16, u16, u16)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub generation: Generation,
    pub descriptor: [u8; 32],
    pub system_info: [u8; 71],
    pub product_id: [u8; 15],
    pub platform_version: u8,
    pub firmware_version: (u8, u8),
    pub electrodes: (u8, u8),
    /// Gen6 queried receive electrodes and the corresponding four-aligned count.
    pub receive_electrodes: Option<(u8, u16)>,
    /// Gen6 ACTIVE/LP1/LP2 intervals, read back without changing policy.
    pub power_intervals: Option<(u16, u16, u16)>,
    pub physical_size_mm: (u16, u16),
    pub maximum: (u16, u16),
    pub maximum_z: u16,
    pub origins: (bool, bool),
    pub button_capabilities: u8,
}
pub struct Device<B, I, T> {
    bus: B,
    interrupt: I,
    timer: T,
    address: Address,
    generation: Generation,
    wake_notice: Option<i2c::Error>,
    state: State,
    capabilities: Option<Capabilities>,
    pending: VecDeque<Packet>,
    failed_packet: Option<Packet>,
    interval_update: Option<IntervalUpdate>,
}
impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    /// The platform grants exclusive ownership of the powered peripheral, bus and IRQ.
    /// No prior ownership epoch may have an outstanding command: six idle headers
    /// drain currently queued data but cannot exclude a delayed identical-opcode reply.
    /// An uncertain prior owner must be retired through platform reset before this grant.
    pub fn new(bus: B, interrupt: I, timer: T, address: Address) -> Result<Self, Error> {
        Self::with_generation(bus, interrupt, timer, address, Generation::Gen5)
    }
    /// Same exclusive startup grant as `new`; Gen6 identity must check
    /// before any Gen6 power/proximity/command-IRQ mutation is permitted.
    pub fn new_gen6(bus: B, interrupt: I, timer: T, address: Address) -> Result<Self, Error> {
        Self::with_generation(bus, interrupt, timer, address, Generation::Gen6)
    }
    fn with_generation(
        bus: B,
        interrupt: I,
        timer: T,
        address: Address,
        generation: Generation,
    ) -> Result<Self, Error> {
        timer.check_duration(5_000_000).map_err(ErrorKind::Clock)?;
        if !matches!(address, Address::SevenBit(value @ 0x08..=0x77) if generation == Generation::Gen6 || value & 1 == 0)
        {
            return Err(ErrorKind::InvalidAddress.into());
        }
        Ok(Self {
            bus,
            interrupt,
            timer,
            address,
            generation,
            wake_notice: None,
            state: State::Fresh,
            capabilities: None,
            pending: VecDeque::new(),
            failed_packet: None,
            interval_update: None,
        })
    }
    /// Most recent expected, controller-recovered Gen6 preparation-ping NACK.
    /// This is held as an observed protocol outcome, not silently discarded.
    pub fn take_wake_notice(&mut self) -> Option<i2c::Error> {
        self.wake_notice.take()
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }
    /// Completed observations are held separately from validated settings,
    /// including after a partial update quarantines the peripheral owner.
    pub fn interval_update(&self) -> Option<&IntervalUpdate> {
        self.interval_update.as_ref()
    }
    /// Earlier physical packets remain owned even if a later command fails.
    pub fn take_pending_packet(&mut self) -> Option<Packet> {
        self.pending.pop_front()
    }
    /// Most recent complete header/packet associated with a failed transfer.
    pub fn take_failed_packet(&mut self) -> Option<Packet> {
        self.failed_packet.take()
    }
}

#[cfg(test)]
mod tests;
