//! Host I²C transactions and the Synopsys DesignWare master controller.
//!
//! This is a polled, PIO implementation of the ordinary 32-bit little-endian
//! DesignWare register interface. The controller engine adapts Linux's
//! `i2c-designware-master.c` FIFO accounting and abort handling at commit
//! `a804c5742bff224d4cb4d25dd383554d598be32b`; see its retained source notices
//! in `i2c/designware.rs`. Register facts were also cross-checked against Intel's
//! fourth generation Core mobile I/O datasheet, section 22. No FreeBSD code is
//! incorporated.
//!
//! The platform owner must discover and power the controller, provide exclusive
//! register ownership, and supply board-correct clock counts. This module does
//! not discover ACPI peripherals, program Intel LPSS power/clock gates, or
//! recover a physically stuck bus through GPIOs. Those paths remain separate
//! requirements. DesignWare interrupts and DMA requests stay disabled.
//! [`amd_mp2`] supplies a separate explicitly owned firmware-mailbox backend;
//! its individual commands do not claim combined repeated-START semantics.
use crate::Clock;
use core::fmt;

pub mod amd_mp2;
mod designware;

pub use designware::{Config, DesignWare, MmioRegisters, Registers, Speed, Timing};

/// One unshifted I²C target address; the controller supplies the direction bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    /// Ordinary unicast addresses, excluding the reserved 0x00–0x07/0x78–0x7f.
    SevenBit(u8),
    TenBit(u16),
}

impl Address {
    fn validate(self) -> Result<(), ErrorKind> {
        match self {
            Self::SevenBit(0x08..=0x77) | Self::TenBit(0..=0x3ff) => Ok(()),
            _ => Err(ErrorKind::InvalidAddress),
        }
    }
}

/// A nonempty message. Each following message begins with a repeated START;
/// only the last message ends with STOP. SMBus quick commands are unsupported.
pub enum Operation<'a> {
    Write(&'a [u8]),
    Read(&'a mut [u8]),
}

impl Operation<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Write(bytes) => bytes.len(),
            Self::Read(bytes) => bytes.len(),
        }
    }
}

/// A serialized I²C master. An error may follow a partial transfer: callers
/// must not automatically replay commands with device-side effects.
pub trait Bus {
    fn transaction(
        &mut self,
        address: Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Error>;
}

/// A progressing timer. Interval users must preflight their maximum duration,
/// retain `start`'s opaque marker and use `elapsed_us`, which permits subtraction
/// before conversion across a native counter rollover. `now_us` is only the
/// legacy absolute quotient. Defaults preserve full-width microsecond models;
/// other counter units must override duration/start/elapsed consistently.
pub trait Timer {
    fn now_us(&self) -> u64;

    fn check_duration(&self, microseconds: u64) -> Result<(), crate::ClockError> {
        if microseconds > u64::MAX / 2 {
            Err(crate::ClockError::DurationTooLong)
        } else {
            Ok(())
        }
    }

    fn start(&self) -> u64 {
        self.now_us()
    }

    fn elapsed_us(&self, start: u64) -> u64 {
        self.now_us().wrapping_sub(start)
    }

    fn relax(&self) {
        crate::waiting();
        core::hint::spin_loop();
    }
}

impl Timer for Clock {
    fn now_us(&self) -> u64 {
        Clock::now_us(self)
    }
    fn check_duration(&self, microseconds: u64) -> Result<(), crate::ClockError> {
        Clock::check_duration(self, microseconds)
    }
    fn start(&self) -> u64 {
        self.try_start().expect("preflighted bus clock")
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.try_elapsed_us(start).expect("preflighted bus clock")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Disable,
    Enable,
    BusIdle,
    Transfer,
    Stop,
}

/// The hardware's abort reason is retained alongside this coarse category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortKind {
    AddressNack,
    DataNack,
    ArbitrationLost,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidAddress,
    EmptyTransaction,
    EmptyMessage,
    InvalidConfiguration,
    /// The 32-bit little-endian DesignWare component signature was absent.
    ComponentType(u32),
    /// No encoded FIFO parameters, unsupported width/speed, or bad depths.
    ComponentParameters(u32),
    UnsupportedVersion(u32),
    /// Clock counts did not read back as requested; fixed timings need an
    /// explicitly matching platform configuration rather than a guessed rate.
    TimingRejected,
    Timeout(Phase),
    Aborted {
        kind: AbortKind,
        source: u32,
    },
    Fifo {
        interrupts: u32,
    },
    UnexpectedReceive,
    UnexpectedStop,
    /// Disable acknowledgement failed on an earlier operation. Recreate the
    /// controller only after the platform has reset it.
    NeedsReset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    NotAttempted,
    /// The controller acknowledged disable and its FIFO/interrupt state was
    /// cleared. This does not assert that external SDA/SCL lines are unstuck.
    Disabled,
    Failed,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I2C {:?} (recovery {:?})", self.kind, self.recovery)
    }
}
