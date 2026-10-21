//! SMBus host transactions for batteries, touchpads and other peripherals.
//!
//! [`i801`] implements Intel's PIO host controller. Peripheral discovery,
//! firmware ownership, battery policy and touchpad protocols are separate.
//! SMBus block transfers carry an on-wire count; they are not interchangeable
//! with arbitrary I²C block transfers.
use core::fmt;

pub mod i801;

pub const MAX_BLOCK: usize = 32;

/// An ordinary, unshifted, seven-bit unicast address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address(u8);

impl Address {
    pub fn new(address: u8) -> Result<Self, Error> {
        if (0x08..=0x77).contains(&address) {
            Ok(Self(address))
        } else {
            Err(ErrorKind::InvalidAddress.into())
        }
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

/// A completed SMBus block read. The empty default is replaced only after a
/// successful transfer; a failure leaves the previous result unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    bytes: [u8; MAX_BLOCK],
    length: u8,
}

impl Default for Block {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_BLOCK],
            length: 0,
        }
    }
}

impl Block {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// One atomic SMBus protocol operation. Read outputs are committed only after
/// completion. Errors can follow a partial write, so replay is caller policy.
#[derive(Debug)]
pub enum Transaction<'a> {
    SendByte(u8),
    ReceiveByte(&'a mut u8),
    WriteByte {
        command: u8,
        data: u8,
    },
    ReadByte {
        command: u8,
        data: &'a mut u8,
    },
    WriteWord {
        command: u8,
        data: u16,
    },
    ReadWord {
        command: u8,
        data: &'a mut u16,
    },
    ProcessCall {
        command: u8,
        request: u16,
        response: &'a mut u16,
    },
    WriteBlock {
        command: u8,
        data: &'a [u8],
    },
    ReadBlock {
        command: u8,
        data: &'a mut Block,
    },
}

pub trait Bus {
    /// `pec` requests end-to-end SMBus packet error checking. Controllers must
    /// reject this explicitly unless both generation and verification exist.
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Completion,
    ByteDone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidAddress,
    InvalidBlockLength(usize),
    InvalidConfiguration,
    InvalidPortRange,
    HostDisabled,
    FirmwareSmi,
    WrongProtocolMode,
    UnsupportedPec,
    /// The controller was busy before this driver started a transaction;
    /// another owner's operation is never killed to acquire the bus.
    Busy,
    StatusStuck,
    BufferModeRejected,
    /// I801 DEV_ERR: NACK, invalid command or controller communication timeout.
    Device,
    ArbitrationLost,
    Failed,
    UnexpectedCompletion,
    Timeout(Phase),
    NeedsReset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    NotAttempted,
    Cleared,
    Killed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// Original host status, retained before W1C clears it.
    pub status: u8,
    pub recovery: Recovery,
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            status: 0,
            recovery: Recovery::NotAttempted,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SMBus {:?}, status {:#04x} (recovery {:?})",
            self.kind, self.status, self.recovery
        )
    }
}
