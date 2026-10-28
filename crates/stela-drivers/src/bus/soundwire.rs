// SPDX-License-Identifier: GPL-2.0-only
//! SoundWire controller protocols. Actual link resources, frame clocks, reset,
//! firmware arbitration, discovery and audio streams require their original
//! platform owner; a command engine or controller identity grants none of them.
//! Source attribution and finite evidence limits: `soundwire/THIRD_PARTY.md`.
pub mod amd;
pub mod cadence;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Configuration,
    Length,
    Allocation,
    Io,
    Link,
    ForeignResponse,
    Timeout,
    Nack,
    Ignored,
    Faulted,
}

/// A failed command batch: where it stopped and how far it got.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: Option<usize>,
    /// A command store was attempted and may have reached a peripheral.
    pub issued: bool,
    /// Acknowledged byte commands, including page commands, completed before
    /// the failure.
    pub completed: usize,
}
