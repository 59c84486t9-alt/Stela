// SPDX-License-Identifier: GPL-2.0-or-later
//! Why an endpoint's power sequence stopped: Stela's own outcome names for
//! the steps in `power.rs`.
use super::super::ConfigError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Config(ConfigError),
    Interrupted,
    Identity,
    Capability,
    Unsupported,
    Clock,
    Read(u16),
    Readback(u16),
    State,
    BusMaster,
    Bars,
    NotReady,
    /// The device's start budget passed during a minimum wait; the wait
    /// itself ran in full (`budget::Bounded`).
    StartBudget,
}
impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::Interrupted => f.write_str("its power change was interrupted"),
            Self::Identity => f.write_str("its identity changed during the power change"),
            Self::Capability => f.write_str("its power management capability is malformed"),
            Self::Unsupported => f.write_str("it does not support the power change"),
            Self::Clock => f.write_str("the delay clock is unavailable"),
            Self::Read(offset) => write!(f, "its register {offset:#x} reads all ones"),
            Self::Readback(offset) => {
                write!(f, "its register {offset:#x} did not keep what was written")
            }
            Self::State => f.write_str("it did not reach full power (D0)"),
            Self::BusMaster => f.write_str("it is still bus mastering"),
            Self::Bars => f.write_str("its BARs were lost in the power change"),
            Self::NotReady => f.write_str("it did not become ready after the power change"),
            Self::StartBudget => f.write_str("its start budget passed while it was not answering"),
        }
    }
}
