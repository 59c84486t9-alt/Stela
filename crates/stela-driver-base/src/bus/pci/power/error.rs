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
}
impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}
