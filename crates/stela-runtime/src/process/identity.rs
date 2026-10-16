//! The guest process ID, 1 to PID_MAX (99999) as in XNU.

use anyhow::{Result, ensure};
use serde::Serialize;

pub const PROFILE_ID: &str = "darwin-explicit-process-identity-v1";
pub const MAX_PROCESS_ID: u32 = 99_999;

/// Shared by the actual guest thread/task owner through Rc. Cloning that owner
/// represents the same process; it must never implement fork. Caller-owned
/// address-space identity supplies the execution binding, not the numeric PID.
/// Future exec must preserve PID under a reviewed address-space replacement
/// protocol; constructing or mutating this immutable owner is not that protocol.
#[derive(Debug)]
pub struct Context {
    address_space: u64,
    pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub profile_id: &'static str,
    pub address_space: u64,
    pub process_id: u32,
}

impl Context {
    pub fn new(address_space: u64, pid: u32) -> Result<Self> {
        ensure!(
            (1..=MAX_PROCESS_ID).contains(&pid),
            "guest process ID is outside the declared normal userspace profile"
        );
        Ok(Self { address_space, pid })
    }

    pub fn address_space(&self) -> u64 {
        self.address_space
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            profile_id: PROFILE_ID,
            address_space: self.address_space,
            process_id: self.pid,
        }
    }
}

#[cfg(test)]
mod tests;
