// SPDX-License-Identifier: GPL-2.0-only
//! Native count-bearing SMBus transport for the donor's ordinary format.
//! The platform supplies an exclusively owned powered peripheral, physical IRQ
//! and SMBus host. No power-rail or reset operation is inferred from a no-op.
use super::{Error, ErrorKind, Frame, Interrupt, Packet, Recovery, State, report};
use crate::bus::{
    i2c::Timer,
    smbus::{Address, Block, Bus, Transaction},
};
mod device;
#[cfg(test)]
mod tests;

/// Actual SMBus query responses. There are no I2C descriptors on this transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queries {
    pub hello: Block,
    pub product: Block,
    pub sample: Block,
    pub firmware: Block,
    pub checksum: Block,
    pub iap_version: Block,
    pub iap_control: Block,
    pub range: Block,
    pub traces: Block,
    pub resolution: Block,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub queries: Queries,
    pub product_id: u16,
    pub ic_type: u8,
    pub sample_version: u8,
    pub clickpad: bool,
    pub firmware_version: u8,
    pub firmware_checksum: u16,
    pub iap_version: u8,
    pub maximum: (u16, u16),
    pub traces: (u8, u8),
    pub raw_resolution: (u8, u8),
    pub resolution_per_mm: (u32, u32),
}
impl Capabilities {
    fn geometry(&self) -> report::Geometry {
        report::Geometry {
            maximum: self.maximum,
            traces: self.traces,
            pressure_adjustment: 25,
        }
    }
    fn same_identity(&self, other: &Self) -> bool {
        // Unknown trailing query bytes are retained but are not an invented
        // identity contract. Compare the actual source-declared fields.
        self.product_id == other.product_id
            && self.ic_type == other.ic_type
            && self.sample_version == other.sample_version
            && self.clickpad == other.clickpad
            && self.firmware_version == other.firmware_version
            && self.firmware_checksum == other.firmware_checksum
            && self.iap_version == other.iap_version
            && self.maximum == other.maximum
            && self.traces == other.traces
            && self.raw_resolution == other.raw_resolution
    }
}
pub struct Device<B, I, T> {
    bus: B,
    interrupt: I,
    timer: T,
    address: Address,
    state: State,
    capabilities: Option<Capabilities>,
}
impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    pub fn new(bus: B, interrupt: I, timer: T, address: Address) -> Self {
        Self {
            bus,
            interrupt,
            timer,
            address,
            state: State::Fresh,
            capabilities: None,
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// Last completely queried metadata; input is available only in Ready.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }
}
