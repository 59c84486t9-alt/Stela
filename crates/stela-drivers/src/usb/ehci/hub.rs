//! Hub ports below the roots, driven as Linux hub.c drives them: port status,
//! power and change acknowledgements, and the port reset that leaves a new
//! device at address 0. The controller owns these requests, since a hub
//! port reset or enable change moves the bus's address-0 owner and retires
//! the devices behind that port.
use super::*;

const GET_STATUS: u8 = 0;
const CLEAR_FEATURE: u8 = 1;
const SET_FEATURE: u8 = 3;
/// Class request to a hub port, host to device and device to host.
const TO_PORT: u8 = 0x23;
const FROM_PORT: u8 = 0xa3;
/// wPortStatus bits (USB 2.0 table 11-21).
pub const PORT_CONNECTION: u16 = 1;
pub const PORT_ENABLE: u16 = 1 << 1;
pub const PORT_OVER_CURRENT: u16 = 1 << 3;
pub const PORT_RESET: u16 = 1 << 4;
pub const PORT_POWER: u16 = 1 << 8;
pub const PORT_LOW_SPEED: u16 = 1 << 9;
pub const PORT_HIGH_SPEED: u16 = 1 << 10;
/// Port feature selectors (USB 2.0 table 11-17).
const FEATURE_ENABLE: u8 = 1;
const FEATURE_RESET: u8 = 4;
const FEATURE_POWER: u8 = 8;
pub const C_PORT_CONNECTION: u8 = 16;
pub const C_PORT_RESET: u8 = 20;
/// Linux `hub_port_reset`: poll every 10 ms, for at most 500 ms.
const RESET_POLL_US: u64 = 10_000;
const RESET_TIMEOUT_US: u64 = 500_000;
/// TRSTRCY plus Linux's slop after a completed port reset.
const RESET_RECOVERY_US: u64 = 50_000;

/// A hub port's wPortStatus and wPortChange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortStatus {
    pub status: u16,
    pub change: u16,
}

impl Controller {
    /// The configured hub `hub` and a valid port number on it.
    fn hub_index(&self, hub: &DeviceId, port: u8) -> Result<usize, Error> {
        let index = self.identity(hub)?;
        let device = self.ports[index].as_ref().expect("validated");
        if device.address == 0 || device.configuration_value == 0 || port == 0 {
            return Err(Error::Invalid);
        }
        Ok(index)
    }

    /// GET_STATUS of `port` on `hub`.
    pub fn hub_port_status(&mut self, hub: &DeviceId, port: u8) -> Result<PortStatus, Error> {
        self.hub_index(hub, port)?;
        let bytes =
            self.control_internal(hub, [FROM_PORT, GET_STATUS, 0, 0, port, 0, 4, 0], &[], 4)?;
        let [status0, status1, change0, change1] = bytes[..] else {
            return Err(Error::Invalid);
        };
        Ok(PortStatus {
            status: u16::from_le_bytes([status0, status1]),
            change: u16::from_le_bytes([change0, change1]),
        })
    }

    /// SET_FEATURE(PORT_POWER) on `port` of `hub`.
    pub fn power_hub_port(&mut self, hub: &DeviceId, port: u8) -> Result<(), Error> {
        self.hub_index(hub, port)?;
        self.control_internal(
            hub,
            [TO_PORT, SET_FEATURE, FEATURE_POWER, 0, port, 0, 0, 0],
            &[],
            0,
        )
        .map(drop)
    }

    /// Acknowledge one change of `port` on `hub`: a C_PORT_* selector.
    pub fn clear_hub_port_change(
        &mut self,
        hub: &DeviceId,
        port: u8,
        feature: u8,
    ) -> Result<(), Error> {
        self.hub_index(hub, port)?;
        if !(C_PORT_CONNECTION..=C_PORT_RESET).contains(&feature) {
            return Err(Error::Invalid);
        }
        self.control_internal(
            hub,
            [TO_PORT, CLEAR_FEATURE, feature, 0, port, 0, 0, 0],
            &[],
            0,
        )
        .map(drop)
    }

    /// Drop every table entry whose hub chain no longer leads to its root,
    /// freeing the addresses of devices a reset or disconnect took away.
    fn prune(&mut self) {
        for index in self.roots..self.ports.len() {
            if self.ports[index].is_some() && !self.attached(index) {
                self.ports[index] = None;
                if self.default_port == Some((index + 1) as u8) {
                    self.default_port = None;
                }
            }
        }
    }

    /// The entry of the device on `port` of the hub at `hub`.
    fn child_at(&self, hub: usize, port: u8) -> Option<usize> {
        (self.roots..self.ports.len()).find(|index| {
            self.ports[*index]
                .as_ref()
                .and_then(|device| device.parent)
                .is_some_and(|parent| parent.index == hub && parent.port == port)
        })
    }

    /// Hub tiers between the device at `index` and its root port.
    fn tier(&self, mut index: usize) -> usize {
        let mut tier = 0;
        while let Some(parent) = self.ports[index].as_ref().and_then(|device| device.parent) {
            tier += 1;
            index = parent.index;
        }
        tier
    }

    /// Linux `hub_port_reset` of `port` on `hub`, then the new device at
    /// address 0, ready for SET_ADDRESS. The device the port held before and
    /// everything behind it retire first. None when nothing is connected
    /// after the reset. A reset that does not finish disables the port; a
    /// port that cannot be disabled keeps the address-0 reservation and
    /// fails the controller, as a root reset does.
    pub fn reset_hub_port(&mut self, hub: &DeviceId, port: u8) -> Result<Option<DeviceId>, Error> {
        let index = self.hub_index(hub, port)?;
        if self.pending.is_some() || self.default_port.is_some() {
            return Err(Error::Busy);
        }
        if self.tier(index) >= MAX_TIERS {
            return Err(Error::Unsupported("USB hub tier beyond the fifth"));
        }
        let slot = (self.roots..self.ports.len())
            .find(|slot| self.ports[*slot].is_none())
            .ok_or(Error::Exhausted)?;
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.next_generation = generation;
        if let Some(old) = self.child_at(index, port) {
            self.ports[old] = None;
            self.prune();
        }
        let hub_device = self.ports[index].as_ref().expect("validated");
        let parent = Parent {
            index,
            generation: hub_device.generation,
            port,
        };
        let (hub_address, hub_speed, hub_tt, root_port) = (
            hub_device.address,
            hub_device.speed,
            hub_device.tt,
            hub_device.root_port,
        );
        // Hold address 0 from the reset on: a failed reset can leave the
        // device answering there.
        self.default_port = Some((slot + 1) as u8);
        let reset = (|| {
            self.control_internal(
                hub,
                [TO_PORT, SET_FEATURE, FEATURE_RESET, 0, port, 0, 0, 0],
                &[],
                0,
            )?;
            let mut waited = 0;
            let status = loop {
                self.delay_minimum(RESET_POLL_US)?;
                waited += RESET_POLL_US;
                let status = self.hub_port_status(hub, port)?;
                if status.status & PORT_RESET == 0 && status.change & (1 << 4) != 0 {
                    break status;
                }
                if waited >= RESET_TIMEOUT_US {
                    return Err(Error::Timeout);
                }
            };
            self.clear_hub_port_change(hub, port, C_PORT_RESET)?;
            Ok(status.status)
        })();
        let status = match reset {
            Ok(status) if status & PORT_CONNECTION == 0 => {
                self.default_port = None;
                return Ok(None);
            }
            Ok(status) if status & PORT_ENABLE != 0 => status,
            Ok(status) => {
                self.default_port = None;
                return Err(Error::Device(u32::from(status)));
            }
            Err(error) => {
                self.disable_hub_port(hub, port)?;
                return Err(error);
            }
        };
        let speed = if status & PORT_HIGH_SPEED != 0 {
            Speed::High
        } else if status & PORT_LOW_SPEED != 0 {
            Speed::Low
        } else {
            Speed::Full
        };
        // Full- and low-speed traffic splits at the nearest high-speed hub.
        let tt = match (speed, hub_speed) {
            (Speed::High, _) => None,
            (_, Speed::High) => Some((hub_address, port)),
            _ => hub_tt,
        };
        let recovered = self.delay_minimum(RESET_RECOVERY_US);
        if let Err(error) = recovered {
            self.disable_hub_port(hub, port)?;
            return Err(error);
        }
        self.ports[slot] = Some(Device {
            generation,
            address: 0,
            root_port,
            parent: Some(parent),
            speed,
            tt,
            control_packet: if speed == Speed::Low { 8 } else { 64 },
            configuration: 0,
            configuration_value: 0,
            endpoints: [None; 32],
            suspended: false,
        });
        Ok(Some(DeviceId {
            owner: self.owner.clone(),
            generation,
            port: root_port,
            slot: (slot + 1) as u8,
        }))
    }

    /// ClearPortFeature(PORT_ENABLE) of `port` on `hub`, retiring the device
    /// there and everything behind it. A disabled port no longer passes
    /// traffic, so the device's address is free again. A failed request
    /// keeps every reservation and fails the controller.
    pub fn disable_hub_port(&mut self, hub: &DeviceId, port: u8) -> Result<(), Error> {
        let index = self.hub_index(hub, port)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let disabled = self.control_internal(
            hub,
            [TO_PORT, CLEAR_FEATURE, FEATURE_ENABLE, 0, port, 0, 0, 0],
            &[],
            0,
        );
        if let Err(error) = disabled {
            return self.fail(error);
        }
        if let Some(child) = self.child_at(index, port) {
            self.ports[child] = None;
            if self.default_port == Some((child + 1) as u8) {
                self.default_port = None;
            }
        } else if self
            .default_port
            .is_some_and(|owner| self.ports[usize::from(owner) - 1].is_none())
        {
            // The address-0 owner of a reset that never minted a device.
            self.default_port = None;
        }
        self.prune();
        Ok(())
    }

    /// The hub and port a device behind a hub hangs from, for its reset.
    pub fn hub_port_of(&self, id: &DeviceId) -> Result<Option<(DeviceId, u8)>, Error> {
        let index = self.identity(id)?;
        let Some(parent) = self.ports[index].as_ref().expect("validated").parent else {
            return Ok(None);
        };
        let hub = self.ports[parent.index].as_ref().ok_or(Error::Stale)?;
        let root_port = hub.root_port;
        Ok(Some((
            DeviceId {
                owner: self.owner.clone(),
                generation: parent.generation,
                port: root_port,
                slot: (parent.index + 1) as u8,
            },
            parent.port,
        )))
    }

    /// The speed of the device `id`.
    pub fn speed(&self, id: &DeviceId) -> Result<Speed, Error> {
        let index = self.identity(id)?;
        Ok(self.ports[index].as_ref().expect("validated").speed)
    }

    /// Set EP0's maximum packet size from the first eight bytes of the
    /// device descriptor, as Linux `hub_port_init` does before reading the
    /// rest. A high-speed device's is always 64.
    pub fn set_control_packet(&mut self, id: &DeviceId, packet: u8) -> Result<(), Error> {
        let index = self.identity(id)?;
        let device = self.ports[index].as_mut().expect("validated");
        let valid = match device.speed {
            Speed::High => packet == 64,
            Speed::Full => matches!(packet, 8 | 16 | 32 | 64),
            Speed::Low => packet == 8,
        };
        if !valid {
            return Err(Error::Invalid);
        }
        device.control_packet = u16::from(packet);
        Ok(())
    }
}
