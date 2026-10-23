// SPDX-License-Identifier: GPL-2.0-only
//! Owned USB current accounting, following pinned hub.c hub_configure,
//! hub_power_remaining and the USB configuration 2-mA/8-mA units.
//! Budgets are USB-standard protocol contracts, not measured current.
use super::*;

const USB2_UNIT_MA: u16 = 100;
const USB3_UNIT_MA: u16 = 150;
const USB2_PORT_MA: u16 = 500;
const USB3_PORT_MA: u16 = 900;
const ROOT_OVER_CURRENT: u32 = 1 << 3;

fn unit(speed: u8) -> u16 {
    if matches!(speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
        USB3_UNIT_MA
    } else {
        USB2_UNIT_MA
    }
}
fn full(speed: u8) -> u16 {
    if matches!(speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
        USB3_PORT_MA
    } else {
        USB2_PORT_MA
    }
}

#[derive(Clone)]
struct Hub {
    ports: u8,
    controller_ma: u16,
    self_powered: bool,
    /// A bit is reserved BEFORE publishing PORT_POWER, and survives failed or
    /// uncertain ACK. Empty powered ports still reserve an initial unit load.
    powered: u32,
}
#[derive(Clone)]
struct Grant {
    attachment: Attachment,
    maximum_ma: u16,
    reserved_ma: u16,
    configurations: Vec<(u8, u16)>,
    hub: Option<Hub>,
}

pub(super) struct Ledger {
    entries: Vec<Option<Grant>>,
}
impl Ledger {
    pub fn new(slots: usize) -> Self {
        Self {
            entries: vec![None; slots],
        }
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self, slot: u8) -> (u16, u16, u16) {
        let grant = self.grant(slot).unwrap();
        (
            grant.maximum_ma,
            grant.reserved_ma,
            self.draw(slot, 0).unwrap(),
        )
    }
    #[cfg(test)]
    pub(super) fn retained(&self, slot: u8) -> bool {
        self.grant(slot).is_ok()
    }
    fn grant(&self, slot: u8) -> Result<&Grant, BlockError> {
        self.entries
            .get(usize::from(slot))
            .and_then(Option::as_ref)
            .ok_or(BlockError::Unsupported(
                "USB device has no retained current grant",
            ))
    }
    fn grant_mut(&mut self, slot: u8) -> Result<&mut Grant, BlockError> {
        self.entries
            .get_mut(usize::from(slot))
            .and_then(Option::as_mut)
            .ok_or(BlockError::Unsupported(
                "USB device has no retained current grant",
            ))
    }
    fn draw(&self, slot: u8, depth: u8) -> Result<u16, BlockError> {
        if depth > MAX_TIERS {
            return Err(BlockError::Unsupported("cyclic USB current ownership"));
        }
        let owner = self.grant(slot)?;
        let Some(hub) = owner.hub.as_ref().filter(|hub| !hub.self_powered) else {
            return Ok(owner.reserved_ma);
        };
        let mut total = hub.controller_ma;
        for port in 1..=hub.ports {
            if hub.powered & (1 << port) == 0 {
                continue;
            }
            let mut downstream = unit(owner.attachment.speed);
            for (id, child) in self.entries.iter().enumerate() {
                if child
                    .as_ref()
                    .is_some_and(|child| child.attachment.parent == Some((slot, port)))
                {
                    downstream = downstream.max(self.draw(id as u8, depth + 1)?);
                }
            }
            total = total
                .checked_add(downstream)
                .ok_or(BlockError::Unsupported("USB current accounting overflow"))?;
        }
        Ok(total.max(owner.reserved_ma))
    }
    fn check(&self) -> Result<(), BlockError> {
        for (slot, owner) in self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(slot, owner)| owner.as_ref().map(|owner| (slot, owner)))
        {
            if self.draw(slot as u8, 0)? > owner.maximum_ma {
                return Err(BlockError::Unsupported(
                    "USB upstream current budget exhausted",
                ));
            }
        }
        Ok(())
    }
    fn reserve(
        &mut self,
        slot: u8,
        attachment: Attachment,
        root_ma: u16,
    ) -> Result<(), BlockError> {
        if self.entries.iter().flatten().any(|owner| {
            owner.attachment.root_port == attachment.root_port
                && owner.attachment.parent == attachment.parent
        }) {
            return Err(BlockError::Unsupported(
                "USB port still has an unretired current owner",
            ));
        }
        let maximum_ma = if let Some((parent, port)) = attachment.parent {
            let ancestor = self.grant(parent)?;
            if ancestor.attachment.root_port != attachment.root_port
                || ancestor.attachment.tier + 1 != attachment.tier
                || attachment.route
                    != ancestor.attachment.route
                        | u32::from(port.min(MAX_ROUTE_PORT)) << (4 * ancestor.attachment.tier)
            {
                return Err(BlockError::Unsupported(
                    "USB child current grant has a foreign physical parent",
                ));
            }
            let hub = ancestor.hub.as_ref().ok_or(BlockError::Unsupported(
                "USB parent has no configured hub power contract",
            ))?;
            if port == 0 || port > hub.ports || hub.powered & (1 << port) == 0 {
                return Err(BlockError::Unsupported(
                    "USB child port power was not reserved",
                ));
            }
            if hub.self_powered {
                full(attachment.speed)
            } else {
                unit(attachment.speed)
            }
        } else {
            if attachment.tier != 0 || attachment.route != 0 || full(attachment.speed) != root_ma {
                return Err(BlockError::Unsupported(
                    "USB root current grant has a foreign protocol/route",
                ));
            }
            root_ma
        };
        let previous = self
            .entries
            .get_mut(usize::from(slot))
            .ok_or(BlockError::Unsupported("USB current slot out of range"))?;
        if previous.is_some() {
            return Err(BlockError::Unsupported(
                "USB current grant slot already owned",
            ));
        }
        *previous = Some(Grant {
            attachment,
            maximum_ma,
            reserved_ma: unit(attachment.speed),
            configurations: Vec::new(),
            hub: None,
        });
        if let Err(error) = self.check() {
            self.entries[usize::from(slot)] = None;
            return Err(error);
        }
        Ok(())
    }
    fn descriptions(&mut self, slot: u8, configurations: &[Vec<u8>]) -> Result<(), BlockError> {
        let owner = self.grant_mut(slot)?;
        if !owner.configurations.is_empty() {
            return Err(BlockError::Unsupported(
                "USB current descriptors already retained",
            ));
        }
        for config in configurations {
            if config.len() < 9
                || config[0] != 9
                || config[1] != CONFIGURATION_DESCRIPTOR
                || config[5] == 0
            {
                return Err(BlockError::Unsupported(
                    "USB current configuration descriptor",
                ));
            }
            let scale = if owner.attachment.speed >= SUPER_SPEED {
                8
            } else {
                2
            };
            owner
                .configurations
                .push((config[5], u16::from(config[8]) * scale));
        }
        Ok(())
    }
    fn demand(&self, slot: u8, value: u8) -> Result<u16, BlockError> {
        let owner = self.grant(slot)?;
        if value == 0 {
            return Ok(unit(owner.attachment.speed));
        }
        owner
            .configurations
            .iter()
            .find(|(id, _)| *id == value)
            .map(|(_, ma)| *ma)
            .ok_or(BlockError::Unsupported(
                "SET_CONFIGURATION has no retained current descriptor",
            ))
    }
    fn configuration_prepare(&mut self, slot: u8, value: u8) -> Result<u16, BlockError> {
        let demand = self.demand(slot, value)?;
        let old = self.grant(slot)?.reserved_ma;
        self.grant_mut(slot)?.reserved_ma = old.max(demand);
        if let Err(error) = self.check() {
            self.grant_mut(slot)?.reserved_ma = old;
            return Err(error);
        }
        Ok(demand)
    }
    fn configuration_ack(&mut self, slot: u8, demand: u16) -> Result<(), BlockError> {
        self.grant_mut(slot)?.reserved_ma = demand;
        Ok(())
    }
    fn hub(
        &mut self,
        slot: u8,
        ports: u8,
        controller_ma: u16,
        self_powered: bool,
    ) -> Result<(), BlockError> {
        let owner = self.grant_mut(slot)?;
        if ports == 0 || ports > MAX_HUB_PORTS || owner.hub.is_some() {
            return Err(BlockError::Unsupported(
                "USB hub current contract already owned or invalid",
            ));
        }
        if !self_powered && owner.maximum_ma <= unit(owner.attachment.speed) {
            return Err(BlockError::Unsupported(
                "consecutive bus-powered hubs exceed one-unit upstream grant",
            ));
        }
        owner.hub = Some(Hub {
            ports,
            controller_ma,
            self_powered,
            powered: 0,
        });
        if let Err(error) = self.check() {
            self.grant_mut(slot)?.hub = None;
            return Err(error);
        }
        Ok(())
    }
    fn powered_port(&mut self, slot: u8, port: u8) -> Result<(), BlockError> {
        let hub = self
            .grant_mut(slot)?
            .hub
            .as_mut()
            .ok_or(BlockError::Unsupported("USB hub power contract absent"))?;
        if port == 0 || port > hub.ports {
            return Err(BlockError::Unsupported("USB hub power port out of range"));
        }
        let previous = hub.powered;
        hub.powered |= 1 << port;
        if let Err(error) = self.check() {
            self.grant_mut(slot)?.hub.as_mut().unwrap().powered = previous;
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn recovery_power(&self, slot: u8, port: u8) -> Result<(), BlockError> {
        if self.powered_ports(slot)? & (1 << port) == 0 {
            return Err(BlockError::Unsupported(
                "USB recovery port has no current reservation",
            ));
        }
        self.check()
    }
    pub(super) fn powered_ports(&self, slot: u8) -> Result<u32, BlockError> {
        self.grant(slot)?
            .hub
            .as_ref()
            .map(|hub| hub.powered)
            .ok_or(BlockError::Unsupported("USB hub power contract absent"))
    }
    pub(super) fn hub_is_self_powered(&self, slot: u8) -> Result<bool, BlockError> {
        self.grant(slot)?
            .hub
            .as_ref()
            .map(|hub| hub.self_powered)
            .ok_or(BlockError::Unsupported("USB hub power contract absent"))
    }
    pub(super) fn belongs_to(&self, mut slot: u8, ancestor: u8) -> bool {
        for _ in 0..=MAX_TIERS {
            if slot == ancestor {
                return true;
            }
            let Ok(owner) = self.grant(slot) else {
                return false;
            };
            let Some((parent, _)) = owner.attachment.parent else {
                return false;
            };
            slot = parent;
        }
        false
    }
    pub(super) fn port_owner(&self, parent: Option<(u8, u8)>, root: u8) -> Option<u8> {
        self.entries.iter().enumerate().find_map(|(slot, grant)| {
            grant
                .as_ref()
                .filter(|grant| {
                    grant.attachment.parent == parent && grant.attachment.root_port == root
                })
                .map(|_| slot as u8)
        })
    }
    pub(super) fn hub_ports(&self, slot: u8) -> Option<u8> {
        self.grant(slot).ok()?.hub.as_ref().map(|hub| hub.ports)
    }
    fn reset_port(&mut self, parent: Option<(u8, u8)>, root: u8) {
        let roots: Vec<u8> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(slot, grant)| {
                grant
                    .as_ref()
                    .filter(|grant| {
                        grant.attachment.parent == parent && grant.attachment.root_port == root
                    })
                    .map(|_| slot as u8)
            })
            .collect();
        let retired: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(slot, _)| {
                roots
                    .iter()
                    .any(|ancestor| self.belongs_to(slot as u8, *ancestor))
                    .then_some(slot)
            })
            .collect();
        for slot in retired {
            self.entries[slot] = None;
        }
    }
}

impl Controller {
    pub(super) fn root_current(&mut self, port: u8, speed: u8) -> Result<u16, BlockError> {
        let major = self
            .port_major
            .get(usize::from(port.wrapping_sub(1)))
            .copied();
        let ma = match (major, speed) {
            (Some(2), LOW_SPEED | FULL_SPEED | HIGH_SPEED) => USB2_PORT_MA,
            (Some(3), SUPER_SPEED | SUPER_SPEED_PLUS) => USB3_PORT_MA,
            _ => {
                self.quarantine_root_current(port);
                return Err(BlockError::Unsupported(
                    "USB root current needs its actual supported protocol",
                ));
            }
        };
        let status = self.registers.read32(self.port_offset(port));
        if status & (PP | CCS) != PP | CCS || status & ROOT_OVER_CURRENT != 0 {
            self.quarantine_root_current(port);
            return Err(BlockError::Unsupported(
                "USB root port power absent or over-current",
            ));
        }
        let wire_speed = ((status >> PORT_SPEED_SHIFT) & PORT_SPEED_FIELD) as u8;
        if !matches!(
            (major, wire_speed),
            (Some(2), LOW_SPEED | FULL_SPEED | HIGH_SPEED)
                | (Some(3), SUPER_SPEED | SUPER_SPEED_PLUS)
        ) {
            self.quarantine_root_current(port);
            return Err(BlockError::Unsupported(
                "USB root current protocol does not match actual port speed",
            ));
        }
        Ok(ma)
    }
    fn quarantine_root_current(&mut self, port: u8) {
        for state in self.slots.iter_mut().flatten() {
            if state.attachment.root_port == port {
                state.retiring = true;
            }
        }
    }
    pub(super) fn reserve_current(
        &mut self,
        slot: u8,
        attachment: Attachment,
    ) -> Result<(), BlockError> {
        let root_speed = if self
            .port_major
            .get(usize::from(attachment.root_port.wrapping_sub(1)))
            == Some(&3)
        {
            SUPER_SPEED
        } else {
            HIGH_SPEED
        };
        let root_ma = self.root_current(attachment.root_port, root_speed)?;
        if let Some((parent, _)) = attachment.parent {
            self.live_slot(parent)?;
        }
        self.power.reserve(slot, attachment, root_ma)
    }
    pub(super) fn current_descriptions(
        &mut self,
        slot: u8,
        configurations: &[Vec<u8>],
    ) -> Result<(), BlockError> {
        self.power.descriptions(slot, configurations)
    }
    pub(super) fn prepare_current_configuration(
        &mut self,
        slot: u8,
        value: u8,
    ) -> Result<u16, BlockError> {
        // A configured hub owns its powered ports and descendant contracts.
        // Endpoint teardown alone cannot authorize replacing that authority.
        // Reconfiguration needs explicit subtree retirement and a fresh hub
        // owner; the cached same-value helper remains a harmless no-op.
        if self.power.grant(slot)?.hub.is_some() {
            return Err(BlockError::Unsupported(
                "USB hub configuration requires complete subtree retirement",
            ));
        }
        self.power.demand(slot, value)?;
        self.observe_current_ancestors(slot, false)?;
        self.power.configuration_prepare(slot, value)
    }
    pub(super) fn observe_current_ancestors(
        &mut self,
        slot: u8,
        include_hub: bool,
    ) -> Result<(), BlockError> {
        let attachment = self.power.grant(slot)?.attachment;
        let root_speed = if self
            .port_major
            .get(usize::from(attachment.root_port.wrapping_sub(1)))
            == Some(&3)
        {
            SUPER_SPEED
        } else {
            HIGH_SPEED
        };
        self.root_current(attachment.root_port, root_speed)?;
        if include_hub {
            self.observe_hub_current(slot)?;
        }
        let mut parent = attachment.parent;
        while let Some((slot, _)) = parent {
            let ancestor = self.power.grant(slot)?.attachment;
            // Raw GET_STATUS does not recurse into SET_CONFIGURATION accounting.
            self.observe_hub_current(slot)?;
            parent = ancestor.parent;
        }
        Ok(())
    }
    pub(super) fn prepare_port_current(&mut self, slot: u8, port: u8) -> Result<(), BlockError> {
        // Reject pure budget/ownership failures before touching MMIO or DMA.
        // Reservation is conservative across any later uncertain health/ACK.
        self.power.powered_port(slot, port)?;
        self.observe_current_ancestors(slot, true)
    }
    pub(super) fn ack_current_configuration(
        &mut self,
        slot: u8,
        demand: u16,
    ) -> Result<(), BlockError> {
        self.power.configuration_ack(slot, demand)
    }
    pub(super) fn install_hub_current(
        &mut self,
        slot: u8,
        ports: u8,
        controller_ma: u16,
        self_powered: bool,
    ) -> Result<(), BlockError> {
        self.power.hub(slot, ports, controller_ma, self_powered)
    }
    pub(super) fn reserve_port_current(&mut self, slot: u8, port: u8) -> Result<(), BlockError> {
        self.power.powered_port(slot, port)
    }
    pub(super) fn observe_hub_current(&mut self, slot: u8) -> Result<(), BlockError> {
        let result = (|| {
            let bytes = self.control(slot, setup(0x80, GET_STATUS, 0, 0, 2), &[])?;
            if bytes.len() != 2 || (bytes[0] & 1 != 0) != self.power.hub_is_self_powered(slot)? {
                return Err(BlockError::Unsupported("USB hub power source changed"));
            }
            for _ in 0..2 {
                let bytes = self.control(slot, setup(0xa0, GET_STATUS, 0, 0, 4), &[])?;
                if bytes.len() != 4 {
                    return Err(BlockError::Unsupported("short USB hub power status"));
                }
                let status = u16::from_le_bytes([bytes[0], bytes[1]]);
                let change = u16::from_le_bytes([bytes[2], bytes[3]]);
                if status != 0 || change & !1 != 0 {
                    return Err(BlockError::Unsupported(
                        "USB hub power/over-current authority lost",
                    ));
                }
                if change == 0 {
                    return Ok(());
                }
                self.control(slot, setup(0x20, CLEAR_FEATURE, 0, 0, 0), &[])?;
            }
            Err(BlockError::Unsupported(
                "USB hub local power change did not clear",
            ))
        })();
        if result.is_err() {
            self.quarantine_current_subtree(slot);
        }
        result
    }
    pub(super) fn quarantine_current_subtree(&mut self, ancestor: u8) {
        for slot in 1..self.slots.len() {
            if self.power.belongs_to(slot as u8, ancestor)
                && let Some(state) = self.slots[slot].as_mut()
            {
                state.retiring = true;
            }
        }
    }
    pub(super) fn current_port_reset(&mut self, parent: Option<(u8, u8)>, root: u8) {
        let owners: Vec<u8> = self
            .power
            .entries
            .iter()
            .enumerate()
            .filter_map(|(slot, grant)| {
                grant
                    .as_ref()
                    .filter(|grant| {
                        grant.attachment.parent == parent && grant.attachment.root_port == root
                    })
                    .map(|_| slot as u8)
            })
            .collect();
        for slot in owners {
            self.quarantine_current_subtree(slot);
        }
        self.power.reset_port(parent, root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturated_route_ports_have_separate_current_owners_and_physical_reset_subtrees() {
        let root = Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed: HIGH_SPEED,
            translator: None,
            parent: None,
        };
        let mut ledger = Ledger::new(8);
        ledger.reserve(1, root, 500).unwrap();
        ledger.hub(1, 31, 0, true).unwrap();
        for (slot, port) in [(2, 15), (3, 16)] {
            ledger.powered_port(1, port).unwrap();
            ledger
                .reserve(
                    slot,
                    Attachment {
                        route: 15,
                        tier: 1,
                        parent: Some((1, port)),
                        ..root
                    },
                    500,
                )
                .unwrap();
        }
        assert!(
            ledger
                .reserve(
                    4,
                    Attachment {
                        route: 15,
                        tier: 1,
                        parent: Some((1, 16)),
                        ..root
                    },
                    500
                )
                .is_err()
        );
        ledger.hub(2, 1, 0, true).unwrap();
        ledger.powered_port(2, 1).unwrap();
        ledger
            .reserve(
                4,
                Attachment {
                    route: 0x1f,
                    tier: 2,
                    parent: Some((2, 1)),
                    ..root
                },
                500,
            )
            .unwrap();
        ledger.reset_port(Some((1, 15)), 1);
        assert!(!ledger.retained(2));
        assert!(!ledger.retained(4));
        assert!(ledger.retained(1));
        assert!(ledger.retained(3));
        ledger
            .reserve(
                5,
                Attachment {
                    route: 15,
                    tier: 1,
                    parent: Some((1, 15)),
                    ..root
                },
                500,
            )
            .unwrap();
    }
}
