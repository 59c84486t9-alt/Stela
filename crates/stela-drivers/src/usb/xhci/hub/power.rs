// SPDX-License-Identifier: GPL-2.0-only
//! Selective external-port suspend/resume, following pinned hub.c
//! usb_port_suspend/usb_port_resume. The topology owner gates client access and
//! controls child wake features; this layer proves the port transition.
use super::*;

const USB2_SUSPEND: u16 = 2;
const SS_LINK_STATE: u16 = 5;
const LINK_MASK: u16 = 15 << 5;
const U3: u16 = 3 << 5;
const SUSPEND_SETTLE_US: u64 = 10_000;
const RESUME_SIGNAL_US: u64 = 40_000;
const RESUME_RECOVERY_US: u64 = 10_000;
const LINK_TRANSITION_US: u64 = 100_000;

#[derive(Clone, Copy)]
struct State {
    status: u16,
    change: u16,
}
impl State {
    fn suspended(self, ss: bool) -> bool {
        if ss {
            self.status & LINK_MASK == U3
        } else {
            self.status & (1 << 2) != 0
        }
    }
    fn resumed(self, ss: bool) -> bool {
        if ss {
            self.status & LINK_MASK <= 2 << 5
        } else {
            !self.suspended(false)
        }
    }
    fn session(self, ss: bool) -> Result<(), BlockError> {
        let power = if ss { 1 << 9 } else { 1 << 8 };
        let allowed_status = if ss { 0x1ffb } else { 0x1f3f };
        let allowed_change = if ss { 1 << 6 } else { 1 << 2 };
        if self.status & !allowed_status != 0
            || self.status & (power | 3 | 8 | 16) != power | 3
            || self.change & !allowed_change != 0
            || !ss && self.status & ((1 << 5) | (1 << 11)) != 0
            || ss && (self.status & (7 << 10) != 0 || self.status & LINK_MASK > 10 << 5)
        {
            return Err(BlockError::Unsupported(
                "USB hub suspend power session lost or changed",
            ));
        }
        Ok(())
    }
}

fn link_request(port: u8, ss: bool, suspend: bool) -> [u8; 8] {
    if ss {
        // hub_set_port_link_state accepts the already shifted wPortStatus
        // link field: (U3 << 3) occupies the high byte of wIndex.
        setup(
            0x23,
            SET_FEATURE,
            SS_LINK_STATE,
            u16::from(port) | if suspend { U3 << 3 } else { 0 },
            0,
        )
    } else {
        setup(
            0x23,
            if suspend { SET_FEATURE } else { CLEAR_FEATURE },
            USB2_SUSPEND,
            u16::from(port),
            0,
        )
    }
}

impl Controller {
    fn hub_suspend_authority(&mut self, slot: u8, port: u8) -> Result<bool, BlockError> {
        self.live_slot(slot)?;
        let attachment = self.slot(slot)?.attachment;
        self.validate_current_graph(attachment.root_port)?;
        let ports = self.power.hub_ports(slot).ok_or(BlockError::Unsupported(
            "USB suspend requires an owned external hub",
        ))?;
        if port == 0 || port > ports || self.power.powered_ports(slot)? & (1 << port) == 0 {
            return Err(BlockError::Unsupported(
                "USB suspend requires a reserved powered port",
            ));
        }
        let child = self
            .power
            .port_owner(Some((slot, port)), attachment.root_port)
            .ok_or(BlockError::Unsupported(
                "USB suspend port has no retained child",
            ))?;
        self.live_slot(child)?;
        // Read output endpoint contexts, not a caller assertion that a
        // class stopped. EP0, streams and a nested hub's interrupt ring all
        // participate. No transition is published on uncertain retirement.
        fence(Ordering::Acquire);
        for (id, state) in self.slots.iter().enumerate() {
            if !self.power.belongs_to(id as u8, child) {
                continue;
            }
            let state = state
                .as_ref()
                .ok_or(BlockError::Unsupported("USB suspend subtree slot absent"))?;
            if state.retiring || self.slot_ownership[id] != reset::Ownership::Enabled {
                return Err(BlockError::Unsupported("USB suspend subtree is retiring"));
            }
            for (dci, endpoint) in state.endpoints.iter().enumerate() {
                let Some(endpoint) = endpoint else {
                    continue;
                };
                if !endpoint.enabled
                    || endpoint.poisoned
                    || endpoint.in_flight != 0
                    || state._output.coherent_u32(dci * self.context())? & 7 != ENDPOINT_STOPPED
                {
                    return Err(BlockError::Unsupported(
                        "USB suspend requires acknowledged subtree endpoint stops",
                    ));
                }
            }
        }
        self.observe_current_ancestors(slot, true)?;
        Ok(matches!(attachment.speed, SUPER_SPEED | SUPER_SPEED_PLUS))
    }

    fn suspend_port_state(&mut self, slot: u8, port: u8, ss: bool) -> Result<State, BlockError> {
        let (status, change) = self.hub_port_status_owned(slot, port)?;
        let state = State { status, change };
        state.session(ss)?;
        Ok(state)
    }

    fn clear_suspend_change(
        &mut self,
        slot: u8,
        port: u8,
        ss: bool,
        state: State,
    ) -> Result<(), BlockError> {
        let (bit, selector) = if ss { (1 << 6, 25) } else { (1 << 2, 18) };
        if state.change & bit != 0 {
            self.control_owned(
                slot,
                setup(0x23, CLEAR_FEATURE, selector, u16::from(port), 0),
                &[],
            )?;
        }
        Ok(())
    }

    /// Caller owns topology serialization, blocks every descendant's public
    /// submissions and has stopped all descendant endpoints. Current contracts
    /// remain reserved across suspend and any uncertain request completion.
    #[cfg(test)]
    pub(in super::super) fn suspend_hub_port(
        &mut self,
        id: impl DeviceRef,
        port: u8,
    ) -> Result<(), BlockError> {
        let slot = id.current_slot(self)?;
        let id = self.device_id(slot)?;
        self.suspend_hub_port_for(id, port)
    }

    pub(in super::super) fn suspend_hub_port_for(
        &mut self,
        id: SlotId,
        port: u8,
    ) -> Result<(), BlockError> {
        let slot = self.validate_topology_id(id)?;
        self.suspend_hub_port_owned(slot, port)
    }

    fn suspend_hub_port_owned(&mut self, slot: u8, port: u8) -> Result<(), BlockError> {
        let ss = self.hub_suspend_authority(slot, port)?;
        let before = self.suspend_port_state(slot, port, ss)?;
        self.clear_suspend_change(slot, port, ss, before)?;
        if !before.suspended(ss) {
            if ss && before.status & LINK_MASK > 2 << 5 {
                return Err(BlockError::Unsupported(
                    "USB hub link is not active before suspend",
                ));
            }
            self.control_owned(slot, link_request(port, ss, true), &[])?;
        }
        self.clock.delay(SUSPEND_SETTLE_US);
        let deadline = self.clock.deadline(LINK_TRANSITION_US);
        loop {
            let state = self.suspend_port_state(slot, port, ss)?;
            if state.suspended(ss) {
                self.observe_current_ancestors(slot, true)?;
                return Ok(());
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            self.clock.delay(1000);
        }
    }

    /// Resume only the power session. A connection/reset/power change
    /// remains visible to the topology owner and requires normal fresh binding.
    #[cfg(test)]
    pub(in super::super) fn resume_hub_port(
        &mut self,
        id: impl DeviceRef,
        port: u8,
    ) -> Result<(), BlockError> {
        let slot = id.current_slot(self)?;
        let id = self.device_id(slot)?;
        self.resume_hub_port_for(id, port)
    }

    pub(in super::super) fn resume_hub_port_for(
        &mut self,
        id: SlotId,
        port: u8,
    ) -> Result<(), BlockError> {
        let slot = self.validate_topology_id(id)?;
        self.resume_hub_port_owned(slot, port)
    }

    fn resume_hub_port_owned(&mut self, slot: u8, port: u8) -> Result<(), BlockError> {
        let ss = self.hub_suspend_authority(slot, port)?;
        let before = self.suspend_port_state(slot, port, ss)?;
        let speed = before.status & (HUB_PORT_LOW_SPEED | HUB_PORT_HIGH_SPEED);
        if !before.resumed(ss) {
            if ss && !before.suspended(true) {
                return Err(BlockError::Unsupported(
                    "USB hub link is not suspended before resume",
                ));
            }
            self.control_owned(slot, link_request(port, ss, false), &[])?;
            self.clock.delay(RESUME_SIGNAL_US);
        }
        let deadline = self.clock.deadline(LINK_TRANSITION_US);
        loop {
            let state = self.suspend_port_state(slot, port, ss)?;
            if !ss && state.status & (HUB_PORT_LOW_SPEED | HUB_PORT_HIGH_SPEED) != speed {
                return Err(BlockError::Unsupported(
                    "USB2 hub speed changed during resume",
                ));
            }
            if state.resumed(ss) {
                self.clear_suspend_change(slot, port, ss, state)?;
                self.clock.delay(RESUME_RECOVERY_US);
                let final_state = self.suspend_port_state(slot, port, ss)?;
                if !final_state.resumed(ss)
                    || final_state.change != 0
                    || !ss
                        && final_state.status & (HUB_PORT_LOW_SPEED | HUB_PORT_HIGH_SPEED) != speed
                {
                    return Err(BlockError::Unsupported(
                        "USB hub resume did not remain stable",
                    ));
                }
                self.observe_current_ancestors(slot, true)?;
                return Ok(());
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            self.clock.delay(1000);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{model::*, tests::controller},
        *,
    };
    use crate::bus::dma::TestRegion;
    use alloc::collections::BTreeMap;

    fn stop_subtree(c: &mut Controller, child: u8) {
        let slots: Vec<_> = (1..c.slots.len())
            .filter(|slot| c.power.belongs_to(*slot as u8, child))
            .map(|slot| slot as u8)
            .collect();
        for slot in slots {
            for dci in 1..32 {
                if c.slots[usize::from(slot)].as_ref().unwrap().endpoints[dci].is_some() {
                    c.cancel(slot, dci as u8).unwrap();
                }
            }
        }
    }

    #[test]
    fn external_hub_suspend_resume_observes_link_and_keeps_identity_current() {
        for speed in [HIGH_SPEED, SUPER_SPEED] {
            for context in [32, 64] {
                let nodes = BTreeMap::from([(0, Node::hub(speed, 1)), (1, Node::leaf(speed))]);
                let mut dma = TestRegion::new(256 * 1024 * 8);
                let (mut c, model) = controller(&mut dma, context, nodes);
                let mut failures = Vec::new();
                let devices = c.enumerate(&mut dma, &mut failures);
                assert!(failures.is_empty(), "{failures:?}");
                assert_eq!(devices.len(), 2);
                let grant = c.power.snapshot(2);
                let before = model.borrow().requests.len();
                assert!(c.suspend_hub_port(1, 1).is_err());
                assert_eq!(
                    model.borrow().requests.len(),
                    before,
                    "no request before stop ACK"
                );
                stop_subtree(&mut c, 2);
                let ss = speed == SUPER_SPEED;
                c.suspend_hub_port(1, 1).unwrap();
                let status = model.borrow().nodes[&0].ports.as_ref().unwrap()[0].status;
                assert!(State { status, change: 0 }.suspended(ss));
                c.resume_hub_port(1, 1).unwrap();
                assert_eq!(c.power.snapshot(2), grant);
                assert_eq!(c.slot_ownership[2], reset::Ownership::Enabled);
                assert!(c.live_slot(2).is_ok());
                let requests = &model.borrow().requests;
                assert!(
                    requests
                        .iter()
                        .any(|(_, _, q)| *q == link_request(1, ss, true))
                );
                assert!(
                    requests
                        .iter()
                        .any(|(_, _, q)| *q == link_request(1, ss, false))
                );
                assert!(!requests[before..].iter().any(|(_, _, q)| q[0] == 0x23
                    && q[1] == SET_FEATURE
                    && [PORT_RESET, PORT_POWER, 28].contains(&u16::from_le_bytes([q[2], q[3]]))));
            }
        }
    }

    #[test]
    fn external_hub_suspend_resume_rejects_missing_link_effect_and_changed_power_session() {
        for speed in [HIGH_SPEED, SUPER_SPEED] {
            for fault in [
                Fault::SuspendIgnored,
                Fault::ResumeIgnored,
                Fault::Disconnect,
                Fault::PowerAbsent,
                Fault::ConnectionChange,
                Fault::OverCurrentChange,
            ] {
                let nodes = BTreeMap::from([(0, Node::hub(speed, 1)), (1, Node::leaf(speed))]);
                let mut dma = TestRegion::new(256 * 1024 * 8);
                let (mut c, model) = controller(&mut dma, 64, nodes);
                let mut failures = Vec::new();
                c.enumerate(&mut dma, &mut failures);
                assert!(failures.is_empty(), "{failures:?}");
                stop_subtree(&mut c, 2);
                let grant = c.power.snapshot(2);
                if fault != Fault::SuspendIgnored {
                    c.suspend_hub_port(1, 1).unwrap();
                }
                {
                    let mut hardware = model.borrow_mut();
                    let port = &mut hardware.nodes.get_mut(&0).unwrap().ports.as_mut().unwrap()[0];
                    port.fault = fault;
                    match fault {
                        Fault::Disconnect => port.status &= !1,
                        Fault::PowerAbsent => {
                            port.status &= !(if speed == SUPER_SPEED { 1 << 9 } else { 1 << 8 })
                        }
                        Fault::ConnectionChange => port.change |= 1,
                        Fault::OverCurrentChange => port.change |= 8,
                        _ => {}
                    }
                }
                let result = if fault == Fault::SuspendIgnored {
                    c.suspend_hub_port(1, 1)
                } else {
                    c.resume_hub_port(1, 1)
                };
                assert!(result.is_err(), "{speed} {fault:?}");
                assert_eq!(c.power.snapshot(2), grant);
                assert_eq!(c.slot_ownership[2], reset::Ownership::Enabled);
            }
        }
    }

    #[test]
    fn external_hub_remote_resume_clears_only_observed_suspend_change() {
        for speed in [HIGH_SPEED, SUPER_SPEED] {
            let nodes = BTreeMap::from([(0, Node::hub(speed, 1)), (1, Node::leaf(speed))]);
            let mut dma = TestRegion::new(256 * 1024 * 8);
            let (mut c, model) = controller(&mut dma, 32, nodes);
            let mut failures = Vec::new();
            c.enumerate(&mut dma, &mut failures);
            assert!(failures.is_empty());
            stop_subtree(&mut c, 2);
            c.suspend_hub_port(1, 1).unwrap();
            let before = model.borrow().requests.len();
            {
                let mut hardware = model.borrow_mut();
                let port = &mut hardware.nodes.get_mut(&0).unwrap().ports.as_mut().unwrap()[0];
                port.status &= !(if speed == SUPER_SPEED {
                    LINK_MASK
                } else {
                    1 << 2
                });
                port.change |= if speed == SUPER_SPEED { 1 << 6 } else { 1 << 2 };
            }
            c.resume_hub_port(1, 1).unwrap();
            let hardware = model.borrow();
            assert!(
                !hardware.requests[before..]
                    .iter()
                    .any(|(_, _, q)| *q == link_request(1, speed == SUPER_SPEED, false))
            );
            assert_eq!(hardware.nodes[&0].ports.as_ref().unwrap()[0].change, 0);
        }
    }

    #[test]
    #[ignore = "oracle: STELA_XHCI_HUB_POWER_ORACLE"]
    fn unchanged_linux_hub_suspend_status_and_link_requests() {
        extern crate std;
        let path = std::env::var("STELA_XHCI_HUB_POWER_ORACLE").unwrap();
        let trace = std::fs::read_to_string(path).unwrap();
        let mut statuses = 0;
        let mut links = 0;
        let mut timing = 0;
        for line in trace.lines() {
            let mut fields = line.split_whitespace();
            let tag = fields.next().unwrap();
            let values: Vec<u16> = fields.map(|field| field.parse().unwrap()).collect();
            match tag {
                "S" => {
                    let [ss, status, expected] = values.as_slice() else {
                        panic!("bad status row");
                    };
                    assert_eq!(
                        u16::from(
                            State {
                                status: *status,
                                change: 0
                            }
                            .suspended(*ss != 0)
                        ),
                        *expected
                    );
                    statuses += 1;
                }
                "L" => {
                    let [port, suspend, feature, index] = values.as_slice() else {
                        panic!("bad request row");
                    };
                    let request = link_request(*port as u8, true, *suspend != 0);
                    assert_eq!(u16::from_le_bytes([request[2], request[3]]), *feature);
                    assert_eq!(u16::from_le_bytes([request[4], request[5]]), *index);
                    links += 1;
                }
                "T" => {
                    assert_eq!(values, [RESUME_SIGNAL_US as u16 / 1000]);
                    timing += 1;
                }
                _ => panic!("unknown oracle row"),
            }
        }
        assert_eq!((statuses, links, timing), (131072, 30, 1));
    }
}
