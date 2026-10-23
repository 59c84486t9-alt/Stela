// SPDX-License-Identifier: GPL-2.0-only
//! SuperSpeed cold hub power/reset protocol on the real EP0 transport.
use super::{descriptor::*, *};

const SET_HUB_DEPTH: u8 = 12;
const PORT_RESET_ATTEMPTS: usize = 5;
// Linux hub_port_reset: TRSTRCY plus its ordinary 40-ms device margin.
const SS_RESET_RECOVERY_US: u64 = 50_000;
const HUB_EXT_PORT_STATUS: u16 = 2;
const BH_PORT_RESET: u16 = 28;
const CONNECTION: u16 = 1;
const ENABLE: u16 = 1 << 1;
const OVER_CURRENT: u16 = 1 << 3;
const RESET: u16 = 1 << 4;
const LINK_STATE: u16 = 15 << 5;
const POWER: u16 = 1 << 9;
const SPEED: u16 = 7 << 10;
const U0: u16 = 0;
const U3: u16 = 3 << 5;
const INACTIVE: u16 = 6 << 5;
const COMPLIANCE: u16 = 10 << 5;
const CHANGE_CONNECTION: u16 = 1;
const CHANGE_OVER_CURRENT: u16 = 1 << 3;
const CHANGE_CONFIG_ERROR: u16 = 1 << 7;
const CHANGES: &[(u16, u16)] = &[
    (1, 16),
    (1 << 3, 19),
    (1 << 4, 20),
    (1 << 5, 29),
    (1 << 6, 25),
    (1 << 7, 26),
];

pub(super) fn depth_request(depth: u8) -> [u8; 8] {
    setup(0x20, SET_HUB_DEPTH, u16::from(depth), 0, 0)
}
pub(super) fn status_request(port: u8, extended: bool) -> [u8; 8] {
    setup(
        0xa3,
        GET_STATUS,
        if extended { HUB_EXT_PORT_STATUS } else { 0 },
        u16::from(port),
        if extended { 8 } else { 4 },
    )
}

#[derive(Clone, Copy)]
pub(super) struct Port {
    status: u16,
    change: u16,
    extended: Option<u32>,
}
impl Port {
    pub fn decode(bytes: &[u8], extended: bool) -> Result<Self, BlockError> {
        if bytes.len() != if extended { 8 } else { 4 } {
            return Err(BlockError::Unsupported("short SuperSpeed hub port status"));
        }
        let status = u16::from_le_bytes([bytes[0], bytes[1]]);
        let change = u16::from_le_bytes([bytes[2], bytes[3]]);
        if status & !0x1ffb != 0
            || change & !0xf9 != 0
            || status & SPEED != 0
            || status & LINK_STATE > COMPLIANCE
        {
            return Err(BlockError::Unsupported(
                "reserved SuperSpeed hub port status",
            ));
        }
        Ok(Self {
            status,
            change,
            extended: extended.then(|| u32::from_le_bytes(bytes[4..8].try_into().unwrap())),
        })
    }
    pub fn warm(self) -> bool {
        matches!(self.status & LINK_STATE, INACTIVE | COMPLIANCE)
    }
    fn powered(self) -> Result<(), BlockError> {
        if self.status & POWER == 0 || self.status & OVER_CURRENT != 0 {
            Err(BlockError::Unsupported(
                "hub port power absent or over-current",
            ))
        } else {
            Ok(())
        }
    }
    fn ready(self) -> Result<(), BlockError> {
        self.powered()?;
        if self.status & (CONNECTION | ENABLE | RESET | LINK_STATE) != CONNECTION | ENABLE | U0
            || self.change != 0
        {
            return Err(BlockError::Unsupported(
                "hub port has no stable enabled U0 link",
            ));
        }
        Ok(())
    }
}

impl Controller {
    pub(in super::super) fn superspeed_hub(
        &mut self,
        device: &Device,
        attachment: Attachment,
        dma: &mut dyn DmaAllocator,
        devices: &mut Vec<Device>,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<(), BlockError> {
        topology(attachment)?;
        let interfaces = interfaces(&device.configuration);
        let mut eligible = interfaces
            .iter()
            .filter_map(|interface| status_endpoint(device, interface));
        let endpoint = eligible.next().ok_or(BlockError::Unsupported(
            "SuperSpeed hub has no status endpoint",
        ))?;
        if eligible.next().is_some() {
            return Err(BlockError::Unsupported(
                "ambiguous SuperSpeed hub interfaces",
            ));
        }
        let slot = device.slot;
        let bytes = self.control(
            slot,
            setup(
                0xa0,
                GET_DESCRIPTOR,
                u16::from(SS_HUB_DESCRIPTOR) << 8,
                0,
                SS_HUB_BYTES as u16,
            ),
            &[],
        )?;
        let descriptor = Descriptor::new(&bytes, &endpoint)?;
        let ssp = if u16::from_le_bytes([device.descriptor[2], device.descriptor[3]]) >= 0x0310 {
            self.hub_ssp(slot)?
        } else {
            None
        };
        if attachment.speed == SUPER_SPEED_PLUS && ssp.is_none() {
            return Err(BlockError::Unsupported(
                "SuperSpeedPlus hub requires actual BOS sublink capabilities",
            ));
        }
        let self_powered = self.hub_power_source(slot)?;
        self.set_configuration(slot, device.configuration_value())?;
        self.install_hub_current(
            slot,
            descriptor.ports,
            descriptor.controller_ma,
            self_powered,
        )?;
        self.observe_hub_power(slot, attachment)?;
        // SuperSpeed has no USB2 transaction translator or MTT/TT think time.
        self.configure(slot, &[endpoint], Some((descriptor.ports, 0, false)), dma)?;
        self.control(slot, depth_request(attachment.tier), &[])?;
        let mut powered_ports = Vec::new();
        for port in 1..=descriptor.ports {
            if let Err(error) = self.reserve_port_current(slot, port) {
                failures.push((
                    format!("{}.{port} reserve initial USB current", device.location),
                    error,
                ));
                continue;
            }
            self.control(
                slot,
                setup(0x23, SET_FEATURE, PORT_POWER, u16::from(port), 0),
                &[],
            )?;
            powered_ports.push(port);
        }
        self.clock.delay(descriptor.power_good_us);
        self.observe_hub_power(slot, attachment)?;
        for port in powered_ports {
            let location = format!("{}.{port}", device.location);
            crate::working(&location);
            let reset = |controller: &mut Self| {
                controller.observe_hub_power(slot, attachment)?;
                let speed = controller.superspeed_port(slot, port, ssp.as_ref());
                // Recheck global authority even when this individual port
                // failed. A local reset error must not hide parent power loss.
                controller.observe_hub_power(slot, attachment)?;
                speed?
                    .map(|speed| child(slot, attachment, port, speed))
                    .transpose()
            };
            self.connect(location, reset, dma, devices, failures);
            if self.live_slot(slot).is_err() {
                // connect already records the actual power observation failure.
                // Keep the inventory as historical identity, never as a live handle.
                break;
            }
        }
        Ok(())
    }

    fn observe_hub_power(&mut self, slot: u8, _attachment: Attachment) -> Result<(), BlockError> {
        self.observe_hub_current(slot)
    }

    pub(in super::super) fn hub_power_source(&mut self, slot: u8) -> Result<bool, BlockError> {
        let bytes = self.control(slot, setup(0x80, GET_STATUS, 0, 0, 2), &[])?;
        if bytes.len() != 2 {
            return Err(BlockError::Unsupported("short USB hub power source status"));
        }
        Ok(bytes[0] & 1 != 0)
    }

    fn hub_ssp(&mut self, slot: u8) -> Result<Option<Ssp>, BlockError> {
        let header = self.descriptor(slot, BOS_DESCRIPTOR, 0, 5)?;
        if header.len() != 5 || header[0] != 5 || header[1] != BOS_DESCRIPTOR {
            return Err(BlockError::Unsupported("invalid hub BOS header"));
        }
        let total = u16::from_le_bytes([header[2], header[3]]);
        if !(5..=CONTROL_BYTES as u16).contains(&total) {
            return Err(BlockError::Unsupported("oversized hub BOS descriptor"));
        }
        let bytes = self.descriptor(slot, BOS_DESCRIPTOR, 0, total)?;
        if bytes.get(..5) != Some(header.as_slice()) {
            return Err(BlockError::Unsupported("hub BOS changed during read"));
        }
        Ssp::bos(&bytes)
    }

    fn superspeed_status(
        &mut self,
        slot: u8,
        port: u8,
        extended: bool,
    ) -> Result<Port, BlockError> {
        let bytes = self.control(slot, status_request(port, extended), &[])?;
        Port::decode(&bytes, extended)
    }

    fn clear_superspeed_changes(
        &mut self,
        slot: u8,
        port: u8,
        change: u16,
    ) -> Result<(), BlockError> {
        for &(bit, selector) in CHANGES {
            if change & bit != 0 {
                self.control(
                    slot,
                    setup(0x23, CLEAR_FEATURE, selector, u16::from(port), 0),
                    &[],
                )?;
            }
        }
        Ok(())
    }

    fn superspeed_port(
        &mut self,
        slot: u8,
        port: u8,
        ssp: Option<&Ssp>,
    ) -> Result<Option<u8>, BlockError> {
        // Qualify the same stable connection interval as USB2/root ports.
        // Clearing CSC once is not evidence that the downstream plug settled.
        let clock = self.clock;
        let mut stable_state = None;
        let connected = super::super::enumerate::debounce(clock, || {
            let state = self.superspeed_status(slot, port, ssp.is_some())?;
            state.powered()?;
            let changed = state.change & CHANGE_CONNECTION != 0;
            self.clear_superspeed_changes(slot, port, state.change)?;
            stable_state = Some(state);
            Ok((state.status & CONNECTION != 0, changed))
        })?;
        if !connected {
            return Ok(None);
        }
        let mut state =
            stable_state.ok_or(BlockError::Unsupported("hub port has no stable status"))?;
        if state.status & LINK_STATE == U3 {
            return Err(BlockError::Unsupported(
                "hub port resume requires a separate lifecycle owner",
            ));
        }
        let mut warm = state.warm();
        // A failed hot reset can require a warm reset. Bound retries and never
        // admit a child on completion bits alone or on an upstream speed guess.
        for _ in 0..PORT_RESET_ATTEMPTS {
            let selector = if warm { BH_PORT_RESET } else { PORT_RESET };
            self.control(
                slot,
                setup(0x23, SET_FEATURE, selector, u16::from(port), 0),
                &[],
            )?;
            let deadline = self.clock.deadline(PORT_RESET_US);
            loop {
                self.clock.delay(1000);
                state = self.superspeed_status(slot, port, ssp.is_some())?;
                state.powered()?;
                // SS connection is unknown during reset, and some devices
                // reconnect only after RESET falls. Do not interpret one CCS=0
                // sample or reset-induced CSC as a physical removal.
                if state.change & (CHANGE_OVER_CURRENT | CHANGE_CONFIG_ERROR) != 0 {
                    return Err(BlockError::Unsupported(
                        "hub port changed power/configuration during reset",
                    ));
                }
                if state.status & RESET == 0 && state.status & CONNECTION != 0 && state.warm() {
                    break;
                }
                if state.status & RESET == 0 && state.status & CONNECTION != 0 {
                    self.clear_superspeed_changes(slot, port, state.change)?;
                    self.clock.delay(SS_RESET_RECOVERY_US);
                    let mut final_state = self.superspeed_status(slot, port, ssp.is_some())?;
                    if final_state.change == 1 << 6 && final_state.status & LINK_STATE == U0 {
                        self.clear_superspeed_changes(slot, port, final_state.change)?;
                        final_state = self.superspeed_status(slot, port, ssp.is_some())?;
                    }
                    final_state.powered()?;
                    if final_state.change & (CHANGE_OVER_CURRENT | CHANGE_CONFIG_ERROR) != 0 {
                        return Err(BlockError::Unsupported(
                            "hub port power/configuration changed after reset",
                        ));
                    }
                    if final_state.ready().is_err() {
                        // Linux retries an acknowledged reset that completes
                        // disabled. Keep the retry budget for ordinary hot
                        // failures too; only Inactive/Compliance selects warm.
                        state = final_state;
                        break;
                    }
                    let root = self.slot(slot)?.attachment.root_port;
                    self.current_port_reset(Some((slot, port)), root);
                    return match ssp {
                        Some(ssp) => ssp.speed(final_state.extended.unwrap()).map(Some),
                        None => Ok(Some(SUPER_SPEED)),
                    };
                }
                if deadline.passed() {
                    if state.status & RESET == 0 {
                        if state.warm() {
                            break;
                        }
                        if state.status & CONNECTION == 0 {
                            self.clear_superspeed_changes(slot, port, state.change)?;
                            return Ok(None);
                        }
                    }
                    return Err(BlockError::Timeout);
                }
            }
            warm |= state.warm();
            self.clear_superspeed_changes(slot, port, state.change)?;
        }
        Err(BlockError::Unsupported(
            "hub port failed bounded hot/warm resets",
        ))
    }
}
