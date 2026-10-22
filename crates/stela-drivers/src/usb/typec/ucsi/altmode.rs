// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2018 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Actual UCSI CAM transactions and native DisplayPort coordination.
//!
//! UCSI cannot read a partner DisplayPort Status VDO. A native provider must
//! supply it, with a real connector attachment lease. No synthetic Enter ACK,
//! guessed HPD/status, or added firmware pin capabilities are produced here.
use super::{Command, ConnectorNumber, Controller, Recipient, Timer, Transport};
use crate::usb::typec::mux::{self, Mode, Orientation, Pin, ResourceError, Route};
use alloc::vec::Vec;

const DP_SVID: u16 = 0xff01;
const MAX_MODES: usize = 30;
const DETAILS: u16 = 1 << 2;
const OVERRIDE: u16 = 1 << 3;
const HPD: u32 = 1 << 7;
const IRQ: u32 = 1 << 8;
const EXIT_REQUEST: u32 = (1 << 5) | (1 << 6);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Ucsi(super::Error),
    Platform(ResourceError),
    Route(mux::Error),
    DetailsUnavailable,
    OverrideUnavailable,
    NotInitialized,
    StaleAttachment,
    Disconnected,
    InvalidModeCount(usize),
    InvalidResponse {
        command: u8,
        bytes: usize,
    },
    InvalidMode(u8),
    UnsupportedConfiguration,
    StatusUnavailable,
    InvalidStatus(u32),
    StaleStatus {
        previous: u64,
        actual: u64,
    },
    ChangedStatusWithoutEvent,
    PartnerRequestsExit(u32),
    CamBusy(u8),
    CamMismatch {
        expected: Option<u8>,
        actual: Option<u8>,
    },
    Faulted,
}
impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        Self::Ucsi(error)
    }
}
/// Native observations from an actual controller/TCPC/GPU status source. The
/// epoch must change on detach, reattachment and provider ownership reset, even
/// if orientation and partner identity repeat. It is not the UCSI reset epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub attachment_epoch: u64,
    pub orientation: Orientation,
    pub partner_status: Option<u32>,
    /// Sequence of the actual status notification; repeated snapshots retain it.
    pub status_sequence: u64,
}
/// Owns the actual connector-to-GPU association and its attachment/status lease.
/// Providers retain resources and serialize physical detach notifications with
/// these operations. Missing Status VDO access must return None, never a guess.
/// `prepare` leaves output disabled; `enable` permits training but does not prove
/// a working link. `hpd` receives the actual level/IRQ after CAM and route setup.
/// `disable` is idempotent and performs actual hardware quiescence. Status
/// sequences identify real received status events, including equal successive
/// VDOs. Snapshots are non-consuming; the platform must retain newer events
/// until a later update. It must not increment the sequence for ordinary reads.
pub trait NativeDisplayPort {
    fn observe(&mut self, connector: ConnectorNumber) -> Result<Observation, ResourceError>;
    fn prepare(&mut self, configuration: u32) -> Result<(), ResourceError>;
    fn enable(&mut self) -> Result<(), ResourceError>;
    fn hpd(&mut self, status: u32) -> Result<(), ResourceError>;
    fn disable(&mut self) -> Result<(), ResourceError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlternateMode {
    /// Actual zero-based PPM table index. Duplicates retain distinct indices.
    pub index: u8,
    pub svid: u16,
    pub vdo: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Modes {
    pub recipient: Recipient,
    entries: Vec<AlternateMode>,
}
impl Modes {
    pub fn entries(&self) -> &[AlternateMode] {
        &self.entries
    }
    pub fn get(&self, index: u8) -> Option<AlternateMode> {
        self.entries
            .iter()
            .copied()
            .find(|mode| mode.index == index)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CableProperty {
    pub raw: [u8; 5],
}
impl CableProperty {
    pub fn active(self) -> bool {
        self.raw[3] & 2 != 0
    }
    pub fn mode_support(self) -> bool {
        self.raw[3] & 32 != 0
    }
}
fn modes<T: Transport, C: Timer>(
    controller: &mut Controller<T, C>,
    connector: ConnectorNumber,
    recipient: Recipient,
    maximum: usize,
) -> Result<Modes, Error> {
    if maximum > MAX_MODES {
        return Err(Error::InvalidModeCount(maximum));
    }
    let mut entries = Vec::new();
    while entries.len() < maximum {
        let mut raw = [0; 12];
        let receipt = controller.execute(
            Command::alternate_mode(connector, recipient, entries.len() as u8),
            &mut raw,
            &[],
        )?;
        if receipt.bytes == 0 {
            break;
        }
        if !receipt.bytes.is_multiple_of(6) {
            return Err(Error::InvalidResponse {
                command: 0x0c,
                bytes: receipt.bytes,
            });
        }
        for chunk in raw[..receipt.bytes].as_chunks::<6>().0 {
            let svid = u16::from_le_bytes([chunk[0], chunk[1]]);
            if svid == 0 {
                return Ok(Modes { recipient, entries });
            }
            if entries.len() == maximum {
                return Err(Error::InvalidModeCount(entries.len() + 1));
            }
            entries.push(AlternateMode {
                index: entries.len() as u8,
                svid,
                vdo: u32::from_le_bytes(chunk[2..6].try_into().unwrap()),
            });
        }
    }
    Ok(Modes { recipient, entries })
}
fn current<T: Transport, C: Timer>(
    controller: &mut Controller<T, C>,
    connector: ConnectorNumber,
) -> Result<Option<u8>, Error> {
    let mut cam = [0; 1];
    let receipt = controller.execute(Command::current_cam(connector), &mut cam, &[])?;
    if receipt.bytes != 1 {
        return Err(Error::InvalidResponse {
            command: 0x0e,
            bytes: receipt.bytes,
        });
    }
    match cam[0] {
        0xff => Ok(None),
        n if usize::from(n) < MAX_MODES => Ok(Some(n)),
        n => Err(Error::InvalidMode(n)),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    connector: ConnectorNumber,
    generation: u64,
    attachment_epoch: u64,
    orientation: Orientation,
    override_supported: bool,
    port: Modes,
    partner: Modes,
    cable: CableProperty,
    cable_modes: Option<Modes>,
}
impl Discovery {
    pub fn port(&self) -> &Modes {
        &self.port
    }
    pub fn partner(&self) -> &Modes {
        &self.partner
    }
    pub fn cable(&self) -> CableProperty {
        self.cable
    }
    pub fn cable_modes(&self) -> Option<&Modes> {
        self.cable_modes.as_ref()
    }
    pub fn override_supported(&self) -> bool {
        self.override_supported
    }
    pub fn read<T: Transport, C: Timer, P: NativeDisplayPort>(
        controller: &mut Controller<T, C>,
        connector: ConnectorNumber,
        native: &mut P,
    ) -> Result<Self, Error> {
        if !controller.initialized() {
            return Err(Error::NotInitialized);
        }
        let capability = controller.capability().ok_or(Error::NotInitialized)?;
        if capability.features & DETAILS == 0 {
            return Err(Error::DetailsUnavailable);
        }
        if !controller.read_status(connector, false)?.connected() {
            return Err(Error::Disconnected);
        }
        let before = native.observe(connector).map_err(Error::Platform)?;
        if before.orientation == Orientation::None {
            return Err(Error::Disconnected);
        }
        let port = modes(
            controller,
            connector,
            Recipient::Connector,
            usize::from(capability.raw[8]),
        )?;
        let partner = modes(controller, connector, Recipient::Partner, MAX_MODES)?;
        let mut raw = [0; 5];
        let receipt = controller.execute(Command::cable_property(connector), &mut raw, &[])?;
        if receipt.bytes != raw.len() {
            return Err(Error::InvalidResponse {
                command: 0x11,
                bytes: receipt.bytes,
            });
        }
        let cable = CableProperty { raw };
        let cable_modes = if cable.active() && cable.mode_support() {
            Some(modes(
                controller,
                connector,
                Recipient::CablePlug,
                MAX_MODES,
            )?)
        } else {
            None
        };
        let after = native.observe(connector).map_err(Error::Platform)?;
        if after.attachment_epoch != before.attachment_epoch
            || after.orientation != before.orientation
        {
            return Err(Error::StaleAttachment);
        }
        if !controller.read_status(connector, false)?.connected() {
            return Err(Error::Disconnected);
        }
        Ok(Self {
            connector,
            generation: controller.generation(),
            attachment_epoch: before.attachment_epoch,
            orientation: before.orientation,
            override_supported: capability.features & OVERRIDE != 0,
            port,
            partner,
            cable,
            cable_modes,
        })
    }
    fn validate<T: Transport, C: Timer, P: NativeDisplayPort>(
        &self,
        controller: &mut Controller<T, C>,
        native: &mut P,
    ) -> Result<Observation, Error> {
        if !controller.initialized() || controller.generation() != self.generation {
            return Err(Error::StaleAttachment);
        }
        let observation = native.observe(self.connector).map_err(Error::Platform)?;
        if observation.attachment_epoch != self.attachment_epoch
            || observation.orientation != self.orientation
        {
            return Err(Error::StaleAttachment);
        }
        if observation.orientation == Orientation::None
            || !controller.read_status(self.connector, false)?.connected()
        {
            return Err(Error::Disconnected);
        }
        Ok(observation)
    }
}
/// Explicit native GPU policy request, checked against unmodified raw port,
/// partner and (for an active cable) cable capabilities. One pin is selected;
/// capability unioning and inferred partner preferences are forbidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceRequest {
    pub port_cam: u8,
    pub partner_mode: u8,
    pub cable_mode: Option<u8>,
    pub pin: Pin,
    pub signalling: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub port_cam: u8,
    pub pin: Pin,
    pub raw: u32,
}
impl Discovery {
    pub fn source_configuration(&self, request: SourceRequest) -> Result<Configuration, Error> {
        let dp = |modes: &Modes, index: u8| {
            modes
                .get(index)
                .filter(|mode| mode.svid == DP_SVID)
                .ok_or(Error::InvalidMode(index))
        };
        let local = dp(&self.port, request.port_cam)?.vdo;
        let partner = dp(&self.partner, request.partner_mode)?.vdo;
        if local & 2 == 0 || partner & 1 == 0 {
            return Err(Error::UnsupportedConfiguration);
        }
        let pins_ufp = |vdo: u32| {
            if vdo & (1 << 6) != 0 {
                (vdo >> 16) & 255
            } else {
                (vdo >> 8) & 255
            }
        };
        let pins_dfp = |vdo: u32| {
            if vdo & (1 << 6) != 0 {
                (vdo >> 8) & 255
            } else {
                (vdo >> 16) & 255
            }
        };
        let mut pins = pins_dfp(local) & pins_ufp(partner);
        let mut signal = ((local >> 2) & 15) & ((partner >> 2) & 15);
        if self.cable.active() {
            let cable = self
                .cable_modes
                .as_ref()
                .ok_or(Error::UnsupportedConfiguration)?;
            let cable = dp(
                cable,
                request.cable_mode.ok_or(Error::UnsupportedConfiguration)?,
            )?
            .vdo;
            pins &= (cable >> 16) & 255;
            signal &= (cable >> 2) & 15;
        } else if request.cable_mode.is_some() {
            return Err(Error::UnsupportedConfiguration);
        }
        let pin = match request.pin {
            Pin::C => 4,
            Pin::D => 8,
            Pin::E => 16,
            Pin::F => 32,
        };
        if pins & pin == 0
            || !(1..=3).contains(&request.signalling)
            || u32::from(request.signalling) & !signal != 0
        {
            return Err(Error::UnsupportedConfiguration);
        }
        Ok(Configuration {
            port_cam: request.port_cam,
            pin: request.pin,
            raw: 2 | (u32::from(request.signalling) << 2) | (pin << 8),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    CamConfirmed(Configuration),
    Configured(Configuration),
    Faulted,
}
/// One exclusive native connection session. The caller owns the real Route
/// association and serializes this session with connector changes. Configured
/// means CAM readback, route programming and output requests succeeded; it is
/// not a physical link-training or display-image assertion. A stale attachment
/// forbids cleanup writes; its native owner must drain/quiesce the old lease.
/// A foreign CAM found before configuration or during exit is left untouched.
/// If CAM changes after this session configured output, update quiesces its
/// owned GPU and route, without issuing SET_NEW_CAM to override the new CAM.
pub struct Session {
    discovery: Discovery,
    state: State,
    observed_cam: Option<Option<u8>>,
    requested_cam: Option<u8>,
    delivered_status: Option<(u64, u32)>,
    fault: Option<Error>,
    cleanup: Vec<Error>,
}
impl Session {
    pub fn new(discovery: Discovery) -> Self {
        Self {
            discovery,
            state: State::Idle,
            observed_cam: None,
            requested_cam: None,
            delivered_status: None,
            fault: None,
            cleanup: Vec::new(),
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn observed_cam(&self) -> Option<Option<u8>> {
        self.observed_cam
    }
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_ref()
    }
    pub fn cleanup_errors(&self) -> &[Error] {
        &self.cleanup
    }
    fn stop<P: NativeDisplayPort, R: Route>(&mut self, native: &mut P, route: &mut R) {
        self.cleanup.clear();
        if let Err(error) = native.disable() {
            self.cleanup.push(Error::Platform(error));
        }
        if let Err(error) = route.set_mode(Mode::Safe) {
            self.cleanup.push(Error::Route(error));
        }
    }
    fn failed<P: NativeDisplayPort, R: Route>(
        &mut self,
        error: Error,
        native: &mut P,
        route: &mut R,
    ) -> Error {
        if matches!(
            error,
            Error::StaleAttachment | Error::CamBusy(_) | Error::OverrideUnavailable
        ) {
            self.cleanup.clear();
            self.cleanup.push(error.clone());
        } else {
            self.stop(native, route);
        }
        self.state = State::Faulted;
        self.fault = Some(error.clone());
        error
    }
    fn status(&self, observation: Observation) -> Result<u32, Error> {
        let status = observation.partner_status.ok_or(Error::StatusUnavailable)?;
        if status & IRQ != 0 && status & HPD == 0 {
            return Err(Error::InvalidStatus(status));
        }
        if status & EXIT_REQUEST != 0 {
            return Err(Error::PartnerRequestsExit(status));
        }
        if status & 2 == 0 {
            return Err(Error::UnsupportedConfiguration);
        }
        if let Some((sequence, raw)) = self.delivered_status {
            if observation.status_sequence < sequence {
                return Err(Error::StaleStatus {
                    previous: sequence,
                    actual: observation.status_sequence,
                });
            }
            if observation.status_sequence == sequence {
                if status != raw {
                    return Err(Error::ChangedStatusWithoutEvent);
                }
                return Ok(status & !IRQ);
            }
        }
        Ok(status)
    }
    pub fn configure<T: Transport, C: Timer, P: NativeDisplayPort, R: Route>(
        &mut self,
        controller: &mut Controller<T, C>,
        native: &mut P,
        route: &mut R,
        request: SourceRequest,
    ) -> Result<Configuration, Error> {
        if self.fault.is_some() {
            return Err(Error::Faulted);
        }
        if !self.discovery.override_supported {
            return Err(Error::OverrideUnavailable);
        }
        if self.state != State::Idle {
            return Err(Error::UnsupportedConfiguration);
        }
        let configuration = self.discovery.source_configuration(request)?;
        let observation = self.discovery.validate(controller, native)?;
        self.status(observation)?;
        let current = current(controller, self.discovery.connector)?;
        self.observed_cam = Some(current);
        if let Some(cam) = current
            && cam != configuration.port_cam
        {
            return Err(Error::CamBusy(cam));
        }
        let result = (|| {
            native.disable().map_err(Error::Platform)?;
            route.set_mode(Mode::Safe).map_err(Error::Route)?;
            route
                .set_orientation(observation.orientation)
                .map_err(Error::Route)?;
            native.prepare(configuration.raw).map_err(Error::Platform)?;
            self.discovery.validate(controller, native)?;
            self.requested_cam = Some(configuration.port_cam);
            controller.execute(
                Command::new_cam_configuration(
                    self.discovery.connector,
                    configuration.port_cam,
                    true,
                    configuration.raw,
                ),
                &mut [],
                &[],
            )?;
            let actual = current_cam(self, controller)?;
            if actual != Some(configuration.port_cam) {
                return Err(Error::CamMismatch {
                    expected: Some(configuration.port_cam),
                    actual,
                });
            }
            self.state = State::CamConfirmed(configuration);
            let observation = self.discovery.validate(controller, native)?;
            let status = self.status(observation)?;
            route
                .set_mode(Mode::DisplayPort(mux::DisplayPort {
                    pin: configuration.pin,
                    status,
                    configuration: configuration.raw,
                }))
                .map_err(Error::Route)?;
            self.discovery.validate(controller, native)?;
            native.enable().map_err(Error::Platform)?;
            self.discovery.validate(controller, native)?;
            native.hpd(status).map_err(Error::Platform)?;
            self.delivered_status = Some((
                observation.status_sequence,
                observation.partner_status.unwrap(),
            ));
            self.state = State::Configured(configuration);
            Ok(configuration)
        })();
        result.map_err(|error| self.failed(error, native, route))
    }
    pub fn update<T: Transport, C: Timer, P: NativeDisplayPort, R: Route>(
        &mut self,
        controller: &mut Controller<T, C>,
        native: &mut P,
        route: &mut R,
    ) -> Result<(), Error> {
        if self.fault.is_some() {
            return Err(Error::Faulted);
        }
        let State::Configured(configuration) = self.state else {
            return Err(Error::NotInitialized);
        };
        let result = (|| {
            let observation = self.discovery.validate(controller, native)?;
            let status = self.status(observation)?;
            let actual = current_cam(self, controller)?;
            if actual != Some(configuration.port_cam) {
                return Err(Error::CamMismatch {
                    expected: Some(configuration.port_cam),
                    actual,
                });
            }
            route
                .set_mode(Mode::DisplayPort(mux::DisplayPort {
                    pin: configuration.pin,
                    status,
                    configuration: configuration.raw,
                }))
                .map_err(Error::Route)?;
            self.discovery.validate(controller, native)?;
            native.hpd(status).map_err(Error::Platform)?;
            self.delivered_status = Some((
                observation.status_sequence,
                observation.partner_status.unwrap(),
            ));
            Ok(())
        })();
        result.map_err(|error| self.failed(error, native, route))
    }
    /// Explicit exit is also the recovery path after a partial configuration.
    /// Only verified CAM=None plus successful real quiescence clears the fault.
    pub fn exit<T: Transport, C: Timer, P: NativeDisplayPort, R: Route>(
        &mut self,
        controller: &mut Controller<T, C>,
        native: &mut P,
        route: &mut R,
    ) -> Result<(), Error> {
        let result = (|| {
            self.discovery.validate(controller, native)?;
            if !self.discovery.override_supported {
                return Err(Error::OverrideUnavailable);
            }
            let actual = current_cam(self, controller)?;
            if let Some(cam) = actual
                && self.requested_cam != Some(cam)
            {
                return Err(Error::CamBusy(cam));
            }
            native.disable().map_err(Error::Platform)?;
            route.set_mode(Mode::Safe).map_err(Error::Route)?;
            if let Some(cam) = actual {
                controller.execute(
                    Command::new_cam_configuration(self.discovery.connector, cam, false, 0),
                    &mut [],
                    &[],
                )?;
                let actual = current_cam(self, controller)?;
                if actual.is_some() {
                    return Err(Error::CamMismatch {
                        expected: None,
                        actual,
                    });
                }
            }
            self.discovery.validate(controller, native)?;
            self.state = State::Idle;
            self.requested_cam = None;
            self.delivered_status = None;
            self.fault = None;
            self.cleanup.clear();
            Ok(())
        })();
        result.map_err(|error| self.failed(error, native, route))
    }
}
fn current_cam<T: Transport, C: Timer>(
    session: &mut Session,
    controller: &mut Controller<T, C>,
) -> Result<Option<u8>, Error> {
    let actual = current(controller, session.discovery.connector)?;
    session.observed_cam = Some(actual);
    Ok(actual)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{Capability, TransportError};
    use super::*;
    use alloc::{collections::VecDeque, rc::Rc, vec};
    use core::cell::{Cell, RefCell};
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Event {
        Command(u64),
        Observe,
        Prepare(u32),
        Enable,
        Hpd(u32),
        Disable,
        Orientation(Orientation),
        Mode(Mode),
    }
    struct Hardware {
        modes: [Vec<AlternateMode>; 4],
        batch: usize,
        malformed: Option<Vec<u8>>,
        cable: [u8; 5],
        cam: Option<u8>,
        apply: bool,
        connected: bool,
        payload: Vec<u8>,
        cci: u32,
        flags: u32,
        events: Vec<Event>,
        calls: usize,
        fail_at: usize,
        fail_after: bool,
    }
    impl Hardware {
        fn new() -> Self {
            let local = AlternateMode {
                index: 0,
                svid: DP_SVID,
                vdo: 2 | 4 | 64 | (0x3c << 8),
            };
            let partner = AlternateMode {
                index: 0,
                svid: DP_SVID,
                vdo: 1 | 4 | 64 | (0x3c << 16),
            };
            Self {
                modes: [vec![local], vec![partner], vec![], vec![]],
                batch: 2,
                malformed: None,
                cable: [0, 0, 0, 32, 0],
                cam: None,
                apply: true,
                connected: true,
                payload: vec![],
                cci: 0,
                flags: 0,
                events: vec![],
                calls: 0,
                fail_at: usize::MAX,
                fail_after: false,
            }
        }
    }
    #[derive(Clone)]
    struct Ppm(Rc<RefCell<Hardware>>);
    impl Transport for Ppm {
        fn read_version(&mut self) -> Result<u16, TransportError> {
            Ok(0x0120)
        }
        fn poll_cci(&mut self) -> Result<u32, TransportError> {
            Ok(self.0.borrow().cci)
        }
        fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
            bytes.copy_from_slice(&self.0.borrow().payload[..bytes.len()]);
            Ok(())
        }
        fn write_message_out(&mut self, _: &[u8]) -> Result<(), TransportError> {
            panic!()
        }
        fn write_control(&mut self, control: u64) -> Result<(), TransportError> {
            let mut hardware = self.0.borrow_mut();
            hardware.calls += 1;
            let fail = hardware.calls == hardware.fail_at;
            if fail && !hardware.fail_after {
                return Err(TransportError::Io(0xa5));
            }
            if control as u8 == 4 {
                hardware.cci = 1 << 29;
            } else {
                hardware.events.push(Event::Command(control));
                hardware.payload = match control as u8 {
                    0x12 => {
                        let mut raw = vec![0; 16];
                        raw[2] = u8::from(hardware.connected) << 3;
                        raw
                    }
                    0x0c => {
                        if let Some(raw) = hardware.malformed.take() {
                            raw
                        } else {
                            let recipient = ((control >> 16) & 7) as usize;
                            let offset = ((control >> 32) & 255) as usize;
                            let mut raw = vec![];
                            for mode in hardware.modes[recipient]
                                .iter()
                                .skip(offset)
                                .take(hardware.batch)
                            {
                                raw.extend_from_slice(&mode.svid.to_le_bytes());
                                raw.extend_from_slice(&mode.vdo.to_le_bytes());
                            }
                            raw
                        }
                    }
                    0x11 => hardware.cable.to_vec(),
                    0x0e => vec![hardware.cam.unwrap_or(0xff)],
                    0x0f => {
                        if hardware.apply {
                            hardware.cam = if control & (1 << 23) != 0 {
                                Some((control >> 24) as u8)
                            } else {
                                None
                            };
                        }
                        vec![]
                    }
                    _ => panic!("unplanned command {control:x}"),
                };
                hardware.cci = (1 << 31) | hardware.flags | ((hardware.payload.len() as u32) << 8);
            }
            if fail {
                Err(TransportError::Io(0xa5))
            } else {
                Ok(())
            }
        }
    }
    #[derive(Clone, Default)]
    struct Time(Rc<Cell<u64>>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn delay_us(&self, value: u64) {
            self.0.set(self.0.get() + value);
        }
    }
    struct Native {
        hardware: Rc<RefCell<Hardware>>,
        observation: Observation,
        observations: VecDeque<Observation>,
        calls: usize,
        fail_at: usize,
        fail_cleanup: bool,
        enabled: bool,
    }
    impl Native {
        fn event(&mut self, event: Event) -> Result<(), ResourceError> {
            self.calls += 1;
            self.hardware.borrow_mut().events.push(event.clone());
            if self.calls == self.fail_at || self.fail_cleanup && event == Event::Disable {
                return Err(ResourceError::Status(self.calls as u64));
            }
            Ok(())
        }
    }
    impl NativeDisplayPort for Native {
        fn observe(&mut self, _: ConnectorNumber) -> Result<Observation, ResourceError> {
            self.event(Event::Observe)?;
            Ok(self.observations.pop_front().unwrap_or(self.observation))
        }
        fn prepare(&mut self, configuration: u32) -> Result<(), ResourceError> {
            self.event(Event::Prepare(configuration))?;
            assert!(!self.enabled);
            Ok(())
        }
        fn enable(&mut self) -> Result<(), ResourceError> {
            self.event(Event::Enable)?;
            assert!(self.hardware.borrow().cam.is_some());
            self.enabled = true;
            Ok(())
        }
        fn hpd(&mut self, status: u32) -> Result<(), ResourceError> {
            self.event(Event::Hpd(status))?;
            assert!(self.enabled);
            Ok(())
        }
        fn disable(&mut self) -> Result<(), ResourceError> {
            self.event(Event::Disable)?;
            self.enabled = false;
            Ok(())
        }
    }
    struct Mux {
        hardware: Rc<RefCell<Hardware>>,
        calls: usize,
        fail_at: usize,
        fail_cleanup: bool,
    }
    impl Route for Mux {
        fn set_orientation(&mut self, orientation: Orientation) -> Result<(), mux::Error> {
            self.calls += 1;
            self.hardware
                .borrow_mut()
                .events
                .push(Event::Orientation(orientation));
            if self.calls == self.fail_at {
                Err(mux::Error::NeedsPlatformReset)
            } else {
                Ok(())
            }
        }
        fn set_mode(&mut self, mode: Mode) -> Result<(), mux::Error> {
            self.calls += 1;
            self.hardware.borrow_mut().events.push(Event::Mode(mode));
            if matches!(mode, Mode::DisplayPort(_)) {
                assert!(self.hardware.borrow().cam.is_some());
            }
            if self.calls == self.fail_at || self.fail_cleanup && mode == Mode::Safe {
                Err(mux::Error::NeedsPlatformReset)
            } else {
                Ok(())
            }
        }
    }
    type TestController = Controller<Ppm, Time>;
    fn setup() -> (TestController, Native, Mux, Rc<RefCell<Hardware>>) {
        let hardware = Rc::new(RefCell::new(Hardware::new()));
        let mut controller = Controller::new(Ppm(hardware.clone()), Time::default()).unwrap();
        controller.ready = true;
        controller.initialized = true;
        let mut raw = [0; 16];
        raw[4] = 1;
        raw[5] = (DETAILS | OVERRIDE) as u8;
        raw[8] = 1;
        controller.capability = Some(Capability::parse(&raw).unwrap());
        let native = Native {
            hardware: hardware.clone(),
            observation: Observation {
                attachment_epoch: 9,
                orientation: Orientation::Normal,
                partner_status: Some(2 | HPD | IRQ),
                status_sequence: 1,
            },
            observations: VecDeque::new(),
            calls: 0,
            fail_at: usize::MAX,
            fail_cleanup: false,
            enabled: false,
        };
        let mux = Mux {
            hardware: hardware.clone(),
            calls: 0,
            fail_at: usize::MAX,
            fail_cleanup: false,
        };
        (controller, native, mux, hardware)
    }
    fn connector() -> ConnectorNumber {
        ConnectorNumber::new(1).unwrap()
    }
    fn request() -> SourceRequest {
        SourceRequest {
            port_cam: 0,
            partner_mode: 0,
            cable_mode: None,
            pin: Pin::C,
            signalling: 1,
        }
    }
    fn session(controller: &mut TestController, native: &mut Native) -> Session {
        Session::new(Discovery::read(controller, connector(), native).unwrap())
    }
    #[test]
    fn raw_inventories_keep_duplicate_cam_indices_and_handle_two_entry_replies() {
        let (mut controller, mut native, _, hardware) = setup();
        let duplicate = hardware.borrow().modes[0][0];
        hardware.borrow_mut().modes[0].extend([duplicate, duplicate]);
        controller.capability.as_mut().unwrap().raw[8] = 3;
        let discovery = Discovery::read(&mut controller, connector(), &mut native).unwrap();
        assert_eq!(
            discovery
                .port
                .entries()
                .iter()
                .map(|m| m.index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(discovery.port.entries()[2].vdo, duplicate.vdo);
        let offsets: Vec<_> = hardware
            .borrow()
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Command(c) if *c as u8 == 0x0c && (c >> 16) & 7 == 0 => {
                    Some((c >> 32) & 255)
                }
                _ => None,
            })
            .collect();
        assert_eq!(offsets, [0, 2]);
    }
    #[test]
    fn inventory_bounds_short_entries_and_missing_optional_services_are_explicit() {
        for length in [1, 2, 3, 4, 5, 7, 8, 9, 10, 11] {
            let (mut controller, mut native, _, hardware) = setup();
            hardware.borrow_mut().malformed = Some(vec![1; length]);
            assert_eq!(
                Discovery::read(&mut controller, connector(), &mut native),
                Err(Error::InvalidResponse {
                    command: 0x0c,
                    bytes: length
                })
            );
        }
        let (mut controller, mut native, _, hardware) = setup();
        controller.capability.as_mut().unwrap().raw[8] = 31;
        assert_eq!(
            Discovery::read(&mut controller, connector(), &mut native),
            Err(Error::InvalidModeCount(31))
        );
        controller.capability.as_mut().unwrap().raw[8] = 1;
        let duplicate = hardware.borrow().modes[0][0];
        hardware.borrow_mut().modes[0].push(duplicate);
        assert_eq!(
            Discovery::read(&mut controller, connector(), &mut native),
            Err(Error::InvalidModeCount(2))
        );
        controller.capability.as_mut().unwrap().features = 0;
        assert_eq!(
            Discovery::read(&mut controller, connector(), &mut native),
            Err(Error::DetailsUnavailable)
        );
    }
    #[test]
    fn cam_configuration_commits_before_route_enable_and_real_hpd_then_exits_exact_cam() {
        let (mut controller, mut native, mut mux, hardware) = setup();
        let mut session = self::session(&mut controller, &mut native);
        hardware.borrow_mut().events.clear();
        let configuration = session
            .configure(&mut controller, &mut native, &mut mux, request())
            .unwrap();
        assert_eq!(configuration.raw, 0x406);
        assert_eq!(session.state(), State::Configured(configuration));
        assert!(native.enabled);
        let events = &hardware.borrow().events.clone();
        let set = events
            .iter()
            .position(|e| *e == Event::Command(0x406_0081_000f))
            .unwrap();
        let route = events
            .iter()
            .position(|e| matches!(e, Event::Mode(Mode::DisplayPort(_))))
            .unwrap();
        let readback = events
            .iter()
            .enumerate()
            .find(|(i, e)| *i > set && **e == Event::Command(0x1000e))
            .unwrap()
            .0;
        let enable = events.iter().position(|e| *e == Event::Enable).unwrap();
        let hpd = events
            .iter()
            .position(|e| *e == Event::Hpd(2 | HPD | IRQ))
            .unwrap();
        assert!(set < readback && readback < route && route < enable && enable < hpd);
        session
            .exit(&mut controller, &mut native, &mut mux)
            .unwrap();
        assert_eq!(session.state(), State::Idle);
        assert_eq!(session.observed_cam(), Some(None));
        assert!(!native.enabled);
        assert!(hardware.borrow().events.contains(&Event::Command(0x1000f)));
    }
    #[test]
    fn accepted_new_cam_without_matching_readback_never_programs_active_route_or_output() {
        let (mut controller, mut native, mut mux, hardware) = setup();
        let mut session = self::session(&mut controller, &mut native);
        hardware.borrow_mut().apply = false;
        assert_eq!(
            session.configure(&mut controller, &mut native, &mut mux, request()),
            Err(Error::CamMismatch {
                expected: Some(0),
                actual: None
            })
        );
        assert_eq!(session.state(), State::Faulted);
        assert!(!native.enabled);
        assert!(!hardware.borrow().events.iter().any(|e| matches!(
            e,
            Event::Enable | Event::Hpd(_) | Event::Mode(Mode::DisplayPort(_))
        )));
        assert_eq!(
            session.configure(&mut controller, &mut native, &mut mux, request()),
            Err(Error::Faulted)
        );
        session
            .exit(&mut controller, &mut native, &mut mux)
            .unwrap();
        assert_eq!(session.state(), State::Idle);
    }
    #[test]
    fn unsupported_and_firmware_owned_modes_do_not_publish_control_or_touch_other_cam() {
        for (status, expected) in [
            (None, Error::StatusUnavailable),
            (Some(2 | IRQ), Error::InvalidStatus(2 | IRQ)),
            (Some(2 | 64), Error::PartnerRequestsExit(2 | 64)),
        ] {
            let (mut controller, mut native, mut mux, hardware) = setup();
            let mut session = self::session(&mut controller, &mut native);
            native.observation.partner_status = status;
            hardware.borrow_mut().events.clear();
            assert_eq!(
                session.configure(&mut controller, &mut native, &mut mux, request()),
                Err(expected)
            );
            assert!(!hardware.borrow().events.iter().any(|e| (matches!(
                e,
                Event::Disable | Event::Prepare(_) | Event::Mode(_)
            ) || matches!(e,Event::Command(c) if *c as u8==0x0f))));
        }
        let (mut controller, mut native, mut mux, hardware) = setup();
        controller.capability.as_mut().unwrap().features = DETAILS;
        let mut session = self::session(&mut controller, &mut native);
        hardware.borrow_mut().events.clear();
        assert_eq!(
            session.configure(&mut controller, &mut native, &mut mux, request()),
            Err(Error::OverrideUnavailable)
        );
        assert!(hardware.borrow().events.is_empty());
        session.discovery.override_supported = true;
        hardware.borrow_mut().cam = Some(4);
        hardware.borrow_mut().events.clear();
        assert_eq!(
            session.configure(&mut controller, &mut native, &mut mux, request()),
            Err(Error::CamBusy(4))
        );
        assert!(
            !hardware
                .borrow()
                .events
                .iter()
                .any(|e| matches!(e, Event::Disable | Event::Mode(_) | Event::Prepare(_)))
        );
    }
    #[test]
    fn detach_reattach_and_ucsi_reset_never_reuse_discovered_caps_or_program_new_owner() {
        let (mut controller, mut native, mut mux, hardware) = setup();
        let mut session = self::session(&mut controller, &mut native);
        let mut changed = native.observation;
        changed.attachment_epoch += 1;
        native
            .observations
            .extend([native.observation, native.observation, changed]);
        hardware.borrow_mut().events.clear();
        assert_eq!(
            session.configure(&mut controller, &mut native, &mut mux, request()),
            Err(Error::StaleAttachment)
        );
        assert_eq!(session.state(), State::Faulted);
        assert_eq!(session.cleanup_errors(), [Error::StaleAttachment]);
        assert!(!hardware.borrow().events.iter().any(|e| matches!(
            e,
            Event::Enable | Event::Hpd(_) | Event::Mode(Mode::DisplayPort(_))
        )));
        let count = hardware.borrow().events.len();
        controller.generation += 1;
        assert_eq!(
            session.exit(&mut controller, &mut native, &mut mux),
            Err(Error::StaleAttachment)
        );
        assert_eq!(hardware.borrow().events.len(), count);
    }
    #[test]
    fn every_native_and_route_failure_quiesces_and_retains_original_and_cleanup_errors() {
        let (mut controller, mut native, mut mux, _) = setup();
        let mut first = self::session(&mut controller, &mut native);
        native.calls = 0;
        first
            .configure(&mut controller, &mut native, &mut mux, request())
            .unwrap();
        let native_calls = native.calls;
        for point in 2..=native_calls {
            let (mut controller, mut native, mut mux, _) = setup();
            let mut session = self::session(&mut controller, &mut native);
            native.calls = 0;
            native.fail_at = point;
            let result = session.configure(&mut controller, &mut native, &mut mux, request());
            assert!(result.is_err(), "point {point}");
            assert_eq!(session.state(), State::Faulted);
            assert!(!native.enabled);
            assert!(matches!(session.fault(), Some(Error::Platform(_))));
        }
        for point in 1..=3 {
            let (mut controller, mut native, mut mux, _) = setup();
            let mut session = self::session(&mut controller, &mut native);
            mux.fail_at = point;
            native.fail_cleanup = point != 1;
            assert!(matches!(
                session.configure(&mut controller, &mut native, &mut mux, request()),
                Err(Error::Route(_)) | Err(Error::Platform(_))
            ));
            assert_eq!(session.state(), State::Faulted);
        }
        let (mut controller, mut native, mut mux, _) = setup();
        let mut session = self::session(&mut controller, &mut native);
        native.calls = 0;
        native.fail_at = 3;
        mux.fail_cleanup = true;
        assert!(matches!(
            session.configure(&mut controller, &mut native, &mut mux, request()),
            Err(Error::Route(_))
        ));
        assert!(!session.cleanup_errors().is_empty());
    }
    #[test]
    fn uncertain_ucsi_publication_cannot_enable_or_replay_and_keeps_actual_cam_distinct() {
        for after in [false, true] {
            let (mut controller, mut native, mut mux, hardware) = setup();
            let mut session = self::session(&mut controller, &mut native);
            let before = hardware.borrow().calls;
            hardware.borrow_mut().fail_at = before + 7;
            hardware.borrow_mut().fail_after = after;
            assert!(
                session
                    .configure(&mut controller, &mut native, &mut mux, request())
                    .is_err()
            );
            assert_eq!(session.state(), State::Faulted);
            assert!(!native.enabled);
            let count = hardware.borrow().events.len();
            assert_eq!(
                session.configure(&mut controller, &mut native, &mut mux, request()),
                Err(Error::Faulted)
            );
            assert_eq!(hardware.borrow().events.len(), count);
        }
    }
    #[test]
    fn active_cable_requires_real_mode_and_common_signals_pins_are_never_union_expanded() {
        let (mut controller, mut native, _, hardware) = setup();
        hardware.borrow_mut().cable[3] = 34;
        let discovery = Discovery::read(&mut controller, connector(), &mut native).unwrap();
        assert_eq!(
            discovery.source_configuration(request()),
            Err(Error::UnsupportedConfiguration)
        );
        hardware.borrow_mut().modes[2].push(AlternateMode {
            index: 0,
            svid: DP_SVID,
            vdo: 4 | (8 << 16),
        });
        let discovery = Discovery::read(&mut controller, connector(), &mut native).unwrap();
        let mut req = request();
        req.cable_mode = Some(0);
        assert_eq!(
            discovery.source_configuration(req),
            Err(Error::UnsupportedConfiguration)
        );
        req.pin = Pin::D;
        assert_eq!(discovery.source_configuration(req).unwrap().raw, 0x806);
        for local in 0u32..16 {
            for partner in 0u32..16 {
                for cable in 0u32..16 {
                    let mut discovery = discovery.clone();
                    discovery.port.entries[0].vdo = 2 | 4 | 64 | (local << 10);
                    discovery.partner.entries[0].vdo = 1 | 4 | 64 | (partner << 18);
                    discovery.cable_modes.as_mut().unwrap().entries[0].vdo = 4 | (cable << 18);
                    for (bit, pin) in [Pin::C, Pin::D, Pin::E, Pin::F].into_iter().enumerate() {
                        req.pin = pin;
                        assert_eq!(
                            discovery.source_configuration(req).is_ok(),
                            local & partner & cable & (1 << bit) != 0
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn current_cam_change_and_partner_exit_quiesce_configured_route_before_any_more_hpd() {
        for changed_cam in [false, true] {
            let (mut controller, mut native, mut mux, hardware) = setup();
            let mut session = self::session(&mut controller, &mut native);
            session
                .configure(&mut controller, &mut native, &mut mux, request())
                .unwrap();
            hardware.borrow_mut().events.clear();
            if changed_cam {
                hardware.borrow_mut().cam = Some(2);
            } else {
                native.observation.partner_status = Some(2 | 32);
            }
            assert!(
                session
                    .update(&mut controller, &mut native, &mut mux)
                    .is_err()
            );
            assert_eq!(session.state(), State::Faulted);
            assert!(!native.enabled);
            assert!(
                !hardware
                    .borrow()
                    .events
                    .iter()
                    .any(|e| matches!(e, Event::Hpd(_)))
            );
        }
    }
    #[test]
    fn actual_status_sequences_deliver_each_hpd_irq_once_and_reject_stale_or_changed_events() {
        let (mut controller, mut native, mut mux, hardware) = setup();
        let mut session = self::session(&mut controller, &mut native);
        session
            .configure(&mut controller, &mut native, &mut mux, request())
            .unwrap();
        hardware.borrow_mut().events.clear();
        session
            .update(&mut controller, &mut native, &mut mux)
            .unwrap();
        assert!(hardware.borrow().events.contains(&Event::Hpd(2 | HPD)));
        assert!(
            !hardware
                .borrow()
                .events
                .contains(&Event::Hpd(2 | HPD | IRQ))
        );
        native.observation.status_sequence += 1;
        hardware.borrow_mut().events.clear();
        session
            .update(&mut controller, &mut native, &mut mux)
            .unwrap();
        assert!(
            hardware
                .borrow()
                .events
                .contains(&Event::Hpd(2 | HPD | IRQ))
        );
        native.observation.status_sequence -= 1;
        assert_eq!(
            session.update(&mut controller, &mut native, &mut mux),
            Err(Error::StaleStatus {
                previous: 2,
                actual: 1
            })
        );
        let (mut controller, mut native, mut mux, _) = setup();
        let mut session = self::session(&mut controller, &mut native);
        session
            .configure(&mut controller, &mut native, &mut mux, request())
            .unwrap();
        native.observation.partner_status = Some(2);
        assert_eq!(
            session.update(&mut controller, &mut native, &mut mux),
            Err(Error::ChangedStatusWithoutEvent)
        );
    }

    #[test]
    #[ignore = "requires pinned unchanged Linux DP helper and CAM macro trace"]
    fn unchanged_linux_dp_source_and_cam_oracle() {
        let trace =
            std::fs::read_to_string(std::env::var("STELA_UCSI_DP_ORACLE").unwrap()).unwrap();
        let (mut controller, mut native, _, _) = setup();
        let base = Discovery::read(&mut controller, connector(), &mut native).unwrap();
        let mut counts = [0; 2];
        for line in trace.lines() {
            let parts: Vec<_> = line.split_whitespace().collect();
            let dec = |i: usize| parts[i].parse::<u32>().unwrap();
            let hex = |i: usize| u32::from_str_radix(parts[i], 16).unwrap();
            match parts[0] {
                "D" => {
                    let mut discovery = base.clone();
                    discovery.port.entries[0].vdo = hex(1);
                    discovery.partner.entries[0].vdo = hex(2);
                    let active = dec(3) != 0;
                    discovery.cable.raw[3] = 32 | if active { 2 } else { 0 };
                    discovery.cable_modes = if active {
                        Some(Modes {
                            recipient: Recipient::CablePlug,
                            entries: vec![AlternateMode {
                                index: 0,
                                svid: DP_SVID,
                                vdo: hex(4),
                            }],
                        })
                    } else {
                        None
                    };
                    let mut signal = ((hex(1) >> 2) & 15) & ((hex(2) >> 2) & 15);
                    if active {
                        signal &= (hex(4) >> 2) & 15;
                    }
                    let mut req = request();
                    req.pin = [Pin::C, Pin::D, Pin::E, Pin::F][dec(5) as usize - 2];
                    req.signalling = signal as u8;
                    req.cable_mode = if active { Some(0) } else { None };
                    let result = discovery.source_configuration(req);
                    if parts[6] == "0" && signal != 0 {
                        assert_eq!(result.unwrap().raw, hex(7), "{line}");
                    } else {
                        assert_eq!(result, Err(Error::UnsupportedConfiguration), "{line}");
                    }
                    counts[0] += 1;
                }
                "C" => {
                    let command = Command::new_cam_configuration(
                        ConnectorNumber::new(dec(1) as u8).unwrap(),
                        dec(2) as u8,
                        dec(3) != 0,
                        hex(4),
                    );
                    assert_eq!(
                        command.control(),
                        u64::from_str_radix(parts[5], 16).unwrap(),
                        "{line}"
                    );
                    counts[1] += 1;
                }
                _ => panic!("{line}"),
            }
        }
        assert_eq!(counts, [23040, 53340]);
    }
    #[test]
    fn exact_nonzero_cam_is_exited_and_foreign_cam_never_receives_cleanup_writes() {
        let (mut controller, mut native, mut mux, hardware) = setup();
        let local = hardware.borrow().modes[0][0];
        hardware.borrow_mut().modes[0].extend([local; 3]);
        controller.capability.as_mut().unwrap().raw[8] = 4;
        let mut session = self::session(&mut controller, &mut native);
        let mut req = request();
        req.port_cam = 3;
        session
            .configure(&mut controller, &mut native, &mut mux, req)
            .unwrap();
        session
            .exit(&mut controller, &mut native, &mut mux)
            .unwrap();
        assert!(
            hardware
                .borrow()
                .events
                .contains(&Event::Command(0x0301000f))
        );
        session
            .configure(&mut controller, &mut native, &mut mux, req)
            .unwrap();
        hardware.borrow_mut().cam = Some(2);
        hardware.borrow_mut().events.clear();
        assert_eq!(
            session.exit(&mut controller, &mut native, &mut mux),
            Err(Error::CamBusy(2))
        );
        assert_eq!(session.cleanup_errors(), [Error::CamBusy(2)]);
        assert!(!hardware.borrow().events.iter().any(|e| matches!(
            e,
            Event::Disable | Event::Mode(_) | Event::Prepare(_) | Event::Enable | Event::Hpd(_)
        )));
    }
}
