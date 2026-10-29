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
mod tests;
