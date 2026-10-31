// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Original-owner cold unassociated MAC allocation, power and beacon filter.
//! No PHY binding, station or data queue is created by this continuation.
use super::*;
use crate::wifi::intel::command::Id;
mod mld;
const MAC_CONTEXT: Id = Id {
    group: 0,
    opcode: 0x28,
    version: 0,
};
const MAC_POWER: Id = Id {
    group: 0,
    opcode: 0xa9,
    version: 0,
};
const BEACON_FILTER: Id = Id {
    group: 0,
    opcode: 0xd2,
    version: 0,
};
const MAC_CONTEXT_BYTES: usize = 148;
const BEACON_FILTER_V4_API: u32 = 47;
const ACTION_ADD: u32 = 1;
const ACTION_REMOVE: u32 = 3;
const MAC_TYPE_BSS_STATION: u32 = 5;
const ACCEPT_GROUP: u32 = 1 << 2;
const ACCEPT_BEACON: u32 = 1 << 6;
const COLD_CCK_BASIC_RESPONSES: u32 = 0xf;
const COLD_OFDM_BASIC_RESPONSES: u32 = (1 << 0) | (1 << 2) | (1 << 4);
const KEEP_ALIVE_SECONDS: u16 = 25;
pub(in crate::wifi::intel::boot::ax200) fn cold_power_bytes(
    version: u8,
    mode: PowerMode,
) -> Vec<u8> {
    let mut bytes = alloc::vec![0; crate::wifi::intel::association::power_bytes(version)];
    bytes[4..6].copy_from_slice(&u16::from(mode == PowerMode::SavePower).to_le_bytes());
    bytes[6..8].copy_from_slice(&KEEP_ALIVE_SECONDS.to_le_bytes());
    bytes
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacCommandKind {
    Add,
    Power,
    DisableBeaconFilter,
    AddInactiveLink,
    RemoveInactiveLink,
    Remove,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacCommand {
    kind: MacCommandKind,
    id: Id,
    bytes: Vec<u8>,
}
impl MacCommand {
    pub fn kind(&self) -> MacCommandKind {
        self.kind
    }
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200MacPhase {
    NotStarted,
    Waiting(MacCommandKind),
    ScanRequired,
    Removed,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200MacError {
    Boot(Error),
    Country(Ax200CountryError),
    MldContinuationRequired,
    MissingApi(MacCommandKind),
    Version { kind: MacCommandKind, version: u8 },
    Deadline(MacCommandKind),
    State,
}
pub struct Ax200Mac<'a, Q: BootIo, B: BiosIo, O: CountryIo> {
    pub(in crate::wifi::intel::boot) country: Ax200Country<'a, Q, B, O>,
    phase: Ax200MacPhase,
    commands: Vec<MacCommand>,
    next: usize,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    uploaded: bool,
    mld: bool,
    link_uploaded: bool,
    removing: bool,
    first_error: Option<Ax200MacError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo> Ax200Country<'a, Q, B, O> {
    /// Allocate the first and only cold managed interface, with NVM MAC.
    /// No reset/import path can reconstruct this owner from public diagnostics.
    pub fn begin_mac_context(self) -> Result<Ax200Mac<'a, Q, B, O>, Box<Self>> {
        if self.phase() != Ax200CountryPhase::MacContextRequired
            || self.first_error().is_some()
            || self.board.scan.mcc.setup.lari.radio.initialized.boot.state != State::PnvmObserved
        {
            return Err(Box::new(self));
        }
        Ok(Ax200Mac {
            country: self,
            phase: Ax200MacPhase::NotStarted,
            commands: Vec::new(),
            next: 0,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            uploaded: false,
            mld: false,
            link_uploaded: false,
            removing: false,
            first_error: None,
        })
    }
    /// Original cap110-selected cold MLD MAC0 and inactive link0. This keeps
    /// its separate protocol identity; no legacy BINDING command may consume
    /// it. The same initialized NVM, country, requester and OS owner survive.
    pub fn begin_mld_mac_context(self) -> Result<Ax200Mac<'a, Q, B, O>, Box<Self>> {
        self.begin_mac_context().map(|mut mac| {
            mac.mld = true;
            mac
        })
    }
}
impl<Q: BootIo, B: BiosIo, O: CountryIo> Ax200Mac<'_, Q, B, O> {
    pub fn phase(&self) -> Ax200MacPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200MacError> {
        self.first_error.as_ref()
    }
    pub fn commands(&self) -> &[MacCommand] {
        &self.commands
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    /// Source first available MAC0/color0 and TSF_A. This historical object ID
    /// is not a station, PHY binding, queue or permission to publish radio work.
    pub fn mac_id_and_color(&self) -> Option<u32> {
        self.uploaded.then_some(0)
    }
    pub fn is_mld(&self) -> bool {
        self.mld
    }
    /// Acknowledged inactive link identity, not activation or permission to TX.
    pub fn inactive_link_id(&self) -> Option<u8> {
        (self.mld && self.link_uploaded && !self.removing).then_some(0)
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.country.initialized_nvm()
    }
    pub fn country(&self) -> Option<&crate::wifi::regulatory::database::Country> {
        self.country.country()
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.country.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(match error {
                Ax200MacError::Boot(error) => error.clone(),
                _ => Error::State,
            });
        }
        let result = self.country.replenish_completed_receive();
        if let Err(error) = &result {
            self.first_error
                .get_or_insert_with(|| Ax200MacError::Boot(error.clone()));
            self.phase = Ax200MacPhase::Failed;
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.country.stop() {
            Ok(()) => {
                self.phase = Ax200MacPhase::Stopped;
                self.uploaded = false;
                self.link_uploaded = false;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200MacError::Boot(error.clone()));
                self.phase = Ax200MacPhase::Failed;
                Err(error)
            }
        }
    }
    fn prepare(&mut self) -> Result<(), Ax200MacError> {
        if self.mld {
            return mld::prepare(self);
        }
        let fw = &self
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
            .firmware;
        // Original ops.c selects the MLD MAC/link operations from cap110.
        // Advertising legacy command bytes does not admit that old owner.
        if fw.supports_capability(110) {
            return Err(Ax200MacError::MldContinuationRequired);
        }
        for (kind, id, versions) in [
            (MacCommandKind::Add, MAC_CONTEXT, &[5][..]),
            (MacCommandKind::Power, MAC_POWER, &[1, 2][..]),
            (
                MacCommandKind::DisableBeaconFilter,
                BEACON_FILTER,
                &[3, 4][..],
            ),
        ] {
            let v = fw
                .command_version(id.wire().group, id.opcode)
                .ok_or(Ax200MacError::MissingApi(kind))?
                .command_version;
            if !versions.contains(&v) {
                return Err(Ax200MacError::Version { kind, version: v });
            }
        }
        let filter_v4 = fw.supports_api(BEACON_FILTER_V4_API);
        let filter_version = fw
            .command_version(1, BEACON_FILTER.opcode)
            .unwrap()
            .command_version;
        if filter_v4 != (filter_version == 4) {
            return Err(Ax200MacError::Version {
                kind: MacCommandKind::DisableBeaconFilter,
                version: filter_version,
            });
        }
        let mut bytes = alloc::vec![0; MAC_CONTEXT_BYTES];
        bytes[4..8].copy_from_slice(&ACTION_ADD.to_le_bytes());
        bytes[8..12].copy_from_slice(&MAC_TYPE_BSS_STATION.to_le_bytes());
        bytes[16..22].copy_from_slice(&self.initialized_nvm().address.bytes);
        bytes[24..30].fill(0xff);
        // Source cold basic_rates==0 closure includes mandatory responses.
        // The object remains unassociated and unbound: this is no ACK/RF grant.
        bytes[32..36].copy_from_slice(&COLD_CCK_BASIC_RESPONSES.to_le_bytes());
        bytes[36..40].copy_from_slice(&COLD_OFDM_BASIC_RESPONSES.to_le_bytes());
        bytes[52..56].copy_from_slice(&(ACCEPT_GROUP | ACCEPT_BEACON).to_le_bytes());
        // Cold software QoS parameters are zero; the source nevertheless sets
        // each legacy AC's Gen2 FIFO bit. AC order is BK,BE,VI,VO; fifth is zero.
        for ac in 0..4 {
            bytes[60 + ac * 8 + 5] = 1 << (ac + 1);
        }
        // Associated-only fields, HE/TWT, QoS and all union padding stay zero.
        self.commands.push(MacCommand {
            kind: MacCommandKind::Add,
            id: MAC_CONTEXT,
            bytes,
        });
        let bytes = cold_power_bytes(2, self.country.board.scan.mcc.setup.options.power_mode);
        self.commands.push(MacCommand {
            kind: MacCommandKind::Power,
            id: MAC_POWER,
            bytes,
        });
        self.commands.push(MacCommand {
            kind: MacCommandKind::DisableBeaconFilter,
            id: BEACON_FILTER,
            bytes: alloc::vec![0; if filter_v4 { 60 } else { 44 }],
        });
        Ok(())
    }
    /// Remove the unbound MAC without a new country/RF admission. The
    /// original command owner still enforces source RF-kill policy; hardware
    /// stop remains available if revocation, RF-kill or faults prevent removal.
    pub fn begin_remove(&mut self) -> Result<(), Ax200MacError> {
        if self.first_error.is_some()
            || self.phase != Ax200MacPhase::ScanRequired
            || !self.uploaded
            || self.ticket.is_some()
            || self.removing
        {
            return Err(Ax200MacError::State);
        }
        if self.mld {
            if !self.link_uploaded {
                return Err(Ax200MacError::State);
            }
            let commands = mld::removal(self);
            self.commands.extend(commands);
            self.removing = true;
            return Ok(());
        }
        let mut bytes = alloc::vec![0; MAC_CONTEXT_BYTES];
        bytes[4..8].copy_from_slice(&ACTION_REMOVE.to_le_bytes());
        self.commands.push(MacCommand {
            kind: MacCommandKind::Remove,
            id: MAC_CONTEXT,
            bytes,
        });
        self.removing = true;
        Ok(())
    }
    /// Advance only from same-owner completed command DMA and CPU reclaim.
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the native
    /// requester/domain under RomBoot's complete publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200MacPhase, Ax200MacError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: exact caller publication contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200MacError::Boot(Error::CommandReclaim(_)))
        {
            self.first_error = Some(error.clone());
            self.phase = Ax200MacPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200MacPhase, Ax200MacError> {
        if self
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
            .state
            != State::PnvmObserved
        {
            return Err(Ax200MacError::State);
        }
        if !self.removing {
            self.country
                .check_selection()
                .map_err(Ax200MacError::Country)?;
        }
        if self.phase == Ax200MacPhase::Removed
            || (self.phase == Ax200MacPhase::ScanRequired && !self.removing)
        {
            self.country
                .board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_one_notification_buffer()
                .map_err(Ax200MacError::Boot)?;
            return Ok(self.phase);
        }
        if self.phase == Ax200MacPhase::NotStarted {
            self.prepare()?;
        }
        if let Some(ticket) = self.ticket.as_ref() {
            let command = &self.commands[self.next - 1];
            let progress = self
                .country
                .board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_command(ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200MacError::Deadline(command.kind));
            }
            match progress.map_err(Ax200MacError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200MacError::Deadline(command.kind));
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let valid = response.command == command.id.opcode
                        && response.group == command.id.wire().group;
                    let (command_id, group) = (response.command, response.group);
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    if !valid {
                        return Err(Ax200MacError::Boot(Error::InitializationResponse {
                            command: command_id,
                            group,
                        }));
                    }
                    if command.kind == MacCommandKind::Add {
                        self.uploaded = true;
                    }
                    if command.kind == MacCommandKind::Remove {
                        self.uploaded = false;
                    }
                    if command.kind == MacCommandKind::AddInactiveLink {
                        self.link_uploaded = true;
                    }
                    if command.kind == MacCommandKind::RemoveInactiveLink {
                        self.link_uploaded = false;
                    }
                }
            }
        }
        let Some(command) = self.commands.get(self.next) else {
            self.phase = if self.removing {
                Ax200MacPhase::Removed
            } else {
                Ax200MacPhase::ScanRequired
            };
            return Ok(self.phase);
        };
        // SAFETY: original private unbound MAC object; no PHY binding or data
        // queue publication, and no indirect resources; source RF-kill enforced.
        self.ticket = Some(
            unsafe {
                self.country
                    .board
                    .scan
                    .mcc
                    .setup
                    .lari
                    .radio
                    .initialized
                    .boot
                    .submit_command(command.id, &command.bytes, source)
            }
            .map_err(Ax200MacError::Boot)?,
        );
        let options = self.country.board.scan.mcc.setup.options;
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        self.next += 1;
        self.phase = Ax200MacPhase::Waiting(command.kind);
        Ok(self.phase)
    }
}
