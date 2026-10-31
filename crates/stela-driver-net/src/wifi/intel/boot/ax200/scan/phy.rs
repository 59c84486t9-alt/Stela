// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Original-owner unbound PHY0 and its complete RX-chain configuration.
//! No MAC binding, autonomous response, station or data queue is created.
use super::*;
use crate::wifi::station::{operations::ChannelDefinition, phy::Width};
use regulatory::Operation;
mod tx_power;
pub use tx_power::{
    Ax200Binding, Ax200BindingError, Ax200BindingPhase, Ax200Coexistence, Ax200CoexistenceError,
    Ax200CoexistencePhase, Ax200LegacyPeer, Ax200LegacyPeerError, Ax200LegacyPeerPhase,
    Ax200ManagementQueue, Ax200ManagementQueueError, Ax200ManagementQueuePhase, Ax200TransmitPower,
    Ax200TransmitPowerError, Ax200TransmitPowerPhase, BindingCommand, BindingCommandKind,
    LegacyPeer, PeerCommand, PeerCommandKind, TransmitPowerLimit,
};

const PHY: Id = Id {
    group: 0,
    opcode: 8,
    version: 0,
};
const RLC: Id = Id {
    group: 5,
    opcode: 8,
    version: 2,
};
/// The first PHY context versions with a secondary control channel and a
/// puncturing mask.
const SECONDARY_CONTROL: u8 = 5;
const PUNCTURING: u8 = 6;
/// `IWL_PHY_CTRL_POS_ABOVE`.
const CONTROL_ABOVE: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhyCommandKind {
    Add,
    ReceiveChains,
    Modify,
    Remove,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhyCommand {
    kind: PhyCommandKind,
    id: Id,
    bytes: [u8; 32],
}
impl PhyCommand {
    pub fn kind(&self) -> PhyCommandKind {
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
pub enum Ax200PhyPhase {
    NotStarted,
    Waiting(PhyCommandKind),
    BindingRequired,
    Removed,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200PhyError {
    Boot(Error),
    Scan(Ax200ScanError),
    Country(Ax200CountryError),
    Regulatory(regulatory::Error),
    MissingApi,
    Version(u8),
    MissingPhySku,
    Antennas,
    Deadline(PhyCommandKind),
    State,
}
pub struct Ax200Phy<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> {
    pub(in crate::wifi::intel::boot) scan: Ax200Scan<'a, Q, B, O>,
    channel: Channel,
    phase: Ax200PhyPhase,
    commands: Vec<PhyCommand>,
    next: usize,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    removing: bool,
    first_error: Option<Ax200PhyError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Scan<'a, Q, B, O> {
    /// Move only the idle original scan owner. A pending or retiring request,
    /// including its deferred RX users, cannot become a PHY configuration.
    /// The channel remains an input until hardware and OS admission.
    pub fn begin_phy_context(self, channel: Channel) -> Result<Ax200Phy<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200ScanPhase::NotStarted
            || self.scanner.phase() != protocol::Phase::Idle
            || self.first_error.is_some()
            || self.scan_ticket.is_some()
            || self.command_ticket.is_some()
            || Arc::strong_count(&self.users) != 1
            || self.mac.phase() != Ax200MacPhase::ScanRequired
            || self.mac.mac_id_and_color() != Some(0)
        {
            return Err(Box::new(self));
        }
        Ok(Ax200Phy {
            scan: self,
            channel,
            phase: Ax200PhyPhase::NotStarted,
            commands: Vec::new(),
            next: 0,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            removing: false,
            first_error: None,
        })
    }
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Phy<'a, Q, B, O> {
    fn boot(&mut self) -> &mut RomBoot<'a, Q> {
        &mut self
            .scan
            .mac
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
    }
    pub fn phase(&self) -> Ax200PhyPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200PhyError> {
        self.first_error.as_ref()
    }
    pub fn channel(&self) -> Channel {
        self.channel
    }
    pub fn commands(&self) -> &[PhyCommand] {
        &self.commands
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    /// Only the complete ADD + required RLC acknowledgement/reclaim yields an
    /// allocated unbound PHY. This never grants association or transmission.
    pub fn phy_id_and_color(&self) -> Option<u32> {
        (self.phase == Ax200PhyPhase::BindingRequired).then_some(0)
    }
    /// `iwl_mvm_phy_ctxt_changed`: the commands that widen the bound context
    /// to `definition`, or none for a width firmware does not take.
    pub(in crate::wifi::intel::boot) fn changed(
        &mut self,
        definition: &ChannelDefinition,
        wide_ofdma: Option<&ChannelDefinition>,
    ) -> Option<Vec<PhyCommand>> {
        let firmware = &self.boot().firmware;
        let ultra_high_band = firmware.supports_capability(48);
        let version = firmware
            .command_version(PHY.wire().group, PHY.opcode)?
            .command_version;
        let add = self.commands.first()?;
        let modified = modified(add, definition, wide_ofdma, version, ultra_high_band)?;
        let chains = self.commands.get(1).cloned();
        Some(core::iter::once(modified).chain(chains).collect())
    }
    pub fn take_other_notification(&mut self) -> Option<FirmwareNotification> {
        self.scan.take_other_notification()
    }
    pub fn poll_receive(&mut self) -> Result<MpduProgress, Ax200PhyError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        let result = self
            .scan
            .poll_pre_scan_receive()
            .map_err(Ax200PhyError::Scan);
        if let Err(error @ Ax200PhyError::Scan(Ax200ScanError::Boot(_))) = &result {
            self.first_error = Some(error.clone());
            self.phase = Ax200PhyPhase::Failed;
        }
        result
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Ax200PhyError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        let result = self
            .scan
            .replenish_completed_receive()
            .map_err(Ax200PhyError::Boot);
        if let Err(error) = &result {
            self.first_error = Some(error.clone());
            self.phase = Ax200PhyPhase::Failed;
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.scan.stop() {
            Ok(()) => {
                self.phase = Ax200PhyPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200PhyError::Boot(error.clone()));
                self.phase = Ax200PhyPhase::Failed;
                Err(error)
            }
        }
    }
    fn prepare(&mut self) -> Result<(), Ax200PhyError> {
        let setup = &self.scan.mac.country.board.scan.mcc.setup;
        self.commands = configuration(
            &setup.lari.radio.initialized.boot.firmware,
            self.scan.mac.initialized_nvm().information.rx_chains,
            self.channel,
            setup.options.power_mode,
        )?;
        Ok(())
    }
    /// Remove the original unbound PHY even after country revocation. Source
    /// RF-kill command policy still applies; native stop remains independent.
    pub fn begin_remove(&mut self) -> Result<(), Ax200PhyError> {
        if self.phase != Ax200PhyPhase::BindingRequired
            || self.first_error.is_some()
            || self.ticket.is_some()
            || self.removing
        {
            return Err(Ax200PhyError::State);
        }
        let mut command = self.commands[0].clone();
        command.kind = PhyCommandKind::Remove;
        command.bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
        self.commands.push(command);
        self.removing = true;
        Ok(())
    }
    /// Return the scan owner once the firmware removed the PHY.
    pub fn into_scan(self) -> Result<Ax200Scan<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200PhyPhase::Removed
            || self.first_error.is_some()
            || self.ticket.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(self.scan)
    }
    fn capture_idle_receive(&mut self) -> Result<(), Ax200PhyError> {
        let boot = self.boot();
        let mut quiet = false;
        for _ in 0..=boot.entries {
            match boot
                .poll_one_notification_buffer()
                .map_err(Ax200PhyError::Boot)?
            {
                NotificationPoll::Pending => {
                    quiet = true;
                    break;
                }
                NotificationPoll::Processed => (),
                NotificationPoll::Backpressure => break,
            }
        }
        if !quiet {
            return Err(Ax200PhyError::Scan(Ax200ScanError::ReceiveBackpressure {
                notifications: boot.hcmd.notification_count(),
            }));
        }
        if boot
            .hcmd
            .has_matching(wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP)
            || boot.hcmd.has_matching(0xc9, 0)
        {
            return Err(Ax200PhyError::Scan(Ax200ScanError::StaleNotification));
        }
        if boot.hcmd.has_matching(0xc1, 0) {
            return Err(Ax200PhyError::Scan(Ax200ScanError::PreScanReceiveRequired));
        }
        Ok(())
    }
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the native
    /// requester/domain under RomBoot's complete publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200PhyPhase, Ax200PhyError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: unchanged original requester/domain page-source contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200PhyError::Boot(Error::CommandReclaim(_)))
            && !(self.next == 0
                && matches!(
                    error,
                    Ax200PhyError::Regulatory(_)
                        | Ax200PhyError::Scan(Ax200ScanError::PreScanReceiveRequired)
                        | Ax200PhyError::Scan(Ax200ScanError::ReceiveBackpressure { .. })
                ))
        {
            self.first_error = Some(error.clone());
            self.phase = Ax200PhyPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200PhyPhase, Ax200PhyError> {
        if let Some(error) = self.scan.first_error.as_ref() {
            return Err(Ax200PhyError::Scan(error.clone()));
        }
        if self.boot().state != State::PnvmObserved {
            return Err(Ax200PhyError::State);
        }
        if !self.removing {
            self.scan
                .mac
                .country
                .check_selection()
                .map_err(Ax200PhyError::Country)?;
        }
        if matches!(
            self.phase,
            Ax200PhyPhase::BindingRequired | Ax200PhyPhase::Removed
        ) && !self.removing
        {
            return Ok(self.phase);
        }
        if self.commands.is_empty() {
            self.prepare()?;
        }
        if let Some(ticket) = self.ticket.clone() {
            let kind = self.commands[self.next - 1].kind;
            let progress = self.boot().poll_command(&ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200PhyError::Deadline(kind));
            }
            match progress.map_err(Ax200PhyError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200PhyError::Deadline(kind));
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let command = &self.commands[self.next - 1];
                    let valid = response.command == command.id.opcode
                        && response.group == command.id.wire().group;
                    let (command, group) = (response.command, response.group);
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    if !valid {
                        return Err(Ax200PhyError::Boot(Error::InitializationResponse {
                            command,
                            group,
                        }));
                    }
                }
            }
        }
        let Some(command) = self.commands.get(self.next).cloned() else {
            self.phase = if self.removing {
                Ax200PhyPhase::Removed
            } else {
                Ax200PhyPhase::BindingRequired
            };
            return Ok(self.phase);
        };
        let ticket = if self.removing {
            // SAFETY: same original unbound PHY; removal grants no emission.
            unsafe {
                self.boot()
                    .submit_command(command.id, &command.bytes, source)
            }
            .map_err(Ax200PhyError::Boot)?
        } else {
            self.capture_idle_receive()?;
            let parts = self
                .scan
                .mac
                .country
                .scan_policy_parts()
                .ok_or(Ax200PhyError::State)?;
            let hardware = policy::Hardware {
                board: parts.board,
                selection: parts.selection,
                channels: parts.channels,
                native: self.scan.native,
            };
            let os = policy::Os {
                service: parts.os,
                selection_revision: parts.selection.revision,
            };
            let mut owner =
                regulatory::Owner::new(hardware, os).map_err(Ax200PhyError::Regulatory)?;
            let operation = Operation::Receive(self.channel);
            let admission = owner.admit(operation).map_err(Ax200PhyError::Regulatory)?;
            // SAFETY: held same-owner hardware then OS leases cover the exact
            // unbound receive configuration, including DMA visibility.
            unsafe {
                owner.publish(admission, operation, |guard| {
                    guard.submit(command.id, &command.bytes, source)
                })
            }
            .map_err(Ax200PhyError::Regulatory)?
            .map_err(Ax200PhyError::Boot)?
        };
        self.ticket = Some(ticket);
        let options = self.scan.mac.country.board.scan.mcc.setup.options;
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        self.next += 1;
        self.phase = Ax200PhyPhase::Waiting(command.kind);
        Ok(self.phase)
    }
}

fn configuration(
    fw: &crate::wifi::intel::firmware::Firmware<'_>,
    nvm_rx: u32,
    channel: Channel,
    mode: PowerMode,
) -> Result<Vec<PhyCommand>, Ax200PhyError> {
    let mut commands = Vec::new();
    let version = fw
        .command_version(PHY.wire().group, PHY.opcode)
        .ok_or(Ax200PhyError::MissingApi)?
        .command_version;
    if !(3..=6).contains(&version) {
        return Err(Ax200PhyError::Version(version));
    }
    // Cold owner has no SISO diversity override, bound interfaces, SMPS
    // request or debugfs override. Source configured chains are 1/1.
    let sku = fw.phy_sku().ok_or(Ax200PhyError::MissingPhySku)?;
    let mut rx = ((sku >> 20) & 0xf) as u8;
    if nvm_rx as u8 != 0 {
        rx &= nvm_rx as u8;
    }
    if rx == 0 || rx & !7 != 0 {
        return Err(Ax200PhyError::Antennas);
    }
    let chains = if mode == PowerMode::ContinuouslyAwake && rx.count_ones() > 1 {
        2
    } else {
        1
    };
    let chain_info = u32::from(rx) << 1 | chains << 10 | chains << 12;
    let rlc = fw
        .command_version(RLC.group, RLC.opcode)
        .map_or(0, |v| v.command_version);
    let mut bytes = [0; 32];
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    // The source capability selects channel-info geometry independently
    // of PHY command version. PHY3/4 always keeps its full 32-byte size.
    // `iwl_mvm_phy_band_from_nl80211`.
    let band = match channel.band {
        Band::Ghz2 => 1,
        Band::Ghz5 => 0,
        Band::Ghz6 => 2,
    };
    if fw.supports_capability(48) {
        bytes[8..12].copy_from_slice(&u32::from(channel.number).to_le_bytes());
        bytes[12] = band;
    } else {
        bytes[8] = band;
        bytes[9] = channel
            .number
            .try_into()
            .map_err(|_| Ax200PhyError::State)?;
    }
    if fw.supports_capability(40) && channel.band != Band::Ghz2 {
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    }
    if rlc < 2 {
        bytes[20..24].copy_from_slice(&chain_info.to_le_bytes());
    }
    if version >= SECONDARY_CONTROL {
        bytes[28] = CONTROL_ABOVE;
    }
    commands.push(PhyCommand {
        kind: PhyCommandKind::Add,
        id: PHY,
        bytes,
    });
    // `iwl_mld_phy_fw_action`: later firmware keeps the chains itself.
    if rlc == 2 {
        let mut bytes = [0; 32];
        bytes[4..8].copy_from_slice(&chain_info.to_le_bytes());
        commands.push(PhyCommand {
            kind: PhyCommandKind::ReceiveChains,
            id: RLC,
            bytes,
        });
    }
    Ok(commands)
}

/// `iwl_mvm_get_ctrl_pos`: the two low bits and the extension bit count 20 MHz
/// steps from the nearest edge of the center, the above bit its side.
fn control_position(offset_mhz: i32) -> u8 {
    if offset_mhz == 0 {
        return 0;
    }
    let steps = ((offset_mhz.unsigned_abs() - 10) / 20) as u8;
    (steps & 3) | ((steps & 4) << 1) | (u8::from(offset_mhz > 0) * CONTROL_ABOVE)
}

/// `iwl_mvm_phy_ctxt_cmd_data`: `add` moved to `definition`'s width. 80+80 MHz
/// has no firmware width and no Intel capability offers it.
/// `iwl_mld_nl80211_width_to_fw`.
fn width_code(width: Width) -> Option<u8> {
    match width {
        Width::Mhz20 => Some(0),
        Width::Mhz40 => Some(1),
        Width::Mhz80 => Some(2),
        Width::Mhz160 => Some(3),
        Width::Mhz320 => Some(4),
        Width::Mhz80P80 => None,
    }
}

fn modified(
    add: &PhyCommand,
    definition: &ChannelDefinition,
    wide_ofdma: Option<&ChannelDefinition>,
    version: u8,
    ultra_high_band: bool,
) -> Option<PhyCommand> {
    let width = width_code(definition.width)?;
    let mut bytes = add.bytes;
    bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
    let at = if ultra_high_band { 13 } else { 10 };
    let position = control_position(definition.control_offset_mhz());
    bytes[at] = width;
    bytes[at + 1] = position;
    if version >= PUNCTURING {
        bytes[22..24].copy_from_slice(&definition.punctured.to_le_bytes());
    }
    if version >= SECONDARY_CONTROL {
        bytes[28] = position ^ CONTROL_ABOVE;
        if let Some(ap) = wide_ofdma {
            bytes[20] = width_code(ap.width)?;
            bytes[21] = control_position(ap.control_offset_mhz());
        }
    }
    Some(PhyCommand {
        kind: PhyCommandKind::Modify,
        id: PHY,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::wifi::intel::firmware::Firmware;

    #[test]
    fn a_wide_channel_names_the_control_channels_place_in_it() {
        for (offset, position) in [
            (0, 0),
            (-10, 0),
            (10, 4),
            (-30, 1),
            (30, 5),
            (-70, 3),
            (70, 7),
            (-90, 8),
            (90, 12),
            (-150, 11),
            (150, 15),
        ] {
            assert_eq!(control_position(offset), position, "{offset}");
        }
    }

    #[test]
    fn a_modified_context_keeps_what_it_was_added_with() {
        let bytes = image(4, 2, true, false, 3);
        let firmware = Firmware::parse(&bytes).unwrap();
        let channel = Channel {
            number: 36,
            frequency_mhz: 5180,
            band: Band::Ghz5,
        };
        let commands = configuration(&firmware, 3, channel, PowerMode::ContinuouslyAwake).unwrap();
        let definition = ChannelDefinition {
            control: channel,
            width: Width::Mhz80,
            center1_mhz: 5210,
            center2_mhz: None,
            punctured: 0,
        };
        let command = modified(&commands[0], &definition, None, 4, true).unwrap();
        assert_eq!(command.kind, PhyCommandKind::Modify);
        assert_eq!(command.bytes[4], 2);
        assert_eq!(command.bytes[8], 36);
        assert_eq!(command.bytes[12..15], [0, 2, 1]);
        assert_eq!(command.bytes[16..], commands[0].bytes[16..]);
        // Without the capability a channel info is four bytes shorter.
        assert_eq!(
            modified(&commands[0], &definition, None, 4, false)
                .unwrap()
                .bytes[10..12],
            [2, 1]
        );
        let unsupported = ChannelDefinition {
            width: Width::Mhz80P80,
            center2_mhz: Some(5530),
            ..definition
        };
        assert!(modified(&commands[0], &unsupported, None, 4, true).is_none());
    }

    #[test]
    fn later_versions_name_a_secondary_control_channel_and_puncturing() {
        let bytes = image(6, 3, true, false, 3);
        let firmware = Firmware::parse(&bytes).unwrap();
        let channel = Channel {
            number: 36,
            frequency_mhz: 5180,
            band: Band::Ghz5,
        };
        let commands = configuration(&firmware, 3, channel, PowerMode::ContinuouslyAwake).unwrap();
        assert_eq!(commands.len(), 1, "firmware keeps the chains itself");
        assert_eq!(commands[0].bytes[20..24], [0; 4]);
        assert_eq!(commands[0].bytes[28], 4);
        let definition = ChannelDefinition {
            control: channel,
            width: Width::Mhz80,
            center1_mhz: 5210,
            center2_mhz: None,
            punctured: 4,
        };
        let command = modified(&commands[0], &definition, None, 6, true).unwrap();
        assert_eq!(command.bytes[22..24], [4, 0]);
        assert_eq!(command.bytes[28], 5);
    }

    fn image(version: u8, rlc: u8, uhb: bool, cdb: bool, antennas: u8) -> Vec<u8> {
        let mut bytes = alloc::vec![0; 88];
        bytes[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&0x4d00u32.to_le_bytes());
        bytes.extend(23u32.to_le_bytes());
        bytes.extend(4u32.to_le_bytes());
        bytes.extend((u32::from(antennas) << 20).to_le_bytes());
        bytes.extend(48u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend([8, 1, version, 0, 8, 5, rlc, 0]);
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(((u32::from(uhb) << 16) | (u32::from(cdb) << 8)).to_le_bytes());
        bytes
    }

    #[test]
    fn phy_lmac_routing_follows_source_cdb_and_band() {
        // Pinned binding.c::iwl_mvm_get_lmac_id and context.h LMAC indices.
        // These four source cases are also covered in the C trace.
        for (cdb, band, number, frequency_mhz, expected_lmac) in [
            (false, Band::Ghz2, 1, 2412, 0u32),
            (true, Band::Ghz2, 1, 2412, 0),
            (false, Band::Ghz5, 36, 5180, 0),
            (true, Band::Ghz5, 36, 5180, 1),
        ] {
            for version in [3, 4] {
                for uhb in [false, true] {
                    let bytes = image(version, 2, uhb, cdb, 3);
                    let firmware = Firmware::parse(&bytes).unwrap();
                    let commands = configuration(
                        &firmware,
                        3,
                        Channel {
                            band,
                            number,
                            frequency_mhz,
                        },
                        PowerMode::ContinuouslyAwake,
                    )
                    .unwrap();
                    assert_eq!(&commands[0].bytes[16..20], &expected_lmac.to_le_bytes());
                    assert_eq!(commands[1].kind, PhyCommandKind::ReceiveChains);
                }
            }
        }
    }

    #[test]
    fn phy_unknown_versions_and_zero_or_unrepresentable_rx_chains_refuse() {
        let channel = Channel {
            band: Band::Ghz2,
            number: 1,
            frequency_mhz: 2412,
        };
        for version in [0, 1, 2, 7, 255] {
            let bytes = image(version, 2, false, false, 3);
            assert_eq!(
                configuration(
                    &Firmware::parse(&bytes).unwrap(),
                    3,
                    channel,
                    PowerMode::ContinuouslyAwake
                ),
                Err(Ax200PhyError::Version(version))
            );
        }
        for (rx, nvm) in [(0, 0), (1, 2), (8, 0)] {
            let bytes = image(3, 2, false, false, rx);
            assert_eq!(
                configuration(
                    &Firmware::parse(&bytes).unwrap(),
                    nvm,
                    channel,
                    PowerMode::ContinuouslyAwake
                ),
                Err(Ax200PhyError::Antennas)
            );
        }
    }

    #[test]
    fn a_6_ghz_context_names_its_band_on_the_high_band_mac() {
        let bytes = image(3, 2, true, true, 3);
        let channel = Channel {
            band: Band::Ghz6,
            number: 37,
            frequency_mhz: 6135,
        };
        let commands = configuration(
            &Firmware::parse(&bytes).unwrap(),
            3,
            channel,
            PowerMode::ContinuouslyAwake,
        )
        .unwrap();
        let add = commands[0].bytes();
        assert_eq!(add[8..12], 37u32.to_le_bytes());
        assert_eq!(add[12], 2);
        assert_eq!(add[16..20], 1u32.to_le_bytes());
    }

    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_PHY_TRACE"]
    fn pinned_linux_phy_context_and_rlc_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_PHY_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "0bc3b839d1250c59b691343adecd88bea2d8eec4f55e5b9d07e99565d9296213"
        );
        let trace = std::str::from_utf8(&trace).unwrap();
        let mut keys = alloc::collections::BTreeSet::new();
        let mut count = 0;
        for line in trace.lines() {
            let mut words = line.split_whitespace();
            let mut values = [0u8; 10];
            for value in &mut values {
                *value = words.next().unwrap().parse().unwrap();
            }
            assert!(keys.insert(values[..9].to_vec()));
            let [
                version,
                rlc,
                uhb,
                cdb,
                antennas,
                nvm,
                cam,
                band,
                remove,
                commands,
            ] = values;
            let bytes = image(version, rlc, uhb != 0, cdb != 0, antennas);
            let fw = Firmware::parse(&bytes).unwrap();
            let channel = if band == 0 {
                Channel {
                    band: Band::Ghz2,
                    number: 1,
                    frequency_mhz: 2412,
                }
            } else {
                Channel {
                    band: Band::Ghz5,
                    number: 36,
                    frequency_mhz: 5180,
                }
            };
            let mut actual = configuration(
                &fw,
                u32::from(nvm),
                channel,
                if cam != 0 {
                    PowerMode::ContinuouslyAwake
                } else {
                    PowerMode::SavePower
                },
            )
            .unwrap();
            if remove != 0 {
                actual.truncate(1);
                actual[0].bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
            }
            assert_eq!(actual.len(), usize::from(commands));
            for command in actual {
                let id: u32 = words.next().unwrap().parse().unwrap();
                assert_eq!(
                    id,
                    u32::from(command.id.opcode)
                        | u32::from(command.id.group) << 8
                        | u32::from(command.id.version) << 16
                );
                let hex = words.next().unwrap();
                let expected: Vec<u8> = hex
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                assert_eq!(command.bytes.as_slice(), expected, "{line}");
            }
            assert!(words.next().is_none());
            count += 1;
        }
        assert_eq!(count, 2560);
    }
}
