// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Unbound MAC0 transmit-power ceiling, not permission to transmit.
//! Source: mvm/mac80211.c::iwl_mvm_set_tx_power and fw/api/power.h.
use super::*;
mod binding;
pub use binding::{
    Ax200Binding, Ax200BindingError, Ax200BindingPhase, Ax200Coexistence, Ax200CoexistenceError,
    Ax200CoexistencePhase, Ax200LegacyPeer, Ax200LegacyPeerError, Ax200LegacyPeerPhase,
    Ax200ManagementQueue, Ax200ManagementQueueError, Ax200ManagementQueuePhase, BindingCommand,
    BindingCommandKind, LegacyPeer, PeerCommand, PeerCommandKind,
};

const COMMAND: Id = Id {
    group: 0,
    opcode: 0x9f,
    version: 0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200TransmitPowerPhase {
    NotStarted,
    Waiting,
    BindingRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200TransmitPowerError {
    Phy(Ax200PhyError),
    Boot(Error),
    Country(Ax200CountryError),
    Regulatory(regulatory::Error),
    MissingApi,
    Version(u8),
    Channel,
    Deadline,
    State,
}
/// Historical programmed ceiling after command completion/reclaim.
/// No public construction or copied observation can program another device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransmitPowerLimit {
    requested_dbm: u8,
    effective_dbm: u8,
    country_max_eirp_mbm: u16,
}
impl TransmitPowerLimit {
    pub fn requested_dbm(&self) -> u8 {
        self.requested_dbm
    }
    pub fn effective_dbm(&self) -> u8 {
        self.effective_dbm
    }
    pub fn country_max_eirp_mbm(&self) -> u16 {
        self.country_max_eirp_mbm
    }
}
pub struct Ax200TransmitPower<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> {
    pub(in crate::wifi::intel::boot) phy: Ax200Phy<'a, Q, B, O>,
    requested_dbm: u8,
    phase: Ax200TransmitPowerPhase,
    bytes: Option<Vec<u8>>,
    planned: Option<TransmitPowerLimit>,
    applied: Option<TransmitPowerLimit>,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    response: Option<CommandResponse>,
    first_error: Option<Ax200TransmitPowerError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Phy<'a, Q, B, O> {
    /// Program an explicit requested ceiling on this original unbound MAC0.
    /// The selected country's full20MHz rule independently clamps this input.
    /// This changes a firmware limit; it never binds/enables the MAC or grants
    /// any autonomous response, management, probe or data transmission.
    pub fn begin_transmit_power(
        self,
        requested_dbm: u8,
    ) -> Result<Ax200TransmitPower<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200PhyPhase::BindingRequired
            || self.first_error.is_some()
            || self.ticket.is_some()
            || self.removing
            || self.scan.first_error.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(Ax200TransmitPower {
            phy: self,
            requested_dbm,
            phase: Ax200TransmitPowerPhase::NotStarted,
            bytes: None,
            planned: None,
            applied: None,
            ticket: None,
            deadline: None,
            response: None,
            first_error: None,
        })
    }
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200TransmitPower<'a, Q, B, O> {
    /// Return the same unbound channel-context reference for real PHY removal.
    /// A binding/link owner cannot return here until its entire source unassign
    /// sequence ACKs and reclaims. No public IDs can reconstruct this parent.
    pub fn into_phy_context(self) -> Result<Ax200Phy<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200TransmitPowerPhase::BindingRequired
            || self.first_error.is_some()
            || self.ticket.is_some()
            || self.phy.phase != Ax200PhyPhase::BindingRequired
            || self.phy.first_error.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(self.phy)
    }
    pub fn phase(&self) -> Ax200TransmitPowerPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200TransmitPowerError> {
        self.first_error.as_ref()
    }
    pub fn command_bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
    pub fn response(&self) -> Option<&CommandResponse> {
        self.response.as_ref()
    }
    /// `iwl_mld_set_tx_power` for the firmware link `seat`, within what the
    /// chain applied and `dbm`.
    pub(in crate::wifi::intel::boot) fn link_limit(
        &self,
        seat: u8,
        dbm: i32,
    ) -> Option<(Id, Vec<u8>)> {
        let applied = self.applied.as_ref()?;
        let limit = i32::from(applied.effective_dbm()).min(dbm).max(0) as u16;
        let mut bytes = self.command_bytes()?.to_vec();
        bytes[4..8].copy_from_slice(&u32::from(seat).to_le_bytes());
        bytes[8..10].copy_from_slice(&(limit * 8).to_le_bytes());
        Some((COMMAND, bytes))
    }
    pub fn applied_limit(&self) -> Option<&TransmitPowerLimit> {
        self.applied.as_ref()
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    pub fn channel(&self) -> Channel {
        self.phy.channel
    }
    pub fn take_other_notification(&mut self) -> Option<FirmwareNotification> {
        self.phy.take_other_notification()
    }
    pub fn poll_receive(&mut self) -> Result<MpduProgress, Ax200TransmitPowerError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        let result = self
            .phy
            .poll_receive()
            .map_err(Ax200TransmitPowerError::Phy);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Ax200TransmitPowerError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        let result = self
            .phy
            .replenish_completed_receive()
            .map_err(Ax200TransmitPowerError::Phy);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.phy.stop() {
            Ok(()) => {
                self.phase = Ax200TransmitPowerPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.fail(Ax200TransmitPowerError::Boot(error.clone()));
                Err(error)
            }
        }
    }
    fn fail(&mut self, error: Ax200TransmitPowerError) {
        self.first_error.get_or_insert(error);
        self.phase = Ax200TransmitPowerPhase::Failed;
    }
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the native
    /// requester/domain under RomBoot's complete publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200TransmitPowerPhase, Ax200TransmitPowerError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: unchanged original-owner page-source contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(
                error,
                Ax200TransmitPowerError::Boot(Error::CommandReclaim(_))
            )
            && !(self.ticket.is_none()
                && matches!(
                    error,
                    Ax200TransmitPowerError::Regulatory(_)
                        | Ax200TransmitPowerError::Phy(Ax200PhyError::Scan(
                            Ax200ScanError::PreScanReceiveRequired
                        ))
                        | Ax200TransmitPowerError::Phy(Ax200PhyError::Scan(
                            Ax200ScanError::ReceiveBackpressure { .. }
                        ))
                ))
        {
            self.fail(error.clone());
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200TransmitPowerPhase, Ax200TransmitPowerError> {
        if let Some(error) = self.phy.first_error.as_ref() {
            return Err(Ax200TransmitPowerError::Phy(error.clone()));
        }
        if self.phy.boot().state != State::PnvmObserved
            || self.phy.phase != Ax200PhyPhase::BindingRequired
        {
            return Err(Ax200TransmitPowerError::State);
        }
        self.phy
            .scan
            .mac
            .country
            .check_selection()
            .map_err(Ax200TransmitPowerError::Country)?;
        if self.phase == Ax200TransmitPowerPhase::BindingRequired {
            return Ok(self.phase);
        }
        if let Some(ticket) = self.ticket.as_ref().cloned() {
            let progress = self.phy.boot().poll_command(&ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200TransmitPowerError::Deadline);
            }
            match progress.map_err(Ax200TransmitPowerError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200TransmitPowerError::Deadline);
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let valid = response.command == COMMAND.opcode
                        && response.group == COMMAND.wire().group;
                    let (command, group) = (response.command, response.group);
                    self.response = Some(response);
                    self.ticket = None;
                    self.deadline = None;
                    if !valid {
                        return Err(Ax200TransmitPowerError::Boot(
                            Error::InitializationResponse { command, group },
                        ));
                    }
                    self.applied = self.planned;
                    self.phase = Ax200TransmitPowerPhase::BindingRequired;
                    return Ok(self.phase);
                }
            }
        }
        self.phy
            .capture_idle_receive()
            .map_err(Ax200TransmitPowerError::Phy)?;
        let options = self.phy.scan.mac.country.board.scan.mcc.setup.options;
        let parts = self
            .phy
            .scan
            .mac
            .country
            .scan_policy_parts()
            .ok_or(Ax200TransmitPowerError::State)?;
        let max_eirp = parts
            .selection
            .country
            .rule(u32::from(self.phy.channel.frequency_mhz) * 1000, 20_000)
            .ok_or(Ax200TransmitPowerError::Channel)?
            .max_eirp_mbm;
        // Source's per-link API accepts whole dBm. Floor the country's
        // ceiling so quantization can never relax its fractional dBm limit.
        let effective_dbm = u16::from(self.requested_dbm).min(max_eirp / 100) as u8;
        let bytes = encode(
            &parts
                .board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .firmware,
            effective_dbm,
        )?;
        let planned = TransmitPowerLimit {
            requested_dbm: self.requested_dbm,
            effective_dbm,
            country_max_eirp_mbm: max_eirp,
        };
        let hardware = policy::Hardware {
            board: parts.board,
            selection: parts.selection,
            channels: parts.channels,
            native: self.phy.scan.native,
        };
        let os = policy::Os {
            service: parts.os,
            selection_revision: parts.selection.revision,
        };
        let mut owner =
            regulatory::Owner::new(hardware, os).map_err(Ax200TransmitPowerError::Regulatory)?;
        let operation = Operation::Receive(self.phy.channel);
        let admission = owner
            .admit(operation)
            .map_err(Ax200TransmitPowerError::Regulatory)?;
        // SAFETY: this exact MAC is still unbound, with no station or
        // transmit queues. The command only programs its ceiling under both
        // current receive guards; it cannot authorize later emission.
        let publication = unsafe {
            owner.publish(admission, operation, |guard| {
                guard.submit(COMMAND, &bytes, source)
            })
        };
        // Preserve exact planned bytes even when native visibility is uncertain.
        self.bytes = Some(bytes);
        self.planned = Some(planned);
        let ticket = publication
            .map_err(Ax200TransmitPowerError::Regulatory)?
            .map_err(Ax200TransmitPowerError::Boot)?;
        self.ticket = Some(ticket);
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        self.phase = Ax200TransmitPowerPhase::Waiting;
        Ok(self.phase)
    }
}
fn encode(
    firmware: &crate::wifi::intel::firmware::Firmware<'_>,
    dbm: u8,
) -> Result<Vec<u8>, Ax200TransmitPowerError> {
    let version = firmware
        .command_version(COMMAND.wire().group, COMMAND.opcode)
        .ok_or(Ax200TransmitPowerError::MissingApi)?
        .command_version;
    if !matches!(version, 3..=5 | 8..=11) {
        return Err(Ax200TransmitPowerError::Version(version));
    }
    let length = if version == 11 {
        116
    } else if version == 10 {
        108
    } else if version == 9 {
        40
    } else if version == 8 {
        120
    } else if firmware.supports_api(45) {
        44
    } else if firmware.supports_capability(84) {
        40
    } else {
        36
    };
    // Source SET_LINK0, original MAC0, 1/8-dBm restriction. This is always an
    // explicit bounded limit: Linux's default22 ->0x7fff automatic sentinel
    // must not replace a requested22dBm ceiling with an unrestricted value.
    // Per-band, per-chain,
    // ACK-reduction and timer fields are zero and irrelevant to SET_LINK.
    let mut bytes = alloc::vec![0; length];
    bytes[8..10].copy_from_slice(&(u16::from(dbm) * 8).to_le_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::wifi::intel::{
        association,
        firmware::{Family, Firmware},
        transmit,
    };
    fn image(version: u8, reduced: bool, ack: bool) -> Vec<u8> {
        let mut bytes = alloc::vec![0; 88];
        bytes[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&0x4d00u32.to_le_bytes());
        bytes.extend(48u32.to_le_bytes());
        bytes.extend(4u32.to_le_bytes());
        bytes.extend([0x9f, 1, version, 0]);
        bytes.extend(29u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend((u32::from(reduced) << 13).to_le_bytes());
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend((u32::from(ack) << 20).to_le_bytes());
        bytes
    }
    #[test]
    fn explicit_22_dbm_is_bounded_and_does_not_select_source_automatic_sentinel() {
        let bytes = image(5, true, true);
        let command = encode(&Firmware::parse(&bytes).unwrap(), 22).unwrap();
        assert_eq!(command.len(), 44);
        assert_eq!(&command[8..10], &[176, 0]);
        assert!(
            command[..8]
                .iter()
                .chain(command[10..].iter())
                .all(|v| *v == 0)
        );
    }
    #[test]
    fn version_8_is_the_whole_command_with_the_same_limit() {
        let bytes = image(8, true, true);
        let command = encode(&Firmware::parse(&bytes).unwrap(), 22).unwrap();
        assert_eq!(command.len(), 120);
        assert_eq!(&command[8..10], &[176, 0]);
    }
    #[test]
    fn each_later_version_has_its_own_length() {
        for (version, length) in [(9, 40), (10, 108), (11, 116)] {
            let bytes = image(version, false, false);
            let command = encode(&Firmware::parse(&bytes).unwrap(), 22).unwrap();
            assert_eq!(command.len(), length);
            assert_eq!(&command[8..10], &[176, 0]);
        }
    }
    /// A model firmware declares only what its test expects, so real images are
    /// the one check of what a gate admits.
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_FIRMWARE"]
    fn released_firmware_passes_the_version_gates() {
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_FIRMWARE").unwrap()).unwrap();
        let firmware = Firmware::parse(&bytes).unwrap();
        super::super::super::wire::validate(&firmware).unwrap();
        encode(&firmware, 22).unwrap();
        let channel = Channel {
            band: Band::Ghz2,
            number: 1,
            frequency_mhz: 2412,
        };
        super::super::configuration(&firmware, 3, channel, PowerMode::ContinuouslyAwake).unwrap();
        crate::wifi::intel::mcc::Response::layout(&firmware).unwrap();
        assert!(
            [Family::Ax200, Family::Ax210, Family::Bz]
                .into_iter()
                .any(|family| transmit::rate_format(&firmware, family).is_ok())
        );
        let version = |group, command| {
            firmware
                .command_version(group, command)
                .map_or(0, |version| version.command_version)
        };
        assert!(association::RateShape::of(version(5, 0x0f)).is_some());
        assert!(version(3, 8) <= 4, "MAC_CONFIG");
        assert!(version(3, 9) <= 8, "LINK_CONFIG");
        assert!(version(3, 0x0a) <= 3, "STA_CONFIG");
        assert!(version(1, 0xa9) <= 3, "MAC_PM_POWER_TABLE");
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_TRANSMIT_POWER_TRACE"]
    fn pinned_linux_transmit_power_bytes_and_explicit_limit_boundary() {
        use sha2::{Digest, Sha256};
        let bytes =
            std::fs::read(std::env::var("STELA_IWLWIFI_TRANSMIT_POWER_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "4c6851d98b7e261344f58733333b9c5e9e5412530e51478c9654463e45e40529"
        );
        let text = std::str::from_utf8(&bytes).unwrap();
        let mut keys = alloc::collections::BTreeSet::new();
        let mut ordinary = 0;
        let mut bounded_default = 0;
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let mut values = [0u8; 5];
            for value in &mut values {
                *value = words.next().unwrap().parse().unwrap();
            }
            assert!(keys.insert(values[..4].to_vec()));
            let [version, reduced, ack, dbm, len] = values;
            let hex = words.next().unwrap();
            let mut expected: Vec<u8> = hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert!(words.next().is_none());
            assert_eq!(expected.len(), usize::from(len));
            if dbm == 22 {
                assert_eq!(&expected[8..10], &[255, 127]);
                expected[8..10].copy_from_slice(&176u16.to_le_bytes());
                bounded_default += 1;
            } else {
                ordinary += 1;
            }
            let bytes = image(version, reduced != 0, ack != 0);
            assert_eq!(
                encode(&Firmware::parse(&bytes).unwrap(), dbm).unwrap(),
                expected,
                "{line}"
            );
        }
        assert_eq!((ordinary, bounded_default), (480, 12));
    }
}
