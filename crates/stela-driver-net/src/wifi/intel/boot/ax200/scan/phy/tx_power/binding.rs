// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Original cold MAC0/PHY0 binding and source mandatory MAC power update.
//! No associated peer, authentication, transmit queue or data link is created.
use super::*;
mod admission;
mod mld_link;
mod peer;
pub use peer::{
    Ax200Coexistence, Ax200CoexistenceError, Ax200CoexistencePhase, Ax200LegacyPeer,
    Ax200LegacyPeerError, Ax200LegacyPeerPhase, Ax200ManagementQueue, Ax200ManagementQueueError,
    Ax200ManagementQueuePhase, LegacyPeer, PeerCommand, PeerCommandKind,
};
const BINDING: Id = Id {
    group: 0,
    opcode: 0x2b,
    version: 0,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingCommandKind {
    Add,
    Power,
    ClearQuotas,
    Remove,
    AttachPhy,
    ActivateLink,
    DeactivateLink,
    RemoveLink,
    RestoreInactiveLink,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingCommand {
    kind: BindingCommandKind,
    id: Id,
    bytes: Vec<u8>,
}
impl BindingCommand {
    pub fn kind(&self) -> BindingCommandKind {
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
pub enum Ax200BindingPhase {
    NotStarted,
    Preparing(BindingCommandKind),
    Waiting(BindingCommandKind),
    AuthenticationRequired,
    Unbound,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200BindingError {
    Power(Ax200TransmitPowerError),
    Phy(Ax200PhyError),
    Boot(Error),
    Country(Ax200CountryError),
    Regulatory(regulatory::Error),
    MissingApi,
    Version { command: u8, version: u8 },
    SmartFifo,
    MldLinkContinuationRequired,
    ResponseLength(usize),
    Status(u32),
    Deadline(BindingCommandKind),
    State,
}
pub struct Ax200Binding<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> {
    pub(in crate::wifi::intel::boot) power: Ax200TransmitPower<'a, Q, B, O>,
    phase: Ax200BindingPhase,
    commands: Vec<BindingCommand>,
    next: usize,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    removing: bool,
    mld: bool,
    first_error: Option<Ax200BindingError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200TransmitPower<'a, Q, B, O> {
    /// Bind the cold MAC0 to its PHY0, with all enabled automatic
    /// response rates independently authorized at native publication.
    /// # Safety
    /// O's same-device OsPolicy service must approve the entire cold
    /// source response envelope and keep restrictive revocation through the
    /// armed binding lifetime. It must coordinate unbind/stop/drain or
    /// hardware enforcement before further responses after a restriction;
    /// polling or updating a revision alone is insufficient. The CountryIo and
    /// OsPolicy interfaces remain the same selected-country/database
    /// service checked by begin_scan. No other binding, station, data queue,
    /// MAC/PHY or SF mutation may occur outside this original owner.
    pub unsafe fn begin_binding(self) -> Result<Ax200Binding<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200TransmitPowerPhase::BindingRequired
            || self.first_error.is_some()
            || self.applied.is_none()
            || self.ticket.is_some()
            || self.phy.phase != Ax200PhyPhase::BindingRequired
            || self.phy.first_error.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(Ax200Binding {
            power: self,
            phase: Ax200BindingPhase::NotStarted,
            commands: Vec::new(),
            next: 0,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            removing: false,
            mld: false,
            first_error: None,
        })
    }
    /// Activate the MLD link0 on this PHY0 and applied power
    /// owner. Legacy BINDING is never substituted for LINK_CONFIG.
    /// # Safety
    /// begin_binding's same-device provider, complete finite response
    /// envelope and restrictive-revocation lifetime contracts apply unchanged.
    /// No external PHY/link/station/queue mutation may race this unique owner.
    pub unsafe fn begin_mld_link(self) -> Result<Ax200Binding<'a, Q, B, O>, Box<Self>> {
        // SAFETY: the same original provider/publication contract is held;
        // the private protocol selector is checked again before any command.
        unsafe { self.begin_binding() }.map(|mut binding| {
            binding.mld = true;
            binding
        })
    }
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Binding<'a, Q, B, O> {
    pub fn phase(&self) -> Ax200BindingPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200BindingError> {
        self.first_error.as_ref()
    }
    pub fn commands(&self) -> &[BindingCommand] {
        &self.commands
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    pub fn channel(&self) -> Channel {
        self.power.channel()
    }
    pub fn applied_limit(&self) -> &TransmitPowerLimit {
        self.power.applied.as_ref().unwrap()
    }
    pub fn take_other_notification(&mut self) -> Option<FirmwareNotification> {
        self.power.take_other_notification()
    }
    pub fn poll_receive(&mut self) -> Result<MpduProgress, Ax200BindingError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        if self.ticket.is_some() {
            return Err(Ax200BindingError::State);
        }
        let result = self.power.poll_receive().map_err(Ax200BindingError::Power);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Ax200BindingError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        let result = self
            .power
            .replenish_completed_receive()
            .map_err(Ax200BindingError::Power);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.power.stop() {
            Ok(()) => {
                self.phase = Ax200BindingPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.fail(Ax200BindingError::Boot(error.clone()));
                Err(error)
            }
        }
    }
    fn fail(&mut self, error: Ax200BindingError) {
        self.first_error.get_or_insert(error);
        self.phase = Ax200BindingPhase::Failed;
    }
    fn prepare(&mut self) -> Result<(), Ax200BindingError> {
        if self.mld {
            return mld_link::prepare(self);
        }
        let mac = &self.power.phy.scan.mac;
        if mac.phase() != Ax200MacPhase::ScanRequired || mac.mac_id_and_color() != Some(0) {
            return Err(Ax200BindingError::State);
        }
        let radio = &mac.country.board.scan.mcc.setup.lari.radio;
        let firmware = &radio.initialized.boot.firmware;
        if firmware.supports_capability(110) {
            return Err(Ax200BindingError::MldLinkContinuationRequired);
        }
        // Private cold prefix established SF_INIT_OFF, or selected
        // source API68 offload. A single unassociated BSS remains INIT_OFF;
        // Linux's sf_update/sf_config therefore issues no new SF command.
        if radio.phase() != ColdRadioPhase::PlatformConfigurationRequired
            || (!firmware.supports_api(68)
                && !radio
                    .prefix_responses()
                    .iter()
                    .any(|response| response.command == 0xd1 && response.group == 1))
        {
            return Err(Ax200BindingError::SmartFifo);
        }
        let bytes = encode(firmware, self.power.channel(), false)?;
        if !firmware.supports_capability(44) {
            // Validate the required non-offloaded teardown ABI before arming
            // even this first binding; missing teardown is never deferred.
            empty_quotas(firmware)?;
        }
        let power = mac
            .commands()
            .iter()
            .find(|command| command.kind() == MacCommandKind::Power)
            .ok_or(Ax200BindingError::State)?;
        self.commands.push(BindingCommand {
            kind: BindingCommandKind::Add,
            id: BINDING,
            bytes,
        });
        // Single unchanged cold station: cfg.ps=false, no DTIM/peer, no BF,
        // no other interface can change device PS. Source's mandatory post-
        // binding MAC power update has the same original cold payload.
        self.commands.push(BindingCommand {
            kind: BindingCommandKind::Power,
            id: power.id(),
            bytes: power.bytes().to_vec(),
        });
        Ok(())
    }
    /// Source unbind and mandatory MAC power update, without requiring
    /// a new emission grant. RF-kill/failure can still require native stop.
    pub fn begin_remove(&mut self) -> Result<(), Ax200BindingError> {
        if self.phase != Ax200BindingPhase::AuthenticationRequired
            || self.first_error.is_some()
            || self.ticket.is_some()
            || self.removing
        {
            return Err(Ax200BindingError::State);
        }
        if self.mld {
            let commands = mld_link::removal(self)?;
            self.commands.extend(commands);
            self.removing = true;
            return Ok(());
        }
        let empty_quotas_applied = self.power.phy.boot().empty_quotas_applied;
        let firmware = &self
            .power
            .phy
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
            .firmware;
        let bytes = encode(firmware, self.power.channel(), true)?;
        if !firmware.supports_capability(44) && !empty_quotas_applied {
            self.commands.push(BindingCommand {
                kind: BindingCommandKind::ClearQuotas,
                id: Id {
                    group: 0,
                    opcode: 0x2c,
                    version: 0,
                },
                bytes: empty_quotas(firmware)?,
            });
        }
        self.commands.push(BindingCommand {
            kind: BindingCommandKind::Remove,
            id: BINDING,
            bytes,
        });
        let power = self.commands[1].clone();
        self.commands.push(power);
        self.removing = true;
        Ok(())
    }
    /// Return the same unbound PHY/power owner only after both unbind
    /// status and source MAC power command completed and reclaimed their DMA.
    pub fn into_transmit_power(self) -> Result<Ax200TransmitPower<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200BindingPhase::Unbound
            || self.first_error.is_some()
            || self.ticket.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(self.power)
    }
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the native
    /// requester/domain under RomBoot's complete publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200BindingPhase, Ax200BindingError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: unchanged original requester/domain publication contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(
                error,
                Ax200BindingError::Boot(Error::CommandReclaim(_))
                    | Ax200BindingError::Phy(Ax200PhyError::Scan(
                        Ax200ScanError::PreScanReceiveRequired
                    ))
                    | Ax200BindingError::Phy(Ax200PhyError::Scan(
                        Ax200ScanError::ReceiveBackpressure { .. }
                    ))
            )
            && !(self.next == 0 && matches!(error, Ax200BindingError::Regulatory(_)))
        {
            self.fail(error.clone());
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200BindingPhase, Ax200BindingError> {
        if let Some(error) = self.power.first_error.as_ref() {
            return Err(Ax200BindingError::Power(error.clone()));
        }
        if self.power.phy.boot().state != State::PnvmObserved {
            return Err(Ax200BindingError::State);
        }
        if !self.removing {
            self.power
                .phy
                .scan
                .mac
                .country
                .check_selection()
                .map_err(Ax200BindingError::Country)?;
        }
        if self.phase == Ax200BindingPhase::Unbound {
            return Ok(self.phase);
        }
        if self.phase == Ax200BindingPhase::AuthenticationRequired && !self.removing {
            self.power
                .phy
                .capture_idle_receive()
                .map_err(Ax200BindingError::Phy)?;
            return Ok(self.phase);
        }
        if self.commands.is_empty() {
            self.prepare()?;
        }
        if let Some(ticket) = self.ticket.as_ref().cloned() {
            let command = &self.commands[self.next - 1];
            let (kind, id) = (command.kind, command.id);
            let progress = self.power.phy.boot().poll_command(&ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200BindingError::Deadline(kind));
            }
            match progress.map_err(Ax200BindingError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200BindingError::Deadline(kind));
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let valid = response.command == id.opcode && response.group == id.wire().group;
                    let (command, group) = (response.command, response.group);
                    let status =
                        if matches!(kind, BindingCommandKind::Add | BindingCommandKind::Remove) {
                            binding_status(&response.raw)
                        } else {
                            Ok(())
                        };
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    if !valid {
                        return Err(Ax200BindingError::Boot(Error::InitializationResponse {
                            command,
                            group,
                        }));
                    }
                    status?;
                    if kind == BindingCommandKind::ClearQuotas {
                        self.power.phy.boot().empty_quotas_applied = true;
                    }
                }
            }
        }
        let Some(command) = self.commands.get(self.next).cloned() else {
            self.phase = if self.removing {
                Ax200BindingPhase::Unbound
            } else {
                Ax200BindingPhase::AuthenticationRequired
            };
            return Ok(self.phase);
        };
        self.phase = Ax200BindingPhase::Preparing(command.kind);
        let options = self.power.phy.scan.mac.country.board.scan.mcc.setup.options;
        let ticket = if self.removing {
            // SAFETY: original unbind/control power commands grant no new RF.
            unsafe {
                self.power
                    .phy
                    .boot()
                    .submit_command(command.id, &command.bytes, source)
            }
            .map_err(Ax200BindingError::Boot)?
        } else {
            self.power
                .phy
                .capture_idle_receive()
                .map_err(Ax200BindingError::Phy)?;
            // SAFETY: complete original finite response envelope checked while
            // both leases remain held through this same native HCMD.
            unsafe { admission::publish(&mut self.power, &command, source) }?
        };
        self.ticket = Some(ticket);
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        self.next += 1;
        self.phase = Ax200BindingPhase::Waiting(command.kind);
        Ok(self.phase)
    }
}
fn encode(
    firmware: &crate::wifi::intel::firmware::Firmware<'_>,
    channel: Channel,
    remove: bool,
) -> Result<Vec<u8>, Ax200BindingError> {
    let version = firmware
        .command_version(1, BINDING.opcode)
        .ok_or(Ax200BindingError::MissingApi)?;
    if !matches!(version.command_version, 1 | 2) {
        return Err(Ax200BindingError::Version {
            command: BINDING.opcode,
            version: version.command_version,
        });
    }
    if version.notification_version != 1 {
        return Err(Ax200BindingError::Version {
            command: BINDING.opcode,
            version: version.notification_version,
        });
    }
    let cdb_binding = firmware.supports_capability(39);
    let mut bytes = alloc::vec![0; if cdb_binding { 28 } else { 24 }];
    bytes[4..8].copy_from_slice(&(if remove { 3u32 } else { 1 }).to_le_bytes());
    bytes[8..20].fill(0xff);
    if !remove {
        bytes[8..12].fill(0);
    }
    if cdb_binding && firmware.supports_capability(40) && channel.band != Band::Ghz2 {
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
    }
    Ok(bytes)
}
fn binding_status(raw: &[u8]) -> Result<(), Ax200BindingError> {
    if raw.len() != 4 {
        return Err(Ax200BindingError::ResponseLength(raw.len()));
    }
    let status = u32::from_le_bytes(raw.try_into().unwrap());
    if status == 0 {
        Ok(())
    } else {
        Err(Ax200BindingError::Status(status))
    }
}
fn empty_quotas(
    firmware: &crate::wifi::intel::firmware::Firmware<'_>,
) -> Result<Vec<u8>, Ax200BindingError> {
    let version = firmware
        .command_version(1, 0x2c)
        .ok_or(Ax200BindingError::MissingApi)?
        .command_version;
    if !matches!(version, 1 | 2) {
        return Err(Ax200BindingError::Version {
            command: 0x2c,
            version,
        });
    }
    // Original unassociated BSS never allocated airtime. The source's first
    // allff last_quota_cmd still differs from this real empty command: it must
    // be sent before REMOVE, not inferred from absence of a station. API38
    // chooses the actual12/16-byte per-binding layout independently of version.
    let stride = if firmware.supports_api(38) { 16 } else { 12 };
    let mut bytes = alloc::vec![0; 4 * stride];
    for slot in 0..4 {
        bytes[slot * stride..slot * stride + 4].fill(0xff);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::wifi::intel::firmware::Firmware;
    fn image(layout: bool, cdb: bool) -> Vec<u8> {
        let mut bytes = alloc::vec![0; 88];
        bytes[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&0x4d00u32.to_le_bytes());
        bytes.extend(48u32.to_le_bytes());
        bytes.extend(4u32.to_le_bytes());
        bytes.extend([0x2b, 1, 2, 1]);
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(((u32::from(layout) << 7) | (u32::from(cdb) << 8)).to_le_bytes());
        bytes
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_QUOTA_TRACE"]
    fn pinned_linux_cold_quota_layout_offload_and_acknowledged_cache() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_QUOTA_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "96063ee5bac2c2de215d7fdda19af651769836c52c07f7051538a6e1c8752cf4"
        );
        let mut keys = alloc::collections::BTreeSet::new();
        for line in std::str::from_utf8(&trace).unwrap().lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            assert_eq!(words.len(), 9);
            let values: Vec<i32> = words[..8]
                .iter()
                .map(|word| word.parse().unwrap())
                .collect();
            let [low, offload, cached, failed, result, sends, length, changed] = values[..] else {
                panic!("source record")
            };
            assert!(keys.insert(values[..4].to_vec()));
            let send = offload == 0 && cached == 0;
            assert_eq!(sends, i32::from(send));
            assert_eq!(result, if send && failed != 0 { -5 } else { 0 });
            assert_eq!(changed, i32::from(send && failed == 0));
            let mut bytes = image(true, false);
            bytes[92..96].copy_from_slice(&8u32.to_le_bytes());
            bytes.splice(100..100, [0x2c, 1, 2, 0]);
            let end = bytes.len();
            bytes[end - 4..]
                .copy_from_slice(&((1u32 << 7) | ((offload as u32) << 12)).to_le_bytes());
            bytes.extend(29u32.to_le_bytes());
            bytes.extend(8u32.to_le_bytes());
            bytes.extend(1u32.to_le_bytes());
            bytes.extend(((low as u32) << 6).to_le_bytes());
            let firmware = Firmware::parse(&bytes).unwrap();
            assert_eq!(firmware.supports_capability(44), offload != 0);
            if send {
                let expected: Vec<_> = words[8]
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                let encoded = empty_quotas(&firmware).unwrap();
                assert_eq!(encoded.len(), length as usize);
                assert_eq!(encoded, expected, "{line}");
            } else {
                assert_eq!(length, 0);
                assert_eq!(words[8], "-");
            }
        }
        assert_eq!(keys.len(), 16);
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_BINDING_TRACE"]
    fn pinned_linux_cold_binding_sf_and_mac_power_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_BINDING_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "2d5a8c78beff7765db3a572eb3e6aefcd1a8a9165914803e16a68cd1aad788e7"
        );
        let text = std::str::from_utf8(&trace).unwrap();
        let mut keys = alloc::collections::BTreeSet::new();
        let mut records = 0;
        for line in text.lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            assert_eq!(words.len(), 12);
            let values: Vec<i32> = words[..10]
                .iter()
                .map(|word| word.parse().unwrap())
                .collect();
            assert!(keys.insert(values[..7].to_vec()));
            let [
                layout,
                cdb,
                band,
                _offload,
                cam,
                remove,
                status,
                result,
                sf_commands,
                length,
            ] = values[..]
            else {
                panic!("source record");
            };
            assert_eq!(sf_commands, 0);
            assert_eq!(result, if status == 0 { 0 } else { -5 });
            assert_eq!(
                binding_status(&(status as u32).to_le_bytes()).is_ok(),
                result == 0
            );
            let decode = |hex: &str| -> Vec<u8> {
                hex.as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect()
            };
            let bytes = image(layout != 0, cdb != 0);
            let firmware = Firmware::parse(&bytes).unwrap();
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
            let binding = encode(&firmware, channel, remove != 0).unwrap();
            assert_eq!(binding.len(), length as usize);
            assert_eq!(binding, decode(words[10]), "{line}");
            let power =
                super::super::super::super::super::mac_context::cold_power_bytes(if cam != 0 {
                    PowerMode::ContinuouslyAwake
                } else {
                    PowerMode::SavePower
                });
            assert_eq!(power, decode(words[11]), "{line}");
            records += 1;
        }
        assert_eq!(records, 128);
    }
}
