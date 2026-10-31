// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Original unassociated legacy-rate AP station0 and mandatory TLC configuration.
//! The selected MLD owner uses its own STA_CONFIG/REMOVE command family.
//! No transmit queue, frame, key, association or normalized station RX exists.
use super::*;
use crate::Mac;
use crate::wifi::intel::firmware::Firmware;
mod mld;
mod queue;
pub use queue::{
    Ax200Coexistence, Ax200CoexistenceError, Ax200CoexistencePhase, Ax200ManagementQueue,
    Ax200ManagementQueueError, Ax200ManagementQueuePhase,
};

/// OS-selected peer capabilities, not calibration, admission or association.
/// Rate bits follow source legacy indices: CCK1..11 bits0..3, OFDM6..54 bits4..11.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyPeer {
    pub address: Mac,
    pub beacon_interval_tu: u16,
    pub rates: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerCommandKind {
    Add,
    Configure,
    Rates,
    Drain,
    Flush,
    Undrain,
    Remove,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCommand {
    kind: PeerCommandKind,
    id: Id,
    bytes: Vec<u8>,
}
impl PeerCommand {
    pub fn kind(&self) -> PeerCommandKind {
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
pub enum Ax200LegacyPeerPhase {
    NotStarted,
    Waiting(PeerCommandKind),
    ManagementQueueRequired,
    Removed,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200LegacyPeerError {
    Binding(Ax200BindingError),
    Boot(Error),
    Phy(Ax200PhyError),
    MissingApi,
    Version { group: u8, command: u8, version: u8 },
    Peer,
    Status(u32),
    ResponseLength(usize),
    FlushStation(u16),
    UnexpectedQueues(u16),
    Deadline(PeerCommandKind),
    State,
}
pub struct Ax200LegacyPeer<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> {
    pub(in crate::wifi::intel::boot) binding: Ax200Binding<'a, Q, B, O>,
    peer: LegacyPeer,
    phase: Ax200LegacyPeerPhase,
    commands: Vec<PeerCommand>,
    next: usize,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    flush_notification: u8,
    removing: bool,
    mld: bool,
    first_error: Option<Ax200LegacyPeerError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Binding<'a, Q, B, O> {
    /// Install only the original single legacy AP station. The same
    /// service must keep restrictive revocation for every configured legacy
    /// rate plus the cold response union, through removal or stop.
    /// # Safety
    /// begin_binding's original provider, exclusive-owner and requester
    /// contracts remain in force. Peer capabilities must be the OS-selected
    /// AP's legacy capabilities. No external station, queue, key, modern
    /// negotiation, action-frame state update or MAC mutation may race this
    /// owner. This method does not authorize transmitting an authentication.
    pub unsafe fn begin_legacy_peer(
        self,
        peer: LegacyPeer,
    ) -> Result<Ax200LegacyPeer<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200BindingPhase::AuthenticationRequired
            || self.first_error.is_some()
            || self.ticket.is_some()
            || self.removing
        {
            return Err(Box::new(self));
        }
        Ok(Ax200LegacyPeer {
            binding: self,
            peer,
            phase: Ax200LegacyPeerPhase::NotStarted,
            commands: Vec::new(),
            next: 0,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            flush_notification: 0,
            removing: false,
            mld: false,
            first_error: None,
        })
    }
    /// Install the original selected MLD station0 on this active link0,
    /// keeping only the OS-selected peer's finite legacy-rate capabilities.
    /// # Safety
    /// begin_legacy_peer's provider, restrictive-revocation and unique
    /// native ownership contracts apply unchanged. No station, session, key,
    /// queue or negotiated HT/HE/association state may be changed externally.
    pub unsafe fn begin_mld_peer(
        self,
        peer: LegacyPeer,
    ) -> Result<Ax200LegacyPeer<'a, Q, B, O>, Box<Self>> {
        if !self.mld {
            return Err(Box::new(self));
        }
        // SAFETY: same complete finite-rate/provider lifetime, with
        // selected protocol checked again before any device publication.
        unsafe { self.begin_legacy_peer(peer) }.map(|mut owner| {
            owner.mld = true;
            owner
        })
    }
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200LegacyPeer<'a, Q, B, O> {
    pub fn phase(&self) -> Ax200LegacyPeerPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200LegacyPeerError> {
        self.first_error.as_ref()
    }
    pub fn commands(&self) -> &[PeerCommand] {
        &self.commands
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    /// Acknowledged firmware identity.
    pub fn station_id(&self) -> Option<u8> {
        (self.phase == Ax200LegacyPeerPhase::ManagementQueueRequired).then_some(0)
    }
    pub fn peer(&self) -> LegacyPeer {
        self.peer
    }
    pub fn take_other_notification(&mut self) -> Option<FirmwareNotification> {
        self.binding.take_other_notification()
    }
    /// Raw original RX only. Host duplicate/reorder/security and associated
    /// normalized RX remain a later station/queue continuation requirement.
    pub fn poll_receive(&mut self) -> Result<MpduProgress, Ax200LegacyPeerError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        if self.ticket.is_some() {
            return Err(Ax200LegacyPeerError::State);
        }
        let result = self
            .binding
            .poll_receive()
            .map_err(Ax200LegacyPeerError::Binding);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Ax200LegacyPeerError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        let result = self
            .binding
            .replenish_completed_receive()
            .map_err(Ax200LegacyPeerError::Binding);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.binding.stop() {
            Ok(()) => {
                self.phase = Ax200LegacyPeerPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.fail(Ax200LegacyPeerError::Boot(error.clone()));
                Err(error)
            }
        }
    }
    fn fail(&mut self, error: Ax200LegacyPeerError) {
        self.first_error.get_or_insert(error);
        self.phase = Ax200LegacyPeerPhase::Failed;
    }
    fn prepare(&mut self) -> Result<(), Ax200LegacyPeerError> {
        if self.mld {
            return mld::prepare(self);
        }
        let power = &self.binding.power;
        let radio = &power.phy.scan.mac.country.board.scan.mcc.setup.lari.radio;
        let firmware = &radio.initialized.boot.firmware;
        // Source's48-byte station body requires new-RX68 or STA_TYPE API30.
        // MLD110 selects another station owner, even if earlier cold setup
        // legitimately used it only to check firmware-internal aux activity.
        // This initial profile
        // has only LMAC0, no previous host peer, queues, keys or rate command.
        // Firmware's auxiliary station is source-owned, not allocated as STA0.
        if firmware.supports_capability(40)
            || !firmware.supports_capability(43)
            || firmware.supports_capability(110)
            || !(firmware.supports_capability(68) || firmware.supports_api(30))
        {
            return Err(Ax200LegacyPeerError::MissingApi);
        }
        for (group, command, valid) in [
            (1, 0x18, 10..=12),
            (1, 0x19, 2..=2),
            (1, 0x1e, 2..=2),
            (5, 0x0f, 1..=4),
        ] {
            let version = firmware
                .command_version(group, command)
                .ok_or(Ax200LegacyPeerError::MissingApi)?;
            if !valid.contains(&version.command_version) {
                return Err(Ax200LegacyPeerError::Version {
                    group,
                    command,
                    version: version.command_version,
                });
            }
            let valid_notification = match command {
                0x18 => matches!(version.notification_version, 1 | 2),
                0x1e => version.notification_version <= 1,
                _ => version.notification_version == 0,
            };
            if !valid_notification {
                return Err(Ax200LegacyPeerError::Version {
                    group,
                    command,
                    version: version.notification_version,
                });
            }
        }
        let allowed = match power.channel().band {
            Band::Ghz2 => 0xfff,
            Band::Ghz5 | Band::Ghz6 => 0xff0,
        };
        if self.peer.address.0 == [0; 6]
            || self.peer.address.is_multicast()
            || self.peer.beacon_interval_tu < 16
            || self.peer.rates == 0
            || self.peer.rates & !allowed != 0
        {
            return Err(Ax200LegacyPeerError::Peer);
        }
        let nvm = &power.phy.scan.mac.initialized_nvm().information;
        let mut antennas =
            ((firmware.phy_sku().ok_or(Ax200LegacyPeerError::MissingApi)? >> 16) & 15) as u8;
        if nvm.tx_chains as u8 != 0 {
            antennas &= nvm.tx_chains as u8;
        }
        if antennas == 0 || antennas & !3 != 0 {
            return Err(Ax200LegacyPeerError::Peer);
        }
        self.flush_notification = firmware
            .command_version(1, 0x1e)
            .unwrap()
            .notification_version;
        self.commands = alloc::vec![
            PeerCommand {
                kind: PeerCommandKind::Add,
                id: Id {
                    group: 0,
                    opcode: 0x18,
                    version: 0
                },
                bytes: station(self.peer.address)
            },
            PeerCommand {
                kind: PeerCommandKind::Rates,
                id: Id {
                    group: 5,
                    opcode: 0x0f,
                    version: 0
                },
                bytes: rates(firmware, self.peer.rates, antennas)?
            }
        ];
        Ok(())
    }
    /// Original no-queue removal still sends drain, station/TID flush,
    /// undrain and REMOVE. A new transmit lease cannot block this teardown.
    pub fn begin_remove(&mut self) -> Result<(), Ax200LegacyPeerError> {
        if self.phase != Ax200LegacyPeerPhase::ManagementQueueRequired
            || self.ticket.is_some()
            || self.first_error.is_some()
            || self.removing
        {
            return Err(Ax200LegacyPeerError::State);
        }
        if self.mld {
            // Source MLD removal always flushes station TIDs first. This
            // unique no-queue/no-key peer leaves wait/disable/key iteration
            // without device effects; STA_REMOVE still requires a real ACK.
            self.commands.extend(mld::removal());
            self.removing = true;
            return Ok(());
        }
        for (kind, opcode, bytes) in [
            (PeerCommandKind::Drain, 0x18, drain(true)),
            (
                PeerCommandKind::Flush,
                0x1e,
                alloc::vec![0, 0, 0, 0, 255, 255, 0, 0],
            ),
            (PeerCommandKind::Undrain, 0x18, drain(false)),
            (PeerCommandKind::Remove, 0x19, alloc::vec![0;4]),
        ] {
            self.commands.push(PeerCommand {
                kind,
                id: Id {
                    group: 0,
                    opcode,
                    version: 0,
                },
                bytes,
            });
        }
        self.removing = true;
        Ok(())
    }
    pub fn into_binding(self) -> Result<Ax200Binding<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200LegacyPeerPhase::Removed
            || self.first_error.is_some()
            || self.ticket.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(self.binding)
    }
    /// # Safety
    /// The original native requester/domain and begin_legacy_peer
    /// service contracts must hold through every visibility and completion.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200LegacyPeerPhase, Ax200LegacyPeerError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        if self.phase == Ax200LegacyPeerPhase::Stopped {
            return Err(Ax200LegacyPeerError::State);
        }
        // SAFETY: unchanged native owner and provider contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(
                error,
                Ax200LegacyPeerError::Boot(Error::CommandReclaim(_))
                    | Ax200LegacyPeerError::Phy(Ax200PhyError::Scan(
                        Ax200ScanError::PreScanReceiveRequired
                            | Ax200ScanError::ReceiveBackpressure { .. }
                    ))
            )
            && !(self.next == 0
                && matches!(
                    error,
                    Ax200LegacyPeerError::Binding(Ax200BindingError::Regulatory(_))
                ))
        {
            self.fail(error.clone());
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200LegacyPeerPhase, Ax200LegacyPeerError> {
        if let Some(error) = self.binding.first_error() {
            return Err(Ax200LegacyPeerError::Binding(error.clone()));
        }
        if self.binding.power.phy.boot().state != State::PnvmObserved {
            return Err(Ax200LegacyPeerError::State);
        }
        if !self.removing {
            self.binding
                .power
                .phy
                .scan
                .mac
                .country
                .check_selection()
                .map_err(|e| Ax200LegacyPeerError::Binding(Ax200BindingError::Country(e)))?;
        }
        if self.phase == Ax200LegacyPeerPhase::Removed {
            return Ok(self.phase);
        }
        if self.phase == Ax200LegacyPeerPhase::ManagementQueueRequired && !self.removing {
            self.binding
                .power
                .phy
                .capture_idle_receive()
                .map_err(Ax200LegacyPeerError::Phy)?;
            return Ok(self.phase);
        }
        if self.commands.is_empty() {
            self.prepare()?;
        }
        if let Some(ticket) = self.ticket.as_ref().cloned() {
            let command = &self.commands[self.next - 1];
            let (kind, id) = (command.kind, command.id);
            let progress = self.binding.power.phy.boot().poll_command(&ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200LegacyPeerError::Deadline(kind));
            }
            match progress.map_err(Ax200LegacyPeerError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200LegacyPeerError::Deadline(kind));
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let status = match kind {
                        PeerCommandKind::Add
                        | PeerCommandKind::Drain
                        | PeerCommandKind::Undrain
                            if !self.mld =>
                        {
                            status(&response.raw)
                        }
                        PeerCommandKind::Flush => flush(&response.raw, self.flush_notification),
                        _ => Ok(()),
                    };
                    let (command, group) = (response.command, response.group);
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    if command != id.opcode || group != id.wire().group {
                        return Err(Ax200LegacyPeerError::Boot(Error::InitializationResponse {
                            command,
                            group,
                        }));
                    }
                    status?;
                }
            }
        }
        let Some(command) = self.commands.get(self.next).cloned() else {
            self.phase = if self.removing {
                Ax200LegacyPeerPhase::Removed
            } else {
                Ax200LegacyPeerPhase::ManagementQueueRequired
            };
            return Ok(self.phase);
        };
        let options = self
            .binding
            .power
            .phy
            .scan
            .mac
            .country
            .board
            .scan
            .mcc
            .setup
            .options;
        let ticket = if self.removing {
            // SAFETY: source no-queue drain/flush/undrain/remove creates no RF.
            unsafe {
                self.binding
                    .power
                    .phy
                    .boot()
                    .submit_command(command.id, &command.bytes, source)
            }
            .map_err(Ax200LegacyPeerError::Boot)?
        } else {
            self.binding
                .power
                .phy
                .capture_idle_receive()
                .map_err(Ax200LegacyPeerError::Phy)?;
            // SAFETY: programmed rate bitmap plus cold responses; held
            // original hardware then OS leases span this native HCMD.
            unsafe {
                admission::publish_legacy(
                    &mut self.binding.power,
                    command.id,
                    &command.bytes,
                    self.peer.rates,
                    source,
                )
            }
            .map_err(Ax200LegacyPeerError::Binding)?
        };
        self.ticket = Some(ticket);
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        self.next += 1;
        self.phase = Ax200LegacyPeerPhase::Waiting(command.kind);
        Ok(self.phase)
    }
}
fn station(address: Mac) -> Vec<u8> {
    let mut bytes = alloc::vec![0;48];
    bytes[2..4].fill(255); // source sta_init disables all TX aggregation
    bytes[8..14].copy_from_slice(&address.0);
    bytes[24..28].copy_from_slice(&0x3c02_0000u32.to_le_bytes());
    bytes
}
fn drain(enabled: bool) -> Vec<u8> {
    let mut bytes = alloc::vec![0;48];
    bytes[0] = 1;
    bytes[20..24].copy_from_slice(&(if enabled { 1u32 << 12 } else { 0 }).to_le_bytes());
    bytes[24..28].copy_from_slice(&(1u32 << 12).to_le_bytes());
    bytes
}
fn rates(
    firmware: &Firmware<'_>,
    mask: u16,
    antennas: u8,
) -> Result<Vec<u8>, Ax200LegacyPeerError> {
    let version = firmware
        .command_version(5, 0x0f)
        .ok_or(Ax200LegacyPeerError::MissingApi)?
        .command_version;
    let mut bytes = alloc::vec![0;match version {1|2=>24,3|4=>28,_=>return Err(Ax200LegacyPeerError::Version{group:5,command:0x0f,version})}];
    bytes[6] = antennas;
    bytes[10..12].copy_from_slice(&mask.to_le_bytes());
    Ok(bytes)
}
fn status(raw: &[u8]) -> Result<(), Ax200LegacyPeerError> {
    if raw.len() != 4 {
        return Err(Ax200LegacyPeerError::ResponseLength(raw.len()));
    }
    let status = u32::from_le_bytes(raw.try_into().unwrap());
    if status & 255 == 1 {
        Ok(())
    } else {
        Err(Ax200LegacyPeerError::Status(status))
    }
}
fn flush(raw: &[u8], notification: u8) -> Result<(), Ax200LegacyPeerError> {
    if notification == 0 {
        return Ok(());
    }
    if raw.len() != 132 {
        return Err(Ax200LegacyPeerError::ResponseLength(raw.len()));
    }
    let station = u16::from_le_bytes(raw[..2].try_into().unwrap());
    if station != 0 {
        return Err(Ax200LegacyPeerError::FlushStation(station));
    }
    let queues = u16::from_le_bytes(raw[2..4].try_into().unwrap());
    // This owner has never created any station queue. An unexpected returned
    // queue cannot supply ownership of untracked DMA or be silently reclaimed.
    if queues != 0 {
        return Err(Ax200LegacyPeerError::UnexpectedQueues(queues));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_PEER_TRACE"]
    fn pinned_linux_legacy_station_tlc_and_no_queue_flush_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_PEER_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "3e2a012e9e53c1f9c138ed103677588b7c1e4b04b48e21da32c4c58fe2259ea7"
        );
        let mut keys = alloc::collections::BTreeSet::new();
        for line in std::str::from_utf8(&trace).unwrap().lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            assert!(keys.insert(words[..words.len() - 1].join(" ")));
            let expected: Vec<u8> = words
                .last()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let number = |i: usize| words[i].parse::<i32>().unwrap();
            match words[0] {
                "S" => {
                    assert_eq!(words.len(), 6);
                    let encoded = match number(1) {
                        0 => station(Mac([2, 3, 4, 5, 6, 7])),
                        1 => drain(true),
                        2 => drain(false),
                        _ => panic!("sourcekind"),
                    };
                    assert_eq!(encoded.len(), number(4) as usize);
                    assert_eq!(encoded, expected, "{line}");
                    assert_eq!(
                        status(&(number(2) as u32).to_le_bytes()).is_ok(),
                        number(3) == 0
                    );
                }
                "T" => {
                    assert_eq!(words.len(), 7);
                    let mut image = alloc::vec![0;88];
                    image[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
                    image[72..76].copy_from_slice(&0x4d00u32.to_le_bytes());
                    image.extend(48u32.to_le_bytes());
                    image.extend(4u32.to_le_bytes());
                    image.extend([15, 5, number(1) as u8, 0]);
                    let firmware = Firmware::parse(&image).unwrap();
                    let encoded = rates(&firmware, number(4) as u16, number(2) as u8).unwrap();
                    assert_eq!(encoded.len(), number(5) as usize);
                    assert_eq!(encoded, expected, "{line}");
                }
                "F" => {
                    assert_eq!(words.len(), 8);
                    assert_eq!(number(6), 8);
                    assert_eq!(expected, [0, 0, 0, 0, 255, 255, 0, 0]);
                    if number(2) == 0 {
                        let mut raw = [0; 132];
                        raw[..2].copy_from_slice(&(number(3) as u16).to_le_bytes());
                        raw[2..4].copy_from_slice(&(number(4) as u16).to_le_bytes());
                        assert_eq!(
                            flush(&raw, number(1) as u8).is_ok(),
                            number(5) == 0,
                            "{line}"
                        );
                    }
                }
                "R" => {
                    assert_eq!(words.len(), 4);
                    assert_eq!(number(1), 0);
                    assert_eq!(number(2), 4);
                    assert_eq!(expected, [0; 4]);
                }
                _ => panic!("source record"),
            }
        }
        assert_eq!(keys.len(), 101);
    }
}
