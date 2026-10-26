// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Actual MLD station0 non-QoS queue allocation and empty queue lifetime.
//! No frame or descriptor is published by this owner yet.
use super::*;
mod coexistence;
use crate::net::wifi::intel::transmit::queue::{self as wire, Configuration, NativeMemory, Reply};
pub use coexistence::{Ax200Coexistence, Ax200CoexistenceError, Ax200CoexistencePhase};
const SCHEDULER: Id = Id {
    group: 5,
    opcode: 0x17,
    version: 0,
};
const FLUSH: Id = Id {
    group: 0,
    opcode: 0x1e,
    version: 0,
};
const STATION_REMOVE: Id = Id {
    group: 3,
    opcode: 0x0c,
    version: 0,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200ManagementQueuePhase {
    NotStarted,
    WaitingAdd,
    ManagementFramesRequired,
    WaitingFlush,
    WaitingRemove,
    WaitingStationRemove,
    Removed,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200ManagementQueueError {
    Peer(Ax200LegacyPeerError),
    Binding(Ax200BindingError),
    Boot(Error),
    Queue(wire::Error),
    ReservedQueue(u16),
    FlushLength(usize),
    FlushStation(u16),
    FlushQueues(u16),
    FlushQueue { tid: u16, queue: u16 },
    Deadline(Ax200ManagementQueuePhase),
    State,
}
pub struct Ax200ManagementQueue<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> {
    pub(in crate::net::wifi::intel::boot) peer: Option<Ax200LegacyPeer<'a, Q, B, O>>,
    pub(in crate::net::wifi::intel::boot) memory: Option<NativeMemory>,
    pub(in crate::net::wifi::intel::boot) configuration: Option<Configuration>,
    reply: Option<Reply>,
    phase: Ax200ManagementQueuePhase,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    first_error: Option<Ax200ManagementQueueError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200LegacyPeer<'a, Q, B, O> {
    /// Allocate the original non-QoS/management queue for this actual MLD peer.
    /// # Safety
    /// The genuine provider, restrictive revocation and unique requester/domain
    /// contracts of begin_mld_peer persist. No competing queue/station worker,
    /// descriptor, frame or interrupt submission may race this polling owner.
    pub unsafe fn begin_mld_management_queue(
        self,
    ) -> Result<Ax200ManagementQueue<'a, Q, B, O>, Box<Self>> {
        if !self.mld
            || self.phase != Ax200LegacyPeerPhase::ManagementQueueRequired
            || self.ticket.is_some()
            || self.first_error.is_some()
            || self.removing
        {
            return Err(Box::new(self));
        }
        Ok(Ax200ManagementQueue {
            peer: Some(self),
            memory: None,
            configuration: None,
            reply: None,
            phase: Ax200ManagementQueuePhase::NotStarted,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            first_error: None,
        })
    }
}
impl<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Drop for Ax200ManagementQueue<'_, Q, B, O> {
    fn drop(&mut self) {
        if self.memory.as_ref().is_some_and(NativeMemory::uncertain) {
            // Extra queue maps can remain uncertain even after RomBoot stopped
            // (for example an invalidation failure). Retain its original OS,
            // board, requester/domain and native owner with those mappings.
            if let Some(peer) = self.peer.take() {
                core::mem::forget(peer);
            }
        }
    }
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200ManagementQueue<'a, Q, B, O> {
    pub fn phase(&self) -> Ax200ManagementQueuePhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200ManagementQueueError> {
        self.first_error.as_ref()
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    /// Actual full nine-bit queue identity, never the five-bit echo sequence.
    pub fn queue_id(&self) -> Option<u16> {
        (self.phase == Ax200ManagementQueuePhase::ManagementFramesRequired)
            .then(|| self.reply.unwrap().queue)
    }
    pub fn write_pointer(&self) -> Option<u16> {
        self.queue_id().map(|_| self.reply.unwrap().write_pointer)
    }
    /// Original raw RX only; no normalized station/frame completion is inferred.
    pub fn poll_receive(&mut self) -> Result<MpduProgress, Ax200ManagementQueueError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        if self.phase != Ax200ManagementQueuePhase::ManagementFramesRequired
            || self.ticket.is_some()
        {
            return Err(Ax200ManagementQueueError::State);
        }
        let result = self
            .peer()
            .poll_receive()
            .map_err(Ax200ManagementQueueError::Peer);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn take_other_notification(&mut self) -> Option<FirmwareNotification> {
        if self.first_error.is_some() || self.ticket.is_some() {
            return None;
        }
        self.peer().take_other_notification()
    }
    fn peer(&mut self) -> &mut Ax200LegacyPeer<'a, Q, B, O> {
        self.peer.as_mut().unwrap()
    }
    fn fail(&mut self, error: Ax200ManagementQueueError) {
        self.first_error.get_or_insert(error);
        self.phase = Ax200ManagementQueuePhase::Failed;
    }
    pub fn replenish_completed_receive(
        &mut self,
    ) -> Result<Replenished, Ax200ManagementQueueError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        let result = self
            .peer()
            .replenish_completed_receive()
            .map_err(Ax200ManagementQueueError::Peer);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    /// Run original MLD station removal: FLUSH, empty transport check,
    /// scheduler REMOVE and DMA release, then STA_REMOVE. No separate
    /// no-queue parent escapes to invent a second removal/flush lifecycle.
    pub fn begin_remove_station(&mut self) -> Result<(), Ax200ManagementQueueError> {
        if self.phase != Ax200ManagementQueuePhase::ManagementFramesRequired
            || self.ticket.is_some()
            || self.first_error.is_some()
        {
            return Err(Ax200ManagementQueueError::State);
        }
        self.phase = Ax200ManagementQueuePhase::WaitingFlush;
        Ok(())
    }
    /// Return the original active link only after actual station removal,
    /// scheduler removal and every extra DMA invalidation have completed.
    pub fn into_binding(mut self) -> Result<Ax200Binding<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200ManagementQueuePhase::Removed
            || self.first_error.is_some()
            || self.ticket.is_some()
            || !self.memory.as_ref().is_some_and(NativeMemory::released)
        {
            return Err(Box::new(self));
        }
        match self.peer.take().unwrap().into_binding() {
            Ok(binding) => Ok(binding),
            Err(peer) => {
                self.peer = Some(*peer);
                Err(Box::new(self))
            }
        }
    }
    pub fn stop(&mut self) -> Result<(), Ax200ManagementQueueError> {
        if let Err(error) = self.peer().stop() {
            let error = Ax200ManagementQueueError::Boot(error);
            self.fail(error.clone());
            return Err(error);
        }
        if let Some(memory) = self.memory.as_mut() {
            // SAFETY: independently acknowledged native stop ended all queue
            // DMA, with no frame/IRQ worker in this unique polling epoch.
            if let Err(error) = unsafe { memory.release() } {
                let error = Ax200ManagementQueueError::Queue(error);
                self.fail(error.clone());
                return Err(error);
            }
        }
        self.phase = Ax200ManagementQueuePhase::Stopped;
        Ok(())
    }
    /// # Safety
    /// Fresh exclusive coherent pages and the original same-device policy,
    /// DMA/domain and no-competing-worker contracts remain in force.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200ManagementQueuePhase, Ax200ManagementQueueError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        // SAFETY: unchanged unique native domain and provider lifetime.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(
                error,
                Ax200ManagementQueueError::Boot(Error::CommandReclaim(_))
            )
            && !(self.phase == Ax200ManagementQueuePhase::NotStarted
                && matches!(
                    error,
                    Ax200ManagementQueueError::Binding(Ax200BindingError::Regulatory(_))
                ))
        {
            self.fail(error.clone());
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200ManagementQueuePhase, Ax200ManagementQueueError> {
        if self.phase == Ax200ManagementQueuePhase::Stopped {
            return Err(Ax200ManagementQueueError::State);
        }
        if let Some(error) = self.peer().first_error() {
            return Err(Ax200ManagementQueueError::Peer(error.clone()));
        }
        if self.peer().binding.power.phy.boot().state != State::PnvmObserved {
            return Err(Ax200ManagementQueueError::State);
        }
        if matches!(
            self.phase,
            Ax200ManagementQueuePhase::ManagementFramesRequired
                | Ax200ManagementQueuePhase::Removed
        ) {
            return Ok(self.phase);
        }
        if let Some(ticket) = self.ticket.clone() {
            let phase = self.phase;
            let progress = self.peer().binding.power.phy.boot().poll_command(&ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200ManagementQueueError::Deadline(phase));
            }
            match progress.map_err(Ax200ManagementQueueError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200ManagementQueueError::Deadline(phase));
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let expected = match phase {
                        Ax200ManagementQueuePhase::WaitingFlush => FLUSH,
                        Ax200ManagementQueuePhase::WaitingStationRemove => STATION_REMOVE,
                        _ => SCHEDULER,
                    }
                    .wire();
                    let valid =
                        response.command == expected.opcode && response.group == expected.group;
                    self.ticket = None;
                    self.deadline = None;
                    let result = if !valid {
                        Err(Ax200ManagementQueueError::Boot(
                            Error::InitializationResponse {
                                command: response.command,
                                group: response.group,
                            },
                        ))
                    } else {
                        match phase {
                            Ax200ManagementQueuePhase::WaitingAdd => self
                                .configuration
                                .as_ref()
                                .unwrap()
                                .parse_reply(&response.raw)
                                .map_err(Ax200ManagementQueueError::Queue)
                                .and_then(|reply| {
                                    // HCMD queue0 already belongs to this exact epoch.
                                    if reply.queue == 0 {
                                        return Err(Ax200ManagementQueueError::ReservedQueue(0));
                                    }
                                    self.reply = Some(reply);
                                    self.phase =
                                        Ax200ManagementQueuePhase::ManagementFramesRequired;
                                    Ok(())
                                }),
                            Ax200ManagementQueuePhase::WaitingFlush => {
                                flush_empty(&response.raw, self.reply.unwrap())
                                    .map(|()| self.phase = Ax200ManagementQueuePhase::WaitingRemove)
                            }
                            Ax200ManagementQueuePhase::WaitingRemove => {
                                // SAFETY: real scheduler REMOVE and its HCMD DMA
                                // reclaim completed; this owner published no frame.
                                unsafe { self.memory.as_mut().unwrap().release() }
                                    .map_err(Ax200ManagementQueueError::Queue)
                                    .map(|()| {
                                        self.phase = Ax200ManagementQueuePhase::WaitingStationRemove
                                    })
                            }
                            Ax200ManagementQueuePhase::WaitingStationRemove => {
                                let peer = self.peer();
                                peer.phase = Ax200LegacyPeerPhase::Removed;
                                peer.removing = true;
                                self.phase = Ax200ManagementQueuePhase::Removed;
                                Ok(())
                            }
                            _ => Err(Ax200ManagementQueueError::State),
                        }
                    };
                    self.responses.push(response);
                    result?;
                }
            }
        }
        if matches!(
            self.phase,
            Ax200ManagementQueuePhase::ManagementFramesRequired
                | Ax200ManagementQueuePhase::Removed
        ) {
            return Ok(self.phase);
        }
        let options = self
            .peer()
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
        let ticket = if self.phase == Ax200ManagementQueuePhase::NotStarted {
            let peer = self.peer.as_mut().unwrap();
            let firmware = &peer.binding.power.phy.boot().firmware;
            if !firmware
                .command_version(5, 0x17)
                .is_some_and(|v| v.command_version == 3 && v.notification_version == 2)
                || !firmware
                    .command_version(1, 0x1e)
                    .is_some_and(|v| v.command_version == 2 && v.notification_version == 1)
            {
                return Err(Ax200ManagementQueueError::Queue(wire::Error::Version));
            }
            peer.binding
                .power
                .phy
                .scan
                .mac
                .country
                .check_selection()
                .map_err(|e| Ax200ManagementQueueError::Binding(Ax200BindingError::Country(e)))?;
            peer.binding
                .power
                .phy
                .capture_idle_receive()
                .map_err(|e| Ax200ManagementQueueError::Peer(Ax200LegacyPeerError::Phy(e)))?;
            let memory = &mut self.memory;
            let configuration = &mut self.configuration;
            // SAFETY: every enabled rate/ceiling and both real leases remain
            // held through fresh queue DMA initialization and actual HCMD.
            unsafe {
                admission::with_legacy_policy(&mut peer.binding.power, peer.peer.rates, |boot| {
                    *memory = Some(
                        NativeMemory::prepare(
                            &boot.firmware,
                            Family::Ax200,
                            source,
                            boot.domain.clone(),
                        )
                        .map_err(Ax200ManagementQueueError::Queue)?,
                    );
                    let command = memory
                        .as_ref()
                        .unwrap()
                        .configuration(1, 15)
                        .map_err(Ax200ManagementQueueError::Queue)?;
                    // SAFETY: exclusive fresh actual queue mappings, before any
                    // address is submitted, under both same-device policy leases.
                    memory
                        .as_mut()
                        .unwrap()
                        .expose()
                        .map_err(Ax200ManagementQueueError::Queue)?;
                    let result = boot
                        .submit_command(command.id(), command.payload(), source)
                        .map_err(Ax200ManagementQueueError::Boot);
                    *configuration = Some(command);
                    result
                })
            }
            .map_err(Ax200ManagementQueueError::Binding)??
        } else {
            let (id, bytes) = match self.phase {
                Ax200ManagementQueuePhase::WaitingFlush => {
                    (FLUSH, alloc::vec![0, 0, 0, 0, 255, 255, 0, 0])
                }
                Ax200ManagementQueuePhase::WaitingStationRemove => {
                    (STATION_REMOVE, alloc::vec![0;4])
                }
                _ => (SCHEDULER, remove_bytes(1)),
            };
            // SAFETY: original empty queue FLUSH/REMOVE creates no new RF;
            // all source entries remain invalid and no frames were published.
            unsafe {
                self.peer()
                    .binding
                    .power
                    .phy
                    .boot()
                    .submit_command(id, &bytes, source)
            }
            .map_err(Ax200ManagementQueueError::Boot)?
        };
        self.ticket = Some(ticket);
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        if self.phase == Ax200ManagementQueuePhase::NotStarted {
            self.phase = Ax200ManagementQueuePhase::WaitingAdd;
        }
        Ok(self.phase)
    }
}
fn remove_bytes(station_mask: u32) -> Vec<u8> {
    let mut bytes = alloc::vec![0;36];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&station_mask.to_le_bytes());
    bytes[8..12].copy_from_slice(&15u32.to_le_bytes());
    bytes
}

fn flush_empty(raw: &[u8], queue: Reply) -> Result<(), Ax200ManagementQueueError> {
    if raw.len() != 132 {
        return Err(Ax200ManagementQueueError::FlushLength(raw.len()));
    }
    let h = |at| u16::from_le_bytes(raw[at..at + 2].try_into().unwrap());
    if h(0) != 0 {
        return Err(Ax200ManagementQueueError::FlushStation(h(0)));
    }
    match h(2) {
        0 => Ok(()),
        1 => {
            if h(4) != 15 || h(6) != queue.queue {
                return Err(Ax200ManagementQueueError::FlushQueue {
                    tid: h(4),
                    queue: h(6),
                });
            }
            // Original pcie_reclaim exits before using read_after when
            // is_flush and host read_ptr == write_ptr. This unique owner has
            // never submitted a frame, so those host pointers remain equal.
            // Raw pointer metadata stays in the retained response; it grants
            // no descriptor completion. Actual SCD_REMOVE still gates release.
            Ok(())
        }
        count => Err(Ax200ManagementQueueError::FlushQueues(count)),
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    #[ignore = "requires unchanged pinned Linux MLD queue removal trace"]
    fn pinned_linux_mld_scheduler_remove_and_original_free_call_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_MLD_QUEUE_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "afa0d2ff532df63b85e3086bd699896cf0ee9e8002e02e4e9af21e3dde7dc182"
        );
        let mut keys = alloc::collections::BTreeSet::new();
        for line in std::str::from_utf8(&trace).unwrap().lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            assert_eq!(words.len(), 12);
            assert!(keys.insert(words[..6].join(" ")));
            let number = |i: usize| words[i].parse::<i64>().unwrap();
            assert!(matches!(number(2), 8 | 15));
            assert_eq!(number(7), 65535);
            assert_eq!(number(8), 1);
            if number(1) == 0 {
                assert_eq!(number(6), 0);
                assert_eq!(number(9), 0);
                assert_eq!(number(10), 0);
                assert_eq!(words[11], "-");
            } else {
                assert_eq!(number(6), if number(5) == 0 { 0 } else { -5 });
                assert_eq!(number(9), 0x517);
                assert_eq!(number(10), 36);
                let bytes: Vec<_> = words[11]
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                    .collect();
                assert_eq!(remove_bytes(number(3) as u32), bytes, "{line}");
            }
        }
        assert_eq!(keys.len(), 72);
    }
}
