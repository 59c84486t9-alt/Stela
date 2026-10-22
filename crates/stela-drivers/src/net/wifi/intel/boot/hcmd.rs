// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Exclusive process-context gen2 host-command queue. This transports raw
//! responses; command-specific status/association/key effects remain separate.
use super::super::command::{Command, Id, Tfd};
use super::*;
use alloc::collections::VecDeque;
const MAX_NOTIFICATIONS: usize = 128;
fn next_write(family: Family, write: u16) -> u16 {
    if family == Family::Ax200 {
        write.wrapping_add(1) & 255
    } else {
        write.wrapping_add(1)
    }
}

#[derive(Clone, Debug)]
pub struct CommandTicket {
    // API identity only, never the actual PCI/BAR ownership guard. Retaining
    // this Arc prevents a different ROM object reusing a ticket's identity.
    epoch: Arc<()>,
    serial: u64,
    sequence: u16,
}
impl CommandTicket {
    pub fn sequence(&self) -> u16 {
        self.sequence
    }
}
impl PartialEq for CommandTicket {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.epoch, &other.epoch)
            && self.serial == other.serial
            && self.sequence == other.sequence
    }
}
impl Eq for CommandTicket {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandResponse {
    pub ticket: CommandTicket,
    pub request: Id,
    pub command: u8,
    pub group: u8,
    pub raw: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareNotification {
    pub command: u8,
    pub group: u8,
    pub sequence: u16,
    pub raw: Vec<u8>,
}
/// Canonical actual packet retained once after completed-RB CPU handoff.
/// Caller-mutable public diagnostics can never be restored into this queue.
pub(super) struct CapturedNotification {
    pub(super) epoch: Arc<()>,
    pub(super) bytes: Vec<u8>,
}
impl CapturedNotification {
    fn into_diagnostics(self) -> FirmwareNotification {
        let mut raw = self.bytes;
        let command = raw[4];
        let group = raw[5];
        let sequence = u16::from_le_bytes([raw[6], raw[7]]);
        raw.drain(..8);
        FirmwareNotification {
            command,
            group,
            sequence,
            raw,
        }
    }
}
pub(super) enum NotificationPoll {
    Pending,
    Processed,
    Backpressure,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandProgress {
    Pending,
    Completed(CommandResponse),
}
struct Pending {
    ticket: CommandTicket,
    request: Id,
    slot: u16,
    remainder: Option<Chunk>,
    response: Option<CommandResponse>,
    descriptor_cpu: bool,
    first_cpu: bool,
    allow_rfkill: bool,
}
pub(super) struct Queue {
    epoch: Arc<()>,
    first: Chunk,
    invalid: Chunk,
    invalid_tfd: Tfd,
    slots: u16,
    write: u16,
    next_serial: u64,
    pending: Option<Pending>,
    notifications: VecDeque<CapturedNotification>,
}
impl Queue {
    pub(super) unsafe fn prepare(
        command: &Chunk,
        profile: &Profile,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        let slots = if profile.family() == Family::Ax210 {
            128
        } else {
            32
        };
        // Exact iwl_pcie_alloc_invalid_tx_cmd header, not an executable fallback.
        let invalid = Chunk::allocate(
            source,
            domain.clone(),
            &[6, 0xf, 0xff, 0xff, 0, 0, 0, 0],
            Direction::Bidirectional,
        )?;
        let first = Chunk::allocate(
            source,
            domain,
            &alloc::vec![0;usize::from(slots)*64],
            Direction::Bidirectional,
        )?;
        let invalid_tfd = Tfd::encode(&[invalid.region()])?;
        let mut descriptors = Vec::with_capacity(usize::from(slots) * 256);
        for _ in 0..slots {
            descriptors.extend_from_slice(invalid_tfd.bytes());
        }
        // This command ring is still private before ROM context publication.
        unsafe {
            command.write_owned(0, &descriptors)?;
        }
        Ok(Self {
            epoch: Arc::new(()),
            first,
            invalid,
            invalid_tfd,
            slots,
            write: 0,
            next_serial: 1,
            pending: None,
            notifications: VecDeque::new(),
        })
    }
    pub(super) fn retain_notification(
        &mut self,
        packet: &receive::Packet<'_>,
    ) -> Result<(), Error> {
        let raw = packet.raw();
        let sequence = u16::from_le_bytes([raw[6], raw[7]]);
        if sequence & 0x8000 == 0 && raw[4..6] != [0x1c, 0] {
            return Err(Error::CommandSequence(sequence));
        }
        if self.notifications.len() == MAX_NOTIFICATIONS {
            return Err(Error::NotificationLimit);
        }
        self.notifications.push_back(CapturedNotification {
            epoch: self.epoch.clone(),
            bytes: packet.raw().to_vec(),
        });
        Ok(())
    }
    pub(super) fn take_matching(&mut self, command: u8, group: u8) -> Option<CapturedNotification> {
        let at = self.notifications.iter().position(|packet| {
            packet.bytes[4..6] == [command, group] && packet.bytes[7] & 0x80 != 0
        })?;
        self.notifications.remove(at)
    }
    pub(super) fn owns_capture(&self, packet: &CapturedNotification) -> bool {
        Arc::ptr_eq(&self.epoch, &packet.epoch)
    }
    pub(super) fn notification_count(&self) -> usize {
        self.notifications.len()
    }
    pub(super) fn expose(&mut self) {
        self.first.expose();
        self.invalid.expose();
    }
    pub(super) unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        if let Some(pending) = self.pending.as_mut()
            && let Some(remainder) = pending.remainder.as_mut()
        {
            unsafe {
                remainder.release()?;
            }
        }
        unsafe {
            self.first.release()?;
            self.invalid.release()?;
        }
        Ok(())
    }
    fn finish(&mut self, command: &Chunk) -> Result<CommandResponse, Error> {
        let pending = self.pending.as_mut().ok_or(Error::CommandTicket)?;
        if pending.response.is_none() {
            return Err(Error::CommandPending);
        }
        let descriptor = usize::from(pending.slot) * 256;
        let first = usize::from(pending.slot) * 64;
        // The matching actual RX response ends device ownership of this
        // descriptor and its bidirectional TB0, including possible writeback.
        // Preserve successful handoffs across a later visibility failure.
        if !pending.descriptor_cpu {
            unsafe { command.complete_for_cpu(descriptor..descriptor + 256) }
                .map_err(Error::CommandReclaim)?;
            pending.descriptor_cpu = true;
        }
        if !pending.first_cpu {
            unsafe { self.first.complete_for_cpu(first..first + 64) }
                .map_err(Error::CommandReclaim)?;
            pending.first_cpu = true;
        }
        // Actual source RX command completion transfers this descriptor back
        // to the CPU. Restore the retained invalid target before reuse.
        unsafe {
            command
                .write_owned(descriptor, self.invalid_tfd.bytes())
                .map_err(Error::CommandReclaim)?;
        }
        if let Some(remainder) = pending.remainder.as_mut() {
            unsafe {
                remainder
                    .release()
                    .map_err(|e| Error::CommandReclaim(dma::Error::Dma(e)))?;
            }
        }
        let mut pending = self.pending.take().unwrap();
        Ok(pending.response.take().unwrap())
    }
}

impl<'a, Q: BootIo> RomBoot<'a, Q> {
    /// Submit one synchronous host command using the actual caller-selected
    /// firmware API. No success is reported until real RX command completion;
    /// that raw transport response is not command-specific status/acceptance.
    /// # Safety
    /// Source supplies fresh exclusive pages under this epoch's retained real
    /// domain/coherency qualification. Only this polling owner can submit or
    /// reset, and the relevant firmware command's actual API was selected.
    /// Caller establishes command-specific prerequisites and retains every
    /// indirect DMA allocation/firmware object through its actual device
    /// completion or stopped/drained teardown. This raw transport supplies no
    /// station, queue, key or indirect-resource authority. A raw HCMD response
    /// alone never ends ownership of a persistent indirect DMA allocation.
    pub unsafe fn submit_command(
        &mut self,
        id: Id,
        payload: &[u8],
        source: &dyn PageSource,
    ) -> Result<CommandTicket, Error> {
        unsafe { self.submit_command_with_policy(id, payload, source, false) }
    }
    // Only source-backed control commands whose Linux flags contain
    // CMD_SEND_IN_RFKILL may use true. The RF kill never becomes RF authority.
    pub(super) unsafe fn submit_command_with_policy(
        &mut self,
        id: Id,
        payload: &[u8],
        source: &dyn PageSource,
        allow_rfkill: bool,
    ) -> Result<CommandTicket, Error> {
        if self.state != State::PnvmObserved {
            return Err(Error::State);
        }
        if self.hcmd.pending.is_some() {
            return Err(Error::CommandPending);
        }
        if self.credits == 0 {
            return Err(Error::CompletionCredit);
        }
        if self.read_register(0x24)? & 0x08000000 == 0 && !allow_rfkill {
            return Err(Error::RfKilled);
        }
        let next_serial = self
            .hcmd
            .next_serial
            .checked_add(1)
            .ok_or(Error::CommandTicket)?;
        let command = Command::encode(id, 0, self.hcmd.write, payload)?;
        let slot = self.hcmd.write & (self.hcmd.slots - 1);
        let mut remainder = if command.remainder().is_empty() {
            None
        } else {
            Some(Chunk::allocate(
                source,
                self.domain.clone(),
                command.remainder(),
                Direction::ToDevice,
            )?)
        };
        let first = super::super::context::Region {
            address: self.hcmd.first.region().address + u64::from(slot) * 64,
            bytes: command.first_tb().len(),
        };
        let tfd = command.tfd(first, remainder.as_ref().map(Chunk::region))?;
        // TB0 remains coherent and pinned for the queue's lifetime. It is
        // initially unused, or its prior actual command response completed.
        unsafe {
            self.hcmd
                .first
                .write_owned(usize::from(slot) * 64, command.first_tb())?;
        }
        if let Some(remainder) = remainder.as_mut() {
            remainder.expose();
        }
        let ticket = CommandTicket {
            epoch: self.hcmd.epoch.clone(),
            serial: self.hcmd.next_serial,
            sequence: command.sequence(),
        };
        self.hcmd.next_serial = next_serial;
        self.hcmd.pending = Some(Pending {
            ticket: ticket.clone(),
            request: command.id(),
            slot,
            remainder,
            response: None,
            descriptor_cpu: false,
            first_cpu: false,
            allow_rfkill,
        });
        let result = (|| {
            // Retained pending payload/owner precedes even this descriptor
            // pointer store, as well as the later producer doorbell.
            unsafe {
                self.command
                    .write_owned(usize::from(slot) * 256, tfd.bytes())?;
            }
            fence(Ordering::Release);
            let next = next_write(self.profile.family(), self.hcmd.write);
            self.hcmd.write = next;
            self.write(0x460, u32::from(next))?; // command queue0 <<16
            Ok(ticket)
        })();
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.hcmd
            .notifications
            .pop_front()
            .map(CapturedNotification::into_diagnostics)
    }
    pub(super) fn take_matching_notification(
        &mut self,
        command: u8,
        group: u8,
    ) -> Option<FirmwareNotification> {
        self.hcmd
            .take_matching(command, group)
            .map(CapturedNotification::into_diagnostics)
    }
    pub fn poll_command(&mut self, ticket: &CommandTicket) -> Result<CommandProgress, Error> {
        if self.state != State::PnvmObserved
            || self
                .hcmd
                .pending
                .as_ref()
                .is_none_or(|p| &p.ticket != ticket)
        {
            return Err(Error::CommandTicket);
        }
        let result = self.poll_command_inner();
        // A failed invalidation after actual completion remains retryable,
        // with its payload/response retained and no new command admitted.
        if result.is_err() && !matches!(result, Err(Error::CommandReclaim(_))) {
            self.state = State::Poisoned;
        }
        result
    }
    fn poll_command_inner(&mut self) -> Result<CommandProgress, Error> {
        if self.hcmd.pending.as_ref().unwrap().response.is_some() {
            return self
                .hcmd
                .finish(&self.command)
                .map(CommandProgress::Completed);
        }
        self.check_command_causes(self.hcmd.pending.as_ref().unwrap().allow_rfkill)?;
        while let Some(bytes) = self.completed_buffer()? {
            self.dispatch_command_packets(&bytes)?;
            if self.hcmd.pending.as_ref().unwrap().response.is_some() {
                return self
                    .hcmd
                    .finish(&self.command)
                    .map(CommandProgress::Completed);
            }
        }
        Ok(CommandProgress::Pending)
    }
    fn check_command_causes(&mut self, allow_rfkill: bool) -> Result<(), Error> {
        let causes = self.read_register(8)?;
        self.write(8, causes | !(1 | (1 << 31)))?;
        if causes & ((1 << 29) | (1 << 25)) != 0 {
            return Err(Error::DeviceError(causes));
        }
        if self.read_register(0x24)? & 0x08000000 == 0 && !allow_rfkill {
            return Err(Error::RfKilled);
        }
        Ok(())
    }
    fn dispatch_command_packets(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for packet in Packets::new(self.profile.family(), 0, bytes)? {
            let packet = packet?;
            // MVM's actual no-reclaim list is legacy TX_CMD0x1c only.
            let reclaim = !packet.unsolicited() && !(packet.group == 0 && packet.command == 0x1c);
            if reclaim {
                let pending = self
                    .hcmd
                    .pending
                    .as_mut()
                    .ok_or(Error::CommandSequence(packet.sequence))?;
                if packet.sequence != pending.ticket.sequence || pending.response.is_some() {
                    return Err(Error::CommandSequence(packet.sequence));
                }
                pending.response = Some(CommandResponse {
                    ticket: pending.ticket.clone(),
                    request: pending.request,
                    command: packet.command,
                    group: packet.group,
                    raw: packet.payload().to_vec(),
                });
            } else {
                self.hcmd.retain_notification(&packet)?;
            }
        }
        Ok(())
    }
    pub(super) fn poll_notification_buffers(&mut self, allow_rfkill: bool) -> Result<(), Error> {
        if self.state != State::PnvmObserved || self.hcmd.pending.is_some() {
            return Err(Error::State);
        }
        let result = (|| {
            self.check_command_causes(allow_rfkill)?;
            while let Some(bytes) = self.completed_buffer()? {
                self.dispatch_command_packets(&bytes)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
    /// One actual fixed 4 KiB RB contains at most 64 AX200 packets (one on AX210). Leave
    /// that complete capacity before taking DMA ownership of another RB.
    /// Backpressure performs no MMIO, completion read or ownership transfer.
    pub(super) fn poll_one_notification_buffer(&mut self) -> Result<NotificationPoll, Error> {
        if self.state != State::PnvmObserved || self.hcmd.pending.is_some() {
            return Err(Error::State);
        }
        let maximum_packets = if self.profile.family() == Family::Ax200 {
            RECEIVE_BUFFER_BYTES / 64
        } else {
            1
        };
        let reservation = MAX_NOTIFICATIONS
            .checked_sub(maximum_packets)
            .ok_or(Error::NotificationLimit)?;
        if self.hcmd.notifications.len() > reservation {
            return Ok(NotificationPoll::Backpressure);
        }
        let result = (|| {
            self.check_command_causes(false)?;
            if let Some(bytes) = self.completed_buffer()? {
                self.dispatch_command_packets(&bytes)?;
                Ok(NotificationPoll::Processed)
            } else {
                Ok(NotificationPoll::Pending)
            }
        })();
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    #[ignore = "requires freshly built unchanged Linux HCMD helper oracle"]
    fn unchanged_linux_sentinel_index_and_reclaim_oracle() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_HCMD_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "7df844e1701655ca51acf38860f871a7e21b35ebbe901f035c02115e17955595"
        );
        let text = core::str::from_utf8(&bytes).unwrap();
        let hex = |bytes: &[u8]| -> alloc::string::String {
            bytes.iter().map(|b| std::format!("{b:02x}")).collect()
        };
        let sentinel = Tfd::encode(&[context::Region {
            address: 0x1234000,
            bytes: 8,
        }])
        .unwrap();
        let mut indices = 0;
        let mut reclaims = 0;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields[0] {
                "invalid" => assert_eq!(fields[1], hex(&[6, 15, 255, 255, 0, 0, 0, 0])),
                "sentinel" => assert_eq!(fields[1], hex(sentinel.bytes())),
                "index" => {
                    let family = if fields[1] == "0" {
                        Family::Ax200
                    } else {
                        Family::Ax210
                    };
                    let index = fields[2].parse::<u16>().unwrap();
                    let slots = if family == Family::Ax200 { 32 } else { 128 };
                    let slot = index & (slots - 1);
                    assert_eq!(fields[3].parse::<u16>().unwrap(), slot);
                    assert_eq!(fields[4].parse::<u16>().unwrap(), next_write(family, index));
                    assert_eq!(
                        fields[5].parse::<u64>().unwrap(),
                        0x3456000 + u64::from(slot) * 64
                    );
                    indices += 1;
                }
                "reclaim" => {
                    let count = fields[1].parse::<usize>().unwrap();
                    assert_eq!(fields[2].parse::<usize>().unwrap(), count - 1);
                    assert_eq!(fields[3], hex(&sentinel.bytes()[..12]));
                    reclaims += 1;
                }
                _ => panic!("unknown trace"),
            }
        }
        assert_eq!((indices, reclaims), (18, 25));
    }
}
