// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! The station's queues while frames flow: every publication holds the same
//! hardware and OS leases the queue's creation held, each TID gets its queue
//! as `iwl_mvm_tvqm_enable_txq` adds it, and TX responses and a removal's
//! flush reclaim what the device finished.
use super::*;
use crate::wifi::intel::boot::ax200::scan::wire as scan_wire;
use crate::wifi::{
    Channel,
    intel::{
        association::SpatialPowerSave,
        firmware::Firmware,
        mcc,
        transmit::{Parameters, Prepared, ring},
    },
    regulatory::database::Country,
    station::phy::Mode,
};

impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200ManagementQueue<'a, Q, B, O> {
    pub fn channel(&self) -> Channel {
        self.peer.as_ref().unwrap().binding.power.channel()
    }

    pub fn firmware(&mut self) -> &Firmware<'a> {
        &self.peer().binding.power.phy.boot().firmware
    }

    pub fn family(&mut self) -> Family {
        self.peer().binding.power.phy.boot().profile.family()
    }

    /// The antennas `iwl_mvm_get_valid_tx_ant` leaves: the firmware's, within
    /// the NVM's.
    pub fn antennas(&mut self) -> u8 {
        let peer = self.peer.as_mut().unwrap();
        let power = &mut peer.binding.power;
        let chains = power.phy.scan.mac.initialized_nvm().information.tx_chains as u8;
        let sku = power.phy.boot().firmware.phy_sku().unwrap_or(0);
        let antennas = ((sku >> 16) & 15) as u8;
        if chains == 0 {
            antennas
        } else {
            antennas & chains
        }
    }

    /// `iwl_mvm_phy_ctxt_changed`: the commands that move the PHY context to
    /// the channel `definition` association negotiated.
    pub fn phy_changed(
        &mut self,
        definition: &ChannelDefinition,
        wide_ofdma: Option<&ChannelDefinition>,
    ) -> Option<Vec<(Id, Vec<u8>)>> {
        let commands = self
            .peer()
            .binding
            .power
            .phy
            .changed(definition, wide_ofdma)?;
        Some(
            commands
                .iter()
                .map(|command| (command.id(), command.bytes().to_vec()))
                .collect(),
        )
    }

    /// Whether the PHY's commands to come hold the receive chains to `spatial`.
    pub fn limit_receive(&mut self, spatial: SpatialPowerSave) -> bool {
        self.peer().binding.power.phy.limit_receive(spatial)
    }

    /// `iwl_mld_change_chanctx`: the context `seat` now runs `definition`.
    pub fn phy_moved(
        &mut self,
        seat: u8,
        definition: &ChannelDefinition,
        wide_ofdma: Option<&ChannelDefinition>,
    ) -> Option<(Id, Vec<u8>)> {
        let phy = &mut self.peer().binding.power.phy;
        let commands = phy.context(seat, definition, wide_ofdma)?;
        let moved = commands.last()?;
        Some((moved.id(), moved.bytes().to_vec()))
    }

    /// The commands that give another link the PHY context `seat`.
    pub fn phy_context(
        &mut self,
        seat: u8,
        definition: &ChannelDefinition,
        wide_ofdma: Option<&ChannelDefinition>,
    ) -> Option<Vec<(Id, Vec<u8>)>> {
        let phy = &mut self.peer().binding.power.phy;
        let commands = phy.context(seat, definition, wide_ofdma)?;
        Some(
            commands
                .iter()
                .map(|command| (command.id(), command.bytes().to_vec()))
                .collect(),
        )
    }

    /// The removal of the PHY context `seat` of a link on `definition`.
    pub fn phy_removal(
        &mut self,
        seat: u8,
        definition: &ChannelDefinition,
    ) -> Option<(Id, Vec<u8>)> {
        let phy = &mut self.peer().binding.power.phy;
        let command = phy.context_removal(seat, definition)?;
        Some((command.id(), command.bytes().to_vec()))
    }

    /// The internal MLO scan of `request`'s channels beside firmware link
    /// `link`. `ebs_failed` is `last_ebs_failed`.
    pub fn internal_scan(
        &mut self,
        request: &crate::wifi::scan::Request,
        local: crate::Mac,
        link: u8,
        traffic: Ax200ScanTraffic,
        ebs_failed: bool,
    ) -> Result<(Id, Vec<u8>), Ax200ScanError> {
        let version = scan_wire::validate(self.firmware())?;
        let ebs = scan_wire::energy_based(self.firmware(), ebs_failed);
        let bytes = scan_wire::encode_internal(request, version, local, link, traffic, ebs)?;
        Ok((scan_wire::REQUEST, bytes))
    }

    /// Whether a scan's EBS status rules EBS out of later scans.
    pub fn energy_based_failed(status: u8) -> bool {
        scan_wire::energy_based_failed(status)
    }

    /// The running scan's end, once all it heard was taken.
    pub fn take_scan_completion(&mut self) -> Option<FirmwareNotification> {
        let boot = self.peer().binding.power.phy.boot();
        let end = (scan_wire::COMPLETE_OPCODE, scan_wire::COMPLETE_GROUP);
        if boot.hcmd.matching_precedes((0xc1, 0), end) {
            return None;
        }
        boot.take_matching_notification(end.0, end.1)
    }

    /// The abort of the one scan firmware runs.
    pub fn scan_abort() -> (Id, Vec<u8>) {
        (scan_wire::ABORT, alloc::vec![0; 8])
    }

    /// The chain's transmit limit for the firmware link `seat`, within `dbm`.
    pub fn transmit_limit(&mut self, seat: u8, dbm: i32) -> Option<(Id, Vec<u8>)> {
        self.peer().binding.power.link_limit(seat, dbm)
    }

    /// Publish a firmware command under the leases.
    ///
    /// # Safety
    /// `advance`'s contract holds, and the command stays within the channel,
    /// power and legacy rates those leases check.
    pub unsafe fn submit(
        &mut self,
        id: Id,
        bytes: &[u8],
        source: &dyn PageSource,
    ) -> Result<CommandTicket, Ax200ManagementQueueError> {
        let peer = self.peer.as_mut().unwrap();
        let rates = peer.peer.rates;
        // SAFETY: forwarded from the caller.
        unsafe {
            admission::with_legacy_policy(&mut peer.binding.power, rates, |boot| {
                boot.submit_command(id, bytes, source)
                    .map_err(Ax200ManagementQueueError::Boot)
            })
        }
        .map_err(Ax200ManagementQueueError::Binding)?
    }

    pub fn poll_submitted(
        &mut self,
        ticket: &CommandTicket,
    ) -> Result<CommandProgress, Ax200ManagementQueueError> {
        self.peer()
            .binding
            .power
            .phy
            .boot()
            .poll_command(ticket)
            .map_err(Ax200ManagementQueueError::Boot)
    }

    pub fn has_queue(&self, tid: u8) -> bool {
        self.rings.iter().any(|(owner, _)| *owner == tid)
    }

    /// The firmware's last country change, which it asks the host to apply.
    pub fn take_country_update(&mut self) -> Option<FirmwareNotification> {
        self.peer().binding.power.phy.boot().take_country_update()
    }

    /// Take up firmware's later word on the country: the channels it leaves,
    /// with their flags.
    pub fn adopt_country(
        &mut self,
        country: Country,
        profile: mcc::Response,
    ) -> Result<Vec<(Channel, u32)>, mcc::channel::InventoryMismatch> {
        let scan = &mut self.peer().binding.power.phy.scan;
        scan.mac.country.adopt(country, profile)?;
        Ok(scan.regulated_channels())
    }

    /// How many frames `tid`'s queue has not finished.
    pub fn in_flight(&self, tid: u8) -> u16 {
        self.rings
            .iter()
            .find(|(owner, _)| *owner == tid)
            .map_or(0, |(_, ring)| ring.used())
    }

    /// How many more frames `tid`'s queue takes.
    pub fn space(&self, tid: u8) -> u16 {
        self.rings
            .iter()
            .find(|(owner, _)| *owner == tid)
            .map_or(0, |(_, ring)| ring.space())
    }

    /// `iwl_txq_gen2_tx`: fill `tid`'s next descriptor with `mpdu` and tell the
    /// device.
    ///
    /// # Safety
    /// As [`Self::submit`], and the frame goes to the peer on the channel.
    pub unsafe fn publish(
        &mut self,
        tid: u8,
        mpdu: &[u8],
        parameters: Parameters,
        source: &dyn PageSource,
    ) -> Result<(), Ax200ManagementQueueError> {
        let peer = self.peer.as_mut().unwrap();
        let Some((_, ring)) = self.rings.iter_mut().find(|(owner, _)| *owner == tid) else {
            return Err(Ax200ManagementQueueError::State);
        };
        let rates = peer.peer.rates;
        // SAFETY: forwarded from the caller; the firmware accepted the ring.
        unsafe {
            admission::with_legacy_policy(&mut peer.binding.power, rates, |boot| {
                let frame =
                    Prepared::prepare(&boot.firmware, boot.profile.family(), mpdu, parameters)
                        .map_err(|error| {
                            Ax200ManagementQueueError::Ring(ring::Error::Frame(error))
                        })?;
                let pointer = ring
                    .publish(&frame, source)
                    .map_err(Ax200ManagementQueueError::Ring)?;
                boot.write_queue_pointer(pointer)
                    .map_err(Ax200ManagementQueueError::Boot)
            })
        }
        .map_err(Ax200ManagementQueueError::Binding)?
    }

    /// Reclaim what a TX response on `queue` finished, up to `next`.
    pub fn reclaim(&mut self, queue: u16, next: u16) -> Result<u16, Ax200ManagementQueueError> {
        let Some((_, ring)) = self
            .rings
            .iter_mut()
            .find(|(_, ring)| ring.queue() == queue)
        else {
            return Err(Ax200ManagementQueueError::FlushQueue { tid: 0, queue });
        };
        // SAFETY: the firmware finished these frames, and only it names them.
        unsafe { ring.reclaim(next) }.map_err(Ax200ManagementQueueError::Ring)
    }

    /// The TID whose queue `queue` is.
    pub fn queue_tid(&self, queue: u16) -> Option<u8> {
        self.rings
            .iter()
            .find(|(_, ring)| ring.queue() == queue)
            .map(|(tid, _)| *tid)
    }

    /// Prepare `tid`'s queue for a peer in `mode` and ask the firmware's
    /// scheduler for it, halving as `iwl_txq_dyn_alloc` does what memory
    /// cannot back, down to the size every peer gets.
    ///
    /// # Safety
    /// As [`Self::submit`].
    pub unsafe fn add_queue(
        &mut self,
        tid: u8,
        mode: Mode,
        stations: u32,
        source: &dyn PageSource,
    ) -> Result<CommandTicket, Ax200ManagementQueueError> {
        let peer = self.peer.as_mut().unwrap();
        let rates = peer.peer.rates;
        let memory = &mut self.memory;
        let configuration = &mut self.configuration;
        // SAFETY: as `advance_inner`'s queue: the leases span the fresh DMA's
        // initialization and the command that publishes its addresses.
        unsafe {
            admission::with_legacy_policy(&mut peer.binding.power, rates, |boot| {
                let family = boot.profile.family();
                let mut slots = wire::data_slots(family, mode);
                *memory = Some(loop {
                    let prepared = NativeMemory::prepare(
                        &boot.firmware,
                        family,
                        slots,
                        source,
                        boot.domain.clone(),
                    );
                    match prepared {
                        Err(wire::Error::Dma(_)) if slots > wire::PLAIN_DATA_SLOTS => slots /= 2,
                        prepared => break prepared.map_err(Ax200ManagementQueueError::Queue)?,
                    }
                });
                let command = memory
                    .as_ref()
                    .unwrap()
                    .configuration(stations, tid)
                    .map_err(Ax200ManagementQueueError::Queue)?;
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
        .map_err(Ax200ManagementQueueError::Binding)?
    }

    /// The scheduler answered [`Self::add_queue`]: `tid`'s frames may flow.
    pub fn queue_added(
        &mut self,
        tid: u8,
        response: &CommandResponse,
    ) -> Result<(), Ax200ManagementQueueError> {
        let reply = self
            .configuration
            .as_ref()
            .ok_or(Ax200ManagementQueueError::State)?
            .parse_reply(&response.raw)
            .map_err(Ax200ManagementQueueError::Queue)?;
        if reply.queue == 0 {
            return Err(Ax200ManagementQueueError::ReservedQueue(0));
        }
        self.attach_ring(tid, reply);
        Ok(())
    }
}
