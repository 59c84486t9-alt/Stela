// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Single-interface MT7925 client ownership. Plain STA_REC installation binds
//! raw-header format to the actual retained peer; generic WMWA facts never do.
use super::{Controller, Phase as ControllerPhase};

mod packet;
mod radio;
use crate::{
    bus::dma::memory::PageSource,
    net::wifi::{
        self,
        frame::{Header, Mpdu},
        mediatek::{
            identity::Chip,
            mailbox::{
                self,
                device::Interface,
                key::{HardwareKey, Removal},
            },
            mcu::{
                client::{self as wire, Profile},
                key::Context as KeyContext,
                runtime::Command,
            },
            registers::BarIo,
            ring::{
                QueueIo,
                data::{self, Receipt, Released},
            },
            rx, txwi,
        },
        scan,
        security::{
            Cipher, Integrity, KeyIdentity, KeyScope, PacketNumber, ReplaySeed, SecurityStatus,
        },
        station::{
            self, Action, Completion, Join, Station, Ticket,
            data::{Ingress, Protection, SequenceOwner, TxClass},
        },
    },
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};

#[derive(Debug)]
pub enum Error {
    WrongPhase,
    WrongDevice,
    WrongProfile,
    Busy,
    NoMemory,
    NeedsDrain,
    NoKey,
    Unsupported,
    GrantTimeout,
    Bootstrap(super::Error),
    Codec(wire::Error),
    Station(station::Error),
    Data(station::data::Error),
    Scan(scan::Error),
    Transport(crate::net::wifi::mediatek::download::TransportFailure),
    Firmware(u32),
    Key(mailbox::key::Error),
    Ring(data::Error),
    Rx(rx::Error),
    Frame(wifi::frame::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MT7925 client: {self:?}")
    }
}
impl core::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Idle,
    Scanning,
    ScanCompleted,
    Joining,
    Associated,
    Removing,
    NeedsDrain,
    Quarantined,
    ControllerDrain,
    Stopped,
}
/// Per-packet retained actual device/peer/key generation, not a copied current
/// epoch lookup. DataRing owns it through actual descriptor + TX-free + unmap.
pub struct PacketOwner<C: 'static> {
    resource: Arc<C>,
    association: u64,
    key: Option<KeyIdentity>,
}
impl<C> PacketOwner<C> {
    pub fn association_epoch(&self) -> u64 {
        self.association
    }
    pub fn key(&self) -> Option<KeyIdentity> {
        self.key
    }
    pub fn resource(&self) -> &C {
        &self.resource
    }
}
struct Owned<I: BarIo, Q: QueueIo, C: 'static> {
    controller: Controller<I, Q, C>,
    interface: Interface<Arc<C>>,
    station: Station,
    scanner: scan::Scanner,
    phase: Phase,
    profile: Option<Profile>,
    peer_generation: u64,
    reserved_wcid: Option<u16>,
    format_generation: Option<u64>,
    ptk: Option<HardwareKey<Arc<C>>>,
    gtk: Option<HardwareKey<Arc<C>>>,
    ptk_removed: Option<Removal>,
    gtk_removed: Option<Removal>,
    remove_ticket: Option<Ticket>,
    interface_removed: Option<mailbox::device::Deactivated>,
    scan_ticket: Option<scan::Ticket>,
    scan_sequence: u8,
    replies: Vec<mailbox::UnifiedReply>,
    transport_facts: Vec<mailbox::bootstrap::Fact>,
    asynchronous: Vec<crate::net::wifi::mediatek::ring::rx::Frame>,
    pending_rx: VecDeque<crate::net::wifi::mediatek::ring::rx::Frame>,
    roc_token: u8,
    roc_deadline: Option<u64>,
}
/// On uncertain/live Drop retain the entire controller, station, real key
/// material history and actual resources. No new owner may reset their PN.
pub struct Client<I: BarIo, Q: QueueIo, C: 'static> {
    owned: Option<Box<Owned<I, Q, C>>>,
}
impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// # Safety
    /// C is the genuine exclusive MT7925 controller/radio/OS-policy guard. It
    /// retains the complete initial interface + sole peer WCID namespace, actual
    /// board/antenna/MAC resources and nonrevoked source/OS regulatory authority.
    /// Every public publication is serialized with reset, key retirement and
    /// restrictive policy change. Revocation must stop/cancel/drain queued radio
    /// work, not merely change preflight booleans. Controller and Interface are
    /// from this same actual requester, after completed bootstrap/source policy.
    /// No external raw mailbox/radio/WTBL or delayed previous peer/scan user
    /// exists; all actual DMA/IRQ/coherence contracts remain those of Controller.
    /// No temporal key used by any earlier native owner may be reinstalled
    /// with reset transmit counters. Preserve this Client/key history through
    /// reconnect/retry; do not create a replacement owner to bypass it. A real
    /// new OS key exchange must supply fresh TX material for a new owner.
    /// Hardware stop/drain alone never proves old material was unused.
    pub unsafe fn new(
        controller: Controller<I, Q, C>,
        interface: Interface<Arc<C>>,
    ) -> Result<Self, Error> {
        if controller.phase() != ControllerPhase::StartFacts
            || controller.state().identity.chip != Chip::Mt7925
        {
            return Err(Error::WrongDevice);
        }
        let m = controller.state().mailbox.as_ref().unwrap();
        let context = interface.registered_context().ok_or(Error::WrongPhase)?;
        if !interface.belongs_to(m)
            || !Arc::ptr_eq(interface.resource(), &controller.state().resource)
        {
            return Err(Error::WrongDevice);
        }
        let station = Station::new(context.address).map_err(Error::Station)?;
        let scanner = scan::Scanner::new(context.address).map_err(Error::Scan)?;
        Ok(Self {
            owned: Some(Box::new(Owned {
                controller,
                interface,
                station,
                scanner,
                phase: Phase::Idle,
                profile: None,
                peer_generation: 0,
                reserved_wcid: None,
                format_generation: None,
                ptk: None,
                gtk: None,
                ptk_removed: None,
                gtk_removed: None,
                remove_ticket: None,
                interface_removed: None,
                scan_ticket: None,
                scan_sequence: 0,
                replies: Vec::new(),
                transport_facts: Vec::new(),
                asynchronous: Vec::new(),
                pending_rx: VecDeque::new(),
                roc_token: 0,
                roc_deadline: None,
            })),
        })
    }
    fn state(&self) -> &Owned<I, Q, C> {
        self.owned.as_deref().unwrap()
    }
    fn state_mut(&mut self) -> &mut Owned<I, Q, C> {
        self.owned.as_deref_mut().unwrap()
    }
    pub fn phase(&self) -> Phase {
        self.state().phase
    }
    pub fn station(&self) -> &Station {
        &self.state().station
    }
    pub fn replies(&self) -> &[mailbox::UnifiedReply] {
        &self.state().replies
    }
    pub fn transport_facts(&self) -> &[mailbox::bootstrap::Fact] {
        &self.state().transport_facts
    }
    fn command(s: &mut Owned<I, Q, C>, command: Command, body: &[u8]) -> Result<(), Error> {
        // Reserve before mutation so actual reply bytes stay owned.
        s.replies.try_reserve(1).map_err(|_| Error::NoMemory)?;
        s.phase = Phase::Quarantined;
        let m = s.controller.state_mut().mailbox.as_mut().unwrap();
        let result = m.unified(command, body);
        match result {
            Ok(reply) => {
                let status = reply.status;
                let complete = reply.dma_released;
                s.replies.push(reply);
                if status != 0 {
                    return Err(Error::Firmware(status));
                }
                if !complete {
                    return Err(Error::NeedsDrain);
                }
                Ok(())
            }
            Err(e) => {
                if let Some(r) = m.interrupted_unified_reply() {
                    s.replies.push(r.clone());
                }
                Err(Error::Transport(e))
            }
        }
    }
    /// Selected actual scan/beacon profile supplies timing/antenna/rate facts;
    /// no PHY capability, channel or OS credential is guessed. The legacy
    /// request/response and this profile must describe the same real BSS.
    pub fn join(
        &mut self,
        join: Join,
        profile: Profile,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        if Some(profile.interface) != s.interface.registered_context()
            || profile.peer != join.bssid
            || profile.channel != join.channel
            || profile.aid != 0
            || profile.cipher != 0
        {
            return Err(Error::WrongProfile);
        }
        if join
            .request
            .key_ciphers()
            .is_some_and(|pair| pair != (Cipher::Ccmp128, Cipher::Ccmp128))
        {
            return Err(Error::Unsupported);
        }
        profile.validate().map_err(Error::Codec)?;
        let source_policy = s
            .controller
            .state()
            .policy
            .as_ref()
            .ok_or(Error::WrongProfile)?;
        if !source_policy
            .initial_channel_present(profile.channel.band, profile.channel.number as u8)
            || source_policy
                .capabilities()
                .observed()
                .phy()
                .and_then(|p| p.antenna_mask().ok())
                != Some(profile.antenna_mask)
        {
            return Err(Error::WrongProfile);
        }
        let (local_rates, _) = rates(join.request.elements(), profile.channel.band)?;
        if profile.supported_rates & !local_rates != 0 {
            return Err(Error::WrongProfile);
        }
        let mut ies = join.request.elements();
        while !ies.is_empty() {
            let len = usize::from(ies[1]);
            if ies[0] == 221 && ies[2..2 + len].starts_with(&[0, 0x50, 0xf2, 2]) {
                return Err(Error::Unsupported);
            }
            ies = &ies[2 + len..];
        }

        if s.reserved_wcid.is_some_and(|wcid| wcid != profile.wcid) {
            return Err(Error::WrongProfile);
        }
        let generation = s.peer_generation.checked_add(1).ok_or(Error::Busy)?;
        // Prepare all source bodies before beginning physical mutation.
        let bss = profile.bss_request(false).map_err(Error::Codec)?;
        let peer = profile.peer_request(true, false).map_err(Error::Codec)?;
        let broadcast = profile.broadcast_request().map_err(Error::Codec)?;
        // source peer-add clears admission counters before BSS(false), then
        // plain STA_REC(NONE). Neither creates an authorized OS port.
        s.profile = Some(profile);
        s.reserved_wcid = Some(profile.wcid);
        s.peer_generation = generation;
        s.format_generation = None;
        s.phase = Phase::Quarantined;
        s.controller
            .state_mut()
            .control
            .clear_peer_admission(profile.wcid)
            .map_err(|e| Error::Bootstrap(super::Error::Control(e)))?;
        Self::command(s, Command::BssInfo, &bss)?;
        Self::command(s, Command::StationRecord, &peer)?;
        s.format_generation = Some(generation);
        Self::command(s, Command::StationRecord, &broadcast)?;
        let key_context = KeyContext {
            bss_index: profile.interface.bss_index,
            omac_index: profile.interface.omac_index,
            station_disabled: false,
        };
        let m = s.controller.state().mailbox.as_ref().unwrap();
        let resource = s.controller.state().resource.clone();
        for (owner, slot, scope) in [
            (&mut s.ptk, profile.wcid, KeyScope::Pairwise(profile.peer)),
            (
                &mut s.gtk,
                profile.interface.broadcast_wcid,
                KeyScope::Group(profile.peer),
            ),
        ] {
            if let Some(key) = owner {
                unsafe { key.rebind(key_context, scope) }.map_err(Error::Key)?;
            } else {
                *owner = Some(
                    unsafe { HardwareKey::claim(m, slot, key_context, scope, resource.clone()) }
                        .map_err(Error::Key)?,
                );
            }
        }
        let action = s.station.begin(join, now, policy).map_err(Error::Station)?;
        s.phase = Phase::Joining;
        Self::action(s, action, now, source, policy)
    }
    fn action(
        s: &mut Owned<I, Q, C>,
        action: Action,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        match action {
            Action::Transmit {
                ticket,
                channel,
                bytes,
            } => {
                if channel != s.profile.ok_or(Error::WrongProfile)?.channel
                    || !policy.allow_management_tx(channel)
                {
                    return Err(Error::WrongProfile);
                }
                Self::reserve_channel(s)?;
                if s.roc_deadline
                    .is_none_or(|d| s.controller.state().control.clock.now_us() >= d)
                {
                    return Err(Error::GrantTimeout);
                }
                Self::submit(s, &bytes, None, true, true, source)?;
                s.station.submitted(ticket).map_err(Error::Station)?;
            }
            Action::Configure {
                ticket,
                bssid,
                channel,
                request: _,
                response,
            } => {
                let mut p = s.profile.ok_or(Error::WrongProfile)?;
                if p.peer != bssid || p.channel != channel || response.aid == 0 {
                    return Err(Error::WrongProfile);
                }
                // Actual response provides AID; actual source/OS observation
                // supplies beacon/DTIM/basic bitmap. Never invent association0.
                p.aid = response.aid;
                let (supported, _) = rates(&response.elements, channel.band)?;
                if p.supported_rates & !supported != 0 {
                    return Err(Error::WrongProfile);
                }
                let bss = p.bss_request(true).map_err(Error::Codec)?;
                let peer = p.peer_request(true, true).map_err(Error::Codec)?;
                Self::command(s, Command::BssInfo, &bss)?;
                s.controller
                    .state_mut()
                    .control
                    .clear_peer_admission(p.wcid)
                    .map_err(|e| Error::Bootstrap(super::Error::Control(e)))?;
                Self::command(s, Command::StationRecord, &peer)?;
                Self::command(
                    s,
                    Command::StationRecord,
                    &p.broadcast_request().map_err(Error::Codec)?,
                )?;
                Self::command(
                    s,
                    Command::BssInfo,
                    &p.beacon_filter().map_err(Error::Codec)?,
                )?;
                s.transport_facts
                    .try_reserve(1)
                    .map_err(|_| Error::NoMemory)?;
                let filter = p.filter_request(true).map_err(Error::Codec)?;
                let fact = s
                    .controller
                    .state_mut()
                    .mailbox
                    .as_mut()
                    .unwrap()
                    .initial(&filter)
                    .map_err(Error::Transport)?;
                s.transport_facts.push(fact);
                Self::command(s, Command::BssInfo, &p.awake().map_err(Error::Codec)?)?;
                s.profile = Some(p);
                s.format_generation = Some(s.peer_generation);
                Self::abort_channel(s)?;
                s.station
                    .complete_configuration(ticket, Completion::Accepted, now)
                    .map_err(Error::Station)?;
                s.phase = Phase::Associated;
            }
            Action::Remove { ticket, .. } => {
                Self::remove(s, ticket)?;
            }
        }
        Ok(())
    }
    pub fn poll_station(
        &mut self,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        if !matches!(s.phase, Phase::Joining | Phase::Associated) {
            return Err(Error::WrongPhase);
        }
        if let Some(a) = s.station.poll(now, policy).map_err(Error::Station)? {
            Self::action(s, a, now, source, policy)?;
        }
        Ok(())
    }
    /// Actual source BSS cipher update precedes first key programming. Frontend
    /// supplies authenticated key/RSC after its real EAPOL exchange; this driver
    /// does not substitute an OS supplicant or treat EAPOL classification as MIC.
    pub fn install_key(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        seed: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated {
            return Err(Error::WrongPhase);
        }
        let mut p = s.profile.ok_or(Error::WrongProfile)?;
        if p.cipher == 0 {
            p.cipher = 4;
            let b = p.bss_request(true).map_err(Error::Codec)?;
            Self::command(s, Command::BssInfo, &b)?;
            s.profile = Some(p);
        }
        let key = if pairwise {
            s.ptk.as_mut()
        } else {
            s.gtk.as_mut()
        }
        .ok_or(Error::NoKey)?;
        s.phase = Phase::Quarantined;
        let outcome = key.install(
            s.controller.state_mut().mailbox.as_mut().unwrap(),
            index,
            Cipher::Ccmp128,
            material,
            seed,
        );
        if !key.is_quarantined() {
            s.phase = Phase::Associated;
        }
        outcome.map_err(Error::Key)
    }
    /// Explicit real OS controlled-port activation against both actual installed
    /// original slots. No firmware PORT_SECURE wire value grants this permission.
    pub fn authorize_port(&mut self, epoch: u64) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated {
            return Err(Error::WrongPhase);
        }
        s.station
            .authorize_port(
                epoch,
                s.ptk.as_ref().ok_or(Error::NoKey)?.slot(),
                s.gtk.as_ref().ok_or(Error::NoKey)?.slot(),
            )
            .map_err(Error::Station)
    }
    /// Poll the actual retained DMA queues and dispatch synchronously. There is
    /// no public "assign current epoch" function for copied/deferred RX bytes.
    pub fn poll(
        &mut self,
        now: u64,
        source: &dyn PageSource,
        policy: &mut (impl station::RegulatoryPolicy + scan::Policy),
    ) -> Result<Vec<Event>, Error> {
        if self.phase() == Phase::Scanning {
            let s = self.state_mut();
            let ticket = s.scan_ticket.ok_or(Error::WrongPhase)?;
            if s.scanner.poll(ticket, now).map_err(Error::Scan)? {
                self.cancel_scan()?;
            }
        }
        let s = self.state_mut();
        if !matches!(
            s.phase,
            Phase::Scanning
                | Phase::ScanCompleted
                | Phase::Joining
                | Phase::Associated
                | Phase::Removing
                | Phase::NeedsDrain
        ) {
            return Err(Error::WrongPhase);
        }
        if s.pending_rx.is_empty() {
            let raw = s.controller.poll_events().map_err(Error::Bootstrap)?;
            s.pending_rx.extend(raw);
            if let Some(f) = s.controller.poll_data().map_err(Error::Bootstrap)? {
                s.pending_rx.push_back(f);
            }
        }
        let mut events = Vec::new();
        while let Some(f) = s.pending_rx.pop_front() {
            if f.drop {
                return Err(Error::WrongProfile);
            }
            let kind = f
                .bytes
                .get(..4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) >> 27);
            if kind == Some(6) {
                let q = s.controller.state_mut().data_tx.as_mut().unwrap();
                let epoch = q.epoch();
                unsafe { q.apply_tx_free(epoch, &f.bytes) }.map_err(Error::Ring)?;
                continue;
            }
            if kind.is_some_and(|k| k != 2 && k != 7) {
                s.asynchronous.push(f);
                continue;
            }
            if let Ok(event) = crate::net::wifi::mediatek::mcu::Event::parse(Chip::Mt7925, &f.bytes)
            {
                if event.event_id == 14
                    && event.is_unsolicited()
                    && s.phase == Phase::Scanning
                    && wire::scan_done(event.payload).map_err(Error::Codec)?
                {
                    s.scanner
                        .completed(s.scan_ticket.unwrap(), scan::Outcome::Completed)
                        .map_err(Error::Scan)?;
                    s.phase = Phase::ScanCompleted;
                }
                if event.event_id == 12
                    && event.is_unsolicited()
                    && s.phase == Phase::Associated
                    && event.payload.len() >= 12
                    && event.payload[0] == s.profile.unwrap().interface.bss_index
                {
                    let action = s.station.disconnect().map_err(Error::Station)?;
                    Self::action(s, action, now, source, policy)?;
                    events.push(Event::ConnectionLost(f));
                } else {
                    s.asynchronous.push(f);
                }
                continue;
            }
            if s.phase == Phase::ScanCompleted {
                s.asynchronous.push(f);
                continue;
            }
            let frame = Self::normalized(s, &f.bytes, policy)?;
            if s.phase == Phase::Scanning {
                events.push(Event::Bss(
                    s.scanner
                        .observe(s.scan_ticket.unwrap(), &frame, policy)
                        .map_err(Error::Scan)?,
                ));
                continue;
            }
            let epoch = s.station.association_epoch().ok_or(Error::WrongPhase)?;
            if frame.header().control & 12 == 0 {
                let action = s
                    .station
                    .receive(epoch, &frame, now, policy)
                    .map_err(Error::Station)?;
                Self::action(s, action, now, source, policy)?;
            } else if s.phase == Phase::Associated {
                let (ptk, gtk) = (
                    s.ptk.as_mut().ok_or(Error::NoKey)?,
                    s.gtk.as_mut().ok_or(Error::NoKey)?,
                );
                let ingress = s
                    .station
                    .receive_msdu_refs(epoch, &frame, &mut [ptk.slot_mut(), gtk.slot_mut()])
                    .map_err(Error::Data)?;
                events.push(Event::Ingress(ingress));
            }
        }
        events.extend(
            core::mem::take(&mut s.asynchronous)
                .into_iter()
                .map(Event::Raw),
        );
        Ok(events)
    }
    fn remove(s: &mut Owned<I, Q, C>, ticket: Ticket) -> Result<(), Error> {
        let p = s.profile.ok_or(Error::WrongProfile)?;
        s.remove_ticket = Some(ticket);
        s.phase = Phase::Removing;
        s.format_generation = None;
        // Stop new publication first, then await actual TX-free, descriptor
        // consumption and mapping release before destroying firmware keys/peer.
        // A local queue-empty/index observation alone is insufficient.
        let q = s.controller.state().data_tx.as_ref().unwrap();
        if q.outstanding_tokens() != 0 || q.pending_descriptors() != 0 {
            return Ok(());
        }
        Self::abort_channel(s)?;
        // Explicit key removal precedes peer destruction. Retain their canonical
        // histories and actual ACKs until independent old-user drain completes.
        for (key, receipt) in [
            (&mut s.ptk, &mut s.ptk_removed),
            (&mut s.gtk, &mut s.gtk_removed),
        ] {
            if let Some(key) = key
                && key.slot().installed().is_some()
            {
                *receipt = Some(
                    key.remove(s.controller.state_mut().mailbox.as_mut().unwrap())
                        .map_err(Error::Key)?,
                );
            }
        }
        Self::command(
            s,
            Command::BssInfo,
            &p.disable_beacon_pm().map_err(Error::Codec)?,
        )?;
        s.transport_facts
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        let fact = s
            .controller
            .state_mut()
            .mailbox
            .as_mut()
            .unwrap()
            .initial(&p.filter_request(false).map_err(Error::Codec)?)
            .map_err(Error::Transport)?;
        s.transport_facts.push(fact);
        Self::command(
            s,
            Command::StationRecord,
            &p.peer_request(false, false).map_err(Error::Codec)?,
        )?;
        s.controller
            .state_mut()
            .control
            .clear_peer_admission(p.wcid)
            .map_err(|e| Error::Bootstrap(super::Error::Control(e)))?;
        Self::command(
            s,
            Command::BssInfo,
            &p.bss_request(false).map_err(Error::Codec)?,
        )?;
        s.phase = Phase::NeedsDrain;
        Ok(())
    }
    pub fn disconnect(&mut self) -> Result<(), Error> {
        let s = self.state_mut();
        if !matches!(s.phase, Phase::Joining | Phase::Associated) {
            return Err(Error::WrongPhase);
        }
        let a = s.station.disconnect().map_err(Error::Station)?;
        if let Action::Remove { ticket, .. } = a {
            Self::remove(s, ticket)
        } else {
            Err(Error::WrongPhase)
        }
    }
    /// # Safety
    /// Actual peer/key removal responses above are complete AND all old RX/TX,
    /// radio, IRQ/deferred users and late notifications are independently
    /// drained. Empty TX tokens alone do not establish RX/firmware quiescence.
    /// The same reserved physical peer/BCMC slots stay owned across reconnect.
    pub unsafe fn retire_peer_after_drain(&mut self) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase == Phase::Removing {
            return Err(Error::NeedsDrain);
        }
        if s.phase != Phase::NeedsDrain {
            return Err(Error::WrongPhase);
        }
        let q = s.controller.state().data_tx.as_ref().unwrap();
        if q.outstanding_tokens() != 0
            || q.pending_descriptors() != 0
            || !s.pending_rx.is_empty()
            || !s.controller.state().data_assembly.is_idle()
            || !s
                .controller
                .state()
                .mailbox
                .as_ref()
                .unwrap()
                .receive_idle()
        {
            return Err(Error::NeedsDrain);
        }
        for (key, receipt) in [
            (&mut s.ptk, &mut s.ptk_removed),
            (&mut s.gtk, &mut s.gtk_removed),
        ] {
            if let Some(r) = receipt.take() {
                unsafe { key.as_mut().unwrap().retire_after_drain(r) }.map_err(Error::Key)?;
            }
        }
        s.station
            .complete_removal(
                s.remove_ticket.take().ok_or(Error::WrongPhase)?,
                Completion::Accepted,
            )
            .map_err(Error::Station)?;
        s.phase = Phase::Idle;
        s.profile = None;
        Ok(())
    }
    /// Actual interface disable ACKs then WFDMA disable/idle observation. This
    /// never claims the independent firmware/CPU/IOMMU fence from idle alone.
    pub fn stop(&mut self) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        s.phase = Phase::Quarantined;
        s.interface_removed = Some(
            s.interface
                .deactivate(s.controller.state_mut().mailbox.as_mut().unwrap())
                .map_err(|e| Error::Bootstrap(super::Error::Interface(e)))?,
        );
        s.controller
            .state_mut()
            .control
            .stop_dma(false)
            .map_err(|e| Error::Bootstrap(super::Error::Control(e)))?;
        s.phase = Phase::ControllerDrain;
        Ok(())
    }
    /// # Safety
    /// Genuine whole-controller radio/firmware/DMA/IOTLB/IRQ/work quiescence
    /// meets Controller::retire_after_quiesce. This is an independent platform
    /// fence, not a command ACK or a local stop-request boolean.
    pub unsafe fn stop_after_quiesce(&mut self) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::ControllerDrain {
            return Err(Error::WrongPhase);
        }
        unsafe { s.controller.retire_after_quiesce() }.map_err(Error::Bootstrap)?;
        unsafe {
            s.interface
                .retire_after_drain(s.interface_removed.take().ok_or(Error::WrongPhase)?)
        }
        .map_err(|e| Error::Bootstrap(super::Error::Interface(e)))?;
        s.phase = Phase::Stopped;
        Ok(())
    }
}
pub enum Event {
    ConnectionLost(crate::net::wifi::mediatek::ring::rx::Frame),
    Bss(scan::result::Bss),
    Ingress(Ingress),
    Raw(crate::net::wifi::mediatek::ring::rx::Frame),
}
impl<I: BarIo, Q: QueueIo, C: 'static> Drop for Client<I, Q, C> {
    fn drop(&mut self) {
        if let Some(s) = self.owned.take()
            && s.phase != Phase::Stopped
        {
            core::mem::forget(s)
        }
    }
}
fn rates(elements: &[u8], band: wifi::Band) -> Result<(u16, u16), Error> {
    let table: &[u8] = if band == wifi::Band::Ghz2 {
        &[2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108]
    } else {
        &[12, 18, 24, 36, 48, 72, 96, 108]
    };
    let mut rest = elements;
    let (mut supported, mut basic) = (0, 0);
    while !rest.is_empty() {
        let n = usize::from(*rest.get(1).ok_or(Error::WrongProfile)?);
        let v = rest.get(2..2 + n).ok_or(Error::WrongProfile)?;
        if matches!(rest[0], 1 | 50) {
            for rate in v {
                if let Some(i) = table.iter().position(|r| *r == rate & 127) {
                    supported |= 1 << i;
                    if rate & 128 != 0 {
                        basic |= 1 << i
                    }
                }
            }
        }
        rest = &rest[2 + n..];
    }
    if supported == 0 {
        return Err(Error::WrongProfile);
    }
    Ok((supported, basic))
}
