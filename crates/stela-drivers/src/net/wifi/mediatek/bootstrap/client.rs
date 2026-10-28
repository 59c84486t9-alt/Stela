// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Single-interface MT7925 client ownership. Plain STA_REC installation binds
//! raw-header format to the actual retained peer; generic WMWA facts never do.
use super::{Controller, Phase as ControllerPhase};

mod action;
mod ba;
mod edca;
mod external;
pub use edca::AppliedEdca;
mod cqm;
mod csa;
mod departure;
pub use csa::ChannelSwitchStep;
mod local;
pub mod management;
mod modern;
mod packet;
mod pmf;
mod six_ghz;
mod txs;
use crate::net::wifi::station::operations::ChannelDefinition;
pub use txs::TxStatus;
pub use wifi::station::NativeBssObservation as PmfBssObservation;
mod policy;
pub use policy::{
    AttachError, BssHandle, Environment, LinkAttachError, LinkControlError, LinkEvent, LinkNotice,
    LinkProgress, ManagedClient, ManagedLink, PolicyError,
};
mod radio;
mod receive;
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
            management::ManagementCipher,
        },
        station::{
            self, Action, Completion, Join, Station, Ticket,
            data::{Ingress, Protection, SequenceOwner, TxClass},
        },
    },
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
pub use local::{Advertisement, LocalError, MloObservations};

#[derive(Debug)]
pub enum Error {
    WrongPhase,
    WrongDevice,
    WrongProfile,
    Local(LocalError),
    Busy,
    NoMemory,
    NeedsDrain,
    NoKey,
    Unsupported,
    GrantTimeout,
    ModernAdmissionRequired,
    Regulatory(wifi::regulatory::Error),
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
    Aggregate(wifi::security::aggregate::Error),
    IncompleteParent,
    BlockAck(station::ba::Error),
    Reorder(crate::net::wifi::mediatek::reorder::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MT7925 client: {self:?}")
    }
}
impl core::error::Error for Error {}
/// `ieee80211_drop_unencrypted_mgmt`'s verdict on a PMF association's robust
/// management frame.
enum Unencrypted {
    Accept,
    Drop,
    /// `cfg80211_rx_unprot_mlme_mgmt`, then drop.
    Report,
    /// An unprotected departure before the handshake's keys.
    Depart,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Idle,
    Scanning,
    ScanCompleted,
    Joining,
    AwaitingModernAdmission,
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
    context: Option<Arc<station::AssociationContext>>,
    tid: Option<u8>,
    /// Sent at the minimum rate, as control-port frames are.
    control_port: bool,
    /// The TXWI packet ID; one of at least 3 asked for TX status.
    pid: u8,
    tx_ba: Option<Arc<station::ba::tx::Session>>,
    authentication: Option<Arc<station::external::Session>>,
    management: Option<Arc<management::Session>>,
}
#[cfg(test)]
impl PacketOwner<()> {
    pub(crate) fn for_tests(association: u64, pid: u8) -> Self {
        Self {
            resource: Arc::new(()),
            association,
            key: None,
            context: None,
            tid: None,
            control_port: false,
            pid,
            tx_ba: None,
            authentication: None,
            management: None,
        }
    }
}
impl<C> PacketOwner<C> {
    pub fn association_epoch(&self) -> u64 {
        self.association
    }
    pub const fn tid(&self) -> Option<u8> {
        self.tid
    }
    pub const fn control_port(&self) -> bool {
        self.control_port
    }
    pub fn tx_block_ack(&self) -> Option<&station::ba::tx::Session> {
        self.tx_ba.as_deref()
    }
    pub fn authentication_session(&self) -> Option<&Arc<station::external::Session>> {
        self.authentication.as_ref()
    }
    pub fn management_session(&self) -> Option<&Arc<management::Session>> {
        self.management.as_ref()
    }
    pub fn key(&self) -> Option<KeyIdentity> {
        self.key
    }
    pub fn resource(&self) -> &C {
        &self.resource
    }
    pub fn association_context(&self) -> Option<&station::AssociationContext> {
        self.context.as_deref()
    }
}
struct Owned<I: BarIo, Q: QueueIo, C: 'static> {
    controller: Controller<I, Q, C>,
    interface: Interface<Arc<C>>,
    station: Station,
    pmf_observations: Vec<Arc<PmfBssObservation>>,
    txs: txs::State,
    pmf_selected: Option<Arc<PmfBssObservation>>,
    pmf_authentication: Option<wifi::regulatory::PmfAuthenticationBinding>,
    scanner: scan::Scanner,
    phase: Phase,
    profile: Option<Profile>,
    ciphers: Option<(Cipher, Cipher)>,
    /// The PMF selection's group management suite.
    management_cipher: Option<ManagementCipher>,
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
    transport_facts: Vec<mailbox::init::Fact>,
    asynchronous: Vec<crate::net::wifi::mediatek::ring::rx::Frame>,
    pending_rx: VecDeque<receive::ReceivedFrame>,
    receive_groups: receive::Groups<C>,
    receive_ba: [Option<ba::Receive<C>>; 8],
    transmit_ba: [Option<ba::Transmit<C>>; 8],
    ba_actions: VecDeque<station::ba::Action>,
    /// OS action registrations and the replies mac80211 would send.
    action: action::State,
    /// A TX block-ack agreement without A-MSDU cleared `wcid->amsdu`.
    amsdu_off: bool,
    ba_management: Option<Arc<management::Session>>,
    ba_management_pn: Option<PacketNumber>,
    roc_token: u8,
    roc_deadline: Option<u64>,
    modern: Option<modern::Configuration>,
    management: Option<Arc<management::Session>>,
    edca: Option<edca::Observed<C>>,
    /// A slot time the AP's beacon changed, not yet sent.
    slot_time: Option<u16>,
    /// The OS's RSSI monitor and the AP's averaged beacon signal.
    cqm: cqm::Cqm,
    /// The AP's announced channel switch.
    csa: csa::State,
    /// The firmware holds the BSS in dynamic power save.
    power_save: bool,
    /// The channel the firmware operates when a beacon narrowed it.
    channel: Option<ChannelDefinition>,
    /// A channel a beacon changed, not yet sent; `None` inside when the
    /// change leaves the associated channel, which mac80211 disconnects for.
    channel_change: Option<Option<ChannelDefinition>>,
    authentication_deadline: Option<u64>,
    authentication_end: Option<(Arc<station::external::Session>, Option<station::Failure>)>,
    /// The latest authentication or association frame, whose TX status
    /// paces the exchange (`ifmgd->status_received`).
    mlme_receipt: Option<Receipt>,
    /// The bound 6 GHz transport until its peer retires after drain.
    six_ghz: Option<six_ghz::Bound>,
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
                pmf_observations: Vec::new(),
                txs: txs::State::default(),
                pmf_selected: None,
                pmf_authentication: None,
                scanner,
                phase: Phase::Idle,
                profile: None,
                ciphers: None,
                management_cipher: None,
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
                receive_groups: receive::Groups::new(),
                receive_ba: core::array::from_fn(|_| None),
                transmit_ba: core::array::from_fn(|_| None),
                ba_actions: VecDeque::new(),
                action: action::State::default(),
                amsdu_off: false,
                ba_management: None,
                ba_management_pn: None,
                roc_token: 0,
                roc_deadline: None,
                modern: None,
                management: None,
                edca: None,
                slot_time: None,
                cqm: cqm::Cqm::default(),
                csa: csa::State::default(),
                power_save: false,
                channel: None,
                channel_change: None,
                authentication_deadline: None,
                authentication_end: None,
                mlme_receipt: None,
                six_ghz: None,
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
    pub fn transport_facts(&self) -> &[mailbox::init::Fact] {
        &self.state().transport_facts
    }
    fn command(s: &mut Owned<I, Q, C>, command: Command, body: &[u8]) -> Result<(), Error> {
        s.replies.try_reserve(1).map_err(|_| Error::NoMemory)?;
        s.phase = Phase::Quarantined;
        Self::command_parts(&mut s.controller, &mut s.replies, command, body)
    }
    fn command_parts(
        controller: &mut Controller<I, Q, C>,
        replies: &mut Vec<mailbox::UnifiedReply>,
        command: Command,
        body: &[u8],
    ) -> Result<(), Error> {
        // Reserve before mutation so actual reply bytes stay owned.
        replies.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let m = controller.state_mut().mailbox.as_mut().unwrap();
        let result = m.unified(command, body);
        match result {
            Ok(reply) => {
                let status = reply.status;
                let complete = reply.dma_released;
                replies.push(reply);
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
                    replies.push(r.clone());
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
        self.join_inner(join, None, profile, now, source, policy)
    }
    fn join_inner(
        &mut self,
        join: Join,
        beacon: Option<scan::result::Bss>,
        profile: Profile,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        if join.request.pmf().is_some() {
            return Err(Error::ModernAdmissionRequired);
        }
        self.join_inner_guarded(join, beacon, profile, now, source, policy, None)
    }
    #[allow(clippy::too_many_arguments)]
    fn join_inner_guarded(
        &mut self,
        join: Join,
        beacon: Option<scan::result::Bss>,
        profile: Profile,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
        mut guard: Option<&mut wifi::regulatory::PmfAuthenticationGuard<'_>>,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::Idle || s.authentication_end.is_some() {
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
        if beacon.is_none()
            && join
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
            if beacon.is_none() && ies[0] == 221 && ies[2..2 + len].starts_with(&[0, 0x50, 0xf2, 2])
            {
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
        let ciphers = join.request.key_ciphers();
        let management_cipher = join.request.pmf().map(|pmf| pmf.management());
        let action = match beacon {
            Some(_) if join.request.pmf().is_some() => s.station.begin_modern_pmf(
                join,
                s.pmf_selected.as_ref().ok_or(Error::WrongProfile)?.clone(),
                now,
                policy,
            ),
            Some(beacon) => s.station.begin_modern(join, beacon, now, policy),
            None => s.station.begin(join, now, policy),
        }
        .map_err(Error::Station)?;
        if s.station.requires_protected_management() {
            let Action::Transmit {
                ticket, ref bytes, ..
            } = action
            else {
                return Err(Error::WrongPhase);
            };
            let outcome = match guard.as_deref_mut() {
                Some(guard) => Self::qualify_pmf_authentication(s, guard, Some((ticket, bytes))),
                None => Err(Error::ModernAdmissionRequired),
            };
            if let Err(error) = outcome {
                // No native mutation has happened: withdraw only this genuine
                // unsubmitted canonical generation, keeping epochs monotonic.
                s.station
                    .withdraw_unsubmitted_pmf(ticket)
                    .map_err(Error::Station)?;
                s.pmf_selected = None;
                s.pmf_authentication = None;
                return Err(error);
            }
        }
        // source peer-add clears admission counters before BSS(false), then
        // plain STA_REC(NONE). Neither creates an authorized OS port.
        s.profile = Some(profile);
        s.ciphers = ciphers;
        s.management_cipher = management_cipher;
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
        Self::claim_keys(s, profile)?;
        s.phase = Phase::Joining;
        let result = Self::action_guarded(s, action, now, source, policy, guard);
        if result.is_err() && s.station.requires_protected_management() {
            s.phase = Phase::Quarantined;
        }
        result
    }
    /// Claim, or rebind from the last association, the PTK and GTK slots of
    /// the profile's peer.
    fn claim_keys(s: &mut Owned<I, Q, C>, profile: Profile) -> Result<(), Error> {
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
                // SAFETY: the key is idle between associations and keeps its retained slot.
                unsafe { key.rebind(key_context, scope) }.map_err(Error::Key)?;
            } else {
                *owner = Some(
                    // SAFETY: the slot is this association's WCID on the client's own mailbox.
                    unsafe { HardwareKey::claim(m, slot, key_context, scope, resource.clone()) }
                        .map_err(Error::Key)?,
                );
            }
        }
        Ok(())
    }
    fn action(
        s: &mut Owned<I, Q, C>,
        action: Action,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        Self::action_guarded(s, action, now, source, policy, None)
    }
    fn action_guarded(
        s: &mut Owned<I, Q, C>,
        action: Action,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
        guard: Option<&mut wifi::regulatory::PmfAuthenticationGuard<'_>>,
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
                if s.station.requires_protected_management() {
                    Self::qualify_pmf_authentication(
                        s,
                        guard.ok_or(Error::ModernAdmissionRequired)?,
                        Some((ticket, &bytes)),
                    )?;
                }
                Self::reserve_channel(s)?;
                if s.roc_deadline
                    .is_none_or(|d| s.controller.state().control.clock.now_us() >= d)
                {
                    return Err(Error::GrantTimeout);
                }
                s.mlme_receipt = Some(Self::submit(s, &bytes, None, true, true, source)?);
                s.station.submitted(ticket).map_err(Error::Station)?;
            }
            Action::Configure {
                ticket,
                bssid,
                channel,
                request: _,
                response,
                context,
            } => {
                if let Some(context) = context {
                    return Self::prepare_modern(s, ticket, context);
                }
                let clock = s.controller.state().control.clock;
                let began = clock.now_us();
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
                    .complete_configuration(
                        ticket,
                        Completion::Accepted,
                        clock
                            .now_us()
                            .checked_sub(began)
                            .and_then(|elapsed| now.checked_add(elapsed))
                            .ok_or(Error::WrongProfile)?,
                    )
                    .map_err(Error::Station)?;
                s.phase = Phase::Associated;
            }
            Action::Remove { ticket, failure } => {
                Self::authentication_ended(s, failure);
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
        if self.station().requires_protected_management() {
            return Err(Error::ModernAdmissionRequired);
        }
        let s = self.state_mut();
        if !matches!(s.phase, Phase::Joining | Phase::Associated) {
            return Err(Error::WrongPhase);
        }
        let now = if s.station.phase() == station::Phase::ExternalAuthenticating
            && s.authentication_deadline
                .is_some_and(|deadline| s.controller.state().control.clock.now_us() >= deadline)
        {
            now.max(s.station.external_deadline().ok_or(Error::WrongPhase)?)
        } else {
            now
        };
        if let Some(a) = s.station.poll(now, policy).map_err(Error::Station)? {
            Self::action(s, a, now, source, policy)?;
        }
        if s.phase == Phase::Joining && s.station.phase() == station::Phase::ExternalAuthenticating
        {
            Self::retransmit_external(s, now, source, policy)?;
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
        if s.modern.is_some() {
            return Err(Error::ModernAdmissionRequired);
        }
        let mut p = s.profile.ok_or(Error::WrongProfile)?;
        if p.cipher == 0 {
            p.cipher = 4;
            let b = Self::bss_request(s, p, true)?;
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
        let mailbox = s.controller.state_mut().mailbox.as_mut().unwrap();
        let outcome = key.install(mailbox, index, Cipher::Ccmp128, material, seed);
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
        if self.station().requires_protected_management()
            && matches!(
                self.phase(),
                Phase::Joining | Phase::AwaitingModernAdmission | Phase::Associated
            )
        {
            return Err(Error::ModernAdmissionRequired);
        }
        self.poll_inner(now, source, policy, None, None)
    }

    fn poll_inner(
        &mut self,
        now: u64,
        source: &dyn PageSource,
        policy: &mut (impl station::RegulatoryPolicy + scan::Policy),
        mut guard: Option<&mut wifi::regulatory::PmfAuthenticationGuard<'_>>,
        mut six: Option<&mut wifi::regulatory::SixGhzAuthenticationGuard<'_>>,
    ) -> Result<Vec<Event>, Error> {
        // A live 6 GHz transport is serviced only under its held providers;
        // cleanup after removal needs none.
        if self.state().six_ghz.is_some() && six.is_none() && self.phase() == Phase::Joining {
            return Err(Error::WrongPhase);
        }
        if self.station().phase() == station::Phase::ExternalAuthenticating {
            self.poll_station(now, source, policy)?;
        }
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
                | Phase::AwaitingModernAdmission
                | Phase::Associated
                | Phase::Removing
                | Phase::NeedsDrain
        ) {
            return Err(Error::WrongPhase);
        }
        if s.pending_rx.is_empty() {
            let raw = s.controller.poll_events().map_err(Error::Bootstrap)?;
            s.pending_rx
                .extend(raw.into_iter().map(|frame| receive::ReceivedFrame {
                    queue: receive::Queue::Event,
                    frame,
                }));
            if let Some(f) = s.controller.poll_data().map_err(Error::Bootstrap)? {
                s.pending_rx.push_back(receive::ReceivedFrame {
                    queue: receive::Queue::Data,
                    frame: f,
                });
            }
        }
        // TX-free stamps each release on the controller's clock, as mt76
        // times status out in jiffies.
        s.txs.expire(s.controller.state().control.clock.now_us());
        let mut events: Vec<_> = s.txs.ready.drain(..).map(Event::TxStatus).collect();
        events.append(&mut s.cqm.ready);
        while let Some(received) = s.pending_rx.pop_front() {
            let receive::ReceivedFrame { queue, frame: f } = received;
            if f.drop {
                s.receive_groups.discard(queue);
                return Err(Error::WrongProfile);
            }
            let kind = f
                .bytes
                .get(..4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) >> 27);
            if kind == Some(6) {
                let q = s.controller.state_mut().data_tx.as_mut().unwrap();
                let epoch = q.epoch();
                // SAFETY: this TX-free event came from the current data ring's own RX path.
                unsafe { q.apply_tx_free(epoch, &f.bytes) }.map_err(Error::Ring)?;
                continue;
            }
            if kind == Some(0) {
                if let Some(p) = s.profile {
                    let reports = s.txs.receive(&f.bytes, p.wcid, p.channel.band);
                    events.extend(reports.into_iter().map(Event::TxStatus));
                }
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
                // mt7925_mcu_rssi_monitor_event: each INFO TLV reports
                // the first TLV's RSSI against the threshold.
                if event.event_id == 0x41
                    && event.is_unsolicited()
                    && s.phase == Phase::Associated
                    && let Some(monitor) = s.cqm.monitor.filter(|m| m.firmware)
                {
                    events.extend(rssi_events(event.payload, monitor.threshold));
                    continue;
                }
                if event.event_id == 12
                    && event.is_unsolicited()
                    && s.phase == Phase::Associated
                    && event.payload.len() >= 12
                    && event.payload[0] == s.profile.unwrap().interface.bss_index
                {
                    let action = s.station.disconnect().map_err(Error::Station)?;
                    Self::action_guarded(s, action, now, source, policy, guard.as_deref_mut())?;
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
            // Cancelled external sessions retain old RX until the independent
            // drain fence; do not reinterpret it as a new association.
            if s.station.external_authentication().is_some()
                && matches!(s.phase, Phase::Removing | Phase::NeedsDrain)
            {
                s.asynchronous.push(f);
                continue;
            }
            let modern_data = s.modern.is_some() && s.phase == Phase::Associated;
            let frame = match Self::normalized(s, &f.bytes, modern_data, policy) {
                Ok(frame) => frame,
                Err(error) => {
                    // An invalid native receive cannot leave an older pending
                    // queue relaxation eligible after uncertain current input.
                    if modern_data {
                        s.edca = None;
                    }
                    return Err(error);
                }
            };
            if s.phase == Phase::Scanning {
                let bss = s
                    .scanner
                    .observe(s.scan_ticket.unwrap(), &frame, policy)
                    .map_err(Error::Scan)?;
                s.pmf_observations
                    .try_reserve(1)
                    .map_err(|_| Error::NoMemory)?;
                if s.pmf_observations.len() == pmf::MAX_OBSERVATIONS {
                    s.pmf_observations.remove(0);
                }
                s.pmf_observations
                    .push(Arc::new(PmfBssObservation { bss: bss.clone() }));
                events.push(Event::Bss(bss));
                continue;
            }
            if s.station.phase() == station::Phase::ExternalAuthenticating {
                let session = s
                    .station
                    .external_authentication()
                    .ok_or(Error::WrongPhase)?
                    .clone();
                if s.authentication_deadline
                    .is_some_and(|deadline| s.controller.state().control.clock.now_us() >= deadline)
                {
                    let deadline = s.station.external_deadline().ok_or(Error::WrongPhase)?;
                    if let Some(action) = s
                        .station
                        .poll(now.max(deadline), policy)
                        .map_err(Error::Station)?
                    {
                        Self::action_guarded(s, action, now, source, policy, guard.as_deref_mut())?;
                    }
                    s.asynchronous.push(f);
                    continue;
                }
                if let Some(guard) = six.as_deref_mut() {
                    Self::qualify_six(s, guard, six_ghz::Use::Receive(&frame), now)?;
                }
                let before = s.station.external_deadline();
                let received = s
                    .station
                    .receive_external_authentication(&session, frame, now)
                    .map_err(Error::Station)?;
                Self::follow_external_deadline(s, before);
                if let Some(received) = received {
                    events.push(Event::ExternalAuthentication(received));
                }
                continue;
            }
            if modern_data && matches!(frame.header().control & 0x00fc, 0x0080 | 0x0050) {
                Self::observe_edca(s, frame)?;
                events.push(Event::Raw(f));
                continue;
            }
            if (s.management.is_some() || s.station.requires_protected_management())
                && wifi::security::management::robust(&frame)
            {
                let pmf = s.station.requires_protected_management();
                if pmf {
                    match Self::unencrypted_management(s, &frame) {
                        Unencrypted::Accept => {}
                        Unencrypted::Drop => continue,
                        Unencrypted::Report => {
                            events.push(Event::UnprotectedDeparture(f));
                            continue;
                        }
                        Unencrypted::Depart => {
                            let epoch = s.station.association_epoch().ok_or(Error::WrongPhase)?;
                            let body = frame.bytes().get(24..).unwrap_or(&[]);
                            let action = s
                                .station
                                .receive_protected_departure(epoch, &frame, body)
                                .map_err(Error::Station)?;
                            Self::action_guarded(
                                s,
                                action,
                                now,
                                source,
                                policy,
                                guard.as_deref_mut(),
                            )?;
                            continue;
                        }
                    }
                }
                let received = Self::receive_management(s, frame, &f.bytes)?;
                // ieee80211_rx_mgmt_deauth: the AP's authenticated departure
                // ends the association; the OS sees the frame too.
                if pmf && matches!(received.frame().header().control & 0x00fc, 0x00a0 | 0x00c0) {
                    let epoch = s.station.association_epoch().ok_or(Error::WrongPhase)?;
                    let action = s
                        .station
                        .receive_protected_departure(epoch, received.frame(), received.body())
                        .map_err(Error::Station)?;
                    events.push(Event::ProtectedManagement(received));
                    Self::action_guarded(s, action, now, source, policy, guard.as_deref_mut())?;
                    continue;
                }
                if Self::channel_switch_action(s, received.frame(), received.body()) {
                    continue;
                }
                // ieee80211_rx_h_action on the decrypted frame: block ack and
                // what the OS takes reach it; the rest the station answers.
                if pmf
                    && received.frame().header().control & 0x00fc == 0x00d0
                    && matches!(
                        Self::receive_protected_action(s, received.frame(), received.body())?,
                        action::Receive::Done
                    )
                {
                    continue;
                }
                events.push(Event::ProtectedManagement(received));
                continue;
            }
            let epoch = s.station.association_epoch().ok_or(Error::WrongPhase)?;
            if modern_data
                && Self::channel_switch_action(s, &frame, frame.bytes().get(24..).unwrap_or(&[]))
            {
                continue;
            }
            if modern_data && frame.header().control & 0x00fc == 0x00d0 {
                match Self::receive_action(s, &frame)? {
                    action::Receive::BlockAck => {}
                    action::Receive::Os => {
                        events.push(Event::Raw(f));
                        continue;
                    }
                    action::Receive::Done => continue,
                }
            }
            if modern_data
                && (frame.header().control & 0x00fc == 0x00d0
                    || frame.header().control & 0x00fc == 0x0084)
            {
                let action = s
                    .station
                    .receive_block_ack(epoch, &frame, now)
                    .map_err(Error::BlockAck)?;
                events.extend(
                    Self::queue_block_ack(s, action, now)?
                        .into_iter()
                        .map(Event::Ingress),
                );
                continue;
            }
            if frame.header().control & 12 == 0 {
                let action = s
                    .station
                    .receive(epoch, &frame, now, policy)
                    .map_err(Error::Station)?;
                Self::action_guarded(s, action, now, source, policy, guard.as_deref_mut())?;
            } else if s.phase == Phase::Associated {
                Self::validate_pmf_data(s)?;
                if modern_data
                    && (frame.header().protected()
                        || frame.header().amsdu
                        || frame.aggregation != wifi::Aggregation::default())
                {
                    events.extend(
                        Self::receive_parent(s, queue, frame, now)?
                            .into_iter()
                            .map(Event::Ingress),
                    );
                    continue;
                }
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
        events.extend(Self::poll_reorder(s, now)?.into_iter().map(Event::Ingress));
        events.append(&mut s.csa.ready);
        events.extend(
            core::mem::take(&mut s.asynchronous)
                .into_iter()
                .map(Event::Raw),
        );
        if let Some((session, failure)) = s.authentication_end.take() {
            events.push(Event::ExternalAuthenticationEnded { session, failure });
        }
        for event in &events {
            if let Event::TxStatus(status) = event
                && Some(status.receipt) == s.mlme_receipt
            {
                s.mlme_receipt = None;
                s.station
                    .management_status(status.acked, now)
                    .map_err(Error::Station)?;
            }
        }
        Ok(events)
    }
    fn remove(s: &mut Owned<I, Q, C>, ticket: Ticket) -> Result<(), Error> {
        let p = s.profile.ok_or(Error::WrongProfile)?;
        s.remove_ticket = Some(ticket);
        s.phase = Phase::Removing;
        s.format_generation = None;
        // Canonical disconnect has already invalidated these sessions. This
        // serialized owner cancels its real timers/callbacks and terminally
        // discards buffered CPU parents before actual firmware peer removal.
        for native in s.receive_ba.iter_mut().flatten() {
            native.stop();
        }
        // Stop new publication first, then await actual TX-free, descriptor
        // consumption and mapping release before destroying firmware keys/peer.
        // A local queue-empty/index observation alone is insufficient.
        let q = s.controller.state().data_tx.as_ref().unwrap();
        if q.outstanding_tokens() != 0 || q.pending_descriptors() != 0 {
            return Ok(());
        }
        Self::abort_channel(s)?;
        let six = s.six_ghz.as_ref().map(|six| six.codec().clone());
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
            &match &six {
                Some(codec) => codec.disable_beacon_pm(),
                None => p.disable_beacon_pm(),
            }
            .map_err(Error::Codec)?,
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
            .initial(
                &match &six {
                    Some(codec) => codec.filter_request(false),
                    None => p.filter_request(false),
                }
                .map_err(Error::Codec)?,
            )
            .map_err(Error::Transport)?;
        s.transport_facts.push(fact);
        Self::command(
            s,
            Command::StationRecord,
            &match &six {
                Some(codec) => codec.peer_request(false),
                None => p.peer_request(false, false),
            }
            .map_err(Error::Codec)?,
        )?;
        s.controller
            .state_mut()
            .control
            .clear_peer_admission(p.wcid)
            .map_err(|e| Error::Bootstrap(super::Error::Control(e)))?;
        let bss = match &six {
            Some(codec) => codec.bss_request().map_err(Error::Codec)?,
            None => Self::bss_request(s, p, false)?,
        };
        Self::command(s, Command::BssInfo, &bss)?;
        s.phase = Phase::NeedsDrain;
        Ok(())
    }
    /// `ieee80211_drop_unencrypted_mgmt` for a robust frame on a PMF
    /// association. A frame protected with keys the association does not
    /// hold yet is dropped, as one `ieee80211_rx_h_decrypt` cannot decrypt;
    /// the PTK and IGTK are installed together, so one protected unicast
    /// frame between them is dropped too.
    fn unencrypted_management(s: &Owned<I, Q, C>, frame: &Mpdu) -> Unencrypted {
        let h = frame.header();
        let departure = matches!(h.control & 0x00fc, 0x00a0 | 0x00c0);
        let keyed = s
            .ptk
            .as_ref()
            .is_some_and(|key| key.slot().installed().is_some());
        if !h.receiver.is_multicast() {
            return match (h.protected(), keyed, departure) {
                (true, true, _) if s.management.is_some() => Unencrypted::Accept,
                (true, ..) => Unencrypted::Drop,
                // Permit unprotected departures during the 4-way handshake.
                (false, false, true) => Unencrypted::Depart,
                (false, true, true) => Unencrypted::Report,
                (false, _, false) => Unencrypted::Drop,
            };
        }
        // BIP leaves the Protected field clear; its MMIE carries the key.
        let bytes = frame.bytes();
        let mmie = bytes.len() >= 24 + 18 && bytes[bytes.len() - 18..][..2] == [76, 16];
        match (mmie, departure) {
            (false, true) => Unencrypted::Report,
            (false, false) => Unencrypted::Drop,
            (true, _) if s.management.is_some() => Unencrypted::Accept,
            (true, _) => Unencrypted::Drop,
        }
    }
    pub fn disconnect(&mut self) -> Result<(), Error> {
        let s = self.state_mut();
        if !matches!(
            s.phase,
            Phase::Joining | Phase::AwaitingModernAdmission | Phase::Associated
        ) {
            return Err(Error::WrongPhase);
        }
        let a = s.station.disconnect().map_err(Error::Station)?;
        if let Action::Remove { ticket, failure } = a {
            Self::authentication_ended(s, failure);
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
                // SAFETY: covered by this function's own safety contract.
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
        // The inherited actual hardware/RX/work drain contract is now complete;
        // incomplete host-only parents can release their retained old owners.
        s.receive_groups.clear();
        s.ciphers = None;
        s.management_cipher = None;
        s.receive_ba = core::array::from_fn(|_| None);
        s.transmit_ba = core::array::from_fn(|_| None);
        s.ba_actions.clear();
        s.action.replies.clear();
        s.amsdu_off = false;
        s.ba_management = None;
        s.ba_management_pn = None;
        s.profile = None;
        s.modern = None;
        s.edca = None;
        s.slot_time = None;
        s.channel = None;
        s.channel_change = None;
        s.csa = csa::State::default();
        s.power_save = false;
        s.management = None;
        s.pmf_selected = None;
        s.pmf_authentication = None;
        s.authentication_deadline = None;
        s.six_ghz = None;
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
        // SAFETY: covered by this function's own safety contract.
        unsafe { s.controller.retire_after_quiesce() }.map_err(Error::Bootstrap)?;
        // SAFETY: covered by this function's own safety contract.
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
    ProtectedManagement(management::Received),
    /// `cfg80211_rx_unprot_mlme_mgmt`: a PMF association dropped this
    /// unprotected deauthentication or disassociation; the OS may check the
    /// AP with an SA Query.
    UnprotectedDeparture(crate::net::wifi::mediatek::ring::rx::Frame),
    ExternalAuthentication(station::external::Received),
    ExternalAuthenticationEnded {
        session: Arc<station::external::Session>,
        failure: Option<station::Failure>,
    },
    ConnectionLost(crate::net::wifi::mediatek::ring::rx::Frame),
    /// The firmware's TX status for a frame that asked for it.
    TxStatus(TxStatus),
    /// `ieee80211_cqm_rssi_notify`: the signal crossed the monitor's
    /// threshold, upward when `high`.
    Rssi {
        rssi: i32,
        high: bool,
    },
    /// `cfg80211_ch_switch_started_notify`: the AP announced a switch to
    /// `definition` in `count` beacons, asking for silence when `block_tx`.
    ChannelSwitchStarted {
        definition: ChannelDefinition,
        count: u8,
        block_tx: bool,
    },
    /// `cfg80211_ch_switch_notify`: the association now operates there.
    ChannelSwitched(ChannelDefinition),
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
/// `mt7925_mcu_rssi_monitor_event` over an event payload: each INFO TLV
/// after the four-byte header reports the first TLV's RSSI.
fn rssi_events(payload: &[u8], threshold: i32) -> Vec<Event> {
    let mut out = Vec::new();
    let tlvs = payload.get(4..).unwrap_or_default();
    let Some(rssi) = tlvs
        .get(4..8)
        .map(|b| i32::from_le_bytes(b.try_into().unwrap()))
    else {
        return out;
    };
    let mut at = 0;
    while let Some(tlv) = tlvs.get(at..at + 4) {
        let len = usize::from(u16::from_le_bytes([tlv[2], tlv[3]]));
        if len == 0 || len > tlvs.len() - at {
            break;
        }
        if tlv[..2] == [0, 0] {
            out.push(Event::Rssi {
                rssi,
                high: rssi > threshold,
            });
        }
        at += len;
    }
    out
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

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use crate::net::wifi::mediatek::bootstrap::tests::*;
    use crate::net::wifi::mediatek::mailbox::clc::tests::*;
    use crate::net::wifi::mediatek::{
        firmware::{
            Requests,
            tests::{catalog, patch_bytes},
        },
        identity::Chip,
        mailbox::tests::*,
        ring::{
            rx::tests::device_receive,
            tests::{Memory, Source},
        },
    };
    use crate::net::wifi::{Band, mediatek::bootstrap::Error as BootError};
    use crate::net::{
        Mac,
        wifi::{
            self,
            mediatek::{
                bootstrap::client::{Client, Error as ClientError, Event, Phase as ClientPhase},
                mcu::{client::Profile, device::Context},
            },
            scan,
            security::ReplaySeed,
            station::{self, Join, PortPolicy, data::TxClass, wire::AssociationRequest},
        },
    };
    use alloc::collections::BTreeMap;
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    pub(crate) const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
    pub(crate) const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
    pub(crate) const CHANNEL: wifi::Channel = wifi::Channel {
        band: Band::Ghz5,
        number: 36,
        frequency_mhz: 5180,
    };
    pub(crate) struct Policy(pub(crate) bool);
    impl station::RegulatoryPolicy for Policy {
        fn allow_management_tx(&mut self, _: wifi::Channel) -> bool {
            self.0
        }
        fn allow_data_tx(&mut self, _: wifi::Channel) -> bool {
            self.0
        }
    }
    impl scan::Policy for Policy {
        fn allow_receive(&mut self, _: wifi::Channel) -> bool {
            self.0
        }
        fn allow_probe(&mut self, _: wifi::Channel) -> bool {
            self.0
        }
        fn lookup_channel(&mut self, b: Band, n: u16) -> Option<wifi::Channel> {
            if self.0 && b == Band::Ghz5 && n == 36 {
                Some(CHANNEL)
            } else {
                None
            }
        }
    }
    pub(crate) fn profile() -> Profile {
        Profile {
            interface: Context {
                bss_index: 0,
                omac_index: 0,
                band_index: 255,
                wmm_index: 0,
                link_index: 0,
                broadcast_wcid: 19,
                address: LOCAL,
            },
            peer: AP,
            wcid: 1,
            channel: CHANNEL,
            aid: 0,
            basic_rates: 0x15,
            supported_rates: 0xff,
            beacon_interval: 100,
            dtim_period: 2,
            slot_time: 9,
            antenna_mask: 3,
            cipher: 0,
        }
    }
    pub(crate) fn join() -> Join {
        Join {
            bssid: AP,
            channel: CHANNEL,
            policy: PortPolicy::Controlled,
            request: AssociationRequest::new(
                0x11,
                10,
                vec![
                    0, 1, b'x', 1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108, 48, 18, 1, 0, 0, 15,
                    172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
                ],
            )
            .unwrap(),
        }
    }
    pub(crate) struct Model {
        pub(crate) response: Arc<Mutex<Response>>,
        pub(crate) bar: Bar,
        pub(crate) queues: BTreeMap<u32, ModelState>,
        pub(crate) memory: Arc<Mutex<Memory>>,
        pub(crate) drops: Arc<AtomicUsize>,
    }
    pub(crate) fn setup() -> (Client<Bar, Q, NativeGuard>, Model) {
        let mut f = NativeFixture::new(Chip::Mt7925);
        f.install().unwrap();
        f.boot(Chip::Mt7925);
        f.policy(Chip::Mt7925);
        unsafe { f.controller.initialize_mac() }.unwrap();
        unsafe { f.controller.start(Band::Ghz5, 36, 5180) }.unwrap();
        let interface = unsafe { f.controller.register_interface(profile().interface) }.unwrap();
        f.model.lock().unwrap().client_execution = true;
        f.model.lock().unwrap().key_execution = true;
        let NativeFixture {
            controller,
            model,
            bar,
            queues,
            memory,
            drops,
            ..
        } = f;
        let driver = unsafe { Client::new(controller, interface) }.unwrap();
        (
            driver,
            Model {
                response: model,
                bar,
                queues,
                memory,
                drops,
            },
        )
    }
    pub(crate) fn pointer(memory: &Memory, address: u64, bytes: usize) -> *const u8 {
        let (&base, (pages, pointer, direction)) =
            memory.mappings.range(..=address).next_back().unwrap();
        let offset = (address - base) as usize;
        assert!(offset + bytes <= pages.bytes());
        assert_ne!(*direction, crate::bus::dma::mapping::Direction::FromDevice);
        (*pointer + offset) as *const u8
    }
    // Actual model device fetches the published descriptor, then TXWI/TXP and
    // payload via the same requester's registry. It retains no CPU-address alias.
    pub(crate) fn finish_tx(model: &Model) -> Vec<Vec<u8>> {
        finish_tx_on(model, 36)
    }
    /// The TXWI of the oldest descriptor the device has not fetched yet.
    pub(crate) fn next_txwi(model: &Model) -> Vec<u8> {
        let queue = model.queues[&0xd4300].lock().unwrap();
        assert_ne!(queue.index, queue.head);
        let memory = model.memory.lock().unwrap();
        let desc = unsafe {
            core::slice::from_raw_parts(
                pointer(&memory, queue.base + u64::from(queue.index) * 16, 16),
                16,
            )
        };
        let address = u32::from_le_bytes(desc[..4].try_into().unwrap()) as u64;
        unsafe { core::slice::from_raw_parts(pointer(&memory, address, 64), 64) }.to_vec()
    }
    pub(crate) fn finish_tx_on(model: &Model, channel: u8) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut queue = model.queues[&0xd4300].lock().unwrap();
        while queue.index != queue.head {
            {
                let r = model.response.lock().unwrap();
                assert_eq!(r.roc_channel.or(r.home_channel), Some(channel));
            }
            let memory = model.memory.lock().unwrap();
            let desc = unsafe {
                core::slice::from_raw_parts(
                    pointer(&memory, queue.base + u64::from(queue.index) * 16, 16),
                    16,
                )
            };
            let address = u32::from_le_bytes(desc[..4].try_into().unwrap()) as u64;
            assert_eq!(
                u32::from_le_bytes(desc[4..8].try_into().unwrap()),
                (64 << 16) | (1 << 30)
            );
            let txwi = unsafe { core::slice::from_raw_parts(pointer(&memory, address, 64), 64) };
            let token = u16::from_le_bytes(txwi[32..34].try_into().unwrap()) & 0x7fff;
            let wcid = u32::from_le_bytes(txwi[4..8].try_into().unwrap()) & 0xfff;
            assert!(
                model
                    .response
                    .lock()
                    .unwrap()
                    .raw_disabled
                    .contains(&(wcid as u16))
            );
            let payload_addr = u32::from_le_bytes(txwi[40..44].try_into().unwrap()) as u64;
            let length = u16::from_le_bytes(txwi[44..46].try_into().unwrap());
            assert_ne!(length & 0x8000, 0);
            let payload = unsafe {
                core::slice::from_raw_parts(
                    pointer(&memory, payload_addr, usize::from(length & 0xfff)),
                    usize::from(length & 0xfff),
                )
            }
            .to_vec();
            out.push(payload);
            let words = [
                (6u32 << 27) | (1 << 16),
                4 << 16,
                (1 << 31) | (wcid << 12),
                (1 << 30) | (3 << 24),
                u32::from(token) | (0x7fff << 15),
            ];
            let free = words
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            drop(memory);
            queue.index = (queue.index + 1) % queue.count;
            device_receive(&model.queues[&0xd4500], &free, true, 0);
        }
        out
    }
    pub(crate) fn incoming_bytes(
        mpdu: &[u8],
        protected: Option<(u16, u8, u64)>,
        translated: bool,
    ) -> Vec<u8> {
        let mut b = vec![0; 32 + if protected.is_some() { 16 } else { 0 }];
        let mut r1 = 0u32;
        let mut r2 = 1u32 << 30;
        if translated {
            r2 |= 1 << 7;
        }
        if let Some((slot, index, pn)) = protected {
            r1 = u32::from(slot) | (u32::from(index) << 21) | (1 << 16) | (1 << 31);
            r2 |= 4 << 16;
            for i in 0..6 {
                b[32 + i] = (pn >> (i * 8)) as u8;
            }
        }
        b[4..8].copy_from_slice(&r1.to_le_bytes());
        b[8..12].copy_from_slice(&r2.to_le_bytes());
        b[12..16].copy_from_slice(
            &((36u32 << 8) | if mpdu[4] & 1 == 0 { 1 << 16 } else { 0 }).to_le_bytes(),
        );
        b.extend_from_slice(mpdu);
        let len = b.len() as u32;
        b[..4].copy_from_slice(&((2 << 27) | len).to_le_bytes());
        b
    }
    pub(crate) fn incoming(
        model: &Model,
        mpdu: &[u8],
        protected: Option<(u16, u8, u64)>,
        translated: bool,
    ) {
        let bytes = incoming_bytes(mpdu, protected, translated);
        device_receive(&model.queues[&0xd4520], &bytes, true, 0);
    }
    pub(crate) fn response(subtype: u16, body: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 24];
        b[..2].copy_from_slice(&subtype.to_le_bytes());
        b[4..10].copy_from_slice(&LOCAL.0);
        b[10..16].copy_from_slice(&AP.0);
        b[16..22].copy_from_slice(&AP.0);
        b.extend_from_slice(body);
        b
    }
    // Native firmware commands use real elapsed time; these frontend model steps
    // are100ms, leaving auth/assoc within500ms and the next operation beyond an
    // accepted Configure's500ms bound. The old microsecond ordinal fixture hid
    // real native execution time and was not a coherent frontend clock.
    pub(crate) fn frontend_tick(step: u64) -> u64 {
        step * 100_000
    }
    pub(crate) fn associated(driver: &mut Client<Bar, Q, NativeGuard>, model: &Model, now: u64) {
        associated_with_configuration_delay(driver, model, now, 0).unwrap();
    }
    pub(crate) fn associated_with_configuration_delay(
        driver: &mut Client<Bar, Q, NativeGuard>,
        model: &Model,
        now: u64,
        delay: u64,
    ) -> Result<(), ClientError> {
        driver
            .join(
                join(),
                profile(),
                frontend_tick(now),
                &Source,
                &mut Policy(true),
            )
            .unwrap();
        assert_eq!(driver.phase(), ClientPhase::Joining);
        assert_eq!(finish_tx(model)[0][..2], [0xb0, 0]);
        driver
            .poll(frontend_tick(now + 1), &Source, &mut Policy(true))
            .unwrap();
        driver.poll_released().unwrap();
        incoming(model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
        driver
            .poll(frontend_tick(now + 2), &Source, &mut Policy(true))
            .unwrap();
        assert_eq!(finish_tx(model)[0][..2], [0, 0]);
        driver
            .poll(frontend_tick(now + 3), &Source, &mut Policy(true))
            .unwrap();
        driver.poll_released().unwrap();
        incoming(
            model,
            &response(
                0x10,
                &[
                    0x11, 0, 0, 0, 1, 0xc0, 1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108,
                ],
            ),
            None,
            false,
        );
        model.response.lock().unwrap().pause_next_index_us = delay;
        driver.poll(frontend_tick(now + 4), &Source, &mut Policy(true))?;
        assert_eq!(driver.phase(), ClientPhase::Associated);
        Ok(())
    }
    pub(crate) fn eth(protocol: u16) -> Vec<u8> {
        let mut b = vec![4, 1, 2, 3, 4, 5];
        b.extend_from_slice(&LOCAL.0);
        b.extend_from_slice(&protocol.to_be_bytes());
        b.extend_from_slice(&[1, 2, 3]);
        b
    }
    #[test]
    fn rssi_events_report_crossings_like_mt7925_mcu_rssi_monitor_event() {
        let mut payload = vec![3, 0, 0, 0];
        payload.extend_from_slice(&[0, 0, 8, 0]);
        payload.extend_from_slice(&(-75i32).to_le_bytes());
        let events = super::rssi_events(&payload, -70);
        assert!(matches!(
            events.as_slice(),
            [Event::Rssi {
                rssi: -75,
                high: false
            }]
        ));
        let events = super::rssi_events(&payload, -80);
        assert!(matches!(
            events.as_slice(),
            [Event::Rssi {
                rssi: -75,
                high: true
            }]
        ));
        payload[6] = 0;
        assert!(super::rssi_events(&payload, -70).is_empty());
        assert!(super::rssi_events(&payload[..6], -70).is_empty());
    }
    #[test]
    fn actual_late_legacy_configuration_ack_cannot_reuse_cached_poll_time() {
        let (mut driver, model) = setup();
        assert!(matches!(
            associated_with_configuration_delay(&mut driver, &model, 0, 600_000),
            Err(ClientError::Station(station::Error::Timeout))
        ));
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert_eq!(driver.station().phase(), station::Phase::Quarantined);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
    pub(crate) fn data(group: bool) -> Vec<u8> {
        let mut b = response(0x4208, &[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3]);
        if group {
            b[4..10].fill(255)
        }
        b[16..22].copy_from_slice(&[4, 1, 2, 3, 4, 5]);
        b
    }
    #[test]
    fn actual_mt7925_init_scan_secure_client_reconnect_and_stop() {
        let (mut driver, model) = setup();
        let request = scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap();
        driver
            .begin_scan(request, 0, 1_000_000, &mut Policy(true))
            .unwrap();
        assert_eq!(driver.phase(), ClientPhase::Scanning);
        // Generic scan command response has no status/scan completion authority.
        assert!(matches!(
            driver.transport_facts().last(),
            Some(crate::net::wifi::mediatek::mailbox::init::Fact::GenericResponse(_))
        ));
        let mut beacon = response(
            0x80,
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0x11, 0, 0, 1, b'x', 1, 1, 0x8c, 5, 4, 0, 2, 0, 0,
            ],
        );
        beacon[4..10].fill(255);
        incoming(&model, &beacon, None, false);
        assert!(matches!(
            driver
                .poll(frontend_tick(1), &Source, &mut Policy(true))
                .unwrap()
                .as_slice(),
            [Event::Bss(_)]
        ));
        let mut done = vec![0; 52];
        done[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
        done[36] = 14;
        done[38] = 6;
        done[50] = 4;
        device_receive(&model.queues[&0xd4500], &done, true, 0);
        driver
            .poll(frontend_tick(2), &Source, &mut Policy(true))
            .unwrap();
        assert_eq!(driver.phase(), ClientPhase::ScanCompleted);
        unsafe { driver.retire_scan_after_drain() }.unwrap();
        associated(&mut driver, &model, 10);
        let epoch = driver.station().association_epoch().unwrap();
        assert!(matches!(
            driver.transmit(
                epoch,
                &eth(0x0800),
                TxClass::Data,
                &Source,
                &mut Policy(true)
            ),
            Err(ClientError::Data(station::data::Error::ClosedPort))
        ));
        driver
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .unwrap();
        driver
            .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
            .unwrap();
        driver.authorize_port(epoch).unwrap();
        let receipt = driver
            .transmit(
                epoch,
                &eth(0x0800),
                TxClass::Data,
                &Source,
                &mut Policy(true),
            )
            .unwrap();
        assert!(driver.poll_released().unwrap().is_empty());
        let transmitted = finish_tx(&model);
        assert_eq!(&transmitted[0][..2], &[8, 0x41]);
        assert_eq!(&transmitted[0][24..30], &[0xaa, 0xaa, 3, 0, 0, 0]);
        driver
            .poll(frontend_tick(20), &Source, &mut Policy(true))
            .unwrap();
        let released = driver.poll_released().unwrap();
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].receipt, receipt);
        assert_eq!(released[0].context.association_epoch(), epoch);
        assert!(released[0].context.key().is_some());
        drop(released);
        incoming(&model, &data(false), Some((1, 0, 1)), false);
        assert!(matches!(
            driver
                .poll(frontend_tick(21), &Source, &mut Policy(true))
                .unwrap()
                .as_slice(),
            [Event::Ingress(station::data::Ingress::Data(_))]
        ));
        incoming(&model, &data(false), Some((1, 0, 1)), false);
        assert!(matches!(
            driver.poll(frontend_tick(22), &Source, &mut Policy(true)),
            Err(ClientError::Data(station::data::Error::Crypto(
                wifi::security::Error::Replay
            )))
        ));
        incoming(&model, &data(true), Some((1, 2, 1)), false);
        driver
            .poll(frontend_tick(23), &Source, &mut Policy(true))
            .unwrap();
        incoming(&model, &data(false), Some((1, 0, 2)), true);
        assert!(matches!(
            driver.poll(frontend_tick(24), &Source, &mut Policy(true)),
            Err(ClientError::Rx(
                crate::net::wifi::mediatek::rx::Error::UnsupportedTranslation
            ))
        ));
        driver.disconnect().unwrap();
        assert_eq!(driver.phase(), ClientPhase::NeedsDrain);
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        associated(&mut driver, &model, 30);
        assert_ne!(driver.station().association_epoch().unwrap(), epoch);
        // As in Linux, removed keys install again; the GTK takes the RSC the OS
        // learned in its key exchange, here PN1.
        driver
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .unwrap();
        driver
            .install_key(
                false,
                2,
                &[2; 16],
                ReplaySeed::uniform(wifi::security::PacketNumber::new(1).unwrap()),
            )
            .unwrap();
        let next = driver.station().association_epoch().unwrap();
        driver.authorize_port(next).unwrap();
        incoming(&model, &data(true), Some((1, 2, 1)), false);
        assert!(matches!(
            driver.poll(frontend_tick(41), &Source, &mut Policy(true)),
            Err(ClientError::Data(station::data::Error::Crypto(
                wifi::security::Error::Replay
            )))
        ));
        incoming(&model, &data(true), Some((1, 2, 2)), false);
        assert!(matches!(
            driver
                .poll(frontend_tick(42), &Source, &mut Policy(true))
                .unwrap()
                .as_slice(),
            [Event::Ingress(station::data::Ingress::Data(_))]
        ));
        assert!(matches!(
            driver.transmit(
                epoch,
                &eth(0x0800),
                TxClass::Data,
                &Source,
                &mut Policy(true)
            ),
            Err(ClientError::Data(station::data::Error::Stale))
        ));
        driver.disconnect().unwrap();
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        driver.stop().unwrap();
        assert_eq!(driver.phase(), ClientPhase::ControllerDrain);
        model.response.lock().unwrap().clc_processing = false;
        model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
        unsafe { driver.stop_after_quiesce() }.unwrap();
        assert_eq!(driver.phase(), ClientPhase::Stopped);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        assert!(model.memory.lock().unwrap().mappings.is_empty());
    }

    #[test]
    fn combo_initial_boot_is_consumed_once_on_success_or_uncertainty() {
        for failed in [false, true] {
            let mut f = NativeFixture::new(Chip::Mt7925);
            f.install().unwrap();
            if failed {
                f.model.lock().unwrap().initial_fail_at = Some(1);
            }
            let requests = Requests::new(&identity(Chip::Mt7925));
            let provider = catalog(&requests, patch_bytes(), ram(&clc_bytes(Chip::Mt7925)));
            let prepared = requests.load(&provider).unwrap();
            assert_eq!(f.controller.boot(&prepared).is_err(), failed);
            let count = f.model.lock().unwrap().initial_commands.len();
            assert_eq!(count, 1);
            assert!(matches!(
                f.controller.boot(&prepared),
                Err(BootError::WrongPhase)
            ));
            assert_eq!(f.model.lock().unwrap().initial_commands.len(), count);
            if !failed {
                f.retire();
            } else {
                drop(f.controller);
                assert_eq!(f.drops.load(Ordering::Relaxed), 0);
            }
        }
    }

    #[test]
    fn failed_actual_peer_ack_retains_programmed_peer_without_packet_admission() {
        let (mut driver, model) = setup();
        model.response.lock().unwrap().status = 0xdeadbeef;
        assert!(matches!(
            driver.join(join(), profile(), 0, &Source, &mut Policy(true)),
            Err(ClientError::Firmware(0xdeadbeef))
        ));
        // Actual device already consumed and programmed the full peer command;
        // response failure cannot become a clean rollback, nor format permission.
        assert!(model.response.lock().unwrap().peers.contains_key(&1));
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }

    #[test]
    fn wrong_actual_roc_token_never_publishes_authentication_or_reuses_owner() {
        let (mut driver, model) = setup();
        model.response.lock().unwrap().wrong_roc_token = true;
        assert!(matches!(
            driver.join(join(), profile(), 0, &Source, &mut Policy(true)),
            Err(ClientError::GrantTimeout)
        ));
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
        // The generic response and foreign grant do not authorize channel use.
        assert!(model.response.lock().unwrap().roc_channel.is_none());
        assert!(
            model
                .response
                .lock()
                .unwrap()
                .initial_commands
                .iter()
                .any(|p| p[34] == 0x27 && p[52] == 1)
        );
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn peer_removal_cannot_retire_outstanding_actual_packet_owners() {
        let (mut driver, model) = setup();
        associated(&mut driver, &model, 0);
        let epoch = driver.station().association_epoch().unwrap();
        driver
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .unwrap();
        driver
            .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
            .unwrap();
        driver.authorize_port(epoch).unwrap();
        driver
            .transmit(
                epoch,
                &eth(0x0800),
                TxClass::Data,
                &Source,
                &mut Policy(true),
            )
            .unwrap();
        driver.disconnect().unwrap();
        assert!(matches!(
            unsafe { driver.retire_peer_after_drain() },
            Err(ClientError::NeedsDrain)
        ));
        // Even real remove ACKs cannot release still-reachable data mappings/key
        // owners. Complete actual hardware users before independent RX/work drain.
        finish_tx(&model);
        driver
            .poll(frontend_tick(10), &Source, &mut Policy(true))
            .unwrap();
        driver.poll_released().unwrap();
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        driver.stop().unwrap();
        model.response.lock().unwrap().clc_processing = false;
        model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
        unsafe { driver.stop_after_quiesce() }.unwrap();
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn partial_actual_receive_chain_blocks_peer_generation_retirement() {
        let (mut driver, model) = setup();
        associated(&mut driver, &model, 0);
        driver
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .unwrap();
        driver
            .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
            .unwrap();
        let bytes = incoming_bytes(&data(false), Some((1, 0, 9)), false);
        device_receive(&model.queues[&0xd4520], &bytes[..40], false, 0);
        driver
            .poll(frontend_tick(10), &Source, &mut Policy(true))
            .unwrap();
        driver.disconnect().unwrap();
        assert!(matches!(
            unsafe { driver.retire_peer_after_drain() },
            Err(ClientError::NeedsDrain)
        ));
        // End and consume the actual old chain before the independent old-user
        // drain can qualify a new key/peer generation. No old bytes are retagged.
        device_receive(&model.queues[&0xd4520], &bytes[40..], true, 0);
        assert!(
            driver
                .poll(frontend_tick(11), &Source, &mut Policy(true))
                .is_err()
        );
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        driver.stop().unwrap();
        model.response.lock().unwrap().clc_processing = false;
        model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
        unsafe { driver.stop_after_quiesce() }.unwrap();
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn actual_roc_expiring_during_native_packet_preparation_never_publishes() {
        use crate::bus::dma::memory::{CacheAttribute, MemoryError, PageSource, PinnedPages};
        struct DelayedSource(AtomicUsize);
        impl PageSource for DelayedSource {
            fn allocate(
                &self,
                bytes: usize,
                alignment: usize,
                attribute: CacheAttribute,
            ) -> Result<PinnedPages, MemoryError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    // The actual source grant is1000ms. Delay only the first real
                    // post-grant payload allocation; firmware/ROC processing and
                    // mailbox allocations use their original source unchanged.
                    std::thread::sleep(std::time::Duration::from_millis(1100));
                }
                Source.allocate(bytes, alignment, attribute)
            }
        }
        let (mut driver, model) = setup();
        let before = model.memory.lock().unwrap().mappings.len();
        let source = DelayedSource(AtomicUsize::new(0));
        assert!(matches!(
            driver.join(join(), profile(), 0, &source, &mut Policy(true)),
            Err(ClientError::GrantTimeout)
        ));
        assert_eq!(source.0.load(Ordering::Relaxed), 2);
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
        assert_eq!(model.memory.lock().unwrap().mappings.len(), before);
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        // This never-published packet may unmap, but the real programmed peer,
        // actual grant and all controller/IRQ resources remain retained.
        assert!(model.response.lock().unwrap().peers.contains_key(&1));
        assert_eq!(model.response.lock().unwrap().roc_channel, Some(36));
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }

    pub(crate) fn retired_group_for_reinstall() -> (
        Client<Bar, Q, NativeGuard>,
        Model,
        wifi::security::KeyIdentity,
    ) {
        let (mut driver, model) = setup();
        associated(&mut driver, &model, 0);
        driver
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .unwrap();
        let old = driver
            .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
            .unwrap();
        driver
            .authorize_port(driver.station().association_epoch().unwrap())
            .unwrap();
        incoming(&model, &data(true), Some((1, 2, 7)), false);
        driver
            .poll(frontend_tick(12), &Source, &mut Policy(true))
            .unwrap();
        driver.disconnect().unwrap();
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        associated(&mut driver, &model, 30);
        driver
            .install_key(true, 0, &[3; 16], ReplaySeed::ZERO)
            .unwrap();
        (driver, model, old)
    }
    #[test]
    fn reinstalled_gtk_keeps_its_slot_and_takes_the_os_rsc() {
        for rsc in [3, 9] {
            let (mut driver, model, old) = retired_group_for_reinstall();
            let seed = ReplaySeed::uniform(wifi::security::PacketNumber::new(rsc).unwrap());
            let key = driver.install_key(false, 2, &[2; 16], seed).unwrap();
            assert_eq!(key.slot(), old.slot());
            assert_eq!(key.native_epoch(), old.native_epoch());
            assert_ne!(key.generation(), old.generation());
            driver
                .authorize_port(driver.station().association_epoch().unwrap())
                .unwrap();
            let floor = rsc;
            incoming(&model, &data(true), Some((1, 2, floor)), false);
            assert!(matches!(
                driver.poll(frontend_tick(41), &Source, &mut Policy(true)),
                Err(ClientError::Data(station::data::Error::Crypto(
                    wifi::security::Error::Replay
                )))
            ));
            incoming(&model, &data(true), Some((1, 2, floor + 1)), false);
            assert!(matches!(
                driver
                    .poll(frontend_tick(42), &Source, &mut Policy(true))
                    .unwrap()
                    .as_slice(),
                [Event::Ingress(station::data::Ingress::Data(_))]
            ));
            driver.disconnect().unwrap();
            unsafe { driver.retire_peer_after_drain() }.unwrap();
            driver.stop().unwrap();
            model.response.lock().unwrap().clc_processing = false;
            model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
            unsafe { driver.stop_after_quiesce() }.unwrap();
            drop(driver);
            assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn uncertain_gtk_install_never_authorizes_port_or_drops_real_peer_owner() {
        let (mut driver, model, _) = retired_group_for_reinstall();
        model.response.lock().unwrap().status = 0xdead;
        assert!(matches!(
            driver.install_key(false, 2, &[2; 16], ReplaySeed::ZERO),
            Err(ClientError::Key(
                crate::net::wifi::mediatek::mailbox::key::Error::Firmware(0xdead)
            ))
        ));
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert!(matches!(
            driver.authorize_port(driver.station().association_epoch().unwrap()),
            Err(ClientError::WrongPhase)
        ));
        assert!(matches!(
            driver.install_key(false, 2, &[2; 16], ReplaySeed::ZERO),
            Err(ClientError::WrongPhase)
        ));
        // Model processes the actual install before returning its nonzero status;
        // no RejectedAndEmpty claim can release the programmed GTK or old floors.
        assert!(
            model
                .response
                .lock()
                .unwrap()
                .keys
                .contains_key(&(profile().interface.broadcast_wcid as u8))
        );
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }

    #[test]
    fn local_advertisement_uses_retained_real_report_image_eeprom_and_policy_inputs() {
        let (driver, model) = setup();
        let count = model.response.lock().unwrap().client_commands.len();
        for band in [Band::Ghz2, Band::Ghz5] {
            let a = driver.local_advertisement(band).unwrap();
            assert_eq!(a.antenna_mask(), 3);
            assert_eq!(a.source_country(), *b"US");
            assert_eq!(a.capabilities().he().unwrap().mcs_80.rx_nss(), 2);
            assert_eq!(a.validate_capabilities(a.capabilities()), Ok(()));
            assert_eq!(a.he_source_maps()[0].rx, 0xfffa);
            assert_eq!(a.he_source_maps()[1].tx, 0xfffa);
            assert_eq!(a.he_source_maps()[2].rx, 0);
            assert_eq!(a.he_source_maps()[2].tx, 0);
            if band == Band::Ghz2 {
                assert_eq!(a.capabilities().he().unwrap().mcs_160, None);
            }
            assert!(a.capabilities().eht().unwrap().mcs.bw320.is_none());
            assert_eq!(a.capabilities().he().unwrap().phy[0] & 16, 0);
        }
        assert!(matches!(
            driver.local_advertisement(Band::Ghz6),
            Err(crate::net::wifi::mediatek::bootstrap::client::LocalError::UnsupportedBand)
        ));
        // A new unqueried model reply is not a current bound hardware observation.
        model.response.lock().unwrap().capability_payload = Some(vec![0xff; 100]);
        assert_eq!(
            driver
                .local_advertisement(Band::Ghz5)
                .unwrap()
                .antenna_mask(),
            3
        );
        assert_eq!(model.response.lock().unwrap().client_commands.len(), count);
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
        assert_eq!(driver.phase(), ClientPhase::Idle);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    }
    // Actual key ACK + completed requester-DMA management RX model.
    use super::{Integrity, Mpdu, PacketNumber, SecurityStatus};
    use station::data::Ingress;
    fn completed(
        driver: &mut Client<Bar, Q, NativeGuard>,
        model: &Model,
        raw: &[u8],
    ) -> Result<Mpdu, ClientError> {
        device_receive(&model.queues[&0xd4520], raw, true, 0);
        let received = driver
            .state_mut()
            .controller
            .poll_data()
            .map_err(ClientError::Bootstrap)?
            .unwrap();
        Client::normalized(
            driver.state_mut(),
            &received.bytes,
            false,
            &mut Policy(true),
        )
    }
    fn raw(pn: u64) -> Vec<u8> {
        incoming_bytes(&response(0x40c0, &[7, 0]), Some((1, 0, pn)), false)
    }
    #[test]
    fn actual_completed_ptk_management_rx_preserves_data_pn_and_retires_with_peer() {
        let (mut driver, model) = setup();
        associated(&mut driver, &model, 0);
        let ptk = driver
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .unwrap();
        driver
            .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
            .unwrap();
        let epoch = driver.station().association_epoch().unwrap();
        driver.authorize_port(epoch).unwrap();
        for case in 0..12 {
            let mut bad = raw(9);
            match case {
                0 => bad[4] = 2,                     // wrong actual raw peer WCID
                1 => bad[6] |= 1 << 5,               // wrong key index
                2 => bad[10] = (bad[10] & !31) | 11, // GCMP status cannot bind CCMP PTK
                3 => bad[7] |= 1 << 1,               // actual ICV failure
                4 => {
                    bad.drain(32..48);
                    bad[6] &= !1;
                } // no group1 PN
                5 => bad[6] |= 1 << 7,               // cipher mismatch
                6 => bad[7] |= 1,                    // cipher length mismatch
                7 => bad[48 + 10] ^= 2,              // wrong transmitter
                8 => bad[48 + 16] ^= 2,              // wrong BSSID
                9 => bad[48 + 4] ^= 2,               // wrong local receiver
                10 => bad[13] = 40,                  // wrong actual channel
                _ => {
                    bad.pop();
                } // incomplete reason code
            }
            if let Ok(frame) = completed(&mut driver, &model, &bad) {
                assert!(
                    driver
                        .state_mut()
                        .ptk
                        .as_mut()
                        .unwrap()
                        .authorize_unicast_management(&frame, LOCAL)
                        .is_err(),
                    "case {case}"
                );
            }
        }
        let frame = completed(&mut driver, &model, &raw(9)).unwrap();
        assert_eq!(frame.security.key, Some(ptk));
        assert_eq!(frame.radio.rate.layout, 0x7925);
        let proof = driver
            .state_mut()
            .ptk
            .as_mut()
            .unwrap()
            .authorize_unicast_management(&frame, LOCAL)
            .unwrap();
        assert_eq!(proof.key(), ptk);
        assert_eq!(proof.body(), &[7, 0]);
        assert_eq!(proof.packet_number().value(), 9);
        // This crypto proof itself changes neither station phase nor controlled port.
        assert_eq!(driver.phase(), ClientPhase::Associated);
        let again = completed(&mut driver, &model, &raw(9)).unwrap();
        assert!(matches!(
            driver
                .state_mut()
                .ptk
                .as_mut()
                .unwrap()
                .authorize_unicast_management(&again, LOCAL),
            Err(wifi::security::Error::Replay)
        ));
        incoming(&model, &data(false), Some((1, 0, 9)), false);
        assert!(matches!(
            driver
                .poll(frontend_tick(12), &Source, &mut Policy(true))
                .unwrap()
                .as_slice(),
            [Event::Ingress(Ingress::Data(_))]
        ));
        // Native exact reinstall is a no-op and cannot rewind management counter16.
        assert_eq!(
            driver
                .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
                .unwrap(),
            ptk
        );
        assert!(matches!(
            driver
                .state_mut()
                .ptk
                .as_mut()
                .unwrap()
                .authorize_unicast_management(&again, LOCAL),
            Err(wifi::security::Error::Replay)
        ));
        driver.disconnect().unwrap();
        assert!(matches!(
            driver
                .state_mut()
                .ptk
                .as_mut()
                .unwrap()
                .authorize_unicast_management(&frame, LOCAL),
            Err(wifi::security::Error::NoInstalledKey)
        ));
        // SAFETY: explicit model peer removal ACK, no firmware/DMA/IRQ/deferred old users.
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        associated(&mut driver, &model, 30);
        let next = driver
            .install_key(true, 0, &[3; 16], ReplaySeed::ZERO)
            .unwrap();
        assert_ne!(next.generation(), ptk.generation());
        assert!(matches!(
            driver
                .state_mut()
                .ptk
                .as_mut()
                .unwrap()
                .authorize_unicast_management(&frame, LOCAL),
            Err(wifi::security::Error::WrongKey)
        ));
        let fresh = completed(&mut driver, &model, &raw(1)).unwrap();
        driver
            .state_mut()
            .ptk
            .as_mut()
            .unwrap()
            .authorize_unicast_management(&fresh, LOCAL)
            .unwrap();
        driver.disconnect().unwrap();
        // SAFETY: the model has explicitly completed removal and all old users.
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        driver.stop().unwrap();
        model.response.lock().unwrap().clc_processing = false;
        model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
        // SAFETY: independent complete modeled controller/radio/DMA/work quiescence.
        unsafe { driver.stop_after_quiesce() }.unwrap();
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        assert!(model.memory.lock().unwrap().mappings.is_empty());
    }

    #[test]
    fn uncertain_ptk_publication_never_authenticates_management_or_releases_owner() {
        for dropped in [false, true] {
            let (mut driver, model) = setup();
            associated(&mut driver, &model, 0);
            // First real GTK ACK also completes the BSS cipher update. Faults below
            // therefore reach the real PTK publication rather than an earlier BSS.
            let gtk = driver
                .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
                .unwrap();
            {
                let mut fault = model.response.lock().unwrap();
                if dropped {
                    fault.drop = true;
                } else {
                    fault.status = 0xdead;
                }
            }
            assert!(
                driver
                    .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
                    .is_err()
            );
            assert_eq!(driver.phase(), ClientPhase::Quarantined);
            assert!(model.response.lock().unwrap().keys.contains_key(&1));
            assert!(completed(&mut driver, &model, &raw(9)).is_err());
            let copied = Mpdu::new(
                response(0x40c0, &[7, 0]),
                wifi::RadioStatus {
                    band: wifi::Band::Ghz5,
                    channel: 36,
                    frequency_mhz: 5180,
                    signal_dbm: None,
                    chain_signal_dbm: [None; 4],
                    rate: wifi::RawRate {
                        layout: 0x7925,
                        words: [0; 4],
                    },
                    rx_rate: None,
                    tsf: None,
                },
                SecurityStatus {
                    key: Some(gtk),
                    pn: PacketNumber::new(9),
                    decrypted: true,
                    integrity: Integrity::Verified,
                    iv_stripped: true,
                    mic_stripped: true,
                    ..SecurityStatus::default()
                },
            )
            .unwrap();
            assert!(matches!(
                driver
                    .state_mut()
                    .ptk
                    .as_mut()
                    .unwrap()
                    .authorize_unicast_management(&copied, LOCAL),
                Err(wifi::security::Error::NoInstalledKey)
            ));
            drop(driver);
            assert_eq!(model.drops.load(Ordering::Relaxed), 0);
            assert!(!model.memory.lock().unwrap().mappings.is_empty());
        }
    }
}
