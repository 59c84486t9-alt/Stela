// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Single-interface MT7925 client ownership. Plain STA_REC installation binds
//! raw-header format to the peer; generic WMWA facts never do.
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

/// One MSDU to transmit: its Ethernet frame, transmit class and QoS TID.
#[derive(Clone, Copy)]
pub struct Msdu<'a> {
    pub ethernet: &'a [u8],
    pub class: TxClass,
    pub tid: Option<u8>,
}

/// The OS's PMF join request and the BSS observation it selected.
pub struct PmfJoin<'a> {
    pub join: Join,
    pub observed: &'a Arc<PmfBssObservation>,
}

/// A join request, the scanned BSS it names when known, and the profile
/// selected for it.
struct JoinTarget {
    join: Join,
    beacon: Option<scan::result::Bss>,
    profile: Profile,
}
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
/// Per-packet kept device/peer/key generation, not a copied current
/// epoch lookup. DataRing owns it through descriptor + TX-free + unmap.
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
/// On uncertain/live Drop keep the entire controller, station, real key
/// material history and resources. No new owner may reset their PN.
pub struct Client<I: BarIo, Q: QueueIo, C: 'static> {
    owned: Option<Box<Owned<I, Q, C>>>,
}
impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// # Safety
    /// C is the exclusive MT7925 controller/radio/OS-policy guard. It
    /// keeps the complete initial interface + sole peer WCID namespace, actual
    /// board/antenna/MAC resources and nonrevoked source/OS regulatory permission.
    /// Every public publication is serialized with reset, key retirement and
    /// restrictive policy change. Revocation must stop/cancel/drain queued radio
    /// work, not change preflight booleans. Controller and Interface are
    /// from this same requester, after completed bootstrap/source policy.
    /// No external raw mailbox/radio/WTBL or delayed previous peer/scan user
    /// exists; all DMA/IRQ/coherence contracts remain those of Controller.
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
        // Reserve before mutation so reply bytes stay owned.
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
    /// Selected scan/beacon profile supplies timing/antenna/rate facts;
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
        self.join_inner_guarded(
            JoinTarget {
                join,
                beacon,
                profile,
            },
            now,
            source,
            policy,
            None,
        )
    }
    fn join_inner_guarded(
        &mut self,
        target: JoinTarget,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
        mut guard: Option<&mut wifi::regulatory::PmfAuthenticationGuard<'_>>,
    ) -> Result<(), Error> {
        let JoinTarget {
            join,
            beacon,
            profile,
        } = target;
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
                // No native mutation has happened: withdraw only this
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
                // SAFETY: the key is idle between associations and keeps its slot.
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
                // Response provides AID; source/OS observation
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
    /// Source BSS cipher update precedes first key programming. Frontend
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
    /// Explicit real OS controlled-port activation against both installed
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
    /// Poll the DMA queues and dispatch synchronously. There is
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
            // Cancelled external sessions keep old RX until the independent
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
            // ieee80211_rx_h_michael_mic_verify: with the MIC stripped, a
            // Michael failure the hardware reports goes to the OS, as
            // cfg80211_michael_mic_failure, and the frame is dropped.
            if modern_data && frame.security.tkip_mic_error && frame.header().data_present() {
                let header = frame.header();
                events.push(Event::MichaelMicFailure {
                    transmitter: header.transmitter.ok_or(Error::WrongProfile)?,
                    group: header.receiver.is_multicast(),
                    key_index: frame.security.key.map(|key| key.index()),
                });
                continue;
            }
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
                // The 6 GHz association response arrives under the held
                // transport's providers, as the exchange's frames did.
                if s.phase == Phase::Joining
                    && let Some(guard) = six.as_deref_mut()
                {
                    Self::qualify_six(s, guard, six_ghz::Use::Receive(&frame), now)?;
                }
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
        // discards buffered CPU parents before firmware peer removal.
        for native in s.receive_ba.iter_mut().flatten() {
            native.stop();
        }
        // Stop new publication first, then await TX-free, descriptor
        // consumption and mapping release before destroying firmware keys/peer.
        // A local queue-empty/index observation alone is insufficient.
        let q = s.controller.state().data_tx.as_ref().unwrap();
        if q.outstanding_tokens() != 0 || q.pending_descriptors() != 0 {
            return Ok(());
        }
        Self::abort_channel(s)?;
        let six = s.six_ghz.as_ref().map(|six| six.codec().clone());
        // Explicit key removal precedes peer destruction. Keep their canonical
        // histories and ACKs until independent old-user drain completes.
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
    /// Peer/key removal responses above are complete AND all old RX/TX,
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
        // The inherited hardware/RX/work drain contract is now complete;
        // incomplete host-only parents can release their old owners.
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
    /// Interface disable ACKs then WFDMA disable/idle observation. This
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
    /// Whole-controller radio/firmware/DMA/IOTLB/IRQ/work quiescence
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
    /// `cfg80211_michael_mic_failure`: a TKIP frame from `transmitter` failed
    /// its Michael MIC under the group or pairwise key `key_index`.
    MichaelMicFailure {
        transmitter: crate::net::Mac,
        group: bool,
        key_index: Option<u8>,
    },
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
pub(crate) mod tests;
