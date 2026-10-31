// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! The function as the connection keeper's radio, as mvm serves mac80211: a
//! join raises the PHY, link, AP station and queues, session protection holds
//! the channel for the exchange, the MLD callbacks of each station state
//! follow in order, keys and port opening go to the firmware, each TID's frames
//! get their queue as they first appear, and a departure takes everything down
//! to the scanning MAC again.
//!
//! Firmware commands run one at a time from a queue: a step that raises or
//! needs a firmware answer waits for the one before it, never for time.
use super::*;
use crate::wifi::{
    Channel,
    connection::keeper::{self, Advertisement, Peer, Radio, Stage as Standing},
    frame::{MAX_AMPDU_BUF_HE, Mpdu},
    intel::{
        association::{self as commands, LinkState, MacState, PeerState},
        command,
        transmit::{
            LegacyRate, Parameters,
            response::{Response, block_ack_queues},
        },
    },
    regulatory::channel::{NO_80MHZ, NO_160MHZ, NO_HT40MINUS, NO_HT40PLUS},
    regulatory::database,
    security::{
        Cipher, InstallOutcome, InstallTicket, Integrity, KeyIdentity, KeyScope, KeySlot,
        PacketNumber, ReplaySeed, TransmitSeed,
        aggregate::{OrderedGroup, Shape},
        management::ManagementCipher,
    },
    station::{
        self, Action, AssociationContext, Completion, Join, NativeBssObservation, Phase as Peering,
        RegulatoryPolicy, Station, Ticket,
        ba::{self, RxSession},
        data::{self, Ingress, Protection, Qos, SequenceOwner, TxClass},
        external,
        multi_link::Affiliation,
        phy::{Capabilities, McsMaps, Role},
        wire::six_ghz::Selection,
    },
};
use alloc::collections::VecDeque;

mod reception;
use reception::{MAX_SESSIONS, Parent, Reception};

type Queue<Q, B> = Ax200ManagementQueue<'static, Q, B, Regulatory>;

/// The most frames a TID holds while its queue is added or full, as the
/// mac80211 queue limit bounds what stands in front of a stopped driver.
const MAX_HELD: usize = 64;
/// The TID the management queue answers to, which non-QoS data shares.
const MANAGEMENT_TID: u8 = 15;
/// `IWL_MVM_MISSED_BEACONS_THRESHOLD_LONG`.
const MISSED_BEACONS: u32 = 19;
/// `IWL_MVM_MISSED_BEACONS_SINCE_RX_THOLD`.
const MISSED_BEACONS_SINCE_RECEIVE: u32 = 4;
/// `MCC_SOURCE_WIFI`.
const COUNTRY_FROM_WIFI: u8 = 5;
/// How long a departure's frame may take to reach the air before the queues
/// flush it, as `ieee80211_flush_queues` waits for it.
const DEPARTURE_DRAIN_US: u64 = 200_000;
const SESSION_PROTECTION_NOTIFICATION: (u8, u8) = (0xfb, 3);
const MISSED_BEACONS_LEGACY_NOTIFICATION: (u8, u8) = (0xa2, 0);
const MISSED_BEACONS_NOTIFICATION: (u8, u8) = (0xf6, 3);
const TRANSMIT_RESPONSE: (u8, u8) = (0x1c, 0);
const BAR_FRAME_RELEASE: (u8, u8) = (0xc2, 0);
const FRAME_RELEASE: (u8, u8) = (0xc3, 0);
const BLOCK_ACK_NOTIFICATION: (u8, u8) = (0xc5, 0);
/// `WLAN_ACTION_BLOCK_ACK`, on an action frame.
const BLOCK_ACK_CATEGORY: u8 = 3;
/// `WLAN_REASON_QSTA_TIMEOUT`.
const SESSION_TIMED_OUT: u16 = 39;
/// `IWL_UCODE_TLV_CAPA_BAID_ML_SUPPORT`, which every firmware of the
/// families here has: their command tables have no `ADD_STA`.
const BLOCK_ACK_ALLOCATION: u32 = 63;
/// `IWL_UCODE_TLV_CAPA_STA_EXP_MFP_SUPPORT`.
const EXPLICIT_MFP: u32 = 114;
/// `IWL_UCODE_TLV_CAPA_COEX_HIGH_PRIO`.
const COEX_HIGH_PRIORITY: u32 = 61;
/// `IWL_UCODE_TLV_API_SMART_FIFO_OFFLOAD`.
const SMART_FIFO_OFFLOAD: u32 = 68;
const BEACON_FILTER_V4_API: u32 = 47;

/// What a raised chain does on arrival.
pub(super) enum Plan {
    /// Authenticate and associate.
    Join {
        join: Join,
        observed: Arc<NativeBssObservation>,
    },
    /// An external exchange is running; its frames wait in the outbox.
    Exchange,
}

/// What a firmware step's answer completes.
enum Then {
    Nothing,
    /// The AP's configuration finished.
    Configured(Ticket),
    Key {
        pairwise: bool,
        index: u8,
        ticket: Box<InstallTicket>,
    },
    /// The port's commands finished: firmware rate selection may widen.
    Authorized,
}

/// A receive Block Ack agreement the firmware is to take up or give up.
struct Agreement {
    ticket: Ticket,
    session: Arc<RxSession>,
    enable: bool,
}

/// One firmware step.
enum Step {
    Command {
        id: command::Id,
        bytes: Vec<u8>,
        then: Then,
    },
    /// `tid`'s queue, from fresh memory.
    Queue {
        tid: u8,
    },
    BlockAck(Agreement),
}

/// A step the firmware has.
struct Waiting {
    ticket: boot::CommandTicket,
    deadline: Deadline,
    step: Step,
}

/// A firmware command's bound, `iwl_trans_send_cmd`'s sync timeout.
const COMMAND_TIMEOUT_US: u64 = 2_000_000;

/// The session protection around the join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Session {
    Off,
    Starting,
    On,
}

/// One installed firmware key.
struct Key {
    slot: KeySlot,
    pairwise: bool,
    index: u8,
    flags: u32,
    acknowledged: bool,
}

/// A data frame waiting for its queue or its queue's room.
struct Held {
    mpdu: Vec<u8>,
    encrypted: bool,
}

/// The transport of an installed IGTK.
pub struct ManagementKey {
    index: u8,
}

/// The association's state beside the kept chain.
pub(super) struct Client {
    station: Station,
    pub(super) plan: Option<Plan>,
    pub(super) observed: Vec<Arc<NativeBssObservation>>,
    pub(super) channels: Vec<(Channel, u32)>,
    pub(super) regulatory: Option<database::Country>,
    steps: VecDeque<Step>,
    waiting: Option<Waiting>,
    /// The IGTKs the firmware holds, by index and flags.
    management_keys: Vec<(u8, u32)>,
    /// The deauthentication a departure sends before anything goes down.
    farewell: Option<Vec<u8>>,
    /// Until when the departure waits for its deauthentication.
    draining: Option<Deadline>,
    /// Management frames waiting for session protection, with the exchange's
    /// ticket each answers to.
    outbox: VecDeque<(Option<Ticket>, Vec<u8>)>,
    events: VecDeque<keeper::Event>,
    received: VecDeque<Vec<u8>>,
    reception: Reception,
    held: [VecDeque<Held>; 16],
    /// TIDs with an added or requested queue.
    requested: u16,
    session: Session,
    /// A management exchange's frame awaits its TX response.
    exchange: bool,
    admitted: Option<(Ticket, Arc<AssociationContext>)>,
    context: Option<Arc<AssociationContext>>,
    ciphers: Option<(Cipher, Cipher)>,
    management_cipher: Option<ManagementCipher>,
    keys: Vec<Key>,
    next_slot: u16,
    port_open: bool,
    antenna: u8,
    /// The departure the chain's removal answers.
    departing: Option<Ticket>,
    /// The chain goes back down once everything queued for it finished.
    leaving: bool,
    /// The way down finished: the keeper retires the peer.
    left: bool,
    reported: Vec<&'static str>,
}

impl Client {
    pub(super) fn new(station: Station) -> Self {
        Self {
            station,
            plan: None,
            observed: Vec::new(),
            channels: Vec::new(),
            regulatory: None,
            steps: VecDeque::new(),
            waiting: None,
            management_keys: Vec::new(),
            farewell: None,
            draining: None,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            received: VecDeque::new(),
            reception: Reception::new(),
            held: core::array::from_fn(|_| VecDeque::new()),
            requested: 1 << MANAGEMENT_TID,
            session: Session::Off,
            exchange: false,
            admitted: None,
            context: None,
            ciphers: None,
            management_cipher: None,
            keys: Vec::new(),
            next_slot: 0,
            port_open: false,
            antenna: 0,
            departing: None,
            leaving: false,
            left: false,
            reported: Vec::new(),
        }
    }

    /// Report an unsupported operation once and carry on without it.
    fn unsupported(&mut self, operation: &'static str) {
        if !self.reported.contains(&operation) {
            self.reported.push(operation);
            self.events.push_back(keeper::Event::Unsupported(operation));
        }
    }

    fn command(&mut self, id: command::Id, bytes: Vec<u8>) {
        self.steps.push_back(Step::Command {
            id,
            bytes,
            then: Then::Nothing,
        });
    }

    fn idle(&self) -> bool {
        self.steps.is_empty() && self.waiting.is_none()
    }

    /// Whether anything the keeper's next step must follow is outstanding.
    fn keys_settled(&self) -> bool {
        self.keys.iter().all(|key| key.acknowledged)
    }

    /// The way down finished.
    pub(super) fn left(&mut self) {
        self.left = true;
        self.leaving = false;
    }

    fn reset(&mut self) {
        self.steps.clear();
        self.outbox.clear();
        self.reception.clear();
        self.held.iter_mut().for_each(VecDeque::clear);
        self.requested = 1 << MANAGEMENT_TID;
        self.session = Session::Off;
        self.exchange = false;
        self.admitted = None;
        self.context = None;
        self.ciphers = None;
        self.management_cipher = None;
        self.keys.clear();
        self.management_keys.clear();
        self.farewell = None;
        self.draining = None;
        self.port_open = false;
        self.departing = None;
        self.leaving = false;
        self.left = false;
    }

    /// A departure began: the chain comes down once its queues drain.
    fn depart(&mut self, ticket: Ticket, failure: Option<station::Failure>) {
        if let Some(failure) = failure
            && self.station.external_authentication().is_some()
        {
            self.events
                .push_back(keeper::Event::SaeEnded(format!("{failure:?}")));
        }
        self.departing = Some(ticket);
        self.leaving = true;
        self.port_open = false;
        self.admitted = None;
        self.outbox.clear();
        self.steps.clear();
        self.held.iter_mut().for_each(VecDeque::clear);
    }

    fn act(&mut self, action: Action) {
        match action {
            Action::Transmit { ticket, bytes, .. } => {
                self.outbox.push_back((Some(ticket), bytes));
            }
            Action::Configure {
                ticket,
                context: Some(context),
                links,
                ..
            } => {
                if !links.is_empty() {
                    self.unsupported("MLO links on Intel Wi-Fi");
                }
                self.admitted = Some((ticket, context));
            }
            // Every join here is a modern one, which carries its context.
            Action::Configure { .. } => {
                self.admitted = None;
                if let Ok(Action::Remove { ticket, failure }) = self.station.disconnect() {
                    self.depart(ticket, failure);
                }
            }
            Action::Remove { ticket, failure } => self.depart(ticket, failure),
        }
    }
}

/// The channels the adapter's rules admit: the real check is the leases at
/// each publication.
struct Admitted<'a>(&'a [(Channel, u32)]);

impl RegulatoryPolicy for Admitted<'_> {
    fn allow_management_tx(&mut self, channel: Channel) -> bool {
        self.0.iter().any(|&(allowed, _)| allowed == channel)
    }
    fn allow_data_tx(&mut self, channel: Channel) -> bool {
        self.allow_management_tx(channel)
    }
}

/// `iwl_mvm_get_tx_rate` for a management frame: the lowest rate the AP takes.
fn lowest_rate(rates: u16) -> LegacyRate {
    const RATES: [LegacyRate; 12] = [
        LegacyRate::Cck1,
        LegacyRate::Cck2,
        LegacyRate::Cck5_5,
        LegacyRate::Cck11,
        LegacyRate::Ofdm6,
        LegacyRate::Ofdm9,
        LegacyRate::Ofdm12,
        LegacyRate::Ofdm18,
        LegacyRate::Ofdm24,
        LegacyRate::Ofdm36,
        LegacyRate::Ofdm48,
        LegacyRate::Ofdm54,
    ];
    RATES[(rates.trailing_zeros() as usize).min(11)]
}

/// `iwl_mvm_next_antenna`: the next of `valid` after `last`.
fn next_antenna(valid: u8, last: u8) -> u8 {
    (1..=4)
        .map(|step| 1u8 << ((last.trailing_zeros() as u8 + step) % 4))
        .find(|antenna| valid & antenna != 0)
        .unwrap_or(valid)
}

/// The station's management header to the AP, with `subtype`'s body.
fn management(local: Mac, ap: Mac, subtype: u16, protected: bool, body: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 24];
    let control = subtype | if protected { 0x4000 } else { 0 };
    bytes[..2].copy_from_slice(&control.to_le_bytes());
    bytes[4..10].copy_from_slice(&ap.0);
    bytes[10..16].copy_from_slice(&local.0);
    bytes[16..22].copy_from_slice(&ap.0);
    bytes.extend_from_slice(body);
    bytes
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// Raise the chain for `bss`.
    fn raise(&mut self, bss: &Bss, plan: Plan) -> Result<(), Error> {
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Scan(scan) = stage else {
            self.stage = stage;
            return Err(Error::Refused("join"));
        };
        self.selected = Some(Selected {
            bss: bss.clone(),
            rates: legacy_rates(&bss.elements, bss.channel.band),
        });
        match (*scan).begin_phy_context(bss.channel) {
            Ok(phy) => {
                self.stage = Stage::Phy(Box::new(phy));
                self.client.plan = Some(plan);
                Ok(())
            }
            Err(scan) => {
                self.stage = Stage::Scan(scan);
                Err(Error::Refused("PHY context"))
            }
        }
    }

    /// One service round on the raised chain.
    fn operate(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        let now = self.clock.now_us();
        if let Some(plan) = self.client.plan.take() {
            self.arrive(plan, now)?;
        }
        self.take_notifications(queue, now)?;
        // A pending command keeps what arrives for after its answer.
        if self.client.waiting.is_none() {
            self.take_frames(queue, now)?;
            self.take_notifications(queue, now)?;
        }
        let client = &mut self.client;
        for tid in client.reception.expired(now) {
            // `tid_rx_timer_expired`, once for an agreement still in force.
            if client.station.active_rx_block_ack(tid).is_some()
                && let Ok(action) = client
                    .station
                    .stop_rx_block_ack(tid, Some(SESSION_TIMED_OUT))
            {
                client.block_ack(action);
            }
        }
        let mut policy = Admitted(&client.channels);
        if !client.leaving
            && let Some(action) = client
                .station
                .poll(now, &mut policy)
                .map_err(Error::Station)?
        {
            client.act(action);
        }
        if !client.leaving
            && !client.exchange
            && client.station.phase() == Peering::ExternalAuthenticating
        {
            let mut policy = Admitted(&client.channels);
            if let Some(bytes) = client
                .station
                .external_retransmission(now, &mut policy)
                .map_err(Error::Station)?
            {
                client.outbox.push_back((None, bytes));
            }
        }
        self.run_steps(queue)?;
        self.send_management(queue)?;
        self.send_data(queue)
    }

    /// The chain is up: start what it was raised for, under session protection.
    fn arrive(&mut self, plan: Plan, now: u64) -> Result<(), Error> {
        let client = &mut self.client;
        if let Plan::Join { join, observed } = plan {
            let mut policy = Admitted(&client.channels);
            client.ciphers = join.request.key_ciphers();
            client.management_cipher = join.request.pmf().map(|pmf| pmf.management());
            let action = if join.request.pmf().is_some() {
                client
                    .station
                    .begin_modern_pmf(join, observed, now, &mut policy)
            } else {
                client
                    .station
                    .begin_modern(join, observed.bss().clone(), now, &mut policy)
            }
            .map_err(Error::Station)?;
            client.act(action);
        }
        Ok(())
    }

    /// `iwl_mvm_mld_mac_sta_state`'s AUTH to ASSOC, then the `vif_cfg_changed`
    /// that follows it.
    fn association_steps(
        &mut self,
        queue: &mut Queue<Q, B>,
        context: &AssociationContext,
        ticket: Ticket,
    ) -> Result<(), Error> {
        let local = self.address;
        let negotiated = context.negotiated();
        let bss = context.beacon();
        let band = bss.channel.band;
        let aid = context.response().aid;
        let he = negotiated.he.is_some();
        let antennas = queue.antennas();
        let firmware = queue.firmware();
        let high_priority = firmware.supports_capability(COEX_HIGH_PRIORITY);
        let fifo_offloaded = firmware.supports_api(SMART_FIFO_OFFLOAD);
        let peer_version = firmware
            .command_version(3, 0x0a)
            .map_or(0, |version| version.command_version);
        let rate_bytes = rate_body(firmware)?;
        let explicit_mfp = firmware.supports_capability(EXPLICIT_MFP);
        let mac = MacState {
            address: local,
            he,
            eht: false,
            aid: None,
            high_priority,
        };
        let rates = commands::rate_config(negotiated, band, antennas, rate_bytes, false)
            .ok_or(Error::Refused("rates"))?;
        let edca = negotiated.edca();
        let link = commands::link_config(LinkState {
            address: local,
            bssid: bss.bssid,
            band,
            basic_rates: negotiated.legacy.basic,
            short_preamble: bss.capabilities & (1 << 5) != 0,
            short_slot: band != Band::Ghz2 || bss.capabilities & (1 << 10) != 0,
            protection: commands::protection(context),
            width: negotiated.width,
            qos: negotiated.wmm.is_some(),
            edca: &edca,
            beacon_interval: bss.beacon_interval,
            dtim_period: context.dtim_period(),
        });
        let peer = commands::station_config(
            peer_version,
            peer_state(context, explicit_mfp, self.client.port_open),
        );
        let client = &mut self.client;
        client.command(commands::MAC_CONFIG, commands::mac_config(mac));
        client.command(commands::LINK_CONFIG, link);
        client.command(commands::RATE_CONFIG, rates);
        client.command(commands::STATION_CONFIG, peer);
        client.command(
            commands::MAC_CONFIG,
            commands::mac_config(MacState {
                aid: Some(aid),
                ..mac
            }),
        );
        if !fifo_offloaded {
            client.command(commands::SMART_FIFO, commands::smart_fifo(negotiated));
        }
        client.steps.push_back(Step::Command {
            id: commands::MAC_POWER,
            bytes: commands::power(self.save_power, bss.beacon_interval, context.dtim_period()),
            then: Then::Configured(ticket),
        });
        Ok(())
    }

    /// Issue the next step, or take the answer the waiting one has.
    fn run_steps(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        loop {
            if let Some(waiting) = &self.client.waiting {
                let progress = queue.poll_submitted(&waiting.ticket).map_err(Error::Queue);
                match progress {
                    Ok(boot::CommandProgress::Pending) if !waiting.deadline.passed() => {
                        return Ok(());
                    }
                    Ok(boot::CommandProgress::Pending) => {
                        return Err(Error::Timeout("firmware command"));
                    }
                    Ok(boot::CommandProgress::Completed(response)) => {
                        let waiting = self.client.waiting.take().unwrap();
                        self.finish(queue, waiting.step, response)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            let Some(step) = self.client.steps.pop_front() else {
                return Ok(());
            };
            let pages = self.pages;
            let ticket = match &step {
                // SAFETY: `new`'s contract holds, and the step stays within
                // the channel, power and rates the chain's leases check.
                Step::Command { id, bytes, .. } => unsafe { queue.submit(*id, bytes, pages) },
                // SAFETY: as above.
                Step::Queue { tid } => unsafe { queue.add_queue(*tid, pages) },
                Step::BlockAck(agreement) => {
                    let (tid, id) = (
                        agreement.session.tid(),
                        self.client.reception.session(agreement.session.tid()),
                    );
                    let bytes = if agreement.enable {
                        commands::allocate_block_ack(
                            tid,
                            agreement.session.start_sequence(),
                            agreement.session.window(),
                        )
                    } else {
                        let version = queue
                            .firmware()
                            .command_version(5, 0x16)
                            .map_or(1, |version| version.command_version);
                        commands::remove_block_ack(version, id.unwrap_or(0), tid)
                    };
                    // SAFETY: as above.
                    unsafe { queue.submit(commands::BLOCK_ACK_ALLOCATION, &bytes, pages) }
                }
            }
            .map_err(Error::Queue)?;
            self.client.waiting = Some(Waiting {
                ticket,
                deadline: self.clock.deadline(COMMAND_TIMEOUT_US),
                step,
            });
        }
    }

    fn finish(
        &mut self,
        queue: &mut Queue<Q, B>,
        step: Step,
        response: boot::CommandResponse,
    ) -> Result<(), Error> {
        let then = match step {
            Step::Command { then, .. } => then,
            Step::Queue { tid } => {
                queue.queue_added(tid, &response).map_err(Error::Queue)?;
                Then::Nothing
            }
            Step::BlockAck(agreement) => {
                self.block_ack_answered(agreement, &response);
                Then::Nothing
            }
        };
        let client = &mut self.client;
        match then {
            Then::Nothing => {}
            Then::Configured(ticket) => {
                let now = self.clock.now_us();
                client
                    .station
                    .complete_configuration(ticket, Completion::Accepted, now)
                    .map_err(Error::Station)?;
                if !queue.firmware().supports_capability(BLOCK_ACK_ALLOCATION) {
                    client.unsupported("receive Block Ack on firmware without session allocation");
                } else if let Err(ba::Error::Station(_) | ba::Error::Stale) = client
                    .station
                    .configure_rx_block_ack(MAX_AMPDU_BUF_HE, true)
                {
                    client.unsupported("receive Block Ack on this association");
                }
            }
            Then::Key {
                pairwise,
                index,
                ticket,
            } => {
                let key = client
                    .keys
                    .iter_mut()
                    .find(|key| key.pairwise == pairwise && key.index == index)
                    .ok_or(Error::Refused("key"))?;
                key.slot
                    .complete_install(*ticket, InstallOutcome::Accepted)
                    .map_err(Error::Key)?;
                key.acknowledged = true;
            }
            Then::Authorized => client.port_open = true,
        }
        Ok(())
    }

    /// Frames from the AP.
    fn take_frames(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        loop {
            match queue.poll_receive().map_err(Error::Queue)? {
                MpduProgress::Pending | MpduProgress::Backpressure { .. } => return Ok(()),
                MpduProgress::Rejected(_) => {}
                MpduProgress::Observed(observed) => match observed.normalize() {
                    // mac80211 drops a frame the station cannot use; the
                    // exchange it answers retries or times out.
                    Ok(normalized) => match self.frame(normalized, &observed.metadata(), now) {
                        Err(Error::Station(_)) => {
                            self.client
                                .unsupported("a management frame the station refuses");
                        }
                        result => result?,
                    },
                    Err(_) => self.client.unsupported("an MPDU the receive path refuses"),
                },
            }
        }
    }

    fn frame(
        &mut self,
        normalized: boot::NormalizedMpdu,
        metadata: &crate::wifi::intel::receive::mpdu::Metadata,
        now: u64,
    ) -> Result<(), Error> {
        let key_index = normalized.key_index();
        let mut frame = normalized.into_frame();
        let header = frame.header();
        let client = &mut self.client;
        let mut policy = Admitted(&client.channels);
        if header.control & 12 == 0 {
            if header.protected() {
                return self.protected_management(frame, now);
            }
            if client.station.phase() == Peering::ExternalAuthenticating {
                let session = client
                    .station
                    .external_authentication()
                    .ok_or(Error::Refused("exchange"))?
                    .clone();
                if let Some(received) = client
                    .station
                    .receive_external_authentication(&session, frame, now)
                    .map_err(Error::Station)?
                {
                    client
                        .events
                        .push_back(keeper::Event::Sae(Box::new(received)));
                }
                return Ok(());
            }
            let Some(epoch) = client.station.association_epoch() else {
                return Ok(());
            };
            if header.control & 0xfc == 0xd0
                && frame.bytes().get(header.length) == Some(&BLOCK_ACK_CATEGORY)
            {
                // mac80211 drops an agreement it cannot take; the peer then
                // sends without one.
                if let Ok(action) = client.station.receive_block_ack(epoch, &frame, now) {
                    client.block_ack(action);
                }
                return Ok(());
            }
            // A PMF association takes a departure only under its keys.
            if client.station.requires_protected_management()
                && matches!(header.control & 0xfc, 0xa0 | 0xc0)
                && client.keys_settled()
                && !client.keys.is_empty()
            {
                return Ok(());
            }
            let action = client
                .station
                .receive(epoch, &frame, now, &mut policy)
                .map_err(Error::Station)?;
            client.act(action);
            return Ok(());
        }
        if header.control & 12 != 8 || !client.port_ready() || !header.data_present() {
            return Ok(());
        }
        if header.fragmented() {
            client.unsupported("a fragmented frame");
            return Ok(());
        }
        if header.protected() {
            // The firmware decrypted the frame under the key of this index,
            // which only this client installed.
            let multicast = header.receiver.is_multicast();
            let installed = client
                .keys
                .iter()
                .filter(|key| key.pairwise != multicast && Some(key.index) == key_index)
                .find_map(|key| key.slot.installed());
            let Some(key) = installed else {
                return Ok(());
            };
            frame.security.key = Some(key);
            frame.security.integrity = Integrity::Verified;
        }
        let Some(parent) = client.reception.gather(frame) else {
            return Ok(());
        };
        if client.reception.repeats(&parent) {
            return Ok(());
        }
        let mut ready = Vec::new();
        client.reception.order(parent, metadata, now, &mut ready);
        client.deliver_all(ready);
        Ok(())
    }

    /// The firmware answered `agreement`: its session and reorder buffer exist
    /// or are gone, and the station's agreement goes on from there.
    fn block_ack_answered(&mut self, agreement: Agreement, response: &boot::CommandResponse) {
        let now = self.clock.now_us();
        let client = &mut self.client;
        let Agreement {
            ticket,
            session,
            enable,
        } = agreement;
        let completion = if enable {
            let id = response
                .raw
                .get(..4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .filter(|id| *id < MAX_SESSIONS);
            if id.is_some_and(|id| client.reception.open(id as u8, session, now)) {
                Completion::Accepted
            } else {
                client.unsupported("a Block Ack session the firmware or memory refused");
                Completion::RejectedAndIdle
            }
        } else {
            let mut ready = Vec::new();
            client.reception.close(session.tid(), &mut ready);
            client.deliver_all(ready);
            Completion::Accepted
        };
        // SAFETY: the firmware answered this ticket's command, and the reorder
        // buffer exists, or is drained, to match. A departure may have
        // outrun it; `leave` then removes what this opened.
        if let Ok(action) = unsafe { client.station.complete_rx_block_ack(ticket, completion) } {
            client.block_ack(action);
        }
    }

    /// A protected management frame the firmware decrypted: its departure
    /// ends the association, and an SA Query is answered, as
    /// `ieee80211_process_sa_query_req` does.
    fn protected_management(&mut self, frame: Mpdu, now: u64) -> Result<(), Error> {
        let client = &mut self.client;
        let Some(epoch) = client.station.association_epoch() else {
            return Ok(());
        };
        let header = frame.header();
        let Some(body) = frame.bytes().get(header.length + 8..) else {
            return Ok(());
        };
        match header.control & 0xfc {
            0xa0 | 0xc0 => {
                let action = client
                    .station
                    .receive_protected_departure(epoch, &frame, body)
                    .map_err(Error::Station)?;
                client.events.push_back(keeper::Event::ConnectionLost);
                client.act(action);
            }
            0xd0 if body.first() == Some(&BLOCK_ACK_CATEGORY) => {
                let Some(context) = client.context.clone() else {
                    return Ok(());
                };
                if let Ok(action) = client
                    .station
                    .receive_authenticated_block_ack(&context, &frame, body, now)
                {
                    client.block_ack(action);
                }
            }
            0xd0 if body.len() >= 4 && body[..2] == [8, 0] => {
                let response = [8, 1, body[2], body[3]];
                let Some(ap) = header.transmitter else {
                    return Ok(());
                };
                let local = self.address;
                client
                    .outbox
                    .push_back((None, management(local, ap, 0xd0, true, &response)));
            }
            _ => {}
        }
        Ok(())
    }

    /// Firmware notifications beside the frames.
    fn take_notifications(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        while let Some(update) = queue.take_country_update() {
            // `iwl_mvm_rx_chub_update_mcc` ignores what the air tells an
            // associated station. Anything else keeps the applied rules.
            let associated = self.client.station.association_epoch().is_some();
            if !(associated && update.raw.get(2) == Some(&COUNTRY_FROM_WIFI)) {
                self.client
                    .unsupported("a firmware country update: the applied rules stay");
            }
        }
        while let Some(notification) = queue.take_other_notification() {
            let raw = &notification.raw;
            let word = |at: usize| {
                raw.get(at..at + 4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            };
            match (notification.command, notification.group) {
                TRANSMIT_RESPONSE => {
                    let family = queue.family();
                    let Ok(response) = Response::parse_notification(
                        queue.firmware(),
                        family,
                        notification.sequence,
                        raw,
                    ) else {
                        self.client
                            .unsupported("a TX response the driver cannot parse");
                        continue;
                    };
                    let (next, queue_id, status) = (
                        response.next_pointer,
                        response.queue,
                        response.reported_outcome(),
                    );
                    if queue.reclaim(queue_id, next).is_err() {
                        self.client
                            .unsupported("a TX response past what is in flight");
                    }
                    if queue.queue_tid(queue_id) == Some(MANAGEMENT_TID) && self.client.exchange {
                        self.client.exchange = false;
                        let acked = matches!(
                            status,
                            crate::wifi::intel::transmit::response::Outcome::Success
                                | crate::wifi::intel::transmit::response::Outcome::DirectDone
                        );
                        self.client
                            .station
                            .management_status(acked, now)
                            .map_err(Error::Station)?;
                    }
                }
                FRAME_RELEASE if raw.len() >= 4 => {
                    let through = u16::from_le_bytes([raw[2], raw[3]]) & 0xfff;
                    self.client.release(raw[0], None, through);
                }
                BAR_FRAME_RELEASE => {
                    // `iwl_bar_frame_release`.
                    let (Some(station), Some(information)) = (word(0), word(4)) else {
                        continue;
                    };
                    self.client.release(
                        (information >> 24 & 0x3f) as u8,
                        Some((station & 0xf) as u8),
                        (information & 0xfff) as u16,
                    );
                }
                BLOCK_ACK_NOTIFICATION => {
                    let Ok(queues) = block_ack_queues(raw) else {
                        self.client.unsupported("a short Block Ack notification");
                        continue;
                    };
                    for (queue_id, next) in queues {
                        if queue.reclaim(queue_id, next).is_err() {
                            self.client
                                .unsupported("a Block Ack past what is in flight");
                        }
                    }
                }
                SESSION_PROTECTION_NOTIFICATION => {
                    let (status, start) = (word(4).unwrap_or(0), word(8).unwrap_or(0));
                    self.client.session = if status == 1 && start == 1 {
                        Session::On
                    } else {
                        Session::Off
                    };
                }
                MISSED_BEACONS_LEGACY_NOTIFICATION | MISSED_BEACONS_NOTIFICATION
                    if word(8).is_some_and(|missed| missed >= MISSED_BEACONS)
                        && word(4).is_some_and(|missed| missed >= MISSED_BEACONS_SINCE_RECEIVE)
                        && self.client.station.association_epoch().is_some()
                        && !self.client.leaving =>
                {
                    self.client.events.push_back(keeper::Event::ConnectionLost);
                    let action = self.client.station.disconnect().map_err(Error::Station)?;
                    self.client.act(action);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn parameters(&mut self, antennas: u8, encrypted: bool) -> Parameters {
        let client = &mut self.client;
        client.antenna = next_antenna(antennas, client.antenna.max(1));
        Parameters {
            station_authorized: Some(client.port_open),
            force_host_rate: false,
            host_rate: lowest_rate(self.selected.as_ref().map_or(0, |selected| selected.rates)),
            host_antenna: client.antenna,
            firmware_encryption: encrypted,
        }
    }

    /// Management frames, once session protection holds the channel for them.
    fn send_management(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        if self.client.outbox.is_empty() {
            return Ok(());
        }
        let associated = self.client.station.phase() == Peering::Associated;
        if !associated && self.client.session != Session::On {
            if self.client.session == Session::Off {
                self.client.session = Session::Starting;
                self.client.command(
                    commands::SESSION_PROTECTION,
                    commands::protect_session(false),
                );
            }
            return self.run_steps(queue);
        }
        // The leases refuse a frame while a command is in flight.
        if self.client.waiting.is_some() {
            return Ok(());
        }
        let antennas = queue.antennas();
        while queue.space(MANAGEMENT_TID) != 0 {
            let Some((ticket, bytes)) = self.client.outbox.pop_front() else {
                break;
            };
            let encrypted = bytes[1] & 0x40 != 0;
            let parameters = Parameters {
                station_authorized: None,
                ..self.parameters(antennas, encrypted)
            };
            let pages = self.pages;
            // SAFETY: `new`'s contract holds; the frame goes to the AP.
            unsafe { queue.publish(MANAGEMENT_TID, &bytes, parameters, pages) }
                .map_err(Error::Queue)?;
            if !associated {
                self.client.exchange = true;
            }
            if let Some(ticket) = ticket {
                self.client
                    .station
                    .submitted(ticket)
                    .map_err(Error::Station)?;
            }
        }
        Ok(())
    }

    /// Data frames onto their TIDs' queues, each adding its queue first.
    fn send_data(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        let antennas = queue.antennas();
        for tid in 0..16u8 {
            if self.client.held[usize::from(tid)].is_empty() {
                continue;
            }
            if self.client.requested & (1 << tid) == 0 {
                self.client.requested |= 1 << tid;
                self.client.steps.push_back(Step::Queue { tid });
            }
            if !queue.has_queue(tid) {
                continue;
            }
            while self.client.waiting.is_none() && queue.space(tid) != 0 {
                let Some(held) = self.client.held[usize::from(tid)].pop_front() else {
                    break;
                };
                let parameters = self.parameters(antennas, held.encrypted);
                let pages = self.pages;
                // SAFETY: `new`'s contract holds; the frame goes to the AP.
                unsafe { queue.publish(tid, &held.mpdu, parameters, pages) }
                    .map_err(Error::Queue)?;
            }
        }
        self.run_steps(queue)
    }

    /// Queue `ethernet` for its TID.
    fn send(&mut self, ethernet: &[u8], class: TxClass) -> Result<(), Error> {
        let client = &mut self.client;
        let epoch = client
            .station
            .association_epoch()
            .ok_or(Error::Refused("no association"))?;
        let context = client.context.clone().ok_or(Error::Refused("no context"))?;
        let tid = data::data_tid(&context, None, None, ethernet);
        let mut policy = Admitted(&client.channels);
        let mut keys: Vec<&mut KeySlot> = client.keys.iter_mut().map(|key| &mut key.slot).collect();
        let plan = match tid {
            Some(tid) => client.station.prepare_qos_msdu_refs(
                epoch,
                ethernet,
                class,
                Qos {
                    context: &context,
                    tid,
                },
                &mut keys,
                &mut policy,
            ),
            None => client.station.prepare_msdu_refs(
                epoch,
                ethernet,
                class,
                SequenceOwner::Device,
                &mut keys,
                &mut policy,
            ),
        }
        .map_err(Error::Data)?;
        let queue = usize::from(tid.unwrap_or(MANAGEMENT_TID));
        if client.held[queue].len() >= MAX_HELD {
            client.held[queue].pop_front();
        }
        client.held[queue].push_back(Held {
            mpdu: plan.plaintext_mpdu().to_vec(),
            encrypted: matches!(plan.protection(), Protection::Firmware { .. }),
        });
        Ok(())
    }

    /// `iwl_mvm_mld_set_key` for the association's data and group keys.
    fn install(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        receive: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        let client = &mut self.client;
        let (unicast, group) = client.ciphers.ok_or(Error::Refused("no ciphers"))?;
        let cipher = if pairwise { unicast } else { group };
        let pmf = client.station.requires_protected_management();
        let flags = commands::key_flags(cipher, pairwise, pmf && pairwise)
            .ok_or(Error::Unsupported("the cipher on Intel Wi-Fi"))?;
        let peer = client
            .station
            .pairwise_peer()
            .ok_or(Error::Refused("no peer"))?;
        let scope = if pairwise {
            KeyScope::Pairwise(peer)
        } else {
            KeyScope::Group(peer)
        };
        // SAFETY: the counter gives each key of the adapter its own slot.
        let mut slot = unsafe { KeySlot::new(client.next_slot) }.map_err(Error::Key)?;
        client.next_slot = client.next_slot.wrapping_add(1);
        let transmit = if pairwise {
            TransmitSeed::FIRMWARE_FRESH
        } else {
            TransmitSeed::RECEIVE_ONLY
        };
        let ticket = slot
            .begin_install(index, cipher, material, receive, scope, transmit)
            .map_err(Error::Key)?;
        let identity = ticket.identity();
        let bytes = commands::add_key(index, flags, material, receive.counters()[0])
            .ok_or(Error::Refused("key material"))?;
        if let Some(old) = client
            .keys
            .iter()
            .position(|key| key.pairwise == pairwise && key.index == index)
        {
            let old = client.keys.remove(old);
            client.command(
                commands::SECURITY_KEY,
                commands::remove_key(old.index, old.flags),
            );
        }
        client.keys.push(Key {
            slot,
            pairwise,
            index,
            flags,
            acknowledged: false,
        });
        client.steps.push_back(Step::Command {
            id: commands::SECURITY_KEY,
            bytes,
            then: Then::Key {
                pairwise,
                index,
                ticket: Box::new(ticket),
            },
        });
        Ok(identity)
    }

    /// The chain's way down, once its last commands finished.
    pub(super) fn leave(&mut self, queue: &mut Queue<Q, B>) -> Result<bool, Error> {
        if !self.client.leaving || !self.client.idle() {
            return Ok(false);
        }
        if let Some(frame) = self.client.farewell.take() {
            let antennas = queue.antennas();
            let parameters = Parameters {
                station_authorized: None,
                ..self.parameters(antennas, frame[1] & 0x40 != 0)
            };
            let pages = self.pages;
            // SAFETY: `new`'s contract holds; the frame goes to the AP.
            unsafe { queue.publish(MANAGEMENT_TID, &frame, parameters, pages) }
                .map_err(Error::Queue)?;
            self.client.draining = Some(self.clock.deadline(DEPARTURE_DRAIN_US));
        }
        if let Some(deadline) = &self.client.draining {
            if queue.in_flight(MANAGEMENT_TID) != 0 && !deadline.passed() {
                return Ok(false);
            }
            self.client.draining = None;
        }
        if self.client.session != Session::Off {
            self.client.session = Session::Off;
            self.client.command(
                commands::SESSION_PROTECTION,
                commands::protect_session(true),
            );
        }
        // `ieee80211_sta_tear_down_BA_sessions`: nothing tells a peer that is
        // going, and nothing can use what the buffers held.
        let version = queue
            .firmware()
            .command_version(5, 0x16)
            .map_or(1, |version| version.command_version);
        for (id, tid) in self.client.reception.take_sessions() {
            self.client.command(
                commands::BLOCK_ACK_ALLOCATION,
                commands::remove_block_ack(version, id, tid),
            );
        }
        for key in core::mem::take(&mut self.client.keys) {
            self.client.command(
                commands::SECURITY_KEY,
                commands::remove_key(key.index, key.flags),
            );
        }
        for (index, flags) in core::mem::take(&mut self.client.management_keys) {
            self.client
                .command(commands::SECURITY_KEY, commands::remove_key(index, flags));
        }
        if !self.client.idle() {
            self.run_steps(queue)?;
            return Ok(false);
        }
        queue.begin_remove_station().map_err(Error::Queue)?;
        Ok(true)
    }

    /// Serve the raised chain.
    pub(super) fn serve(&mut self) -> Result<(), Error> {
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Ready(mut queue) = stage else {
            self.stage = stage;
            return Ok(());
        };
        let mut result = self.operate(&mut queue);
        let down = result.is_ok()
            && match self.leave(&mut queue) {
                Ok(down) => down,
                Err(error) => {
                    result = Err(error);
                    false
                }
            };
        self.stage = if down {
            Stage::Removing(queue)
        } else {
            Stage::Ready(queue)
        };
        result
    }

    fn observed(&self, handle: usize) -> Result<Arc<NativeBssObservation>, Error> {
        self.client
            .observed
            .get(handle)
            .cloned()
            .ok_or(Error::Refused("BSS"))
    }
}

/// The body of the firmware's `TLC_MNG_CONFIG_CMD` version.
fn rate_body(firmware: &crate::wifi::intel::firmware::Firmware<'_>) -> Result<usize, Error> {
    match firmware
        .command_version(5, 0x0f)
        .map(|version| version.command_version)
    {
        Some(1 | 2) => Ok(24),
        Some(3 | 4) => Ok(28),
        _ => Err(Error::Refused("TLC_MNG_CONFIG_CMD version")),
    }
}

fn peer_state(context: &AssociationContext, explicit_mfp: bool, authorized: bool) -> PeerState {
    let negotiated = context.negotiated();
    PeerState {
        address: context.bssid(),
        aid: context.response().aid,
        mfp: explicit_mfp && (context.pmf().is_some() || !authorized),
        mimo: negotiated.rx_nss > 1,
        ampdu_spacing: negotiated.peer_mpdu_spacing,
        ampdu_exponent: commands::ampdu_exponent(negotiated),
        wmm_service_period: negotiated.wmm.as_ref().map(|wmm| wmm.max_service_period),
        uapsd_queues: negotiated.wmm.as_ref().map_or(0, |wmm| wmm.uapsd_queues),
    }
}

/// `iwl_init_ht_hw_capab`, `iwl_init_vht_hw_capab` and mac80211's SMPS-off
/// HT capabilities for a device of `tx`, `rx` chains.
fn capability_elements(band: Band, tx: u32, rx: u32, wide: bool) -> Vec<u8> {
    let mut elements = Vec::new();
    let mut element = |id: u8, body: &[u8]| {
        elements.extend_from_slice(&[id, body.len() as u8]);
        elements.extend_from_slice(body);
    };
    if band == Band::Ghz2 {
        element(1, &[2, 4, 11, 22, 12, 18, 24, 36]);
        element(50, &[48, 72, 96, 108]);
    } else {
        element(1, &[12, 18, 24, 36, 48, 72, 96, 108]);
    }
    let mut ht = [0; 26];
    let capability: u16 = 0x1000 // DSSSCCK40
        | 1 << 8 // RX STBC, one stream
        | u16::from(tx > 1) << 7 // TX STBC
        | 1 // LDPC
        | 0x800 // 7935-byte A-MSDU
        | 0xc // SMPS off
        | 0x20 // SGI 20
        | 0x2 // 20/40
        | 0x40; // SGI 40
    ht[..2].copy_from_slice(&capability.to_le_bytes());
    ht[2] = 3 | 5 << 2; // 64 KB A-MPDUs at 4 us spacing
    ht[3] = 0xff;
    ht[4] = if rx >= 2 { 0xff } else { 0 };
    ht[13..15].copy_from_slice(&(150 * rx as u16).to_le_bytes());
    ht[15] = 1;
    if tx != rx {
        ht[15] |= 2 | ((tx.saturating_sub(1) as u8) << 2);
    }
    element(45, &ht);
    if band == Band::Ghz5 {
        let mut vht = [0; 12];
        let capability: u32 = 2 // 11454-byte MPDUs
            | 0x10 // RX LDPC
            | 0x20 // SGI 80
            | 0x100 // RX STBC 1
            | 0x800 << 1 // SU beamformee
            | 3 << 13 // beamformee STS
            | 0x10_0000 // MU beamformee
            | 7 << 23 // 1 MB A-MPDUs
            | if wide { 0x44 } else { 0 } // 160 MHz, SGI 160
            | if tx > 1 { 0x80 } else { 0x2000_0000 }
            | if rx == 1 { 0x1000_0000 } else { 0 };
        vht[..4].copy_from_slice(&capability.to_le_bytes());
        let map: u16 = if rx >= 2 { 0xfffa } else { 0xfffe };
        vht[4..6].copy_from_slice(&map.to_le_bytes());
        vht[8..10].copy_from_slice(&map.to_le_bytes());
        element(191, &vht);
    }
    // `ieee80211_add_wmm_info_ie`, without U-APSD.
    element(221, &[0, 0x50, 0xf2, 2, 0, 1, 0]);
    elements
}

/// Polling the link serves the station; frames flow once its port is open.
impl<Q: BootIo, B: BiosIo> Link for Wifi<Q, B> {
    fn mac(&self) -> Mac {
        self.address
    }
    fn carrier(&mut self) -> bool {
        self.client.port_open
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !self.client.port_open {
            return Err(LinkError::NoCarrier);
        }
        self.send(frame, TxClass::Data)
            .map_err(|error| LinkError::Adapter(format!("{error}")))
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        Ok(self.client.received.pop_front())
    }
}

impl<Q: BootIo, B: BiosIo> Radio for Wifi<Q, B> {
    type Handle = usize;
    type Profile = ();
    type Management = Arc<ManagementKey>;
    type Error = Error;

    const NAME: &'static str = "iwlwifi";
    /// `IWL_MVM_CONN_LISTEN_INTERVAL`.
    const LISTEN_INTERVAL: u16 = 10;

    fn deferred(error: &Error) -> bool {
        matches!(error, Error::Pending)
    }

    fn service(&mut self) -> Result<(), Error> {
        self.poll();
        if let Some(error) = &self.error
            && !self.reported
        {
            self.reported = true;
            return Err(error.clone());
        }
        self.serve()
    }

    fn take_event(&mut self) -> Option<keeper::Event> {
        self.client.events.pop_front()
    }

    fn stage(&self) -> Standing {
        match &self.stage {
            Stage::Scan(_) if self.client.left => Standing::NeedsDrain,
            Stage::Scan(scan) => match scan.phase() {
                Ax200ScanPhase::NotStarted => Standing::Idle,
                Ax200ScanPhase::DrainRequired => Standing::Scanned,
                _ => Standing::Busy,
            },
            Stage::Ready(_) if self.client.admitted.is_some() => Standing::Admitted,
            _ => Standing::Busy,
        }
    }

    fn station(&self) -> &Station {
        &self.client.station
    }

    fn channels(&self, band: Band) -> Vec<(Channel, u32)> {
        self.client
            .channels
            .iter()
            .filter(|(channel, _)| channel.band == band)
            .copied()
            .collect()
    }

    /// Scans listen until the firmware scan request builds its probes.
    fn probes(&self, _: Channel) -> bool {
        false
    }

    fn supported_channels(&self, band: Band) -> &'static [u8] {
        match band {
            Band::Ghz2 => &[1, 14],
            Band::Ghz5 => &[36, 28, 149, 9],
            Band::Ghz6 => &[],
        }
    }

    fn regulated_power_dbm(&self, frequency_mhz: u16) -> i32 {
        self.client
            .regulatory
            .as_ref()
            .map_or(0, |country| country.channel(frequency_mhz).max_reg_dbm)
    }

    fn advertisement(&self, band: Band) -> Result<Advertisement, Error> {
        if band == Band::Ghz6 {
            return Err(Error::Unsupported("6 GHz on Intel Wi-Fi"));
        }
        let (tx, rx) = self.chains;
        let wide = self
            .client
            .channels
            .iter()
            .any(|(channel, flags)| channel.band == Band::Ghz5 && flags & NO_160MHZ == 0);
        let elements = capability_elements(band, tx.count_ones(), rx.count_ones(), wide);
        let capabilities = Capabilities::parse(band, Role::Station, &elements)
            .map_err(|_| Error::Refused("advertisement"))?;
        Ok(Advertisement {
            capabilities,
            elements,
            he_source_maps: [McsMaps { rx: 0, tx: 0 }; 3],
            multi_link: Some(false),
        })
    }

    fn profile(&self, _: Peer) -> Result<(), Error> {
        Ok(())
    }

    fn begin_scan(&mut self, request: scan::Request, budget_us: u64) -> Result<(), Error> {
        let pages = self.pages;
        let Stage::Scan(owner) = &mut self.stage else {
            return Err(Error::Refused("scan"));
        };
        while !matches!(
            owner.poll_pre_scan_receive().map_err(Error::Scan)?,
            MpduProgress::Pending | MpduProgress::Backpressure { .. }
        ) {}
        self.client.observed.clear();
        // SAFETY: `new`'s contract covers the scan's pages.
        unsafe { owner.start(request, budget_us, pages) }.map_err(Error::Scan)?;
        Ok(())
    }

    unsafe fn retire_scan(&mut self) -> Result<(), Error> {
        let Stage::Scan(owner) = &mut self.stage else {
            return Err(Error::Refused("scan"));
        };
        while owner
            .poll_retiring_receive()
            .map_err(Error::Scan)?
            .is_some()
        {}
        owner.retire().map_err(Error::Scan)?;
        Ok(())
    }

    fn six_ghz_scan(
        &self,
        _: &scan::Request,
        _: scan::six_ghz::Options,
    ) -> Result<Option<scan::Request>, Error> {
        Ok(None)
    }

    fn bss(&self) -> Vec<(usize, &Bss)> {
        self.client
            .observed
            .iter()
            .enumerate()
            .map(|(handle, observed)| (handle, observed.bss()))
            .collect()
    }

    fn observation(&self, handle: usize) -> Result<Arc<NativeBssObservation>, Error> {
        self.observed(handle)
    }

    fn join(&mut self, handle: usize, join: Join, _: ()) -> Result<(), Error> {
        let observed = self.observed(handle)?;
        let bss = observed.bss().clone();
        self.raise(&bss, Plan::Join { join, observed })
    }

    fn begin_external_authentication(
        &mut self,
        handle: usize,
        _: (),
        multi_link: Option<Affiliation>,
        budget_us: u64,
    ) -> Result<Arc<external::Session>, Error> {
        if multi_link.is_some() {
            return Err(Error::Unsupported("MLO on Intel Wi-Fi"));
        }
        let observed = self.observed(handle)?;
        let bss = observed.bss().clone();
        let now = self.clock.now_us();
        let client = &mut self.client;
        let mut policy = Admitted(&client.channels);
        let session = client
            .station
            .begin_external_authentication(
                external::Peer {
                    bssid: bss.bssid,
                    channel: bss.channel,
                    ssid: bss.ssid.clone().unwrap_or_default(),
                    multi_link: None,
                },
                now,
                budget_us,
                &mut policy,
            )
            .map_err(Error::Station)?;
        self.raise(&bss, Plan::Exchange)?;
        Ok(session)
    }

    fn begin_six_ghz_external_authentication(
        &mut self,
        _: usize,
        _: Selection,
        _: (),
        _: u64,
    ) -> Result<Arc<external::Session>, Error> {
        Err(Error::Unsupported("6 GHz on Intel Wi-Fi"))
    }

    fn transmit_external_authentication(
        &mut self,
        session: &external::Session,
        frame: external::Frame<'_>,
    ) -> Result<(), Error> {
        let now = self.clock.now_us();
        let client = &mut self.client;
        let mut policy = Admitted(&client.channels);
        let bytes = client
            .station
            .external_authentication_transmit(session, frame, now, &mut policy)
            .map_err(Error::Station)?;
        client.outbox.push_back((None, bytes));
        Ok(())
    }

    fn associate_external(
        &mut self,
        session: &external::Session,
        handle: usize,
        join: Join,
    ) -> Result<(), Error> {
        let observed = self.observed(handle)?;
        let now = self.clock.now_us();
        let client = &mut self.client;
        let mut policy = Admitted(&client.channels);
        client.ciphers = join.request.key_ciphers();
        client.management_cipher = join.request.pmf().map(|pmf| pmf.management());
        let action = client
            .station
            .associate_external_pmf(session, join, observed, now, &mut policy)
            .map_err(Error::Station)?;
        client.act(action);
        Ok(())
    }

    fn configure(&mut self) -> Result<(), Error> {
        let (ticket, context) = self
            .client
            .admitted
            .take()
            .ok_or(Error::Refused("configuration"))?;
        self.client.context = Some(context.clone());
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Ready(mut queue) = stage else {
            self.stage = stage;
            return Err(Error::Refused("configuration"));
        };
        let result = self.association_steps(&mut queue, &context, ticket);
        self.stage = Stage::Ready(queue);
        result
    }

    fn send_control(&mut self, ethernet: &[u8], key: Option<KeyIdentity>) -> Result<(), Error> {
        let class = key.map_or(TxClass::ControlPortPlaintext, TxClass::ControlPortProtected);
        self.send(ethernet, class)
    }

    fn install_key(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        receive: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        self.install(pairwise, index, material, receive)
    }

    fn install_link_key(
        &mut self,
        _: u8,
        _: u8,
        _: &[u8],
        _: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        Err(Error::Unsupported("MLO on Intel Wi-Fi"))
    }

    unsafe fn install_management_key(
        &mut self,
        _: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        let client = &mut self.client;
        if !client.keys_settled() {
            return Err(Error::Pending);
        }
        let flags = commands::management_key_flags(
            client
                .management_cipher
                .ok_or(Error::Refused("no management cipher"))?,
        );
        let bytes = commands::add_key(index, flags, material, receive.value())
            .ok_or(Error::Refused("key material"))?;
        client.command(commands::SECURITY_KEY, bytes);
        client.management_keys.push((index, flags));
        Ok(Arc::new(ManagementKey { index }))
    }

    unsafe fn rotate_management_key(
        &mut self,
        session: &Arc<ManagementKey>,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        // SAFETY: forwarded from the keeper.
        let installed = unsafe { self.install_management_key(0, index, material, receive) }?;
        let client = &mut self.client;
        if let Some(old) = client
            .management_keys
            .iter()
            .position(|key| key.0 == session.index)
        {
            let (index, flags) = client.management_keys.remove(old);
            client.command(commands::SECURITY_KEY, commands::remove_key(index, flags));
        }
        Ok(installed)
    }

    fn authorize_port(&mut self, epoch: u64) -> Result<(), Error> {
        let client = &mut self.client;
        if !client.keys_settled() || !client.idle() {
            return Err(Error::Pending);
        }
        let context = client.context.clone().ok_or(Error::Refused("no context"))?;
        let ptk = client
            .keys
            .iter()
            .find(|key| key.pairwise)
            .ok_or(Error::Refused("no pairwise key"))?;
        let gtk = client
            .keys
            .iter()
            .rev()
            .find(|key| !key.pairwise)
            .ok_or(Error::Refused("no group key"))?;
        let links = [(&ptk.slot, &gtk.slot)];
        if client.station.requires_protected_management() {
            client
                .station
                .authorize_protected_port(&context, epoch, &links)
        } else {
            client.station.authorize_port(epoch, &links)
        }
        .map_err(Error::Station)?;
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Ready(mut queue) = stage else {
            self.stage = stage;
            return Err(Error::Refused("port"));
        };
        let result = self.authorized_steps(&mut queue, &context);
        self.stage = Stage::Ready(queue);
        result
    }

    fn deauthenticate(&mut self, reason: u16) -> Result<(), Error> {
        let client = &mut self.client;
        if client.leaving || client.left {
            return Ok(());
        }
        if client.station.phase() == Peering::Idle {
            client.plan = None;
            // A chain on its way up comes back down; nothing else is raised.
            client.leaving = matches!(
                self.stage,
                Stage::Phy(_)
                    | Stage::Power(_)
                    | Stage::Link(_)
                    | Stage::Peer(_)
                    | Stage::Queue(_)
                    | Stage::Coexistence(_)
                    | Stage::Ready(_)
            );
            return Ok(());
        }
        if let (Some(ap), true) = (
            client.station.pairwise_peer(),
            matches!(self.stage, Stage::Ready(_)),
        ) {
            let protected = client.station.protected_port_authorized();
            client.farewell = Some(management(
                self.address,
                ap,
                0xc0,
                protected,
                &reason.to_le_bytes(),
            ));
        }
        let action = client.station.disconnect().map_err(Error::Station)?;
        client.act(action);
        Ok(())
    }

    unsafe fn retire_peer(&mut self) -> Result<(), Error> {
        let client = &mut self.client;
        if let Some(ticket) = client.departing {
            client
                .station
                .complete_removal(ticket, Completion::Accepted)
                .map_err(Error::Station)?;
        }
        client.reset();
        Ok(())
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// `iwl_mvm_mld_mac_sta_state`'s ASSOC to AUTHORIZED: the beacon filter,
    /// the MAC's and station's authorized state, and rates at full width.
    fn authorized_steps(
        &mut self,
        queue: &mut Queue<Q, B>,
        context: &AssociationContext,
    ) -> Result<(), Error> {
        let negotiated = context.negotiated();
        let band = context.beacon().channel.band;
        let antennas = queue.antennas();
        let firmware = queue.firmware();
        let filter = if firmware.supports_api(BEACON_FILTER_V4_API) {
            60
        } else {
            44
        };
        let peer_version = firmware
            .command_version(3, 0x0a)
            .map_or(0, |version| version.command_version);
        let rate_bytes = rate_body(firmware)?;
        let explicit_mfp = firmware.supports_capability(EXPLICIT_MFP);
        let rates = commands::rate_config(negotiated, band, antennas, rate_bytes, true)
            .ok_or(Error::Refused("rates"))?;
        let mac = MacState {
            address: self.address,
            he: negotiated.he.is_some(),
            eht: false,
            aid: Some(context.response().aid),
            high_priority: false,
        };
        let peer = commands::station_config(peer_version, peer_state(context, explicit_mfp, true));
        let client = &mut self.client;
        client.command(commands::BEACON_FILTER, commands::beacon_filter(filter));
        client.command(commands::MAC_CONFIG, commands::mac_config(mac));
        client.command(commands::STATION_CONFIG, peer);
        client.steps.push_back(Step::Command {
            id: commands::RATE_CONFIG,
            bytes: rates,
            then: Then::Authorized,
        });
        Ok(())
    }
}

impl Client {
    fn port_ready(&self) -> bool {
        self.context.is_some()
    }

    /// A step of the station's Block Ack agreements.
    fn block_ack(&mut self, action: ba::Action) {
        match action {
            ba::Action::Program {
                ticket,
                session,
                enable,
            } => self.steps.push_back(Step::BlockAck(Agreement {
                ticket,
                session,
                enable,
            })),
            ba::Action::Transmit {
                context, mut bytes, ..
            } => {
                // Block Ack action frames are robust.
                if context.pmf().is_some() {
                    bytes[1] |= 0x40;
                }
                self.outbox.push_back((None, bytes));
            }
            ba::Action::Bar {
                session,
                start_sequence,
            } => {
                if let Some(id) = self.reception.session(session.tid()) {
                    self.release(id, Some(session.tid()), start_sequence);
                }
            }
            // The firmware runs transmit agreements itself, as
            // `TX_AMPDU_SETUP_IN_HW` tells mac80211.
            ba::Action::Tx(_) | ba::Action::None => {}
        }
    }

    fn release(&mut self, id: u8, tid: Option<u8>, through: u16) {
        let mut ready = Vec::new();
        self.reception.release(id, tid, through, &mut ready);
        self.deliver_all(ready);
    }

    fn deliver_all(&mut self, ready: Vec<Parent>) {
        for parent in ready {
            self.deliver(parent);
        }
    }

    /// `parent`, its turn come, to the station. mac80211 drops what its
    /// replay and port checks refuse.
    fn deliver(&mut self, parent: Parent) {
        let Parent { members, shape } = parent;
        let ingress = if shape == Shape::WholeMpdu && !members[0].header().amsdu {
            let Some(epoch) = self.station.association_epoch() else {
                return;
            };
            let mut keys: Vec<&mut KeySlot> =
                self.keys.iter_mut().map(|key| &mut key.slot).collect();
            match self
                .station
                .receive_msdu_refs(epoch, &members[0], &mut keys)
            {
                Ok(ingress) => alloc::vec![ingress],
                Err(_) => return,
            }
        } else {
            let Some(context) = self.context.clone() else {
                return;
            };
            let key = members[0].security.key;
            // SAFETY: `Reception` gathered every record of this MPDU in the
            // order the receive queue gave them and after any reorder release.
            // `depart` and `reset` drop what they hold for an older association.
            let group = unsafe { OrderedGroup::new(context, members, shape, ()) };
            let slot = self
                .keys
                .iter_mut()
                .map(|key| &mut key.slot)
                .find(|slot| key.is_some() && slot.installed() == key);
            let Ok(received) = self.station.receive_ordered_group(&group, slot) else {
                return;
            };
            let keys: Vec<&KeySlot> = self.keys.iter().map(|key| &key.slot).collect();
            match self.station.receive_group_refs(&received, &keys) {
                Ok(ingress) => ingress,
                Err(_) => return,
            }
        };
        for ingress in ingress {
            match ingress {
                Ingress::Data(ethernet) => self.received.push_back(ethernet),
                Ingress::ControlPort { ethernet, .. } => {
                    self.events.push_back(keeper::Event::Eapol(ethernet));
                }
            }
        }
    }
}

/// The regulatory flags `ieee80211_determine_chan_mode` reads, from the
/// firmware's channel restrictions.
pub fn channel_flags(no_plus: bool, no_minus: bool, no_80: bool, no_160: bool) -> u32 {
    let mut flags = 0;
    if no_plus {
        flags |= NO_HT40PLUS;
    }
    if no_minus {
        flags |= NO_HT40MINUS;
    }
    if no_80 {
        flags |= NO_80MHZ;
    }
    if no_160 {
        flags |= NO_160MHZ;
    }
    flags
}
