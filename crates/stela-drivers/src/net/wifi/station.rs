// SPDX-License-Identifier: GPL-2.0-only
// Management state rules adapted from Linux net/mac80211/mlme.c and key.c.
// Copyright 2003-2008 Jouni Malinen; 2004 Instant802 Networks, Inc.;
// 2005 Devicescape Software, Inc.; 2006-2007 Jiri Benc; 2007 Michael Wu;
// 2013-2014 Intel Mobile Communications GmbH;
// 2015-2017 Intel Deutschland GmbH; 2018-2026 Intel Corporation.
//! Single-link open-system authentication and association control.
//!
//! The OS/frontend chooses the BSS and complete negotiated association IEs.
//! WPA/802.1X authentication remains with that OS service. This layer cannot
//! synthesize authorization: controlled-port opening requires an explicit
//! association-scoped frontend command and actual acknowledged PTK/GTK keys.
//! Vendor code owns DMA/radio resources and actual command acknowledgements.

use super::{
    Channel,
    frame::Mpdu,
    security::{KeyIdentity, KeyScope, KeySlot},
};
use crate::net::Mac;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

pub mod wire;

static NEXT_ASSOCIATION: AtomicU64 = AtomicU64::new(1);
// Linux no-ACK-status auth/assoc response timing and retry count.
const MANAGEMENT_RESPONSE_TIMEOUT_US: u64 = 500_000;
const MANAGEMENT_ATTEMPTS: u8 = 3;
const CONFIGURATION_TIMEOUT_US: u64 = 500_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortPolicy {
    Open,
    Controlled,
}

/// Regulatory authorization must come from the real OS/radio policy service.
/// The frame engine supplies no permissive default or country/DFS guesses.
pub trait RegulatoryPolicy {
    fn allow_management_tx(&mut self, channel: Channel) -> bool;
}

#[derive(Clone, Debug)]
pub struct Join {
    pub bssid: Mac,
    pub channel: Channel,
    pub policy: PortPolicy,
    pub request: wire::AssociationRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    epoch: u64,
    serial: u32,
}

impl Ticket {
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
    pub const fn serial(self) -> u32 {
        self.serial
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Authenticating,
    Associating,
    Configuring,
    Associated,
    Disconnecting,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Accepted,
    RejectedAndIdle,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    InvalidAddress,
    Regulatory,
    ClockRegressed,
    Overflow,
    Stale,
    NotQueued,
    WrongChannel,
    Wire(wire::Error),
    Timeout,
    NotAssociated,
    WrongKey,
    Unsupported(&'static str),
}

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Self::Wire(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    PeerRejected(u16),
    PeerDeparture(u16),
    Timeout,
    Transmit,
}

#[derive(Clone, Debug)]
pub enum Action {
    /// Queue these real bytes on the specified permitted channel. Before
    /// calling `submitted`, the vendor must establish successful ownership
    /// transfer into its actual TX path. DMA completion is not an air ACK.
    Transmit {
        ticket: Ticket,
        channel: Channel,
        bytes: Vec<u8>,
    },
    /// Program actual firmware association context and match its real status.
    Configure {
        ticket: Ticket,
        bssid: Mac,
        channel: Channel,
        request: wire::AssociationRequest,
        response: wire::AssociationResponse,
    },
    /// Remove association/keys, mask/drain associated work, then acknowledge.
    Remove {
        ticket: Ticket,
        failure: Option<Failure>,
    },
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    ticket: Ticket,
    queued: bool,
    deadline: u64,
    attempts: u8,
}

#[derive(Debug)]
pub struct Station {
    local: Mac,
    phase: Phase,
    join: Option<Join>,
    epoch: u64,
    serial: u32,
    sequence: u16,
    now: u64,
    pending: Option<Pending>,
    authorization: Option<(KeyIdentity, KeyIdentity)>,
}

impl Station {
    pub fn new(local: Mac) -> Result<Self, Error> {
        if local.is_multicast() || local.0 == [0; 6] {
            return Err(Error::InvalidAddress);
        }
        Ok(Self {
            local,
            phase: Phase::Idle,
            join: None,
            epoch: 0,
            serial: 0,
            sequence: 0,
            now: 0,
            pending: None,
            authorization: None,
        })
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn association_epoch(&self) -> Option<u64> {
        if matches!(self.phase, Phase::Idle) {
            None
        } else {
            Some(self.epoch)
        }
    }

    fn clock(&mut self, now_us: u64) -> Result<(), Error> {
        if now_us < self.now {
            return Err(Error::ClockRegressed);
        }
        self.now = now_us;
        Ok(())
    }

    fn ticket(&mut self) -> Result<Ticket, Error> {
        self.serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Ticket {
            epoch: self.epoch,
            serial: self.serial,
        })
    }

    fn transmit(
        &mut self,
        phase: Phase,
        attempts: u8,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Action, Error> {
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        let channel = join.channel;
        if !policy.allow_management_tx(channel) {
            return Err(Error::Regulatory);
        }
        let bytes = match phase {
            Phase::Authenticating => wire::authentication(self.local, join.bssid, self.sequence),
            Phase::Associating => join.request.encode(self.local, join.bssid, self.sequence),
            _ => return Err(Error::Busy),
        }?;
        let deadline = self
            .now
            .checked_add(MANAGEMENT_RESPONSE_TIMEOUT_US)
            .ok_or(Error::Overflow)?;
        let ticket = self.ticket()?;
        self.sequence = (self.sequence + 1) & 0xfff;
        self.phase = phase;
        self.pending = Some(Pending {
            ticket,
            queued: false,
            deadline,
            attempts,
        });
        Ok(Action::Transmit {
            ticket,
            channel,
            bytes,
        })
    }

    pub fn begin(
        &mut self,
        join: Join,
        now_us: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Action, Error> {
        if self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        self.clock(now_us)?;
        if join.bssid.is_multicast() || join.bssid.0 == [0; 6] || join.bssid == self.local {
            return Err(Error::InvalidAddress);
        }
        if join.channel.band == super::Band::Ghz6 {
            return Err(Error::Unsupported("6GHz HE/SAE/PMF association"));
        }
        join.request.validate_policy(join.policy)?;
        self.epoch = NEXT_ASSOCIATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| Error::Overflow)?;
        self.serial = 0;
        self.join = Some(join);
        self.phase = Phase::Authenticating;
        match self.transmit(Phase::Authenticating, 1, policy) {
            Ok(action) => Ok(action),
            Err(error) => {
                self.phase = Phase::Idle;
                self.join = None;
                Err(error)
            }
        }
    }

    pub fn submitted(&mut self, ticket: Ticket) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Authenticating | Phase::Associating) {
            return Err(Error::Stale);
        }
        let pending = self.pending.as_mut().ok_or(Error::Stale)?;
        if pending.ticket != ticket {
            return Err(Error::Stale);
        }
        pending.queued = true;
        Ok(())
    }

    /// Call after an actual failed queue/air result. The current association is
    /// retired explicitly; callers may begin again after real removal/drain.
    pub fn transmit_failed(&mut self, ticket: Ticket) -> Result<Action, Error> {
        if !matches!(self.phase, Phase::Authenticating | Phase::Associating) {
            return Err(Error::Stale);
        }
        if self.pending.is_none_or(|pending| pending.ticket != ticket) {
            return Err(Error::Stale);
        }
        self.remove(Some(Failure::Transmit))
    }

    /// `epoch` must be retained from the actual firmware/RX association context;
    /// never retag old deferred RX by looking up the current epoch at delivery.
    pub fn receive(
        &mut self,
        epoch: u64,
        frame: &Mpdu,
        now_us: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Action, Error> {
        self.clock(now_us)?;
        if epoch != self.epoch {
            return Err(Error::Stale);
        }
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        if (
            frame.radio.band,
            frame.radio.channel,
            frame.radio.frequency_mhz,
        ) != (
            join.channel.band,
            join.channel.number,
            join.channel.frequency_mhz,
        ) {
            return Err(Error::WrongChannel);
        }
        if frame.fcs_error || frame.monitor_only {
            return Err(Error::Wire(wire::Error::Integrity));
        }
        wire::check_peer(frame, self.local, join.bssid)?;
        if matches!(frame.header().control & 0x00fc, 0x00a0 | 0x00c0) {
            let reason = wire::departure(frame)?;
            return self.remove(Some(Failure::PeerDeparture(reason)));
        }
        let pending = self.pending.ok_or(Error::Stale)?;
        if !pending.queued {
            return Err(Error::NotQueued);
        }
        if matches!(self.phase, Phase::Authenticating | Phase::Associating)
            && self.now >= pending.deadline
        {
            if pending.attempts < MANAGEMENT_ATTEMPTS {
                return self.transmit(self.phase, pending.attempts + 1, policy);
            }
            return self.remove(Some(Failure::Timeout));
        }
        match self.phase {
            Phase::Authenticating => {
                let status = wire::authentication_response(frame)?;
                if status != 0 {
                    return self.remove(Some(Failure::PeerRejected(status)));
                }
                self.transmit(Phase::Associating, 1, policy)
            }
            Phase::Associating => {
                let response = wire::association_response(frame)?;
                if response.status != 0 {
                    return self.remove(Some(Failure::PeerRejected(response.status)));
                }
                let bssid = join.bssid;
                let channel = join.channel;
                let request = join.request.clone();
                let deadline = self
                    .now
                    .checked_add(CONFIGURATION_TIMEOUT_US)
                    .ok_or(Error::Overflow)?;
                let ticket = self.ticket()?;
                self.phase = Phase::Configuring;
                self.pending = Some(Pending {
                    ticket,
                    queued: true,
                    deadline,
                    attempts: 0,
                });
                Ok(Action::Configure {
                    ticket,
                    bssid,
                    channel,
                    request,
                    response,
                })
            }
            _ => Err(Error::Stale),
        }
    }

    pub fn poll(
        &mut self,
        now_us: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Option<Action>, Error> {
        self.clock(now_us)?;
        let Some(pending) = self.pending else {
            return Ok(None);
        };
        if self.phase == Phase::Configuring && self.now >= pending.deadline {
            self.phase = Phase::Quarantined;
            self.pending = None;
            return Err(Error::Timeout);
        }
        if !matches!(self.phase, Phase::Authenticating | Phase::Associating)
            || self.now < pending.deadline
        {
            return Ok(None);
        }
        if !pending.queued || pending.attempts >= MANAGEMENT_ATTEMPTS {
            return self.remove(Some(Failure::Timeout)).map(Some);
        }
        self.transmit(self.phase, pending.attempts + 1, policy)
            .map(Some)
    }

    pub fn complete_configuration(
        &mut self,
        ticket: Ticket,
        result: Completion,
        now_us: u64,
    ) -> Result<(), Error> {
        self.clock(now_us)?;
        if self.phase != Phase::Configuring
            || self.pending.is_none_or(|pending| pending.ticket != ticket)
        {
            return Err(Error::Stale);
        }
        if self
            .pending
            .is_some_and(|pending| self.now >= pending.deadline)
        {
            self.phase = Phase::Quarantined;
            self.pending = None;
            return Err(Error::Timeout);
        }
        self.pending = None;
        self.phase = match result {
            Completion::Accepted => Phase::Associated,
            Completion::RejectedAndIdle => {
                self.join = None;
                Phase::Idle
            }
            Completion::Uncertain => Phase::Quarantined,
        };
        Ok(())
    }

    /// Generic OS controlled-port command, not proof generated by this layer.
    /// The trusted frontend must issue it only after authenticating the real
    /// handshake and peer. Both keys must already have genuine firmware ACKs.
    pub fn authorize_port(
        &mut self,
        epoch: u64,
        pairwise: &KeySlot,
        group: &KeySlot,
    ) -> Result<(), Error> {
        if self.phase != Phase::Associated || epoch != self.epoch {
            return Err(Error::NotAssociated);
        }
        let bssid = self.join.as_ref().ok_or(Error::NotAssociated)?.bssid;
        let ptk = pairwise
            .installed()
            .filter(|key| key.scope() == KeyScope::Pairwise(bssid))
            .ok_or(Error::WrongKey)?;
        let gtk = group
            .installed()
            .filter(|key| key.scope() == KeyScope::Group(bssid))
            .ok_or(Error::WrongKey)?;
        if ptk.index() != 0 {
            return Err(Error::Unsupported("extended pairwise key ID"));
        }
        if self
            .join
            .as_ref()
            .and_then(|join| join.request.key_ciphers())
            != Some((ptk.cipher(), gtk.cipher()))
        {
            return Err(Error::WrongKey);
        }
        self.authorization = Some((ptk, gtk));
        Ok(())
    }

    pub fn close_port(&mut self) {
        self.authorization = None;
    }

    /// Recheck current acknowledged identities, so external key invalidation or
    /// rekey cannot leave a cached successful-looking carrier value.
    pub fn port_open(&self, pairwise: Option<&KeySlot>, group: Option<&KeySlot>) -> bool {
        if self.phase != Phase::Associated {
            return false;
        }
        if self
            .join
            .as_ref()
            .is_some_and(|join| join.policy == PortPolicy::Open)
        {
            return true;
        }
        self.authorization.is_some_and(|(ptk, gtk)| {
            pairwise.and_then(KeySlot::installed) == Some(ptk)
                && group.and_then(KeySlot::installed) == Some(gtk)
        })
    }

    pub fn disconnect(&mut self) -> Result<Action, Error> {
        self.remove(None)
    }

    fn remove(&mut self, failure: Option<Failure>) -> Result<Action, Error> {
        if matches!(self.phase, Phase::Idle | Phase::Disconnecting) {
            return Err(Error::NotAssociated);
        }
        self.authorization = None;
        let ticket = self.ticket()?;
        self.phase = Phase::Disconnecting;
        self.pending = Some(Pending {
            ticket,
            queued: true,
            deadline: u64::MAX,
            attempts: 0,
        });
        Ok(Action::Remove { ticket, failure })
    }

    /// Accepted removal includes actual radio/key/RX/deferred-work quiescence.
    /// Uncertainty quarantines the session; it never permits another join.
    pub fn complete_removal(&mut self, ticket: Ticket, result: Completion) -> Result<(), Error> {
        if self.phase != Phase::Disconnecting
            || self.pending.is_none_or(|pending| pending.ticket != ticket)
        {
            return Err(Error::Stale);
        }
        self.pending = None;
        self.authorization = None;
        self.phase = if result == Completion::Accepted {
            self.join = None;
            Phase::Idle
        } else {
            Phase::Quarantined
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wifi::{
        Band, RadioStatus, RawRate,
        security::{Cipher, InstallOutcome, ReplaySeed, SecurityStatus},
    };
    use alloc::vec;

    const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
    const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
    struct Policy(bool);
    impl RegulatoryPolicy for Policy {
        fn allow_management_tx(&mut self, _: Channel) -> bool {
            self.0
        }
    }

    fn join(policy: PortPolicy) -> Join {
        let mut elements = vec![0, 1, b'x', 1, 3, 0x8c, 0x98, 0xb0];
        if policy == PortPolicy::Controlled {
            elements.extend_from_slice(&[
                48, 18, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
            ]);
        }
        Join {
            bssid: AP,
            channel: Channel {
                band: Band::Ghz5,
                number: 36,
                frequency_mhz: 5180,
            },
            policy,
            request: wire::AssociationRequest::new(
                if policy == PortPolicy::Open { 1 } else { 0x11 },
                10,
                elements,
            )
            .unwrap(),
        }
    }

    fn ticket(action: &Action) -> Ticket {
        match action {
            Action::Transmit { ticket, .. }
            | Action::Configure { ticket, .. }
            | Action::Remove { ticket, .. } => *ticket,
        }
    }

    fn response(control: u16, body: &[u8]) -> Mpdu {
        let mut bytes = vec![0; 24];
        bytes[..2].copy_from_slice(&control.to_le_bytes());
        bytes[4..10].copy_from_slice(&LOCAL.0);
        bytes[10..16].copy_from_slice(&AP.0);
        bytes[16..22].copy_from_slice(&AP.0);
        bytes.extend_from_slice(body);
        Mpdu::new(
            bytes,
            RadioStatus {
                band: Band::Ghz5,
                channel: 36,
                frequency_mhz: 5180,
                signal_dbm: Some(-45),
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 1,
                    words: [0; 4],
                },
                tsf: None,
            },
            SecurityStatus::default(),
        )
        .unwrap()
    }

    fn configure(station: &mut Station, policy: PortPolicy) -> Ticket {
        let auth = station.begin(join(policy), 1, &mut Policy(true)).unwrap();
        let epoch = ticket(&auth).epoch();
        assert!(!station.port_open(None, None));
        station.submitted(ticket(&auth)).unwrap();
        let assoc = station
            .receive(
                epoch,
                &response(0xb0, &[0, 0, 2, 0, 0, 0]),
                2,
                &mut Policy(true),
            )
            .unwrap();
        station.submitted(ticket(&assoc)).unwrap();
        let config = station
            .receive(
                epoch,
                &response(0x10, &[1, 0, 0, 0, 7, 0xc0, 1, 3, 0x8c, 0x98, 0xb0]),
                3,
                &mut Policy(true),
            )
            .unwrap();
        assert!(matches!(config, Action::Configure { .. }));
        ticket(&config)
    }

    fn key(slot: u16, scope: KeyScope) -> KeySlot {
        // Independent protocol fixture has no real slots, DMA or deferred RX.
        let mut key = unsafe { KeySlot::new(slot).unwrap() };
        let index = if matches!(scope, KeyScope::Pairwise(_)) {
            0
        } else {
            2
        };
        let ticket = key
            .begin_install(
                index,
                Cipher::Ccmp128,
                &[slot as u8; 16],
                ReplaySeed::ZERO,
                scope,
            )
            .unwrap();
        key.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        key
    }

    #[test]
    fn open_port_needs_actual_auth_association_and_firmware_ack() {
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Open);
        assert_eq!(station.phase(), Phase::Configuring);
        assert!(!station.port_open(None, None));
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        assert!(station.port_open(None, None));
        assert_eq!(
            station.complete_configuration(config, Completion::Accepted, 4),
            Err(Error::Stale)
        );
    }

    #[test]
    fn secured_port_needs_frontend_command_and_current_pairwise_and_group_keys() {
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Controlled);
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        let mut ptk = key(1, KeyScope::Pairwise(AP));
        let gtk = key(2, KeyScope::Group(AP));
        assert!(!station.port_open(Some(&ptk), Some(&gtk)));
        assert_eq!(
            station.authorize_port(config.epoch() + 1, &ptk, &gtk),
            Err(Error::NotAssociated)
        );
        station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
        assert!(station.port_open(Some(&ptk), Some(&gtk)));
        assert!(!station.port_open(Some(&ptk), None));
        ptk.invalidate();
        assert!(!station.port_open(Some(&ptk), Some(&gtk)));
    }

    #[test]
    fn wrong_bss_purpose_or_key_ack_cannot_open_port() {
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Controlled);
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        let ptk = key(1, KeyScope::Pairwise(Mac([2, 0, 0, 0, 0, 1])));
        let gtk = key(2, KeyScope::Group(AP));
        assert_eq!(
            station.authorize_port(config.epoch(), &ptk, &gtk),
            Err(Error::WrongKey)
        );
        assert_eq!(
            station.authorize_port(config.epoch(), &gtk, &gtk),
            Err(Error::WrongKey)
        );
        assert!(!station.port_open(Some(&ptk), Some(&gtk)));
    }

    #[test]
    fn old_epoch_unsubmitted_and_wrong_channel_responses_do_not_advance() {
        let mut station = Station::new(LOCAL).unwrap();
        let auth = station
            .begin(join(PortPolicy::Open), 1, &mut Policy(true))
            .unwrap();
        let epoch = ticket(&auth).epoch();
        let frame = response(0xb0, &[0, 0, 2, 0, 0, 0]);
        assert!(matches!(
            station.receive(epoch, &frame, 2, &mut Policy(true)),
            Err(Error::NotQueued)
        ));
        station.submitted(ticket(&auth)).unwrap();
        assert!(matches!(
            station.receive(epoch + 1, &frame, 3, &mut Policy(true)),
            Err(Error::Stale)
        ));
        let mut wrong = frame.clone();
        wrong.radio.channel = 40;
        assert!(matches!(
            station.receive(epoch, &wrong, 4, &mut Policy(true)),
            Err(Error::WrongChannel)
        ));
        assert_eq!(station.phase(), Phase::Authenticating);
        assert!(station.receive(epoch, &frame, 5, &mut Policy(true)).is_ok());
    }

    #[test]
    fn negative_peer_response_requires_real_removal_before_retry() {
        let mut station = Station::new(LOCAL).unwrap();
        let auth = station
            .begin(join(PortPolicy::Open), 1, &mut Policy(true))
            .unwrap();
        station.submitted(ticket(&auth)).unwrap();
        let remove = station
            .receive(
                ticket(&auth).epoch(),
                &response(0xb0, &[0, 0, 2, 0, 13, 0]),
                2,
                &mut Policy(true),
            )
            .unwrap();
        assert!(matches!(
            remove,
            Action::Remove {
                failure: Some(Failure::PeerRejected(13)),
                ..
            }
        ));
        assert_eq!(station.phase(), Phase::Disconnecting);
        assert!(matches!(
            station.begin(join(PortPolicy::Open), 3, &mut Policy(true)),
            Err(Error::Busy)
        ));
        station
            .complete_removal(ticket(&remove), Completion::Accepted)
            .unwrap();
        let next = station
            .begin(join(PortPolicy::Open), 4, &mut Policy(true))
            .unwrap();
        assert_ne!(ticket(&next).epoch(), ticket(&auth).epoch());
        assert_eq!(station.submitted(ticket(&auth)), Err(Error::Stale));
    }

    #[test]
    fn three_attempt_timeout_closes_session_and_does_not_assume_idle() {
        let mut station = Station::new(LOCAL).unwrap();
        let first = station
            .begin(join(PortPolicy::Open), 0, &mut Policy(true))
            .unwrap();
        station.submitted(ticket(&first)).unwrap();
        for now in [500_000, 1_000_000] {
            let next = station.poll(now, &mut Policy(true)).unwrap().unwrap();
            assert!(matches!(next, Action::Transmit { .. }));
            station.submitted(ticket(&next)).unwrap();
        }
        let remove = station.poll(1_500_000, &mut Policy(true)).unwrap().unwrap();
        assert!(matches!(
            remove,
            Action::Remove {
                failure: Some(Failure::Timeout),
                ..
            }
        ));
        station
            .complete_removal(ticket(&remove), Completion::Uncertain)
            .unwrap();
        assert_eq!(station.phase(), Phase::Quarantined);
        assert!(!station.port_open(None, None));
    }

    #[test]
    fn regulator_and_clock_failures_do_not_create_carrier_or_firmware_success() {
        let mut station = Station::new(LOCAL).unwrap();
        assert!(matches!(
            station.begin(join(PortPolicy::Open), 10, &mut Policy(false)),
            Err(Error::Regulatory)
        ));
        assert_eq!(station.phase(), Phase::Idle);
        assert!(matches!(
            station.begin(join(PortPolicy::Open), 9, &mut Policy(true)),
            Err(Error::ClockRegressed)
        ));
        let config = {
            let mut fresh = Station::new(LOCAL).unwrap();
            let config = configure(&mut fresh, PortPolicy::Open);
            station = fresh;
            config
        };
        assert!(matches!(
            station.poll(500_003, &mut Policy(true)),
            Err(Error::Timeout)
        ));
        assert_eq!(station.phase(), Phase::Quarantined);
        assert_eq!(
            station.complete_configuration(config, Completion::Accepted, 500_003),
            Err(Error::Stale)
        );
    }

    #[test]
    fn actual_peer_departure_closes_open_port_before_device_teardown() {
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Open);
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        let remove = station
            .receive(
                config.epoch(),
                &response(0xc0, &[3, 0]),
                4,
                &mut Policy(true),
            )
            .unwrap();
        assert!(matches!(
            remove,
            Action::Remove {
                failure: Some(Failure::PeerDeparture(3)),
                ..
            }
        ));
        assert!(!station.port_open(None, None));
    }

    #[test]
    fn invalid_aid_preserves_linux_no_power_save_fallback() {
        for (aid, expected) in [(0, 0), (1, 1), (2007, 2007), (2008, 0), (2047, 0)] {
            let raw = aid | 0xc000_u16;
            let [low, high] = raw.to_le_bytes();
            let frame = response(0x10, &[1, 0, 0, 0, low, high, 1, 3, 0x8c, 0x98, 0xb0]);
            let parsed = wire::association_response(&frame).unwrap();
            assert_eq!(parsed.raw_aid, raw);
            assert_eq!(parsed.aid, expected);
            assert_eq!(parsed.power_save_allowed, expected != 0);
        }
    }

    #[test]
    fn truncated_or_wrong_peer_management_cannot_advance_authentication() {
        let mut station = Station::new(LOCAL).unwrap();
        let auth = station
            .begin(join(PortPolicy::Open), 0, &mut Policy(true))
            .unwrap();
        station.submitted(ticket(&auth)).unwrap();
        for length in 0..6 {
            assert!(
                station
                    .receive(
                        ticket(&auth).epoch(),
                        &response(0xb0, &[0, 0, 2, 0, 0, 0][..length]),
                        1,
                        &mut Policy(true)
                    )
                    .is_err()
            );
        }
        for offset in [4, 10, 16] {
            let original = response(0xb0, &[0, 0, 2, 0, 0, 0]);
            let mut bytes = original.bytes().to_vec();
            bytes[offset] ^= 2;
            let altered = Mpdu::new(bytes, original.radio.clone(), original.security).unwrap();
            assert!(matches!(
                station.receive(ticket(&auth).epoch(), &altered, 2, &mut Policy(true)),
                Err(Error::Wire(wire::Error::WrongPeer))
            ));
        }
        assert_eq!(station.phase(), Phase::Authenticating);
        assert!(!station.port_open(None, None));
    }

    #[test]
    fn uncertain_configuration_and_deadline_overflow_stay_closed() {
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Open);
        station
            .complete_configuration(config, Completion::Uncertain, 4)
            .unwrap();
        assert_eq!(station.phase(), Phase::Quarantined);
        assert!(!station.port_open(None, None));
        let mut fresh = Station::new(LOCAL).unwrap();
        assert!(matches!(
            fresh.begin(join(PortPolicy::Open), u64::MAX - 1, &mut Policy(true)),
            Err(Error::Overflow)
        ));
        assert_eq!(fresh.phase(), Phase::Idle);
        assert!(!fresh.port_open(None, None));
    }

    #[test]
    fn late_success_cannot_bypass_response_or_configuration_deadline() {
        let mut station = Station::new(LOCAL).unwrap();
        let auth = station
            .begin(join(PortPolicy::Open), 0, &mut Policy(true))
            .unwrap();
        station.submitted(ticket(&auth)).unwrap();
        let retry = station
            .receive(
                ticket(&auth).epoch(),
                &response(0xb0, &[0, 0, 2, 0, 0, 0]),
                500_000,
                &mut Policy(true),
            )
            .unwrap();
        assert!(matches!(retry, Action::Transmit { .. }));
        assert_eq!(station.phase(), Phase::Authenticating);
        assert_ne!(ticket(&retry), ticket(&auth));
        let mut fresh = Station::new(LOCAL).unwrap();
        let config = configure(&mut fresh, PortPolicy::Open);
        assert_eq!(
            fresh.complete_configuration(config, Completion::Accepted, 500_003),
            Err(Error::Timeout)
        );
        assert_eq!(fresh.phase(), Phase::Quarantined);
        assert!(!fresh.port_open(None, None));
    }
}
