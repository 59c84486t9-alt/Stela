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
    frame::{DEAUTHENTICATION, DISASSOCIATION, Mpdu, QOS_TIDS, TYPE_SUBTYPE, next_sequence},
    security::{KeyIdentity, KeyScope, KeySlot},
};
use crate::net::Mac;
use alloc::{sync::Arc, vec::Vec};

mod aggregate;
mod context;
pub mod csa;
pub mod external;
mod sequence;
pub use context::{AssociationContext, AssociationIntent, NativeBssObservation};
pub mod ba;
pub mod data;
pub mod operations;
pub mod phy;
pub mod wire;

static NEXT_ASSOCIATION: super::Identities = super::Identities::new();
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
    fn allow_data_tx(&mut self, channel: Channel) -> bool;
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
    ExternalAuthenticating,
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
    Phy(phy::Error),
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
        /// Exact retained modern configuration. Legacy actions carry None.
        context: Option<Arc<AssociationContext>>,
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
    external: Option<Arc<external::Session>>,
    selected_beacon: Option<super::scan::result::Bss>,
    context: Option<Arc<AssociationContext>>,
    /// Where a channel switch moved the association of this context ticket.
    switched: Option<(Ticket, operations::ChannelDefinition)>,
    pmf_observation: Option<Arc<NativeBssObservation>>,
    epoch: u64,
    serial: u32,
    sequence: u16,
    qos_sequence: [u16; QOS_TIDS],
    now: u64,
    pending: Option<Pending>,
    authorization: Option<(KeyIdentity, KeyIdentity)>,
    rx_ba: ba::Sessions,
    tx_ba: ba::tx::Sessions,
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
            external: None,
            selected_beacon: None,
            context: None,
            switched: None,
            pmf_observation: None,
            epoch: 0,
            serial: 0,
            sequence: 0,
            qos_sequence: [0; 16],
            now: 0,
            pending: None,
            authorization: None,
            rx_ba: ba::Sessions::new(),
            tx_ba: ba::tx::Sessions::new(),
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
        self.sequence = next_sequence(self.sequence);
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
        if join.request.modern().is_some() {
            return Err(Error::Unsupported(
                "modern join requires selected actual beacon",
            ));
        }
        self.begin_inner(join, None, now_us, policy)
    }

    /// Start an explicit modern association using the actual selected beacon.
    /// This supplies no SAE/PMF, OS authentication or native radio authority;
    /// 6GHz remains refused until those actual boundaries are operational.
    pub fn begin_modern(
        &mut self,
        join: Join,
        beacon: super::scan::result::Bss,
        now_us: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Action, Error> {
        if join.request.pmf().is_some() {
            return Err(Error::Unsupported(
                "PMF requires original native observation/OS authority",
            ));
        }
        self.begin_modern_inner(join, beacon, now_us, policy)
    }
    pub(in crate::net::wifi) fn begin_modern_pmf(
        &mut self,
        join: Join,
        observed: Arc<NativeBssObservation>,
        now_us: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Action, Error> {
        if join.request.pmf().is_none() {
            return Err(Error::Unsupported("selected PMF request required"));
        }
        let action = self.begin_modern_inner(join, observed.bss.clone(), now_us, policy)?;
        self.pmf_observation = Some(observed);
        Ok(action)
    }
    fn begin_modern_inner(
        &mut self,
        join: Join,
        beacon: super::scan::result::Bss,
        now_us: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Action, Error> {
        let selection = join
            .request
            .modern()
            .ok_or(Error::Unsupported("modern request required"))?;
        if selection.capabilities().band() != join.channel.band
            || beacon.channel != join.channel
            || beacon.bssid != join.bssid
            || beacon.transmitter != join.bssid
        {
            return Err(Error::Unsupported("selected beacon/local PHY mismatch"));
        }
        self.begin_inner(join, Some(beacon), now_us, policy)
    }

    pub(in crate::net::wifi) fn pmf_authentication(
        &self,
    ) -> Result<(Ticket, &Join, &Arc<NativeBssObservation>), Error> {
        if !matches!(self.phase, Phase::Authenticating | Phase::Associating) {
            return Err(Error::Stale);
        }
        let join = self.join.as_ref().ok_or(Error::Stale)?;
        if join.request.pmf().is_none() {
            return Err(Error::Stale);
        }
        Ok((
            self.pending.ok_or(Error::Stale)?.ticket,
            join,
            self.pmf_observation.as_ref().ok_or(Error::Stale)?,
        ))
    }

    /// Withdraw only this genuine first never-submitted PMF request. Native
    /// code calls this before its first peer/ROC/DMA mutation; it releases no
    /// hardware owner and supplies no retirement proof. Epochs are not reused.
    pub(in crate::net::wifi) fn withdraw_unsubmitted_pmf(
        &mut self,
        ticket: Ticket,
    ) -> Result<(), Error> {
        if self.phase != Phase::Authenticating
            || self.pending.is_none_or(|pending| {
                pending.ticket != ticket || pending.queued || pending.attempts != 1
            })
            || !self.requires_protected_management()
        {
            return Err(Error::Stale);
        }
        self.pending = None;
        self.join = None;
        self.selected_beacon = None;
        self.context = None;
        self.pmf_observation = None;
        self.phase = Phase::Idle;
        Ok(())
    }

    /// Identity preflight, not a publication lease. Native submission must also
    /// hold genuine current association/radio/regulatory guards through submit.
    pub fn validate_association_context(&self, context: &AssociationContext) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Configuring | Phase::Associated)
            || self
                .context
                .as_ref()
                .is_none_or(|current| !core::ptr::eq(current.as_ref(), context))
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// The channel the current association operates: its own, or where a
    /// channel switch moved it.
    pub fn operating_definition(&self) -> Option<operations::ChannelDefinition> {
        let context = self.context.as_ref()?;
        Some(match self.switched {
            Some((ticket, definition)) if ticket == context.ticket() => definition,
            _ => context.definition(),
        })
    }

    /// mac80211 `ieee80211_chswitch_done`: the associated `context` now
    /// operates `definition`, on the same band.
    pub fn switch_channel(
        &mut self,
        context: &AssociationContext,
        definition: operations::ChannelDefinition,
    ) -> Result<(), Error> {
        self.validate_association_context(context)?;
        if self.phase != Phase::Associated {
            return Err(Error::NotAssociated);
        }
        definition.validate().map_err(Error::Phy)?;
        if definition.control.band != context.channel().band {
            return Err(Error::Unsupported("channel switch to another band"));
        }
        self.switched = Some((context.ticket(), definition));
        Ok(())
    }

    pub fn association_context(&self) -> Option<&AssociationContext> {
        self.context
            .as_deref()
            .filter(|context| self.validate_association_context(context).is_ok())
    }

    fn begin_inner(
        &mut self,
        join: Join,
        beacon: Option<super::scan::result::Bss>,
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
        self.epoch = NEXT_ASSOCIATION.next().ok_or(Error::Overflow)?;
        self.serial = 0;
        self.join = Some(join);
        self.selected_beacon = beacon;
        self.context = None;
        self.pmf_observation = None;
        self.phase = Phase::Authenticating;
        match self.transmit(Phase::Authenticating, 1, policy) {
            Ok(action) => Ok(action),
            Err(error) => {
                self.phase = Phase::Idle;
                self.join = None;
                self.selected_beacon = None;
                self.context = None;
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
        if join.request.pmf().is_some() && super::security::management::robust(frame) {
            return Err(Error::Unsupported(
                "PMF requires authenticated management consumer",
            ));
        }
        if matches!(
            frame.header().control & TYPE_SUBTYPE,
            DISASSOCIATION | DEAUTHENTICATION
        ) {
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
                let context = if request.modern().is_some() {
                    let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
                    let beacon = self
                        .selected_beacon
                        .as_ref()
                        .ok_or(Error::Unsupported("selected beacon required"))?;
                    let context = if request.pmf().is_some() {
                        AssociationContext::build_with_native(
                            ticket,
                            join,
                            beacon,
                            &response,
                            self.pmf_observation.as_ref(),
                        )?
                    } else {
                        AssociationContext::build(ticket, join, beacon, &response)?
                    };
                    Some(Arc::new(context))
                } else {
                    None
                };
                self.context = context.clone();
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
                    context,
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
        if self.phase == Phase::ExternalAuthenticating
            && self
                .external
                .as_ref()
                .is_some_and(|session| self.now >= session.deadline())
        {
            return self.remove(Some(Failure::Timeout)).map(Some);
        }
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
                self.selected_beacon = None;
                self.context = None;
                self.pmf_observation = None;
                Phase::Idle
            }
            Completion::Uncertain => Phase::Quarantined,
        };
        Ok(())
    }

    pub(in crate::net::wifi) fn protected_port_authorized(&self) -> bool {
        self.requires_protected_management() && self.authorization.is_some()
    }

    pub fn requires_protected_management(&self) -> bool {
        self.join
            .as_ref()
            .is_some_and(|join| join.request.pmf().is_some())
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
        if self.requires_protected_management() {
            return Err(Error::Unsupported(
                "PMF requires current OS/key session authority",
            ));
        }
        self.authorize_port_keys(epoch, pairwise, group)
    }

    /// Internal native consumer: caller has validated the original current
    /// management Session and holds the genuine OS protected-port authority.
    pub(in crate::net::wifi) fn authorize_protected_port(
        &mut self,
        context: &AssociationContext,
        epoch: u64,
        pairwise: &KeySlot,
        group: &KeySlot,
    ) -> Result<(), Error> {
        self.validate_association_context(context)?;
        if context.pmf().is_none() {
            return Err(Error::Unsupported("no selected PMF policy"));
        }
        self.authorize_port_keys(epoch, pairwise, group)
    }

    fn authorize_port_keys(
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
        if ptk.nonce_owner() == super::security::NonceOwner::ReceiveOnly {
            return Err(Error::WrongKey);
        }
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
            // Accepted removal includes every actual BA/reorder/deferred user.
            self.rx_ba = ba::Sessions::new();
            self.tx_ba = ba::tx::Sessions::new();
            self.qos_sequence = [0; 16];
            self.join = None;
            self.external = None;
            self.selected_beacon = None;
            self.context = None;
            self.pmf_observation = None;
            Phase::Idle
        } else {
            Phase::Quarantined
        };
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::net::wifi::{
        Band, RadioStatus, RawRate,
        scan::result::{Bss, Kind},
        security::{Cipher, InstallOutcome, ReplaySeed, SecurityStatus},
        station::phy::{Mode, Width},
    };
    use alloc::vec;

    pub(crate) const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
    pub(crate) const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
    pub(crate) struct Policy(pub(crate) bool);
    impl RegulatoryPolicy for Policy {
        fn allow_management_tx(&mut self, _: Channel) -> bool {
            self.0
        }
        fn allow_data_tx(&mut self, _: Channel) -> bool {
            self.0
        }
    }
    pub(crate) fn join(policy: PortPolicy) -> Join {
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
    pub(crate) fn ticket(action: &Action) -> Ticket {
        match action {
            Action::Transmit { ticket, .. }
            | Action::Configure { ticket, .. }
            | Action::Remove { ticket, .. } => *ticket,
        }
    }
    pub(crate) fn response(control: u16, body: &[u8]) -> Mpdu {
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
                rx_rate: None,
                tsf: None,
            },
            SecurityStatus::default(),
        )
        .unwrap()
    }
    pub(crate) fn configure(station: &mut Station, policy: PortPolicy) -> Ticket {
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
    pub(crate) fn key(slot: u16, scope: KeyScope) -> KeySlot {
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
                if matches!(scope, KeyScope::Pairwise(_)) {
                    crate::net::wifi::security::TransmitSeed::FIRMWARE_FRESH
                } else {
                    crate::net::wifi::security::TransmitSeed::RECEIVE_ONLY
                },
            )
            .unwrap();
        key.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        key
    }
    pub(crate) fn broadcast(frame: Mpdu) -> Mpdu {
        let mut bytes = frame.bytes().to_vec();
        bytes[4..10].copy_from_slice(&Mac::BROADCAST.0);
        Mpdu::new(bytes, frame.radio, frame.security).unwrap()
    }
    pub(crate) fn ie(out: &mut Vec<u8>, id: u8, b: &[u8]) {
        out.extend_from_slice(&[id, b.len() as u8]);
        out.extend_from_slice(b);
    }
    pub(crate) fn extension(out: &mut Vec<u8>, id: u8, b: &[u8]) {
        let mut v = vec![id];
        v.extend_from_slice(b);
        ie(out, 255, &v);
    }
    impl crate::net::wifi::scan::Policy for Policy {
        fn allow_receive(&mut self, _: Channel) -> bool {
            self.0
        }
        fn allow_probe(&mut self, _: Channel) -> bool {
            self.0
        }
        fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
            Some(Channel {
                band,
                number,
                frequency_mhz: 5180,
            })
        }
    }
    pub(crate) fn modern_ies(ap: bool) -> Vec<u8> {
        let mut out = vec![0, 1, b'x', 1, 3, 0x8c, 0x98, 0xb0];
        let mut ht = [0; 26];
        ht[0] = 2;
        ht[2] = 3;
        ht[3] = 0xff;
        ht[15] = 1;
        ie(&mut out, 45, &ht);
        let mut vht = [0; 12];
        vht[..4].copy_from_slice(&4_u32.to_le_bytes());
        vht[4..6].copy_from_slice(&0xfffe_u16.to_le_bytes());
        vht[8..10].copy_from_slice(&0xfffe_u16.to_le_bytes());
        ie(&mut out, 191, &vht);
        let mut he = vec![0; 17];
        he[6] = 12;
        for _ in 0..2 {
            he.extend_from_slice(&[0xfe, 0xff, 0xfe, 0xff]);
        }
        extension(&mut out, 35, &he);
        let mut eht = vec![0; 11];
        eht.extend_from_slice(&[0x11; 6]);
        extension(&mut out, 108, &eht);
        if ap {
            ie(
                &mut out,
                221,
                &[
                    0, 0x50, 0xf2, 2, 1, 1, 0x80, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43,
                    94, 0, 0x62, 0x32, 47, 0,
                ],
            );
            let mut ht_op = [0; 22];
            ht_op[0] = 36;
            ht_op[1] = 5;
            ht_op[2] = 3;
            ie(&mut out, 61, &ht_op);
            ie(&mut out, 192, &[1, 42, 0, 0xff, 0xff]);
            extension(&mut out, 36, &[3, 0x20, 0, 0x2a, 0xff, 0xff]);
            extension(&mut out, 106, &[1, 0, 0, 0, 0, 2, 42, 0]);
            ie(&mut out, 5, &[0, 3, 0, 0]);
        } else {
            ie(&mut out, 221, &[0, 0x50, 0xf2, 2, 0, 1, 0]);
        }
        out
    }
    pub(crate) fn modern_join() -> Join {
        let mut j = join(PortPolicy::Open);
        j.request = wire::AssociationRequest::new_modern(
            1,
            10,
            modern_ies(false),
            Band::Ghz5,
            Mode::Eht,
            Width::Mhz80,
        )
        .unwrap();
        j
    }
    pub(crate) fn beacon(j: &Join) -> Bss {
        let scan = crate::net::wifi::scan::Scanner::new(LOCAL)
            .unwrap()
            .begin(
                crate::net::wifi::scan::Request::new(vec![j.channel], vec![], vec![]).unwrap(),
                0,
                100,
                &mut Policy(true),
            )
            .unwrap();
        Bss {
            ticket: scan,
            kind: Kind::Beacon,
            bssid: AP,
            transmitter: AP,
            timestamp: 100,
            beacon_interval: 100,
            capabilities: 1,
            channel: j.channel,
            observed: response(0xb0, &[0; 6]).radio,
            signal_dbm: Some(-45),
            ssid: Some(vec![b'x']),
            elements: modern_ies(true),
        }
    }
    pub(crate) fn configuration(s: &mut Station, j: Join, bss: Bss) -> Result<Action, Error> {
        let start = s.now;
        let a = s.begin_modern(j, bss, start, &mut Policy(true))?;
        s.submitted(ticket(&a))?;
        let a = s.receive(
            s.association_epoch().unwrap(),
            &response(0xb0, &[0, 0, 2, 0, 0, 0]),
            start + 1,
            &mut Policy(true),
        )?;
        s.submitted(ticket(&a))?;
        let mut body = vec![1, 0, 0, 0, 1, 0xc0];
        body.extend_from_slice(&modern_ies(true));
        s.receive(
            s.association_epoch().unwrap(),
            &response(0x10, &body),
            start + 2,
            &mut Policy(true),
        )
    }
    pub(crate) fn response_metadata(elements: Vec<u8>) -> wire::AssociationResponse {
        wire::AssociationResponse {
            capabilities: 1,
            status: 0,
            raw_aid: 0xc001,
            aid: 1,
            power_save_allowed: true,
            elements,
        }
    }
    pub(crate) fn filtered(mut bytes: &[u8], remove: impl Fn(u8, &[u8]) -> bool) -> Vec<u8> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let length = usize::from(bytes[1]);
            let b = &bytes[2..2 + length];
            if !remove(bytes[0], b) {
                out.extend_from_slice(&bytes[..2 + length]);
            }
            bytes = &bytes[2 + length..];
        }
        out
    }
    pub(crate) fn edit_elements(mut bytes: &mut [u8], mut edit: impl FnMut(u8, &mut [u8])) {
        while !bytes.is_empty() {
            let n = usize::from(bytes[1]);
            let id = bytes[0];
            edit(id, &mut bytes[2..2 + n]);
            bytes = &mut bytes[2 + n..];
        }
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

    #[test]
    fn broadcast_ap_departures_close_authorized_controlled_port() {
        for subtype in [0xa0, 0xc0] {
            let mut station = Station::new(LOCAL).unwrap();
            let config = configure(&mut station, PortPolicy::Controlled);
            station
                .complete_configuration(config, Completion::Accepted, 4)
                .unwrap();
            let ptk = key(1, KeyScope::Pairwise(AP));
            let gtk = key(2, KeyScope::Group(AP));
            station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
            assert!(station.port_open(Some(&ptk), Some(&gtk)));
            let action = station
                .receive(
                    config.epoch(),
                    &broadcast(response(subtype, &[3, 0])),
                    5,
                    &mut Policy(true),
                )
                .unwrap();
            assert!(matches!(
                action,
                Action::Remove {
                    failure: Some(Failure::PeerDeparture(3)),
                    ..
                }
            ));
            assert_eq!(station.phase(), Phase::Disconnecting);
            assert!(!station.port_open(Some(&ptk), Some(&gtk)));
        }
    }

    #[test]
    fn broadcast_departure_from_wrong_ap_does_not_close_port() {
        for subtype in [0xa0, 0xc0] {
            let mut station = Station::new(LOCAL).unwrap();
            let config = configure(&mut station, PortPolicy::Controlled);
            station
                .complete_configuration(config, Completion::Accepted, 4)
                .unwrap();
            let ptk = key(1, KeyScope::Pairwise(AP));
            let gtk = key(2, KeyScope::Group(AP));
            station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
            for offset in [10, 16] {
                let frame = broadcast(response(subtype, &[3, 0]));
                let mut bytes = frame.bytes().to_vec();
                bytes[offset] ^= 2;
                let wrong = Mpdu::new(bytes, frame.radio, frame.security).unwrap();
                assert!(matches!(
                    station.receive(config.epoch(), &wrong, 5, &mut Policy(true)),
                    Err(Error::Wire(wire::Error::WrongPeer))
                ));
                assert!(station.port_open(Some(&ptk), Some(&gtk)));
            }
        }
    }

    #[test]
    fn broadcast_authentication_and_association_responses_are_not_accepted() {
        let mut station = Station::new(LOCAL).unwrap();
        let auth = station
            .begin(join(PortPolicy::Open), 0, &mut Policy(true))
            .unwrap();
        station.submitted(ticket(&auth)).unwrap();
        let epoch = ticket(&auth).epoch();
        assert!(matches!(
            station.receive(
                epoch,
                &broadcast(response(0xb0, &[0, 0, 2, 0, 0, 0])),
                1,
                &mut Policy(true)
            ),
            Err(Error::Wire(wire::Error::WrongPeer))
        ));
        assert_eq!(station.phase(), Phase::Authenticating);
        let assoc = station
            .receive(
                epoch,
                &response(0xb0, &[0, 0, 2, 0, 0, 0]),
                2,
                &mut Policy(true),
            )
            .unwrap();
        station.submitted(ticket(&assoc)).unwrap();
        assert!(matches!(
            station.receive(
                epoch,
                &broadcast(response(
                    0x10,
                    &[1, 0, 0, 0, 7, 0xc0, 1, 3, 0x8c, 0x98, 0xb0]
                )),
                3,
                &mut Policy(true)
            ),
            Err(Error::Wire(wire::Error::WrongPeer))
        ));
        assert_eq!(station.phase(), Phase::Associating);
        assert!(!station.port_open(None, None));
    }

    #[test]
    fn receive_only_pairwise_key_cannot_authorize_a_data_port() {
        use crate::net::wifi::security::{NonceOwner, TransmitSeed};
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Controlled);
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        let mut ptk = unsafe { KeySlot::new(1).unwrap() };
        let ticket = ptk
            .begin_install(
                0,
                Cipher::Ccmp128,
                &[1; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(AP),
                TransmitSeed::RECEIVE_ONLY,
            )
            .unwrap();
        ptk.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        assert_eq!(
            ptk.installed().unwrap().nonce_owner(),
            NonceOwner::ReceiveOnly
        );
        let gtk = key(2, KeyScope::Group(AP));
        assert_eq!(
            station.authorize_port(config.epoch(), &ptk, &gtk),
            Err(Error::WrongKey)
        );
        assert!(!station.port_open(Some(&ptk), Some(&gtk)));
    }

    #[test]
    fn host_nonce_exhaustion_closes_a_previously_authorized_data_port() {
        use crate::net::wifi::security::{PacketNumber, TransmitSeed};
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Controlled);
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        let mut ptk = unsafe { KeySlot::new(1).unwrap() };
        let ticket = ptk
            .begin_install(
                0,
                Cipher::Ccmp128,
                &[1; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(AP),
                TransmitSeed::host(PacketNumber::new((1_u64 << 48) - 2).unwrap()),
            )
            .unwrap();
        ptk.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        let identity = ptk.installed().unwrap();
        let gtk = key(2, KeyScope::Group(AP));
        station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
        assert!(station.port_open(Some(&ptk), Some(&gtk)));
        assert!(ptk.reserve_host_tx_nonce(identity).is_ok());
        assert!(ptk.reserve_host_tx_nonce(identity).is_err());
        assert!(!station.port_open(Some(&ptk), Some(&gtk)));
    }

    #[test]
    fn modern_configuration_is_retained_bound_and_invalidated_before_removal() {
        let mut s = Station::new(LOCAL).unwrap();
        let j = modern_join();
        assert!(matches!(
            s.begin(j.clone(), 0, &mut Policy(true)),
            Err(Error::Unsupported(_))
        ));
        let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
        let Action::Configure {
            ticket,
            context: Some(context),
            ..
        } = a
        else {
            panic!("modern context required")
        };
        assert_eq!(context.ticket(), ticket);
        assert_eq!(context.bssid(), AP);
        assert_eq!(context.definition().center1_mhz, 5210);
        assert_eq!(context.definition().width, Width::Mhz80);
        assert_eq!(context.dtim_period(), 3);
        assert_eq!(context.negotiated().mode, Mode::Eht);
        assert_eq!(context.operations().ht.as_ref().unwrap().protection, 3);
        let he = context.operations().he.as_ref().unwrap();
        assert_eq!(
            (he.packet_extension(), he.rts_threshold(), he.color()),
            (3, 512, 42)
        );
        s.validate_association_context(&context).unwrap();
        s.complete_configuration(ticket, Completion::Accepted, 3)
            .unwrap();
        s.validate_association_context(&context).unwrap();
        let removal = s.disconnect().unwrap();
        assert!(s.validate_association_context(&context).is_err());
        assert!(s.association_context().is_none());
        s.complete_removal(tests::ticket(&removal), Completion::Accepted)
            .unwrap();
        let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
        let Action::Configure {
            context: Some(next),
            ..
        } = a
        else {
            panic!()
        };
        assert_ne!(next.ticket().epoch(), context.ticket().epoch());
        assert!(s.validate_association_context(&context).is_err());
        s.validate_association_context(&next).unwrap();
    }
    #[test]
    fn modern_uncertainty_retains_configuration_but_never_usable_identity() {
        let mut s = Station::new(LOCAL).unwrap();
        let j = modern_join();
        let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
        let Action::Configure {
            ticket,
            context: Some(context),
            ..
        } = a
        else {
            panic!()
        };
        s.complete_configuration(ticket, Completion::Uncertain, 3)
            .unwrap();
        assert!(s.association_context().is_none());
        assert!(s.validate_association_context(&context).is_err());
        assert!(s.context.is_some());
        assert!(!s.port_open(None, None));
        assert!(matches!(
            s.begin_modern(j.clone(), beacon(&j), 4, &mut Policy(true)),
            Err(Error::Busy)
        ));
    }
    #[test]
    fn selected_beacon_timing_peer_ssid_and_width_are_required_not_defaulted() {
        let j = modern_join();
        for damage in 0..6 {
            let mut b = beacon(&j);
            match damage {
                0 => b.beacon_interval = 0,
                1 => b.kind = Kind::ProbeResponse,
                2 => b.ssid = Some(vec![b'y']),
                3 => b.elements.truncate(b.elements.len() - 6),
                4 => {
                    let n = b.elements.len();
                    b.elements[n - 3] = 0;
                }
                _ => b.transmitter = LOCAL,
            }
            assert!(
                configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), b).is_err(),
                "damage {damage}"
            );
        }
        let mut j = modern_join();
        j.request = wire::AssociationRequest::new_modern(
            1,
            10,
            modern_ies(false),
            Band::Ghz5,
            Mode::Eht,
            Width::Mhz160,
        )
        .unwrap();
        assert!(configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), beacon(&j)).is_err());
    }

    #[test]
    fn admission_controlled_categories_downgrade_like_ieee80211_downgrade_queue() {
        let j = modern_join();
        let b = beacon(&j);
        // Voice and video require admission control.
        let mut elements = modern_ies(true);
        let mut at = 0;
        while at + 2 <= elements.len() {
            let len = usize::from(elements[at + 1]);
            if elements[at] == 221 && elements[at + 2..at + 6] == [0, 0x50, 0xf2, 2] {
                for record in (at + 10..at + 2 + len).step_by(4) {
                    if (elements[record] >> 5) & 3 >= 2 {
                        elements[record] |= 0x10;
                    }
                }
            }
            at += 2 + len;
        }
        let ticket = Ticket {
            epoch: 1,
            serial: 2,
        };
        let context =
            AssociationContext::build(ticket, &j, &b, &response_metadata(elements)).unwrap();
        let mut ef = vec![0; 34];
        ef[12..16].copy_from_slice(&[8, 0, 0x45, 46 << 2]);
        let mut eapol = vec![0; 14];
        eapol[12..].copy_from_slice(&[0x88, 0x8e]);
        let mut cs1 = ef.clone();
        cs1[15] = 8 << 2;
        assert_eq!(
            [&ef, &eapol, &cs1].map(|frame| data::data_tid(&context, None, frame)),
            [Some(3), Some(3), Some(1)]
        );
    }

    #[test]
    fn generic_missing_ht_vht_wmm_fallback_retains_actual_beacon_but_not_he_eht() {
        let j = modern_join();
        let b = beacon(&j);
        let elements = filtered(&modern_ies(true), |id, _| {
            matches!(id, 45 | 61 | 191 | 192 | 221)
        });
        let response = response_metadata(elements);
        let context = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response,
        )
        .unwrap();
        assert!(context.negotiated().wmm.is_some());
        assert!(context.operations().ht.is_some());
        assert_eq!(context.response().elements, response.elements);
        for id in [35, 36, 106, 108] {
            let elements = filtered(&modern_ies(true), |other, b| other == 255 && b[0] == id);
            assert!(
                AssociationContext::build(
                    Ticket {
                        epoch: 1,
                        serial: 2
                    },
                    &j,
                    &b,
                    &response_metadata(elements)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn normal_basic_rules_keep_he_eht_and_real_rates_but_not_strict_only_ht_checks() {
        let j = modern_join();
        let b = beacon(&j);
        for kind in 0..4 {
            let mut bytes = modern_ies(true);
            let mut rest = bytes.as_mut_slice();
            while !rest.is_empty() {
                let length = usize::from(rest[1]);
                let id = rest[0];
                let data = &mut rest[2..2 + length];
                match kind {
                    0 if id == 1 => data[1] &= 0x7f,
                    1 if id == 61 => data[7] = 1,
                    2 if id == 255 && data[0] == 36 => {
                        data[5] = 0xf0;
                        data[6] = 0xff;
                    }
                    3 if id == 255 && data[0] == 106 => data[2] = 2,
                    _ => (),
                }
                rest = &mut rest[2 + length..];
            }
            assert_eq!(
                AssociationContext::build(
                    Ticket {
                        epoch: 1,
                        serial: 2
                    },
                    &j,
                    &b,
                    &response_metadata(bytes)
                )
                .is_ok(),
                kind == 1,
                "kind{kind}"
            );
        }
    }

    #[test]
    fn final_vht_operation_uses_actual_source_capability_width_not_raw_segments_alone() {
        let mut j = modern_join();
        j.request = wire::AssociationRequest::new_modern(
            1,
            10,
            modern_ies(false),
            Band::Ghz5,
            Mode::He,
            Width::Mhz160,
        )
        .unwrap();
        let mut b = beacon(&j);
        let mut elements = modern_ies(true);
        for bytes in [&mut b.elements, &mut elements] {
            let mut rest = bytes.as_mut_slice();
            while !rest.is_empty() {
                let n = usize::from(rest[1]);
                if rest[0] == 191 {
                    rest[2..6].copy_from_slice(&0_u32.to_le_bytes());
                }
                if rest[0] == 192 {
                    rest[4] = 50;
                } // raw ccfs1 suggests160, source ignores it for peer width0.
                rest = &mut rest[2 + n..];
            }
        }
        assert!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(elements)
            )
            .is_err()
        );
    }

    #[test]
    fn review_eht_basic_mcs_cannot_ignore_advertised_wider_local_map() {
        let mut local = modern_ies(false);
        let mutate = |bytes: &mut Vec<u8>, own: bool| {
            let mut at = 0;
            while at < bytes.len() {
                let len = usize::from(bytes[at + 1]);
                let id = bytes[at];
                let b = &mut bytes[at + 2..at + 2 + len];
                if id == 255 && b[0] == 108 {
                    b[12..15].fill(0x22);
                    b[15..18].fill(if own { 0x11 } else { 0x22 });
                }
                if id == 255 && b[0] == 106 {
                    b[2..6].fill(0x22);
                }
                at += 2 + len;
            }
        };
        mutate(&mut local, true);
        let mut j = modern_join();
        j.request =
            wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, Mode::Eht, Width::Mhz80)
                .unwrap();
        let mut b = beacon(&j);
        mutate(&mut b.elements, false);
        let mut elements = modern_ies(true);
        mutate(&mut elements, false);
        let result = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(elements),
        );
        assert!(
            result.is_err(),
            "local advertised160 map fails actual EHT basic2NSS even when selected80 passes, got {result:?}"
        );
    }

    #[test]
    fn basic_eht_local_rx_tx_orientation_is_not_selected_common_orientation() {
        fn maps(bytes: &mut [u8], cap: u8, basic: u8) {
            let mut at = 0;
            while at < bytes.len() {
                let n = usize::from(bytes[at + 1]);
                let id = bytes[at];
                let b = &mut bytes[at + 2..at + 2 + n];
                if id == 255 && b[0] == 108 {
                    b[12..].fill(cap);
                }
                if id == 255 && b[0] == 106 {
                    b[2..6].fill(basic);
                }
                at += 2 + n;
            }
        }
        let mut own = modern_ies(false);
        maps(&mut own, 0x12, 0);
        let mut j = modern_join();
        j.request =
            wire::AssociationRequest::new_modern(1, 10, own, Band::Ghz5, Mode::Eht, Width::Mhz80)
                .unwrap();
        for (basic, accepted) in [(0x12, true), (0x21, false)] {
            let mut beacon = beacon(&j);
            maps(&mut beacon.elements, 0x22, basic);
            let mut response = modern_ies(true);
            maps(&mut response, 0x22, basic);
            let result = AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2,
                },
                &j,
                &beacon,
                &response_metadata(response),
            );
            assert_eq!(result.is_ok(), accepted, "basic {basic:#x}: {result:?}");
        }
    }

    #[test]
    fn unselected_ap_mlo_never_changes_single_link_context_bssid_or_outgoing_request() {
        let j = modern_join();
        let mut b = beacon(&j);
        let baseline = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(modern_ies(true)),
        )
        .unwrap();
        let mut raw = Vec::new();
        extension(&mut raw, 107, &[0, 0, 7, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        b.elements.extend_from_slice(&raw);
        let mut response = modern_ies(true);
        response.extend_from_slice(&raw);
        let c = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(response),
        )
        .unwrap();
        assert_eq!(c.intent(), AssociationIntent::SingleLink);
        assert_eq!(c.bssid(), AP);
        assert_eq!(c.definition(), baseline.definition());
        assert_eq!(c.negotiated().eht, baseline.negotiated().eht);
        assert_eq!(c.negotiated().peer().unselected_multi_link_elements(), raw);
        assert!(
            j.request
                .modern()
                .unwrap()
                .capabilities()
                .unselected_multi_link_elements()
                .is_empty()
        );
        assert_eq!(j.request.elements(), modern_ies(false));
        let mut requested = modern_ies(false);
        requested.extend_from_slice(&raw);
        assert!(matches!(
            wire::AssociationRequest::new_modern(
                1,
                10,
                requested,
                Band::Ghz5,
                Mode::Eht,
                Width::Mhz80
            ),
            Err(wire::Error::Unsupported(_))
        ));
    }
    #[test]
    fn malformed_unselected_ml_body_and_fragment_cannot_replace_single_link_operation() {
        let j = modern_join();
        let mut b = beacon(&j);
        let mut response = modern_ies(true);
        let mut body = vec![0; 254];
        body[..3].copy_from_slice(&[7, 0, 255]);
        let mut raw = Vec::new();
        extension(&mut raw, 107, &body);
        ie(&mut raw, 242, &[61, 2, 149, 3, 192, 3, 3, 155, 171]);
        b.elements.extend_from_slice(&raw);
        response.extend_from_slice(&raw);
        let c = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(response),
        )
        .unwrap();
        assert_eq!(c.intent(), AssociationIntent::SingleLink);
        assert_eq!(c.bssid(), AP);
        assert_eq!(c.channel().number, 36);
        assert_eq!(c.definition().center1_mhz, 5210);
        assert_eq!(c.negotiated().peer().unselected_multi_link_elements(), raw);
    }

    #[test]
    fn review_source_eht_basic_local_support_does_not_require_peer_common_envelope() {
        let mutate = |bytes: &mut Vec<u8>, own: bool| {
            let mut at = 0;
            while at < bytes.len() {
                let len = usize::from(bytes[at + 1]);
                let id = bytes[at];
                let b = &mut bytes[at + 2..at + 2 + len];
                if id == 255 && b[0] == 108 {
                    b[12..18].fill(if own { 0x22 } else { 0x12 });
                }
                if id == 255 && b[0] == 106 {
                    b[2..6].fill(0x22);
                }
                at += 2 + len;
            }
        };
        let mut local = modern_ies(false);
        mutate(&mut local, true);
        let mut j = modern_join();
        j.request =
            wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, Mode::Eht, Width::Mhz80)
                .unwrap();
        assert!(
            j.request
                .modern()
                .unwrap()
                .capabilities()
                .meets_eht_basic([0x22; 4])
        );
        let mut b = beacon(&j);
        mutate(&mut b.elements, false);
        let mut elements = modern_ies(true);
        mutate(&mut elements, false);
        let peer = phy::Capabilities::parse(Band::Ghz5, phy::Role::AccessPoint, &elements).unwrap();
        let n = phy::Negotiated::between(
            j.request.modern().unwrap().capabilities(),
            &peer,
            Mode::Eht,
            Width::Mhz80,
        )
        .unwrap();
        assert!(n.rx_nss > 0 && n.tx_nss > 0);
        let result = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(elements),
        );
        assert!(
            result.is_ok(),
            "source local requirement passes; usable asymmetric common envelope is not a second Basic predicate: {result:?}"
        );
    }

    #[test]
    fn default_ht_vht_basic_claims_remain_raw_without_rejecting_usable_profiles() {
        for (mode, width) in [(Mode::Ht, Width::Mhz40), (Mode::Vht, Width::Mhz80)] {
            for basic in [0, 0x5555_u16, 0xffff] {
                let mut j = modern_join();
                j.request = wire::AssociationRequest::new_modern(
                    1,
                    10,
                    modern_ies(false),
                    Band::Ghz5,
                    mode,
                    width,
                )
                .unwrap();
                let mut b = beacon(&j);
                let mut response = modern_ies(true);
                for bytes in [&mut b.elements, &mut response] {
                    edit_elements(bytes, |id, data| {
                        if id == 61 {
                            data[6..16].fill(0xff);
                        }
                        if id == 192 {
                            data[3..5].copy_from_slice(&basic.to_le_bytes());
                        }
                    });
                }
                let c = AssociationContext::build(
                    Ticket {
                        epoch: 1,
                        serial: 2,
                    },
                    &j,
                    &b,
                    &response_metadata(response),
                )
                .unwrap();
                assert_eq!(c.negotiated().mode, mode);
                assert_eq!(c.definition().width, width);
                assert!(c.negotiated().rx_nss > 0 && c.negotiated().tx_nss > 0);
                assert_eq!(
                    &c.operations().ht.as_ref().unwrap().basic_mcs[..10],
                    &[0xff; 10]
                );
                assert_eq!(c.operations().vht.as_ref().unwrap().basic_mcs, basic);
            }
        }
    }
    #[test]
    fn zero_he_basic_compatibility_cannot_invent_streams_or_bypass_peer_one_ss() {
        let j = modern_join();
        let b = beacon(&j);
        let mut response = modern_ies(true);
        edit_elements(&mut response, |id, data| {
            if id == 255 && data[0] == 36 {
                data[5..7].fill(0);
            }
        });
        let c = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(response.clone()),
        )
        .unwrap();
        assert_eq!((c.negotiated().rx_nss, c.negotiated().tx_nss), (1, 1));
        assert_eq!(c.operations().he.as_ref().unwrap().basic_mcs, 0);
        for start in [18, 20] {
            let mut broken = response.clone();
            edit_elements(&mut broken, |id, data| {
                if id == 255 && data[0] == 35 {
                    data[start..start + 2].fill(0xff);
                }
            });
            assert!(
                AssociationContext::build(
                    Ticket {
                        epoch: 1,
                        serial: 2
                    },
                    &j,
                    &b,
                    &response_metadata(broken)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn full_local_he_source_slots_are_explicit_and_preserve_normal_one_width_semantics() {
        let own = modern_ies(false);
        let local = phy::Capabilities::parse(Band::Ghz5, phy::Role::Station, &own).unwrap();
        let he = local.he().unwrap();
        let m = he.mcs_80;
        let source = [m, he.mcs_160.unwrap(), phy::McsMaps { rx: 0, tx: 0 }];
        assert_eq!(he.mcs_80p80, None);
        assert_eq!(local.local_he_source_maps(), None);
        let mut j = modern_join();
        let mut b = beacon(&j);
        let mut response = modern_ies(true);
        for bytes in [&mut b.elements, &mut response] {
            edit_elements(bytes, |id, data| {
                if id == 255 && data[0] == 35 {
                    data[18..22].copy_from_slice(&[0xf0, 0xff, 0xf0, 0xff]);
                }
                if id == 255 && data[0] == 36 {
                    data[5..7].copy_from_slice(&0xfff0_u16.to_le_bytes());
                }
            });
        }
        let result = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(response.clone()),
        );
        assert!(matches!(
            result,
            Err(Error::Phy(phy::Error::Missing(
                "complete local HE source MCS slots"
            )))
        ));
        let local = local.with_local_he_source_maps(source).unwrap();
        let mut changed = own.clone();
        edit_elements(&mut changed, |id, b| {
            if id == 45 {
                b[0] ^= 1;
            }
        });
        assert!(
            wire::AssociationRequest::new_modern_with_local(
                1,
                10,
                changed,
                local.clone(),
                Mode::Eht,
                Width::Mhz80
            )
            .is_err()
        );
        j.request = wire::AssociationRequest::new_modern_with_local(
            1,
            10,
            own,
            local,
            Mode::Eht,
            Width::Mhz80,
        )
        .unwrap();
        let c = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &b,
            &response_metadata(response),
        )
        .unwrap();
        assert_eq!(c.negotiated().local().local_he_source_maps(), Some(&source));
        assert_eq!(c.negotiated().local().he().unwrap().mcs_80p80, None);
        assert_eq!((c.negotiated().rx_nss, c.negotiated().tx_nss), (1, 1));
    }

    #[test]
    fn transmitted_bssid_ignores_opaque_nested_profiles_and_keeps_outer_facts() {
        let j = modern_join();
        let mut bss = beacon(&j);
        let mut nested = vec![1, 0, 25]; // max indicator, opaque subelement
        ie(&mut nested, 83, &[0x11, 0]);
        ie(&mut nested, 0, b"other");
        ie(&mut nested, 85, &[1, 9, 8]);
        ie(&mut nested, 3, &[149]);
        ie(&mut nested, 48, &[1, 0, 0, 0]);
        ie(&mut bss.elements, 71, &nested);
        // An invalid inner subelement still cannot become profile authority.
        ie(&mut bss.elements, 71, &[255, 0, 255]);
        let raw = bss.elements.clone();
        let mut station = Station::new(LOCAL).unwrap();
        let Action::Configure {
            context: Some(c), ..
        } = configuration(&mut station, j.clone(), bss).unwrap()
        else {
            panic!("modern context")
        };
        assert_eq!(c.bssid(), j.bssid);
        assert_eq!(c.beacon().transmitter, j.bssid);
        assert_eq!(c.beacon().ssid, Some(vec![b'x']));
        assert_eq!(c.beacon().capabilities, 1);
        assert_eq!(c.beacon().elements, raw);
        assert_eq!((c.dtim_count(), c.dtim_period()), (0, 3));
        assert_eq!(c.channel(), j.channel);
        assert_eq!(c.definition().center1_mhz, 5210);
        assert_eq!(c.operations().ht.as_ref().unwrap().primary, 36);
    }

    #[test]
    fn transmitted_bssid_retains_outer_bounds_and_refuses_profile_selection() {
        let j = modern_join();
        let mut bss = beacon(&j);
        bss.elements.extend_from_slice(&[71, 5, 1]);
        assert!(configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), bss).is_err());
        let mut bss = beacon(&j);
        ie(&mut bss.elements, 85, &[1, 9, 8]);
        assert!(matches!(
            configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), bss),
            Err(Error::Unsupported(_))
        ));
        let mut bss = beacon(&j);
        bss.transmitter = Mac([4; 6]);
        ie(&mut bss.elements, 71, &[1]);
        assert!(matches!(
            configuration(&mut Station::new(LOCAL).unwrap(), j, bss),
            Err(Error::Unsupported(_))
        ));
    }
}
