// SPDX-License-Identifier: GPL-2.0-only
// SAE authentication transport follows Linux net/mac80211/{mlme,util}.c;
// source notices and pin are retained in wifi/THIRD_PARTY.md.
//! Bounded OS-supplicant SAE transport. Commit/confirm/token/group/H2E bytes
//! remain opaque to this layer; as `ieee80211_rx_mgmt_auth` does, it follows
//! only the exchange's order and status codes, so the AP's successful confirm
//! of the station's confirm marks the exchange authenticated. That authorizes
//! no key. Session identity binds the complete exchange, including delayed OS
//! replies.

use super::*;

/// One OS-produced SAE transmit frame. Consumers validate their session and
/// authority before serializing these named fields and opaque payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub transaction: u16,
    pub status: u16,
    pub data: &'a [u8],
}

const SAE: u16 = 3;
/// The longest exchange an OS may reserve: room for each frame of a commit,
/// token retry and confirm to take IEEE80211_AUTH_MAX_TRIES tries of
/// IEEE80211_AUTH_TIMEOUT_SAE, which mac80211 bounds only per frame.
const MAX_EXCHANGE_US: u64 = 30_000_000;
/// IEEE80211_AUTH_WAIT_ASSOC: an authenticated exchange waits this long for
/// its association.
const WAIT_ASSOCIATION_US: u64 = 5_000_000;
/// IEEE80211_AUTH_WAIT_SAE_RETRY: a status asking for another commit waits
/// this long for the OS's retry.
const WAIT_RETRY_US: u64 = 2_000_000;
/// IEEE80211_AUTH_TIMEOUT_LONG: a sent frame waits this long for its TX
/// status, IEEE80211_AUTH_TIMEOUT_SAE this long for the AP once acked.
const WAIT_STATUS_US: u64 = 500_000;
const WAIT_PEER_US: u64 = 2_000_000;
/// IEEE80211_AUTH_MAX_TRIES.
const MAX_TRIES: u8 = 3;
/// WLAN_STATUS_ANTI_CLOG_REQUIRED, _SAE_HASH_TO_ELEMENT and _SAE_PK.
const ANTI_CLOGGING: u16 = 76;
const HASH_TO_ELEMENT: u16 = 126;
const SAE_PK: u16 = 127;

/// The SAE progress `ieee80211_mgd_auth_data` keeps.
#[derive(Clone, Debug, Default)]
pub(super) struct Progress {
    /// `expected_transaction`: the transaction of the station's last frame.
    expected: u16,
    peer_confirmed: bool,
    /// `done`: authenticated, waiting for association.
    done: bool,
    denied: Option<u16>,
    deadline: u64,
    /// The OS's last frame (`trans`, `status`, `data`) and its `tries`.
    last: Option<(u16, u16, Vec<u8>)>,
    tries: u8,
    /// When that frame is sent again; `None` while `waiting` for the OS.
    retry: Option<u64>,
}
impl Progress {
    fn new(deadline: u64) -> Self {
        Self {
            expected: 1,
            deadline,
            ..Self::default()
        }
    }
    pub(super) const fn denied(&self) -> Option<u16> {
        self.denied
    }
    pub(super) const fn deadline(&self) -> u64 {
        self.deadline
    }
    /// `ieee80211_sta_work` on the last frame's TX status: the AP gets
    /// IEEE80211_AUTH_TIMEOUT_SAE to answer, and a lost frame goes again.
    pub(super) fn transmit_status(&mut self, acked: bool, now: u64) -> Result<(), Error> {
        if self.retry.is_some() && !self.done {
            self.retry = Some(if acked {
                now.checked_add(WAIT_PEER_US).ok_or(Error::Overflow)?
            } else {
                now
            });
        }
        Ok(())
    }
    /// Whether the last frame's tries ran out while it is due again.
    pub(super) fn exhausted(&self, now: u64) -> bool {
        !self.done && self.tries >= MAX_TRIES && self.retry.is_some_and(|retry| now >= retry)
    }
    /// `ieee80211_mark_sta_auth`.
    fn authenticated(&mut self, now: u64) -> Result<(), Error> {
        self.done = true;
        self.deadline = now
            .checked_add(WAIT_ASSOCIATION_US)
            .ok_or(Error::Overflow)?;
        Ok(())
    }
}
const AUTHENTICATION: u16 = 0x00b0;
const FIXED_BYTES: usize = 30;
// IEEE80211_MAX_DATA_LEN (2304), less the six fixed authentication bytes.
const MAX_AUTHENTICATION_DATA: usize = 2304 - 6;

/// Retained identity of one selected single-link authentication attempt.
/// No public constructor, mutation or conversion into association authority.
#[derive(Debug)]
pub struct Session {
    epoch: u64,
    local: Mac,
    peer: Mac,
    channel: Channel,
    ssid: Vec<u8>,
    deadline: u64,
    six_ghz: Option<SixGhzBinding>,
}
/// Original native inputs retained transitively by every actual packet Session.
#[derive(Debug)]
struct SixGhzBinding {
    observation: Arc<NativeBssObservation>,
    selection: wire::six_ghz::Selection,
    local: phy::Capabilities,
}
impl Session {
    pub fn six_ghz_observation(&self) -> Option<&Arc<NativeBssObservation>> {
        self.six_ghz.as_ref().map(|s| &s.observation)
    }
    pub fn six_ghz_selection(&self) -> Option<&wire::six_ghz::Selection> {
        self.six_ghz.as_ref().map(|s| &s.selection)
    }
    pub fn six_ghz_local_capabilities(&self) -> Option<&phy::Capabilities> {
        self.six_ghz.as_ref().map(|s| &s.local)
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn local(&self) -> Mac {
        self.local
    }
    pub const fn peer(&self) -> Mac {
        self.peer
    }
    pub const fn channel(&self) -> Channel {
        self.channel
    }
    pub fn ssid(&self) -> &[u8] {
        &self.ssid
    }
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }
}

/// Original RX bytes for the real OS supplicant. The native implementation
/// creates these only from its completed owned RX queue. This observation is
/// deliberately not a successful SAE result or a credential/key capability.
pub struct Received {
    session: Arc<Session>,
    frame: Mpdu,
}
impl Received {
    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }
    pub fn frame(&self) -> &Mpdu {
        &self.frame
    }
    pub fn transaction(&self) -> u16 {
        u16::from_le_bytes(self.frame.bytes()[26..28].try_into().unwrap())
    }
    pub fn status(&self) -> u16 {
        u16::from_le_bytes(self.frame.bytes()[28..30].try_into().unwrap())
    }
    pub fn data(&self) -> &[u8] {
        &self.frame.bytes()[FIXED_BYTES..]
    }
}

impl Station {
    /// Reserve an exchange for an actual OS-selected BSS. Native publication
    /// must additionally bind this to actual hardware/source/regulatory owners.
    /// The deadline covers OS computation as well as transport; repeated commits
    /// do not extend it. Only the OS's last frame is sent again, as
    /// `ieee80211_auth` retries it.
    pub fn begin_external_authentication(
        &mut self,
        peer: Mac,
        channel: Channel,
        ssid: Vec<u8>,
        now: u64,
        budget: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Arc<Session>, Error> {
        if self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        self.clock(now)?;
        if peer.is_multicast() || peer.0 == [0; 6] || peer == self.local {
            return Err(Error::InvalidAddress);
        }
        if channel.band == super::super::Band::Ghz6 {
            return Err(Error::Unsupported(
                "6GHz native authentication channel ownership",
            ));
        }
        if ssid.len() > 32 || budget == 0 || budget > MAX_EXCHANGE_US {
            return Err(Error::Wire(wire::Error::Invalid(
                "external authentication bounds",
            )));
        }
        if !policy.allow_management_tx(channel) {
            return Err(Error::Regulatory);
        }
        let deadline = now.checked_add(budget).ok_or(Error::Overflow)?;
        let epoch = NEXT_ASSOCIATION.next().ok_or(Error::Overflow)?;
        let session = Arc::new(Session {
            epoch,
            local: self.local,
            peer,
            channel,
            ssid,
            deadline,
            six_ghz: None,
        });
        self.epoch = epoch;
        self.serial = 0;
        self.external = Some(session.clone());
        self.sae = Progress::new(deadline);
        self.phase = Phase::ExternalAuthenticating;
        Ok(session)
    }

    /// CPU-only preparation for the sole native owner's dedicated guarded
    /// transport. This does not publish Station state or confer permission.
    pub(crate) fn prepare_six_ghz_authentication(
        &mut self,
        observation: Arc<NativeBssObservation>,
        selection: wire::six_ghz::Selection,
        local: phy::Capabilities,
        now: u64,
        budget: u64,
    ) -> Result<Arc<Session>, Error> {
        if self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        self.clock(now)?;
        let bss = observation.bss();
        if bss.channel.band != super::super::Band::Ghz6
            || bss.bssid.is_multicast()
            || bss.bssid.0 == [0; 6]
            || bss.bssid == self.local
            || bss.transmitter != bss.bssid
        {
            return Err(Error::InvalidAddress);
        }
        let ssid = bss
            .ssid
            .as_ref()
            .ok_or(Error::Wire(wire::Error::Invalid("6GHz SSID absent")))?;
        if ssid.len() > 32 || budget == 0 || budget > MAX_EXCHANGE_US {
            return Err(Error::Wire(wire::Error::Invalid(
                "external authentication bounds",
            )));
        }
        selection
            .validate_peer(&bss.elements)
            .map_err(Error::Wire)?;
        let channel = bss.channel;
        let peer = bss.bssid;
        let ssid = ssid.clone();
        Ok(Arc::new(Session {
            epoch: NEXT_ASSOCIATION.next().ok_or(Error::Overflow)?,
            local: self.local,
            peer,
            channel,
            ssid,
            deadline: now.checked_add(budget).ok_or(Error::Overflow)?,
            six_ghz: Some(SixGhzBinding {
                observation,
                selection,
                local,
            }),
        }))
    }
    /// Only a native callback holding both actual transport providers calls
    /// this after qualifying the original prepared Session and both clocks.
    pub(crate) fn commit_six_ghz_authentication(
        &mut self,
        session: Arc<Session>,
        now: u64,
    ) -> Result<(), Error> {
        if self.phase != Phase::Idle || session.local != self.local || session.six_ghz.is_none() {
            return Err(Error::Stale);
        }
        self.clock(now)?;
        if now >= session.deadline {
            return Err(Error::Timeout);
        }
        self.epoch = session.epoch;
        self.serial = 0;
        self.sae = Progress::new(session.deadline);
        self.external = Some(session);
        self.phase = Phase::ExternalAuthenticating;
        Ok(())
    }

    /// Identity observation only; a retained old handle stays inspectable but
    /// every operation must pass validate_external_authentication again.
    pub fn external_authentication(&self) -> Option<&Arc<Session>> {
        self.external.as_ref()
    }
    pub fn validate_external_authentication(&self, session: &Session) -> Result<(), Error> {
        if self.phase != Phase::ExternalAuthenticating
            || self
                .external
                .as_ref()
                .is_none_or(|current| !core::ptr::eq(current.as_ref(), session))
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// The exchange is the station's until its association is answered, as
    /// `ieee80211_mgd_assoc` keeps the authenticated data while it waits.
    pub fn validate_external_exchange(&self, session: &Session) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::ExternalAuthenticating | Phase::Associating
        ) || self
            .external
            .as_ref()
            .is_none_or(|current| !core::ptr::eq(current.as_ref(), session))
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Whether the exchange authenticated the station, as
    /// `ieee80211_mark_sta_auth` records it: the AP confirmed after the
    /// station's confirm, or before it.
    pub fn external_authenticated(&self) -> bool {
        self.phase == Phase::ExternalAuthenticating && self.sae.done
    }
    /// When the exchange ends unless it progresses: its budget, the OS's
    /// retry wait, or the wait for association once authenticated.
    pub fn external_deadline(&self) -> Option<u64> {
        (self.phase == Phase::ExternalAuthenticating).then_some(self.sae.deadline)
    }

    /// Build only the ordinary authentication header and fixed SAE fields.
    /// The OS supplies complete transaction/status/data, including anti-clogging
    /// retries. This does not parse or fabricate secret SAE arithmetic.
    pub fn external_authentication_transmit(
        &mut self,
        session: &Session,
        frame: Frame<'_>,
        now: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Vec<u8>, Error> {
        let Frame {
            transaction,
            status,
            data,
        } = frame;

        self.validate_external_authentication(session)?;
        self.clock(now)?;
        if self.sae.done || self.sae.denied.is_some() {
            return Err(Error::Stale);
        }
        if now >= self.sae.deadline {
            return Err(Error::Timeout);
        }
        if !matches!(transaction, 1 | 2) || data.len() > MAX_AUTHENTICATION_DATA {
            return Err(Error::Wire(wire::Error::Invalid(
                "SAE authentication transaction/length",
            )));
        }
        if !policy.allow_management_tx(session.channel) {
            return Err(Error::Regulatory);
        }
        let last = data.to_vec();
        let bytes = self.external_frame(session, transaction, status, data)?;
        self.sae.expected = transaction;
        // ieee80211_mgd_auth starts each frame's tries afresh.
        self.sae.last = Some((transaction, status, last));
        self.sae.tries = 1;
        self.sae.retry = Some(now.checked_add(WAIT_STATUS_US).ok_or(Error::Overflow)?);
        // ieee80211_mgd_auth: confirming a peer that already confirmed
        // completes the exchange.
        if transaction == 2 && self.sae.peer_confirmed {
            self.sae.authenticated(now)?;
        }
        Ok(bytes)
    }

    fn external_frame(
        &mut self,
        session: &Session,
        transaction: u16,
        status: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = wire::authentication(self.local, session.peer, self.sequence)?;
        bytes[24..26].copy_from_slice(&SAE.to_le_bytes());
        bytes[26..28].copy_from_slice(&transaction.to_le_bytes());
        bytes[28..30].copy_from_slice(&status.to_le_bytes());
        bytes.extend_from_slice(data);
        self.sequence = next_sequence(self.sequence);
        Ok(bytes)
    }

    /// `ieee80211_auth` sending the OS's last frame again once its wait
    /// passed, until IEEE80211_AUTH_MAX_TRIES; `poll` ends the exchange
    /// after the last try.
    pub fn external_retransmission(
        &mut self,
        now: u64,
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.phase != Phase::ExternalAuthenticating
            || self.sae.done
            || self.sae.denied.is_some()
            || self.sae.tries >= MAX_TRIES
            || self.sae.retry.is_none_or(|retry| now < retry)
        {
            return Ok(None);
        }
        self.clock(now)?;
        let session = self.external.clone().ok_or(Error::Stale)?;
        if !policy.allow_management_tx(session.channel) {
            return Err(Error::Regulatory);
        }
        let (transaction, status, data) = self.sae.last.take().ok_or(Error::Stale)?;
        let bytes = self.external_frame(&session, transaction, status, &data);
        self.sae.last = Some((transaction, status, data));
        let bytes = bytes?;
        self.sae.tries += 1;
        self.sae.retry = Some(now.checked_add(WAIT_STATUS_US).ok_or(Error::Overflow)?);
        Ok(Some(bytes))
    }

    /// `ieee80211_rx_mgmt_auth` for the OS's exchange: `None` for a frame
    /// mac80211 ignores, after authentication or out of the exchange's order.
    /// The caller must retain the actual RX/peer owner; copied security bits
    /// supply no authority.
    pub fn receive_external_authentication(
        &mut self,
        session: &Arc<Session>,
        frame: Mpdu,
        now: u64,
    ) -> Result<Option<Received>, Error> {
        self.validate_external_authentication(session)?;
        self.clock(now)?;
        if now >= self.sae.deadline {
            return Err(Error::Timeout);
        }
        if self.sae.done || self.sae.denied.is_some() {
            return Ok(None);
        }
        if (
            frame.radio.band,
            frame.radio.channel,
            frame.radio.frequency_mhz,
        ) != (
            session.channel.band,
            session.channel.number,
            session.channel.frequency_mhz,
        ) {
            return Err(Error::WrongChannel);
        }
        if frame.bytes().len() > FIXED_BYTES + MAX_AUTHENTICATION_DATA {
            return Err(Error::Wire(wire::Error::Invalid(
                "authentication frame length",
            )));
        }
        if frame.fcs_error || frame.monitor_only {
            return Err(Error::Wire(wire::Error::Integrity));
        }
        wire::check_peer(&frame, self.local, session.peer)?;
        if frame.header().control & TYPE_SUBTYPE != AUTHENTICATION {
            return Err(Error::Wire(wire::Error::Invalid("authentication subtype")));
        }
        let fixed = frame
            .bytes()
            .get(24..FIXED_BYTES)
            .ok_or(Error::Wire(wire::Error::Truncated))?;
        let algorithm = u16::from_le_bytes(fixed[..2].try_into().unwrap());
        let transaction = u16::from_le_bytes(fixed[2..4].try_into().unwrap());
        let status = u16::from_le_bytes(fixed[4..6].try_into().unwrap());
        if algorithm != SAE || transaction < self.sae.expected || transaction > 2 {
            return Ok(None);
        }
        if status != 0 {
            if status == ANTI_CLOGGING
                || (transaction == 1 && matches!(status, HASH_TO_ELEMENT | SAE_PK))
            {
                // Waiting for the OS's next commit.
                self.sae.deadline = now.checked_add(WAIT_RETRY_US).ok_or(Error::Overflow)?;
                self.sae.retry = None;
            } else {
                self.sae.denied = Some(status);
            }
        } else if transaction == 2 && self.sae.expected == 2 {
            self.sae.authenticated(now)?;
        } else if transaction == 2 {
            self.sae.peer_confirmed = true;
        }
        Ok(Some(Received {
            session: session.clone(),
            frame,
        }))
    }
}
