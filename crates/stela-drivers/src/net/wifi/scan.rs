// SPDX-License-Identifier: GPL-2.0-only
// Scan lifetime rules adapt Linux net/mac80211/scan.c:
// Copyright 2003 Jouni Malinen; 2004 Instant802 Networks, Inc.;
// 2005 Devicescape Software, Inc.; 2006-2007 Jiri Benc; 2007 Michael Wu;
// 2013-2015 Intel Mobile Communications GmbH; 2016-2017 Intel Deutschland GmbH;
// 2018-2025 Intel Corporation. See THIRD_PARTY.md.
//! Bounded hardware-scan request lifetime. A request/command acknowledgement
//! never means scan completion. Cancellation/timeout keeps ownership until
//! the completion and radio/request retirement are both established.

use super::{Band, Channel};
use alloc::vec::Vec;

pub mod result;
pub mod six_ghz;

static NEXT_SCAN: super::Identities = super::Identities::new();
// Shared ceilings informed by initial AX200/210, MT7921/22/25, RTL8822CE/8852BE
// sources. These are not capabilities: vendor encoders must enforce narrower
// negotiated firmware limits and built-probe/reserved-page bounds.
pub(super) const MAX_SSIDS: usize = 4;
pub(super) const MAX_SSID_BYTES: usize = 32;
pub(super) const MAX_SIX_GHZ: usize = 64;
pub(super) const MAX_CHANNELS: usize = 64;
pub(super) const MAX_EXTRA_ELEMENTS: usize = 384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Unsupported(&'static str),
    Busy,
    Stale,
    WrongPhase,
    ClockRegressed,
    Overflow,
    Regulatory,
    Integrity,
    WrongPeer,
    WrongChannel,
    TimedOut,
}

/// Physical regulatory/channel provider. No permissive default, country guess
/// or conversion from arbitrary channel integers to a usable radio channel.
pub trait Policy {
    fn allow_receive(&mut self, channel: Channel) -> bool;
    fn allow_probe(&mut self, channel: Channel) -> bool;
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel>;
}

/// A 6 GHz target [`six_ghz::second_part`] plans, as cfg80211_scan_6ghz does.
/// RNR/PSC metadata selects firmware targets; it never grants probe permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SixGhz {
    pub channel_index: usize,
    pub bssid: crate::net::Mac,
    pub short_ssid: Option<u32>,
    pub unsolicited_probe: bool,
    pub psc_no_listen: bool,
    pub psd_20: i8,
}
#[derive(Debug)]
pub struct Request {
    channels: Vec<Channel>,
    ssids: Vec<Vec<u8>>,
    extra_elements: Vec<u8>,
    six_ghz: Vec<SixGhz>,
}

impl Request {
    /// No SSIDs means passive scan. One zero-length SSID means an active
    /// wildcard probe; preserve that distinction and arbitrary binary SSIDs.
    /// Extra IEs exclude SSID (provided by `ssids`) and unsupported mode claims.
    pub fn new(
        channels: Vec<Channel>,
        ssids: Vec<Vec<u8>>,
        extra_elements: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::with_six_ghz(channels, ssids, extra_elements, Vec::new())
    }
    /// Explicit prepared 6GHz targets, keeping all source input fields. A
    /// vendor must implement their protocol or refuse before publication.
    pub fn with_six_ghz(
        channels: Vec<Channel>,
        ssids: Vec<Vec<u8>>,
        extra_elements: Vec<u8>,
        six_ghz: Vec<SixGhz>,
    ) -> Result<Self, Error> {
        if six_ghz.len() > MAX_SIX_GHZ
            || six_ghz.iter().any(|p| {
                channels
                    .get(p.channel_index)
                    .is_none_or(|ch| ch.band != Band::Ghz6)
            })
        {
            return Err(Error::Invalid("6GHz target count/channel index"));
        }
        if channels.is_empty() || channels.len() > MAX_CHANNELS {
            return Err(Error::Invalid("explicit scan channel count"));
        }
        if channels
            .iter()
            .enumerate()
            .any(|(index, channel)| channels[..index].contains(channel))
        {
            return Err(Error::Invalid("duplicate scan channel"));
        }
        if ssids.len() > MAX_SSIDS || ssids.iter().any(|ssid| ssid.len() > MAX_SSID_BYTES) {
            return Err(Error::Invalid("scan SSID count/length"));
        }
        if extra_elements.len() > MAX_EXTRA_ELEMENTS {
            return Err(Error::Invalid("scan extra IE length"));
        }
        for (id, data) in result::elements(&extra_elements)? {
            match id {
                0 => return Err(Error::Invalid("extra SSID element")),
                45 | 61 | 191 | 192 => return Err(Error::Unsupported("HT/VHT probe context")),
                255 if data
                    .first()
                    .is_some_and(|id| matches!(id, 35 | 36 | 59 | 106 | 107 | 108)) =>
                {
                    return Err(Error::Unsupported("HE/EHT/MLO probe context"));
                }
                _ => (),
            }
        }
        Ok(Self {
            channels,
            ssids,
            extra_elements,
            six_ghz,
        })
    }

    /// Fallible immutable snapshot of this already validated request. No
    /// parser reruns or arbitrary-parts constructor can introduce unchecked
    /// allocations into a native regulatory-publication preparation path.
    pub(super) fn try_snapshot(&self) -> Result<Self, alloc::collections::TryReserveError> {
        fn copy<T: Copy>(source: &[T]) -> Result<Vec<T>, alloc::collections::TryReserveError> {
            let mut destination = Vec::new();
            destination.try_reserve_exact(source.len())?;
            destination.extend_from_slice(source);
            Ok(destination)
        }
        let channels = copy(&self.channels)?;
        let mut ssids = Vec::new();
        ssids.try_reserve_exact(self.ssids.len())?;
        for ssid in &self.ssids {
            ssids.push(copy(ssid)?);
        }
        let extra_elements = copy(&self.extra_elements)?;
        let six_ghz = copy(&self.six_ghz)?;
        Ok(Self {
            channels,
            ssids,
            extra_elements,
            six_ghz,
        })
    }

    pub fn six_ghz(&self) -> &[SixGhz] {
        &self.six_ghz
    }
    pub fn channels(&self) -> &[Channel] {
        &self.channels
    }
    pub fn ssids(&self) -> &[Vec<u8>] {
        &self.ssids
    }
    pub fn extra_elements(&self) -> &[u8] {
        &self.extra_elements
    }
    pub fn active(&self) -> bool {
        !self.ssids.is_empty()
    }
    fn validate_policy(&self, policy: &mut impl Policy) -> Result<(), Error> {
        for &channel in self.channels() {
            if policy.lookup_channel(channel.band, channel.number) != Some(channel)
                || !policy.allow_receive(channel)
                || (self.active() && !policy.allow_probe(channel))
            {
                return Err(Error::Regulatory);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket(u64);
impl Ticket {
    pub const fn epoch(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Starting,
    Submitted,
    Cancelling,
    Retiring,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    Aborted,
    Failed(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retirement {
    /// Any accepted scan completed/aborted; operating-channel
    /// restoration (when applicable), DMA and old notification/deferred-user
    /// drain are proven. A never-submitted rejected request has no hardware
    /// scan to complete, but must likewise have no outstanding users.
    Confirmed,
    Uncertain,
}

#[derive(Debug)]
pub struct Scanner {
    local: crate::net::Mac,
    phase: Phase,
    ticket: Ticket,
    request: Option<Request>,
    now: u64,
    deadline: u64,
    cancelled: bool,
    outcome: Option<Outcome>,
}

impl Scanner {
    /// Pure protocol state, not ownership of a physical radio. The vendor's
    /// single canonical radio owner serializes scans against association/data
    /// channel work and keeps this state until request retirement.
    pub fn new(local: crate::net::Mac) -> Result<Self, Error> {
        if local.is_multicast() || local.0 == [0; 6] {
            return Err(Error::Invalid("scan interface address"));
        }
        Ok(Self {
            local,
            phase: Phase::Idle,
            ticket: Ticket(0),
            request: None,
            now: 0,
            deadline: 0,
            cancelled: false,
            outcome: None,
        })
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn local(&self) -> crate::net::Mac {
        self.local
    }
    pub fn request(&self) -> Option<&Request> {
        self.request.as_ref()
    }

    fn current(&self, ticket: Ticket) -> Result<(), Error> {
        if self.phase == Phase::Idle || self.ticket != ticket {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::ClockRegressed);
        }
        self.now = now;
        Ok(())
    }

    /// Caller supplies its real scan budget. This only grants a request ticket;
    /// the firmware scan encoder/transport remains the vendor's job.
    pub fn begin(
        &mut self,
        request: Request,
        now: u64,
        budget_us: u64,
        policy: &mut impl Policy,
    ) -> Result<Ticket, Error> {
        if self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        self.clock(now)?;
        if budget_us == 0 {
            return Err(Error::Invalid("zero scan budget"));
        }
        let deadline = now.checked_add(budget_us).ok_or(Error::Overflow)?;
        request.validate_policy(policy)?;
        let epoch = NEXT_SCAN.next().ok_or(Error::Overflow)?;
        self.ticket = Ticket(epoch);
        self.request = Some(request);
        self.deadline = deadline;
        self.cancelled = false;
        self.outcome = None;
        self.phase = Phase::Starting;
        Ok(self.ticket)
    }

    /// Recheck just before transport publication, serialized by the
    /// canonical owner with cancellation and regulatory changes. This grants
    /// no hardware acknowledgement. Expiration keeps the cancelled request.
    pub fn validate_submission(
        &mut self,
        ticket: Ticket,
        now: u64,
        policy: &mut impl Policy,
    ) -> Result<(), Error> {
        self.current(ticket)?;
        if self.phase != Phase::Starting {
            return Err(Error::WrongPhase);
        }
        self.clock(now)?;
        if now >= self.deadline {
            self.cancel(ticket)?;
            return Err(Error::TimedOut);
        }
        self.request
            .as_ref()
            .ok_or(Error::WrongPhase)?
            .validate_policy(policy)
    }

    /// Release a locally prepared request that never reached transport. The
    /// vendor owner must call submitted before handoff; once Submitted (or
    /// cancelling/retiring), only completion/drain may retire the scan.
    /// This records no invented firmware rejection or terminal outcome.
    pub(super) fn withdraw_unsubmitted(&mut self, ticket: Ticket) -> Result<Request, Error> {
        self.current(ticket)?;
        if self.phase != Phase::Starting {
            return Err(Error::WrongPhase);
        }
        let request = self.request.take().ok_or(Error::WrongPhase)?;
        self.phase = Phase::Idle;
        self.cancelled = false;
        self.outcome = None;
        Ok(request)
    }

    /// Mark transport handoff after validate_submission, within that
    /// same owner serialization; not firmware acceptance or completion.
    pub fn submitted(&mut self, ticket: Ticket) -> Result<(), Error> {
        self.current(ticket)?;
        if self.phase != Phase::Starting {
            return Err(Error::WrongPhase);
        }
        self.phase = Phase::Submitted;
        Ok(())
    }

    /// True means request cancellation from the vendor. No resources
    /// are released here, including cancellation during command submission.
    pub fn cancel(&mut self, ticket: Ticket) -> Result<bool, Error> {
        self.current(ticket)?;
        match self.phase {
            Phase::Starting | Phase::Submitted => {
                self.cancelled = true;
                self.phase = Phase::Cancelling;
                Ok(true)
            }
            Phase::Cancelling | Phase::Retiring => {
                self.cancelled = true;
                Ok(false)
            }
            _ => Err(Error::WrongPhase),
        }
    }

    /// Only the active scan has a deadline. A terminal event ends that budget;
    /// delayed retirement keeps ownership without retroactively timing it out.
    /// Timeout requests cancellation; it never synthesizes scan completion.
    pub fn poll(&mut self, ticket: Ticket, now: u64) -> Result<bool, Error> {
        self.current(ticket)?;
        if self.phase == Phase::Quarantined {
            return Err(Error::WrongPhase);
        }
        self.clock(now)?;
        if self.phase == Phase::Retiring || now < self.deadline {
            return Ok(false);
        }
        self.cancel(ticket)
    }

    /// Bind to the vendor request generation/notification,
    /// never tag an old raw scan ID with the current ticket. A transport ACK or
    /// local abort helper alone cannot supply this completion observation.
    pub fn completed(&mut self, ticket: Ticket, outcome: Outcome) -> Result<(), Error> {
        self.current(ticket)?;
        if !matches!(self.phase, Phase::Submitted | Phase::Cancelling) {
            return Err(Error::WrongPhase);
        }
        self.outcome = Some(outcome);
        self.phase = Phase::Retiring;
        Ok(())
    }

    /// Ticket is bound to the transport/RX scan generation.
    /// Device raw IDs may be narrower; old notification drain is required
    /// before their reuse, never a current-ticket lookup on an old event.
    pub fn observe(
        &self,
        ticket: Ticket,
        frame: &super::frame::Mpdu,
        policy: &mut impl Policy,
    ) -> Result<result::Bss, Error> {
        self.current(ticket)?;
        if !matches!(self.phase, Phase::Submitted | Phase::Cancelling) {
            return Err(Error::WrongPhase);
        }
        let request = self.request.as_ref().ok_or(Error::WrongPhase)?;
        let observed = Channel {
            band: frame.radio.band,
            number: frame.radio.channel,
            frequency_mhz: frame.radio.frequency_mhz,
        };
        if !request.channels().contains(&observed) {
            return Err(Error::WrongChannel);
        }
        result::parse(ticket, frame, self.local, policy)
    }

    /// Record a local encoder rejection before submission, or a
    /// rejection of the original start command. An abort/cancel response (for
    /// example "not found") is not this proof. Retirement still requires proof
    /// that it did not start and no hardware/old notification users remain.
    pub fn start_rejected(&mut self, ticket: Ticket, status: u32) -> Result<(), Error> {
        self.current(ticket)?;
        if !matches!(
            self.phase,
            Phase::Starting | Phase::Submitted | Phase::Cancelling
        ) {
            return Err(Error::WrongPhase);
        }
        self.outcome = Some(Outcome::Failed(status));
        self.phase = Phase::Retiring;
        Ok(())
    }

    pub fn retire(&mut self, ticket: Ticket, proof: Retirement) -> Result<Option<Outcome>, Error> {
        self.current(ticket)?;
        if self.phase != Phase::Retiring {
            return Err(Error::WrongPhase);
        }
        if proof == Retirement::Uncertain {
            self.phase = Phase::Quarantined;
            return Ok(None);
        }
        let outcome = match self.outcome.ok_or(Error::WrongPhase)? {
            Outcome::Completed if self.cancelled => Outcome::Aborted,
            outcome => outcome,
        };
        self.phase = Phase::Idle;
        self.request = None;
        Ok(Some(outcome))
    }

    /// # Safety
    /// The canonical owner must have independently stopped/reset this
    /// radio, restored the operating context as needed, drained DMA and all old
    /// scan notifications/deferred users. Requesting reset is insufficient.
    pub unsafe fn reset_drained(&mut self, ticket: Ticket) -> Result<Outcome, Error> {
        self.current(ticket)?;
        self.request = None;
        self.phase = Phase::Idle;
        Ok(Outcome::Aborted)
    }
}

#[cfg(test)]
mod tests;
