// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2007-2010, 2018-2026 Intel Corporation;
// 2015-2017 Intel Deutschland GmbH. See THIRD_PARTY.md for full source notices.
//! Ordinary single-link TX Block Ack, adapted from mac80211 agg-tx.c.
//!
//! The native owner holds and preserves this TID's pending packets from Prepare
//! through Operational/ResumeLegacy. Prepare synchronizes old TX and supplies
//! the canonical next software per-TID sequence. This is host MLME/header input,
//! independent of the firmware's on-air sequence assignment. Real firmware
//! operational completion enables TX;
//! plans, peer responses and descriptor flags alone never do. Stop invalidates
//! publication first, then requires command/TX-user retirement. Other
//! controller DMA, peer/key and queue owners remain independently kept.

use super::{AssociationContext, Completion, Error, Phase, Station, TIDS, Ticket, wire};
use crate::wifi::frame::{self, MAX_AMPDU_BUF_EHT, MAX_AMPDU_BUF_HE, MAX_AMPDU_BUF_HT};
use alloc::{sync::Arc, vec::Vec};

const RESPONSE_INTERVAL_US: u64 = 1_000_000;
const RETRIES_PERIOD_US: u64 = 15_000_000;
const MAX_RETRIES: u8 = 15;
const BURST_RETRIES: u8 = 3;
const TU_US: u64 = 1024;
const NOT_USING_BLOCK_ACK: u16 = 37;

/// Private identity of this association's particular TX negotiation.
#[derive(Debug)]
pub struct Session {
    ticket: Ticket,
    context: Arc<AssociationContext>,
    tid: u8,
    dialog: u8,
}
impl Session {
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }
    pub fn context(&self) -> &Arc<AssociationContext> {
        &self.context
    }
    pub const fn tid(&self) -> u8 {
        self.tid
    }
    pub const fn dialog(&self) -> u8 {
        self.dialog
    }
}

/// Peer-negotiated values, still requiring real native operational completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agreement {
    window: u16,
    timeout: u16,
    amsdu: bool,
}
impl Agreement {
    pub const fn window(self) -> u16 {
        self.window
    }
    pub const fn timeout_tu(self) -> u16 {
        self.timeout
    }
    pub const fn amsdu_in_ampdu(self) -> bool {
        self.amsdu
    }
}

#[derive(Debug)]
pub enum Action {
    Prepare {
        ticket: Ticket,
        session: Arc<Session>,
    },
    /// Some agreement programs TX_OPERATIONAL; None is TX_STOP.
    Program {
        ticket: Ticket,
        session: Arc<Session>,
        agreement: Option<Agreement>,
    },
    /// Exact wire bytes are held privately and checked before publication.
    Transmit {
        ticket: Ticket,
        session: Arc<Session>,
        bytes: Vec<u8>,
    },
    /// Native may release kept pending TX into this active agreement only
    /// under its ordinary current association/radio/key publication guards.
    Operational {
        session: Arc<Session>,
        agreement: Agreement,
    },
    /// The old native aggregation owner is idle/retired. Preserve pending
    /// packets and resume ordinary TX only if current association grants allow;
    /// after disconnect this action does not authorize publication.
    ResumeLegacy {
        session: Arc<Session>,
    },
    None,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Preparing,
    CancelingPrepare { notify: bool },
    Publishing { ticket: Ticket, deadline: u64 },
    CancelingPublish { ticket: Ticket, notify: bool },
    Waiting { deadline: u64 },
    Programming { ticket: Ticket },
    CancelingProgram { ticket: Ticket, notify: bool },
    Active,
    Stopping { ticket: Ticket, notify: bool },
    Deleting { ticket: Ticket },
    Quarantined,
}
#[derive(Debug)]
struct Record {
    session: Arc<Session>,
    state: State,
    timeout: u16,
    agreement: Option<Agreement>,
    idle_deadline: Option<u64>,
    wire: Option<Vec<u8>>,
    early_response: Option<Response>,
}
#[derive(Clone, Copy, Debug)]
struct Response {
    window: u16,
    timeout: u16,
    status: u16,
    amsdu: bool,
}
#[derive(Clone, Copy, Debug, Default)]
struct Retry {
    count: u8,
    last: u64,
}

#[derive(Debug)]
pub(in crate::wifi::station) struct Sessions {
    context: Option<Arc<AssociationContext>>,
    maximum: Option<u16>,
    dialog: u8,
    retries: [Retry; TIDS],
    no_amsdu: [bool; TIDS],
    records: [Option<Record>; TIDS],
}
impl Sessions {
    pub(in crate::wifi::station) fn new() -> Self {
        Self {
            context: None,
            maximum: None,
            dialog: 0,
            retries: [Retry::default(); TIDS],
            no_amsdu: [false; TIDS],
            records: core::array::from_fn(|_| None),
        }
    }
    pub(super) fn is_idle(&self) -> bool {
        self.records.iter().all(Option::is_none)
    }
    pub(super) fn has_session(&self, tid: u8) -> bool {
        self.records
            .get(usize::from(tid))
            .is_some_and(Option::is_some)
    }
}

fn deadline(now: u64, interval: u64) -> Result<u64, Error> {
    now.checked_add(interval)
        .ok_or(Error::Station(super::super::Error::Overflow))
}

impl Station {
    /// Source hardware maximum; this is metadata and grants no radio,
    /// aggregation, firmware completion or permission to release pending TX.
    pub fn configure_tx_block_ack(&mut self, maximum: u16) -> Result<(), Error> {
        if maximum == 0 || maximum > MAX_AMPDU_BUF_EHT {
            return Err(Error::InvalidLimits);
        }
        let context = self.ba_context()?;
        let same = self
            .tx_ba
            .context
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, &context));
        if self.tx_ba.records.iter().any(Option::is_some)
            && (!same || self.tx_ba.maximum != Some(maximum))
        {
            return Err(Error::Busy);
        }
        if !same {
            self.tx_ba = Sessions::new();
        }
        self.tx_ba.context = Some(context);
        self.tx_ba.maximum = Some(maximum);
        Ok(())
    }

    pub fn begin_tx_block_ack(
        &mut self,
        tid: u8,
        timeout_tu: u16,
        now_us: u64,
    ) -> Result<Action, Error> {
        if self.requires_protected_management() {
            return Err(Error::Unsupported);
        }
        self.begin_authenticated_tx_block_ack(tid, timeout_tu, now_us)
    }

    /// Internal only: the native consumer validates a current authenticated
    /// management Session and holds both exact OS/hardware policy guards.
    pub(in crate::wifi) fn begin_authenticated_tx_block_ack(
        &mut self,
        tid: u8,
        timeout_tu: u16,
        now_us: u64,
    ) -> Result<Action, Error> {
        self.clock(now_us)?;
        let context = self.ba_context()?;
        if usize::from(tid) >= TIDS || self.tx_ba.maximum.is_none() {
            return Err(Error::InvalidLimits);
        }
        if self
            .tx_ba
            .context
            .as_ref()
            .is_none_or(|old| !Arc::ptr_eq(old, &context))
        {
            return Err(Error::Stale);
        }
        let index = usize::from(tid);
        let retry = self.tx_ba.retries[index];
        if retry.count > MAX_RETRIES
            || (retry.count > BURST_RETRIES && now_us < deadline(retry.last, RETRIES_PERIOD_US)?)
        {
            return Err(Error::Busy);
        }
        if self.tx_ba.records[index].is_some() {
            return Err(Error::Busy);
        }
        let ticket = self.ticket()?;
        self.tx_ba.dialog = self.tx_ba.dialog.wrapping_add(1);
        let session = Arc::new(Session {
            ticket,
            context,
            tid,
            dialog: self.tx_ba.dialog,
        });
        self.tx_ba.records[index] = Some(Record {
            session: session.clone(),
            state: State::Preparing,
            timeout: timeout_tu,
            agreement: None,
            idle_deadline: None,
            wire: None,
            early_response: None,
        });
        Ok(Action::Prepare { ticket, session })
    }

    fn tx_ba_identity(&self, session: &Session) -> Result<&Record, Error> {
        if session.ticket.epoch() != self.epoch
            || self
                .context
                .as_ref()
                .is_none_or(|c| !core::ptr::eq(c.as_ref(), session.context.as_ref()))
        {
            return Err(Error::Stale);
        }
        let record = self
            .tx_ba
            .records
            .get(usize::from(session.tid))
            .and_then(Option::as_ref)
            .ok_or(Error::NoSession)?;
        if !core::ptr::eq(record.session.as_ref(), session) {
            return Err(Error::Stale);
        }
        Ok(record)
    }

    /// Recognize only the original operation canceled in the canonical
    /// record. This does not prove native nonpublication or TX retirement.
    pub(crate) fn validate_tx_block_ack_cancellation(&self, action: &Action) -> Result<(), Error> {
        let (ticket, session) = match action {
            Action::Prepare { ticket, session }
            | Action::Transmit {
                ticket, session, ..
            }
            | Action::Program {
                ticket, session, ..
            } => (*ticket, session),
            _ => return Err(Error::Stale),
        };
        let record = self.tx_ba_identity(session)?;
        let valid = match (action, record.state) {
            (Action::Prepare { .. }, State::CancelingPrepare { .. }) => session.ticket == ticket,
            (Action::Transmit { bytes, .. }, State::CancelingPublish { ticket: t, .. }) => {
                ticket == t && record.wire.as_deref() == Some(bytes.as_slice())
            }
            (Action::Program { agreement, .. }, State::CancelingProgram { ticket: t, .. }) => {
                ticket == t && agreement.is_some() && *agreement == record.agreement
            }
            _ => false,
        };
        if valid { Ok(()) } else { Err(Error::Stale) }
    }

    pub fn validate_tx_block_ack_prepare(
        &self,
        ticket: Ticket,
        session: &Session,
    ) -> Result<(), Error> {
        let record = self.tx_ba_identity(session)?;
        if self.phase != Phase::Associated
            || session.ticket != ticket
            || !matches!(record.state, State::Preparing)
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    fn tx_ba_resume(&mut self, index: usize) -> Action {
        let record = self.tx_ba.records[index].take().unwrap();
        Action::ResumeLegacy {
            session: record.session,
        }
    }

    fn tx_ba_stop_program(&mut self, index: usize, notify: bool) -> Result<Action, Error> {
        let ticket = self.ticket()?;
        let record = self.tx_ba.records[index].as_mut().ok_or(Error::NoSession)?;
        record.state = State::Stopping { ticket, notify };
        record.idle_deadline = None;
        record.wire = None;
        Ok(Action::Program {
            ticket,
            session: record.session.clone(),
            agreement: None,
        })
    }

    /// # Safety
    /// Matching TID preparation is terminal. Accepted includes blocked
    /// new TX, synchronized old TX users and the canonical per-TID next
    /// 12-bit software sequence counter (as Linux sta->tid_seq>>4). It is not an
    /// observation of firmware/on-air sequence and must not be invented as zero
    /// because the descriptor requests hardware sequence assignment. Native
    /// must keep that TID/queue owner through all following actions. Rejection
    /// may release it only with independently established idle state. Pending
    /// packets remain owned, including every failure/cancellation path.
    pub unsafe fn complete_tx_block_ack_prepare(
        &mut self,
        ticket: Ticket,
        result: Completion,
        next_sequence: Option<u16>,
        now_us: u64,
    ) -> Result<Action, Error> {
        self.clock(now_us)?;
        let index = self
            .tx_ba
            .records
            .iter()
            .position(|r| {
                r.as_ref().is_some_and(|r| {
                    r.session.ticket == ticket
                        && matches!(r.state, State::Preparing | State::CancelingPrepare { .. })
                })
            })
            .ok_or(Error::Stale)?;
        if result == Completion::Uncertain {
            self.tx_ba.records[index].as_mut().unwrap().state = State::Quarantined;
            return Ok(Action::None);
        }
        if result == Completion::RejectedAndIdle {
            return Ok(self.tx_ba_resume(index));
        }
        let State::CancelingPrepare { notify } = self.tx_ba.records[index].as_ref().unwrap().state
        else {
            if self.phase != Phase::Associated {
                return self.tx_ba_stop_program(index, false);
            }
            let sequence = next_sequence
                .filter(|s| *s < 4096)
                .ok_or(Error::InvalidLimits)?;
            let response_deadline = deadline(now_us, RESPONSE_INTERVAL_US)?;
            let record = self.tx_ba.records[index].as_ref().unwrap();
            self.validate_association_context(&record.session.context)?;
            let n = record.session.context.negotiated();
            let maximum = self.tx_ba.maximum.unwrap();
            // Source non-STRICT HT requests 64 even if the HW
            // maximum is smaller; the peer result is clamped later.
            let window = if n.eht.is_some() {
                maximum
            } else if n.he.is_some() {
                maximum.min(MAX_AMPDU_BUF_HE)
            } else {
                MAX_AMPDU_BUF_HT
            };
            let request = wire::Request {
                dialog: record.session.dialog,
                tid: index as u8,
                start: sequence,
                window,
                timeout: record.timeout,
                immediate: true,
                extension: 0,
            };
            let wire = wire::request(
                self.local,
                record.session.context.bssid(),
                self.sequence,
                request,
                n.he.is_some(),
            );
            let wire_ticket = self.ticket()?;
            self.sequence = frame::next_sequence(self.sequence);
            let retry = &mut self.tx_ba.retries[index];
            retry.count += 1;
            retry.last = now_us;
            let record = self.tx_ba.records[index].as_mut().unwrap();
            record.state = State::Publishing {
                ticket: wire_ticket,
                deadline: response_deadline,
            };
            record.wire = Some(wire.clone());
            return Ok(Action::Transmit {
                ticket: wire_ticket,
                session: record.session.clone(),
                bytes: wire,
            });
        };
        self.tx_ba_stop_program(index, notify)
    }

    pub fn validate_tx_block_ack_transmit(
        &self,
        ticket: Ticket,
        session: &Session,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let record = self.tx_ba_identity(session)?;
        if self.phase != Phase::Associated
            || record.wire.as_deref() != Some(bytes)
            || !matches!(record.state, State::Publishing { ticket: t, .. } | State::Deleting { ticket: t } if t == ticket)
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// # Safety
    /// The exact management frame's matching physical publication is
    /// terminal. Accepted means admitted and queued/published, without
    /// assuming an on-air ACK. Uncertainty keeps the session/owners; it cannot
    /// be converted into permission to reuse an old TX agreement or queue.
    pub unsafe fn complete_tx_block_ack_transmit(
        &mut self,
        ticket: Ticket,
        result: Completion,
        now_us: u64,
    ) -> Result<Action, Error> {
        self.clock(now_us)?;
        let index = self.tx_ba.records.iter().position(|r| r.as_ref().is_some_and(|r|
            matches!(r.state, State::Publishing { ticket: t, .. } | State::CancelingPublish { ticket: t, .. }
                | State::Deleting { ticket: t } if t == ticket))).ok_or(Error::Stale)?;
        let state = self.tx_ba.records[index].as_ref().unwrap().state;
        if result == Completion::Uncertain {
            self.tx_ba.records[index].as_mut().unwrap().state = State::Quarantined;
            return Ok(Action::None);
        }
        match state {
            State::Deleting { .. } => Ok(self.tx_ba_resume(index)),
            State::CancelingPublish { notify, .. } => self.tx_ba_stop_program(index, notify),
            State::Publishing { deadline, .. }
                if result == Completion::Accepted && self.phase == Phase::Associated =>
            {
                let record = self.tx_ba.records[index].as_mut().unwrap();
                record.state = State::Waiting { deadline };
                record.wire = None;
                let early = record.early_response.take();
                let dialog = record.session.dialog;
                if let Some(response) = early {
                    self.tx_ba_response(
                        dialog,
                        index as u8,
                        response.window,
                        response.timeout,
                        response.status,
                        response.amsdu,
                    )
                } else {
                    Ok(Action::None)
                }
            }
            State::Publishing { .. } => self.tx_ba_stop_program(index, false),
            _ => unreachable!(),
        }
    }

    pub(in crate::wifi::station) fn tx_ba_response(
        &mut self,
        dialog: u8,
        tid: u8,
        window: u16,
        timeout: u16,
        status: u16,
        amsdu: bool,
    ) -> Result<Action, Error> {
        let index = usize::from(tid);
        if index >= TIDS {
            return Ok(Action::None);
        }
        // Source latches NO_AMSDU before checking current dialog/session.
        if !amsdu {
            self.tx_ba.no_amsdu[index] = true;
        }
        let Some(record) = self.tx_ba.records[index].as_mut() else {
            return Ok(Action::None);
        };
        if record.session.dialog != dialog {
            return Ok(Action::None);
        }
        if matches!(record.state, State::Publishing { .. }) {
            // The peer may respond after real publication but before its native
            // publication callback is dispatched. Keep the first matching
            // response without activating anything. The terminal result
            // must still be Accepted; cancellation/failure cannot replay this.
            record.early_response.get_or_insert(Response {
                window,
                timeout,
                status,
                amsdu,
            });
            return Ok(Action::None);
        }
        if !matches!(record.state, State::Waiting { .. }) {
            return Ok(Action::None);
        }
        let window = window.min(self.tx_ba.maximum.ok_or(Error::InvalidLimits)?);
        if status != 0 || window == 0 {
            return self.stop_tx_block_ack(tid, false);
        }
        let idle_deadline = if timeout == 0 {
            None
        } else {
            Some(deadline(self.now, u64::from(timeout) * TU_US)?)
        };
        let ticket = self.ticket()?;
        self.tx_ba.retries[index].count = 0;
        let agreement = Agreement {
            window,
            timeout,
            amsdu,
        };
        let record = self.tx_ba.records[index].as_mut().unwrap();
        record.agreement = Some(agreement);
        record.idle_deadline = idle_deadline;
        record.state = State::Programming { ticket };
        Ok(Action::Program {
            ticket,
            session: record.session.clone(),
            agreement: Some(agreement),
        })
    }

    pub fn validate_tx_block_ack_program(
        &self,
        ticket: Ticket,
        session: &Session,
        agreement: Option<Agreement>,
    ) -> Result<(), Error> {
        let record = self.tx_ba_identity(session)?;
        let valid = match record.state {
            State::Programming { ticket: t } => {
                t == ticket
                    && self.phase == Phase::Associated
                    && agreement.is_some()
                    && agreement == record.agreement
            }
            State::Stopping { ticket: t, .. } => t == ticket && agreement.is_none(),
            _ => false,
        };
        if valid { Ok(()) } else { Err(Error::Stale) }
    }

    /// # Safety
    /// Matching real native operation is terminal. Accepted operational means
    /// exact peer/TID/window/A-MSDU programming ACKed, with kept pending TX
    /// still blocked until Operational is consumed. Accepted stop means
    /// firmware disable and retirement of old command callbacks and TX users,
    /// including already-published aggregate TX. Independent controller/key/
    /// requester owners remain alive. A rejected stop never proves retirement.
    pub unsafe fn complete_tx_block_ack_program(
        &mut self,
        ticket: Ticket,
        result: Completion,
    ) -> Result<Action, Error> {
        let index = self.tx_ba.records.iter().position(|r| r.as_ref().is_some_and(|r|
            matches!(r.state, State::Programming { ticket: t } | State::CancelingProgram { ticket: t, .. }
                | State::Stopping { ticket: t, .. } if t == ticket))).ok_or(Error::Stale)?;
        let state = self.tx_ba.records[index].as_ref().unwrap().state;
        if result == Completion::Uncertain
            || (matches!(state, State::Stopping { .. }) && result != Completion::Accepted)
        {
            self.tx_ba.records[index].as_mut().unwrap().state = State::Quarantined;
            return Ok(Action::None);
        }
        match state {
            State::CancelingProgram { notify, .. } => self.tx_ba_stop_program(index, notify),
            State::Programming { .. }
                if result == Completion::Accepted && self.phase == Phase::Associated =>
            {
                let record = self.tx_ba.records[index].as_mut().unwrap();
                record.state = State::Active;
                Ok(Action::Operational {
                    session: record.session.clone(),
                    agreement: record.agreement.unwrap(),
                })
            }
            State::Programming { .. } => self.tx_ba_stop_program(index, false),
            State::Stopping { notify: true, .. } if self.phase == Phase::Associated => {
                let record = self.tx_ba.records[index].as_ref().unwrap();
                let bytes = wire::delete(
                    self.local,
                    record.session.context.bssid(),
                    self.sequence,
                    index as u8,
                    true,
                    NOT_USING_BLOCK_ACK,
                );
                let ticket = self.ticket()?;
                self.sequence = frame::next_sequence(self.sequence);
                let record = self.tx_ba.records[index].as_mut().unwrap();
                record.state = State::Deleting { ticket };
                record.wire = Some(bytes.clone());
                Ok(Action::Transmit {
                    ticket,
                    session: record.session.clone(),
                    bytes,
                })
            }
            State::Stopping { .. } => Ok(self.tx_ba_resume(index)),
            _ => unreachable!(),
        }
    }

    /// Revoke aggregate publication before native stop. A local request
    /// sends initiator DELBA only after completed stop; peer/decline uses false.
    /// An in-flight prepare/publication/operational command must finish before
    /// its dependent stop is emitted, so a late success cannot revive the TID.
    pub fn stop_tx_block_ack(&mut self, tid: u8, notify_peer: bool) -> Result<Action, Error> {
        let record = self
            .tx_ba
            .records
            .get_mut(usize::from(tid))
            .and_then(Option::as_mut)
            .ok_or(Error::NoSession)?;
        let state = record.state;
        record.idle_deadline = None;
        match state {
            State::Preparing => {
                record.state = State::CancelingPrepare {
                    notify: notify_peer,
                };
                Ok(Action::None)
            }
            State::Publishing { ticket, .. } => {
                record.state = State::CancelingPublish {
                    ticket,
                    notify: notify_peer,
                };
                Ok(Action::None)
            }
            State::Programming { ticket } => {
                record.state = State::CancelingProgram {
                    ticket,
                    notify: notify_peer,
                };
                Ok(Action::None)
            }
            State::Waiting { .. } | State::Active | State::Quarantined => {
                self.tx_ba_stop_program(usize::from(tid), notify_peer)
            }
            _ => Err(Error::Busy),
        }
    }

    pub fn active_tx_block_ack(&self, tid: u8) -> Option<&Arc<Session>> {
        let record = self.tx_ba.records.get(usize::from(tid))?.as_ref()?;
        self.validate_tx_block_ack(&record.session).ok()?;
        Some(&record.session)
    }

    /// Pending/uncertain native transitions must preserve and block ordinary
    /// TID TX, including software sequence allocation. Active is usable only
    /// with the current association's independent publication guards. A TID
    /// without a BA record follows ordinary non-aggregate policy.
    pub fn tx_block_ack_blocks_data(&self, tid: u8) -> bool {
        self.tx_ba
            .records
            .get(usize::from(tid))
            .and_then(Option::as_ref)
            .is_some_and(|r| self.phase != Phase::Associated || !matches!(r.state, State::Active))
    }

    pub fn validate_tx_block_ack(&self, session: &Session) -> Result<Agreement, Error> {
        let record = self.tx_ba_identity(session)?;
        self.validate_association_context(&session.context)?;
        if self.phase != Phase::Associated || !matches!(record.state, State::Active) {
            return Err(Error::Stale);
        }
        Ok(record.agreement.unwrap())
    }

    /// Source software TXQ_NO_AMSDU policy, separate from the raw peer A-MSDU
    /// value programmed by TX_OPERATIONAL and the native peer HW-AMSDU TLV.
    pub fn tx_block_ack_allows_software_amsdu(&self, session: &Session) -> Result<bool, Error> {
        Ok(self.validate_tx_block_ack(session)?.amsdu
            && !self.tx_ba.no_amsdu[usize::from(session.tid)])
    }

    /// # Safety
    /// Called only for an aggregate TX publication under current native
    /// association/radio/key guards, with this same session. Queuing,
    /// packet construction, stale callbacks and failed publication do not count.
    pub unsafe fn tx_block_ack_published(
        &mut self,
        session: &Session,
        now_us: u64,
    ) -> Result<(), Error> {
        self.clock(now_us)?;
        let agreement = self.validate_tx_block_ack(session)?;
        let value = if agreement.timeout == 0 {
            None
        } else {
            Some(deadline(now_us, u64::from(agreement.timeout) * TU_US)?)
        };
        self.tx_ba.records[usize::from(session.tid)]
            .as_mut()
            .unwrap()
            .idle_deadline = value;
        Ok(())
    }

    /// Monotonic microseconds replace Linux jiffies; TU is exactly 1024us.
    /// Call at the earliest returned deadline, and again after each returned
    /// action until no other TID is due. Native command timeouts are separate.
    pub fn next_tx_block_ack_deadline(&self) -> Option<u64> {
        self.tx_ba
            .records
            .iter()
            .filter_map(|r| r.as_ref())
            .filter_map(|r| match r.state {
                State::Publishing { deadline, .. } | State::Waiting { deadline } => Some(deadline),
                State::Programming { .. } | State::Active => r.idle_deadline,
                _ => None,
            })
            .min()
    }

    pub fn poll_tx_block_ack(&mut self, now_us: u64) -> Result<Action, Error> {
        self.clock(now_us)?;
        let index = self.tx_ba.records.iter().position(|r| {
            r.as_ref().is_some_and(|r| match r.state {
                State::Publishing { deadline, .. } | State::Waiting { deadline } => {
                    now_us >= deadline
                }
                State::Programming { .. } | State::Active => {
                    r.idle_deadline.is_some_and(|d| now_us >= d)
                }
                _ => false,
            })
        });
        if let Some(index) = index {
            self.stop_tx_block_ack(index as u8, true)
        } else {
            Ok(Action::None)
        }
    }
}

#[cfg(test)]
mod tests;
