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
//! publication first, then requires actual command/TX-user retirement. Other
//! controller DMA, peer/key and queue owners remain independently retained.

use super::{AssociationContext, Completion, Error, Phase, Station, TIDS, Ticket, wire};
use crate::net::wifi::frame::{self, MAX_AMPDU_BUF_EHT, MAX_AMPDU_BUF_HE, MAX_AMPDU_BUF_HT};
use alloc::{sync::Arc, vec::Vec};

const RESPONSE_INTERVAL_US: u64 = 1_000_000;
const RETRIES_PERIOD_US: u64 = 15_000_000;
const MAX_RETRIES: u8 = 15;
const BURST_RETRIES: u8 = 3;
const TU_US: u64 = 1024;
const NOT_USING_BLOCK_ACK: u16 = 37;

/// Private identity of this actual association's particular TX negotiation.
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
    /// Some agreement programs TX_OPERATIONAL; None is actual TX_STOP.
    Program {
        ticket: Ticket,
        session: Arc<Session>,
        agreement: Option<Agreement>,
    },
    /// Exact wire bytes are retained privately and checked before publication.
    Transmit {
        ticket: Ticket,
        session: Arc<Session>,
        bytes: Vec<u8>,
    },
    /// Native may release retained pending TX into this active agreement only
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
pub(in crate::net::wifi::station) struct Sessions {
    context: Option<Arc<AssociationContext>>,
    maximum: Option<u16>,
    dialog: u8,
    retries: [Retry; TIDS],
    no_amsdu: [bool; TIDS],
    records: [Option<Record>; TIDS],
}
impl Sessions {
    pub(in crate::net::wifi::station) fn new() -> Self {
        Self {
            context: None,
            maximum: None,
            dialog: 0,
            retries: [Retry::default(); TIDS],
            no_amsdu: [false; TIDS],
            records: core::array::from_fn(|_| None),
        }
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
    /// Actual source hardware maximum; this is metadata and grants no radio,
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

    /// Recognize only the exact original operation canceled in the canonical
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
    /// Matching actual TID preparation is terminal. Accepted includes blocked
    /// new TX, synchronized old TX users and the actual canonical per-TID next
    /// 12-bit software sequence counter (as Linux sta->tid_seq>>4). It is not an
    /// observation of firmware/on-air sequence and must not be invented as zero
    /// because the descriptor requests hardware sequence assignment. Native
    /// must retain that TID/queue owner through all following actions. Rejection
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
            // Source non-STRICT HT deliberately requests 64 even if the HW
            // actual maximum is smaller; the peer result is clamped later.
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
    /// The exact retained management frame's matching physical publication is
    /// terminal. Accepted means admitted and actually queued/published, without
    /// assuming an on-air ACK. Uncertainty retains the session/owners; it cannot
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

    pub(in crate::net::wifi::station) fn tx_ba_response(
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
            // publication callback is dispatched. Retain the first matching
            // response without activating anything. The actual terminal result
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
    /// exact peer/TID/window/A-MSDU programming ACKed, with retained pending TX
    /// still blocked until Operational is consumed. Accepted stop means actual
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

    /// Revoke aggregate publication before actual native stop. A local request
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
    /// Called only for an actual aggregate TX publication under current native
    /// association/radio/key guards, with this same retained session. Queuing,
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
mod tests {
    use crate::net::wifi::Band;
    use crate::net::wifi::station::ba::{
        Action as BaAction, Error as BaError,
        tx::{Action as TxAction, Agreement, Session},
    };
    use crate::net::wifi::station::phy::{Mode, Width};
    use crate::net::wifi::station::{ba::tests::*, tests::*, *};

    fn station(maximum: u16) -> Station {
        let mut s = associated(1024, true);
        s.configure_tx_block_ack(maximum).unwrap();
        s
    }
    fn prepare(s: &mut Station, tid: u8, timeout: u16) -> (Ticket, Arc<Session>) {
        let TxAction::Prepare { ticket, session } =
            s.begin_tx_block_ack(tid, timeout, s.now + 1).unwrap()
        else {
            panic!("real prepare expected")
        };
        s.validate_tx_block_ack_prepare(ticket, &session).unwrap();
        (ticket, session)
    }
    fn transmit(action: TxAction) -> (Ticket, Arc<Session>, Vec<u8>) {
        let TxAction::Transmit {
            ticket,
            session,
            bytes,
        } = action
        else {
            panic!("wire expected")
        };
        (ticket, session, bytes)
    }
    fn programming(action: TxAction, enabled: bool) -> (Ticket, Arc<Session>, Option<Agreement>) {
        let TxAction::Program {
            ticket,
            session,
            agreement,
        } = action
        else {
            panic!("real program expected")
        };
        assert_eq!(agreement.is_some(), enabled);
        (ticket, session, agreement)
    }
    fn request_sent(s: &mut Station, tid: u8) -> Arc<Session> {
        let (ticket, session) = prepare(s, tid, 0);
        // SAFETY: pure model supplies exact synchronized next sequence and readiness.
        let (wire, same, bytes) = transmit(
            unsafe {
                s.complete_tx_block_ack_prepare(ticket, Completion::Accepted, Some(4095), s.now + 1)
            }
            .unwrap(),
        );
        assert!(Arc::ptr_eq(&session, &same));
        s.validate_tx_block_ack_transmit(wire, &session, &bytes)
            .unwrap();
        assert_eq!(&bytes[31..33], &0xfff0u16.to_le_bytes());
        // SAFETY: modeled exact frame actually admitted/queued, without air-ACK claim.
        assert!(matches!(
            unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }
                .unwrap(),
            TxAction::None
        ));
        session
    }
    fn peer_response(
        session: &Session,
        dialog: u8,
        status: u16,
        window: u16,
        timeout: u16,
        amsdu: bool,
    ) -> Mpdu {
        let parameters =
            u16::from(amsdu) | 2 | u16::from(session.tid()) << 2 | (window & 1023) << 6;
        let mut body = vec![3, 1, dialog];
        body.extend_from_slice(&status.to_le_bytes());
        body.extend_from_slice(&parameters.to_le_bytes());
        body.extend_from_slice(&timeout.to_le_bytes());
        if window >= 1024 {
            body.extend_from_slice(&[159, 1, 1 | ((window >> 10) as u8) << 5]);
        }
        response(0xd0, &body)
    }
    fn receive_tx(s: &mut Station, frame: &Mpdu) -> TxAction {
        let BaAction::Tx(action) = receive(s, frame).unwrap() else {
            panic!("canonical TX ingress")
        };
        action
    }
    fn operational(s: &mut Station, tid: u8, timeout: u16) -> Arc<Session> {
        let session = request_sent(s, tid);
        let frame = peer_response(&session, session.dialog(), 0, 1024, timeout, true);
        let (ticket, same, agreement) = programming(receive_tx(s, &frame), true);
        assert!(Arc::ptr_eq(&session, &same));
        s.validate_tx_block_ack_program(ticket, &session, agreement)
            .unwrap();
        // SAFETY: model represents exact successful native operational programming.
        let TxAction::Operational {
            session: active, ..
        } = unsafe { s.complete_tx_block_ack_program(ticket, Completion::Accepted) }.unwrap()
        else {
            panic!("native ACK required")
        };
        assert!(Arc::ptr_eq(&active, &session));
        s.validate_tx_block_ack(&session).unwrap();
        session
    }

    #[test]
    fn actual_sequence_peer_response_and_native_ack_are_all_required_before_aggregate_tx() {
        let mut s = station(512);
        let (prepare, session) = prepare(&mut s, 3, 19);
        assert!(s.active_tx_block_ack(3).is_none());
        // SAFETY: modeled synchronized TID/actual next sequence.
        let (wire, _, bytes) = transmit(
            unsafe {
                s.complete_tx_block_ack_prepare(prepare, Completion::Accepted, Some(321), s.now + 1)
            }
            .unwrap(),
        );
        assert_eq!(
            &bytes[24..],
            &[3, 0, session.dialog(), 15, 128, 19, 0, 16, 20, 159, 1, 1]
        );
        let frame = peer_response(&session, session.dialog(), 0, 1024, 9, true);
        assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
        let mut changed = bytes.clone();
        changed[31] ^= 1;
        assert!(
            s.validate_tx_block_ack_transmit(wire, &session, &changed)
                .is_err()
        );
        s.validate_tx_block_ack_transmit(wire, &session, &bytes)
            .unwrap();
        // SAFETY: exact wire publication completed; a real matching early peer
        // response is retained until this acknowledgement, then programs firmware.
        let (program, _, agreement) = programming(
            unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }
                .unwrap(),
            true,
        );
        let wrong = peer_response(&session, session.dialog().wrapping_add(1), 0, 512, 0, true);
        assert!(matches!(receive_tx(&mut s, &wrong), TxAction::None));
        assert_eq!(agreement.unwrap().window(), 512);
        assert_eq!(agreement.unwrap().timeout_tu(), 9);
        assert!(s.validate_tx_block_ack(&session).is_err());
        assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
        s.validate_tx_block_ack_program(program, &session, agreement)
            .unwrap();
        // SAFETY: actual matching firmware install ACK modeled.
        assert!(matches!(
            unsafe { s.complete_tx_block_ack_program(program, Completion::Accepted) }.unwrap(),
            TxAction::Operational { .. }
        ));
        assert_eq!(
            s.validate_tx_block_ack(&session).unwrap(),
            agreement.unwrap()
        );
        // SAFETY: old matching ticket is now stale and cannot activate again.
        assert!(unsafe { s.complete_tx_block_ack_program(program, Completion::Accepted) }.is_err());
    }

    #[test]
    fn genuine_tid_block_preserves_software_cursor_until_synchronized_prepare_snapshot() {
        let mut s = station(1024);
        let context = Arc::clone(s.context.as_ref().unwrap());
        for sequence in 0..17 {
            assert_eq!(s.allocate_qos_sequence(&context, 3), Ok(sequence));
        }
        let (prepare, session) = prepare(&mut s, 3, 0);
        assert!(s.tx_block_ack_blocks_data(3));
        assert_eq!(s.allocate_qos_sequence(&context, 3), Err(Error::Busy));
        assert_eq!(s.next_qos_sequence(&context, 3), Ok(17));
        assert_eq!(s.allocate_qos_sequence(&context, 4), Ok(0));
        // SAFETY: fixture models the actual native synchronization of old TID users
        // before reading this real canonical cursor; independent TIDs keep working.
        let snapshot = s.next_qos_sequence(&context, 3).unwrap();
        let (wire, _, bytes) = transmit(
            unsafe {
                s.complete_tx_block_ack_prepare(
                    prepare,
                    Completion::Accepted,
                    Some(snapshot),
                    s.now + 1,
                )
            }
            .unwrap(),
        );
        assert_eq!(
            u16::from_le_bytes(bytes[31..33].try_into().unwrap()) >> 4,
            17
        );
        // SAFETY: actual request publication then actual peer response modeled.
        unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }.unwrap();
        let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
        let (program, _, _) = programming(receive_tx(&mut s, &frame), true);
        assert_eq!(s.allocate_qos_sequence(&context, 3), Err(Error::Busy));
        // SAFETY: exact successful firmware operation permits the queued TID again.
        unsafe { s.complete_tx_block_ack_program(program, Completion::Accepted) }.unwrap();
        assert!(!s.tx_block_ack_blocks_data(3));
        assert_eq!(s.allocate_qos_sequence(&context, 3), Ok(17));
        s.stop_tx_block_ack(3, false).unwrap();
        assert!(s.tx_block_ack_blocks_data(3));
        assert_eq!(s.allocate_qos_sequence(&context, 3), Err(Error::Busy));
        assert_eq!(s.next_qos_sequence(&context, 3), Ok(18));
    }

    #[test]
    fn early_peer_reply_cannot_bypass_cancelled_rejected_or_uncertain_real_request_publication() {
        for result in [
            Completion::Accepted,
            Completion::RejectedAndIdle,
            Completion::Uncertain,
        ] {
            let mut s = station(1024);
            let (prepare_ticket, session) = prepare(&mut s, 3, 0);
            // SAFETY: actual synchronized software TID counter and retained queue.
            let (wire, _, _) = transmit(
                unsafe {
                    s.complete_tx_block_ack_prepare(
                        prepare_ticket,
                        Completion::Accepted,
                        Some(8),
                        s.now + 1,
                    )
                }
                .unwrap(),
            );
            let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
            assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
            if result == Completion::Accepted {
                let delba = response(0xd0, &[3, 2, 0, 0x30, 37, 0]);
                assert!(matches!(receive_tx(&mut s, &delba), TxAction::None));
            }
            // SAFETY: matching real publication outcome, including uncertain state.
            let action =
                unsafe { s.complete_tx_block_ack_transmit(wire, result, s.now + 1) }.unwrap();
            if result == Completion::Uncertain {
                assert!(matches!(action, TxAction::None));
            } else {
                programming(action, false);
            }
            assert!(s.validate_tx_block_ack(&session).is_err());
        }
    }

    #[test]
    fn decline_and_zero_buffer_stop_without_sending_delba_or_enabling_aggregation() {
        for (status, window) in [(37, 64), (0, 0)] {
            let mut s = station(1024);
            let session = request_sent(&mut s, 3);
            let frame = peer_response(&session, session.dialog(), status, window, 0, true);
            let (ticket, _, agreement) = programming(receive_tx(&mut s, &frame), false);
            s.validate_tx_block_ack_program(ticket, &session, agreement)
                .unwrap();
            // SAFETY: completed actual disable/retirement before legacy queue release.
            assert!(matches!(
                unsafe { s.complete_tx_block_ack_program(ticket, Completion::Accepted) }.unwrap(),
                TxAction::ResumeLegacy { .. }
            ));
            assert!(s.active_tx_block_ack(3).is_none());
        }
    }

    #[test]
    fn non_strict_ht_requests_sixty_four_and_he_caps_request_at_two_fifty_six_before_response_hw_clamp()
     {
        for (mode, hardware_maximum, request_window, peer_window, final_window) in
            [(Mode::Ht, 32, 64, 512, 32), (Mode::He, 512, 256, 768, 512)]
        {
            let mut j = modern_join();
            let source = modern_ies(false);
            let mut local = Vec::new();
            let mut rest = source.as_slice();
            while !rest.is_empty() {
                let size = usize::from(rest[1]);
                let element = &rest[..size + 2];
                let omit = (mode == Mode::Ht && element[0] == 191)
                    || (element[0] == 255
                        && (element.get(2) == Some(&108)
                            || (mode == Mode::Ht && element.get(2) == Some(&35))));
                if !omit {
                    local.extend_from_slice(element);
                }
                rest = &rest[size + 2..];
            }
            let width = if mode == Mode::Ht {
                Width::Mhz40
            } else {
                Width::Mhz80
            };
            j.request = wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, mode, width)
                .unwrap();
            let mut s = Station::new(LOCAL).unwrap();
            let configured = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
            s.complete_configuration(ticket(&configured), Completion::Accepted, 3)
                .unwrap();
            s.configure_tx_block_ack(hardware_maximum).unwrap();
            let (prepare, session) = prepare(&mut s, 3, 0);
            // SAFETY: source canonical software cursor after actual native TID drain.
            let (wire, _, bytes) = transmit(
                unsafe {
                    s.complete_tx_block_ack_prepare(
                        prepare,
                        Completion::Accepted,
                        Some(17),
                        s.now + 1,
                    )
                }
                .unwrap(),
            );
            let parameters = u16::from_le_bytes(bytes[27..29].try_into().unwrap());
            assert_eq!(parameters >> 6, request_window);
            assert_eq!(bytes.len(), if mode == Mode::Ht { 33 } else { 36 });
            // SAFETY: actual request publication modeled before the real peer input.
            unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }
                .unwrap();
            let frame = peer_response(&session, session.dialog(), 0, peer_window, 0, true);
            let (_, _, agreement) = programming(receive_tx(&mut s, &frame), true);
            assert_eq!(agreement.unwrap().window(), final_window);
        }
    }

    #[test]
    fn source_no_amsdu_latches_even_on_wrong_dialog_and_does_not_clear_on_later_yes() {
        let mut s = station(1024);
        let session = operational(&mut s, 3, 0);
        assert!(s.tx_block_ack_allows_software_amsdu(&session).unwrap());
        let frame = peer_response(&session, session.dialog().wrapping_add(1), 0, 64, 0, false);
        assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
        assert!(!s.tx_block_ack_allows_software_amsdu(&session).unwrap());
        let positive = peer_response(&session, session.dialog(), 0, 64, 0, true);
        assert!(matches!(receive_tx(&mut s, &positive), TxAction::None));
        assert!(!s.tx_block_ack_allows_software_amsdu(&session).unwrap());
    }

    #[test]
    fn local_stop_revokes_before_disable_then_delba_publication_before_tid_reuse() {
        let mut s = station(1024);
        let session = operational(&mut s, 3, 0);
        let (stop, _, _) = programming(s.stop_tx_block_ack(3, true).unwrap(), false);
        assert!(s.validate_tx_block_ack(&session).is_err());
        // SAFETY: real disable/old TX callbacks/aggregate owners retired.
        let (wire, _, bytes) = transmit(
            unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
        );
        assert_eq!(&bytes[24..], &[3, 2, 0, 0x38, 37, 0]);
        assert!(matches!(
            s.begin_tx_block_ack(3, 0, s.now + 1),
            Err(BaError::Busy)
        ));
        s.validate_tx_block_ack_transmit(wire, &session, &bytes)
            .unwrap();
        // SAFETY: queued old DELBA cannot be published after a future request.
        assert!(matches!(
            unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }
                .unwrap(),
            TxAction::ResumeLegacy { .. }
        ));
        assert!(matches!(
            s.begin_tx_block_ack(3, 0, s.now + 1).unwrap(),
            TxAction::Prepare { .. }
        ));
    }

    #[test]
    fn recipient_delba_cancels_pending_prepare_request_and_operational_completion() {
        for stage in 0..3 {
            let mut s = station(1024);
            let (prepare_ticket, session) = prepare(&mut s, 3, 0);
            let mut pending = prepare_ticket;
            let mut agreement = None;
            if stage >= 1 {
                // SAFETY: actual synchronized TID state, retained through cancellation.
                let (wire, _, _) = transmit(
                    unsafe {
                        s.complete_tx_block_ack_prepare(
                            pending,
                            Completion::Accepted,
                            Some(3),
                            s.now + 1,
                        )
                    }
                    .unwrap(),
                );
                pending = wire;
            }
            if stage == 2 {
                // SAFETY: request publication acknowledged before actual peer input.
                unsafe {
                    s.complete_tx_block_ack_transmit(pending, Completion::Accepted, s.now + 1)
                }
                .unwrap();
                let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
                let (ticket, _, a) = programming(receive_tx(&mut s, &frame), true);
                pending = ticket;
                agreement = a;
            }
            let delba = response(0xd0, &[3, 2, 0, 0x30, 37, 0]);
            assert!(matches!(receive_tx(&mut s, &delba), TxAction::None));
            assert!(s.active_tx_block_ack(3).is_none());
            match stage {
                0 => assert!(s.validate_tx_block_ack_prepare(pending, &session).is_err()),
                1 => assert!(
                    s.validate_tx_block_ack_transmit(pending, &session, &[])
                        .is_err()
                ),
                _ => assert!(
                    s.validate_tx_block_ack_program(pending, &session, agreement)
                        .is_err()
                ),
            }
            // SAFETY: model the old real operation finishing after peer cancellation.
            let action = unsafe {
                match stage {
                    0 => s.complete_tx_block_ack_prepare(
                        pending,
                        Completion::Accepted,
                        Some(3),
                        s.now + 1,
                    ),
                    1 => s.complete_tx_block_ack_transmit(pending, Completion::Accepted, s.now + 1),
                    _ => s.complete_tx_block_ack_program(pending, Completion::Accepted),
                }
            }
            .unwrap();
            let (stop, _, _) = programming(action, false);
            // SAFETY: only an actual completed stop now releases retained pending TX.
            assert!(matches!(
                unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
                TxAction::ResumeLegacy { .. }
            ));
            assert!(s.validate_tx_block_ack(&session).is_err());
        }
    }

    #[test]
    fn response_and_inactivity_deadlines_use_actual_publication_and_cannot_extend_from_queueing() {
        let mut s = station(1024);
        let session = request_sent(&mut s, 3);
        let due = s.next_tx_block_ack_deadline().unwrap();
        assert!(matches!(
            s.poll_tx_block_ack(due - 1).unwrap(),
            TxAction::None
        ));
        let (stop, _, _) = programming(s.poll_tx_block_ack(due).unwrap(), false);
        let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
        assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
        // SAFETY: actual stop completion modeled.
        let (wire, _, _) = transmit(
            unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
        );
        // SAFETY: terminal rejected old DELBA publication still permits native legacy reuse.
        unsafe { s.complete_tx_block_ack_transmit(wire, Completion::RejectedAndIdle, s.now + 1) }
            .unwrap();

        let active = operational(&mut s, 4, 10);
        let first = s.next_tx_block_ack_deadline().unwrap();
        assert!(matches!(
            s.poll_tx_block_ack(first - 1).unwrap(),
            TxAction::None
        ));
        // SAFETY: only a real current aggregate publication refreshes inactivity.
        unsafe { s.tx_block_ack_published(&active, first - 1) }.unwrap();
        let refreshed = s.next_tx_block_ack_deadline().unwrap();
        assert_eq!(refreshed, first - 1 + 10 * 1024);
        assert!(matches!(
            s.poll_tx_block_ack(first).unwrap(),
            TxAction::None
        ));
        programming(s.poll_tx_block_ack(refreshed).unwrap(), false);
        assert!(s.validate_tx_block_ack(&active).is_err());
    }

    #[test]
    fn source_retry_burst_and_total_limits_count_wire_requests_and_reset_on_peer_acceptance() {
        let mut s = station(1024);
        for attempt in 0..16 {
            if attempt >= 4 {
                assert!(matches!(
                    s.begin_tx_block_ack(3, 0, s.now + 1),
                    Err(BaError::Busy)
                ));
                s.clock(s.now + 15_000_000).unwrap();
            }
            let session = request_sent(&mut s, 3);
            let declined = peer_response(&session, session.dialog(), 37, 64, 0, true);
            let (stop, _, _) = programming(receive_tx(&mut s, &declined), false);
            // SAFETY: each independent native owner actually stopped/drained.
            unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap();
        }
        s.clock(s.now + 15_000_000).unwrap();
        assert!(matches!(
            s.begin_tx_block_ack(3, 0, s.now + 1),
            Err(BaError::Busy)
        ));
        // Other TIDs retain independent budgets. Four actual failed wire requests
        // exhaust the burst, then a real accepted peer resets that TID's count.
        for _ in 0..4 {
            let session = request_sent(&mut s, 4);
            let declined = peer_response(&session, session.dialog(), 37, 64, 0, true);
            let (stop, _, _) = programming(receive_tx(&mut s, &declined), false);
            // SAFETY: matching actual stop completes before this TID's next attempt.
            unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap();
        }
        assert!(matches!(
            s.begin_tx_block_ack(4, 0, s.now + 1),
            Err(BaError::Busy)
        ));
        s.clock(s.now + 15_000_000).unwrap();
        let other = operational(&mut s, 4, 0);
        assert_eq!(other.tid(), 4);
        let (stop, _, _) = programming(s.stop_tx_block_ack(4, false).unwrap(), false);
        // SAFETY: exact native session stop/drain modeled.
        unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap();
        assert!(matches!(
            s.begin_tx_block_ack(4, 0, s.now + 1).unwrap(),
            TxAction::Prepare { .. }
        ));
    }

    #[test]
    fn uncertain_prepare_and_rejected_stop_hold_identity_and_never_release_pending_tx() {
        let mut s = station(1024);
        let (ticket, session) = prepare(&mut s, 3, 0);
        // SAFETY: model explicitly uncertain real preparation; no idle proof.
        assert!(matches!(
            unsafe {
                s.complete_tx_block_ack_prepare(ticket, Completion::Uncertain, None, s.now + 1)
            }
            .unwrap(),
            TxAction::None
        ));
        assert!(matches!(
            s.begin_tx_block_ack(3, 0, s.now + 1),
            Err(BaError::Busy)
        ));
        let (stop, _, _) = programming(s.stop_tx_block_ack(3, false).unwrap(), false);
        // SAFETY: rejected disable is deliberately insufficient for actual retirement.
        assert!(matches!(
            unsafe { s.complete_tx_block_ack_program(stop, Completion::RejectedAndIdle) }.unwrap(),
            TxAction::None
        ));
        assert!(s.validate_tx_block_ack(&session).is_err());
        assert!(matches!(
            s.begin_tx_block_ack(3, 0, s.now + 1),
            Err(BaError::Busy)
        ));
    }

    #[test]
    fn uncertain_operational_ack_cannot_be_replayed_into_success_or_legacy_queue_release() {
        let mut s = station(1024);
        let session = request_sent(&mut s, 3);
        let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
        let (enable, _, _) = programming(receive_tx(&mut s, &frame), true);
        // SAFETY: transport cannot establish the actual terminal command result.
        assert!(matches!(
            unsafe { s.complete_tx_block_ack_program(enable, Completion::Uncertain) }.unwrap(),
            TxAction::None
        ));
        assert!(s.validate_tx_block_ack(&session).is_err());
        // SAFETY: a late old ticket cannot be recast as an activation acknowledgement.
        assert!(unsafe { s.complete_tx_block_ack_program(enable, Completion::Accepted) }.is_err());
        assert!(matches!(
            s.begin_tx_block_ack(3, 0, s.now + 1),
            Err(BaError::Busy)
        ));
        let (stop, _, _) = programming(s.stop_tx_block_ack(3, false).unwrap(), false);
        // SAFETY: independently completed actual disable includes retirement of the
        // old uncertain command callback and every old-session TX user.
        assert!(matches!(
            unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
            TxAction::ResumeLegacy { .. }
        ));
    }

    #[test]
    fn disconnect_revokes_data_and_late_operational_ack_requires_actual_stop_without_delba() {
        let mut s = station(1024);
        let session = request_sent(&mut s, 3);
        let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
        let (enable, _, _) = programming(receive_tx(&mut s, &frame), true);
        let removal = s.disconnect().unwrap();
        assert!(s.validate_tx_block_ack(&session).is_err());
        // SAFETY: old successful operation finishes after actual association revocation.
        let (stop, _, agreement) = programming(
            unsafe { s.complete_tx_block_ack_program(enable, Completion::Accepted) }.unwrap(),
            false,
        );
        s.validate_tx_block_ack_program(stop, &session, agreement)
            .unwrap();
        // SAFETY: independently acknowledged native stop under retained old ownership.
        assert!(matches!(
            unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
            TxAction::ResumeLegacy { .. }
        ));
        s.complete_removal(ticket(&removal), Completion::Accepted)
            .unwrap();
        assert!(s.active_tx_block_ack(3).is_none());
    }
    #[test]
    fn cancellation_validator_requires_exact_pending_ticket_session_and_payload() {
        for stage in 0..3 {
            let mut s = station(1024);
            let (ticket, session) = prepare(&mut s, 3, 0);
            let mut action = TxAction::Prepare {
                ticket,
                session: session.clone(),
            };
            if stage >= 1 {
                // SAFETY: this canonical peer model has synchronized actual TID preparation.
                action = unsafe {
                    s.complete_tx_block_ack_prepare(
                        ticket,
                        Completion::Accepted,
                        Some(3),
                        s.now + 1,
                    )
                }
                .unwrap();
            }
            if stage == 2 {
                let TxAction::Transmit { ticket, .. } = action else {
                    unreachable!()
                };
                // SAFETY: actual modeled publication completed before the peer response.
                unsafe {
                    s.complete_tx_block_ack_transmit(ticket, Completion::Accepted, s.now + 1)
                }
                .unwrap();
                let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
                action = receive_tx(&mut s, &frame);
            }
            assert!(s.validate_tx_block_ack_cancellation(&action).is_err());
            let delba = response(0xd0, &[3, 2, 0, 0x30, 37, 0]);
            assert!(matches!(receive_tx(&mut s, &delba), TxAction::None));
            s.validate_tx_block_ack_cancellation(&action).unwrap();
            let clone = |replacement: Arc<Session>, bad_ticket: bool, bad_payload: bool| {
                let change = |mut ticket: Ticket| {
                    if bad_ticket {
                        ticket.serial += 1;
                    }
                    ticket
                };
                match &action {
                    TxAction::Prepare { ticket, .. } => TxAction::Prepare {
                        ticket: change(*ticket),
                        session: replacement,
                    },
                    TxAction::Transmit { ticket, bytes, .. } => {
                        let mut bytes = bytes.clone();
                        if bad_payload {
                            bytes.push(0);
                        }
                        TxAction::Transmit {
                            ticket: change(*ticket),
                            session: replacement,
                            bytes,
                        }
                    }
                    TxAction::Program {
                        ticket, agreement, ..
                    } => {
                        let agreement = agreement.map(|mut a| {
                            if bad_payload {
                                a.window += 1;
                            }
                            a
                        });
                        TxAction::Program {
                            ticket: change(*ticket),
                            session: replacement,
                            agreement,
                        }
                    }
                    _ => unreachable!(),
                }
            };
            let copied = Arc::new(Session {
                ticket: session.ticket,
                context: session.context.clone(),
                tid: session.tid,
                dialog: session.dialog,
            });
            assert!(
                s.validate_tx_block_ack_cancellation(&clone(copied, false, false))
                    .is_err()
            );
            assert!(
                s.validate_tx_block_ack_cancellation(&clone(session.clone(), true, false))
                    .is_err()
            );
            if stage != 0 {
                assert!(
                    s.validate_tx_block_ack_cancellation(&clone(session.clone(), false, true))
                        .is_err()
                );
            }
            s.validate_tx_block_ack_cancellation(&action).unwrap();
        }
    }
}
