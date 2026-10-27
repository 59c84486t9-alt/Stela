// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2003 Jouni Malinen; 2002-2005 Instant802 Networks, Inc.;
// 2005-2006 Devicescape Software, Inc.; 2006-2007 Jiri Benc;
// 2007 Michael Wu; 2007-2010, 2018-2026 Intel Corporation;
// 2015-2017 Intel Deutschland GmbH. See THIRD_PARTY.md.
//! Current single-link receive Block Ack agreements for driver-owned reorder.
//!
//! Protocol plans do not establish firmware/radio authority. The native owner
//! must serialize these actions with the same current association, qualify
//! management/autonomous radio effects, and await actual queue/firmware ACKs.
//! A session plan becomes usable only through Station's active-session check.
//! Removal invalidates that check immediately; actual uncertain owners remain
//! retained until acknowledged stop or complete association removal/drain.

use super::{AssociationContext, Completion, Phase, Station, Ticket};
use crate::net::wifi::frame::{
    BLOCK_ACK_REQUEST, MAX_AMPDU_BUF_EHT, MAX_AMPDU_BUF_HE, MAX_AMPDU_BUF_HT, Mpdu, TYPE_SUBTYPE,
    next_sequence,
};
use alloc::{sync::Arc, vec::Vec};

pub mod tx;
mod wire;

/// Block Ack agreements exist for the eight user-priority TIDs.
const TIDS: usize = 8;
/// IEEE 802.11 status codes (Linux `WLAN_STATUS_*`).
const DECLINED: u16 = 37;
const INVALID_QOS: u16 = 38;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Station(super::Error),
    InvalidLimits,
    InvalidFrame,
    Truncated,
    Unsupported,
    Busy,
    Stale,
    NoSession,
}
impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        Self::Station(error)
    }
}

/// Exact current native capability limits; observations, never a radio grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Limits {
    window: u16,
    amsdu: bool,
}

/// Immutable protocol/firmware plan, retained by the actual native session.
/// A copy/Arc alone does not prove it is currently active.
#[derive(Debug)]
pub struct RxSession {
    ticket: Ticket,
    context: Arc<AssociationContext>,
    tid: u8,
    start: u16,
    window: u16,
    timeout: u16,
    dialog: u8,
    amsdu: bool,
    extension: u8,
}
impl RxSession {
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }
    pub fn context(&self) -> &Arc<AssociationContext> {
        &self.context
    }
    pub const fn tid(&self) -> u8 {
        self.tid
    }
    pub const fn start_sequence(&self) -> u16 {
        self.start
    }
    pub const fn window(&self) -> u16 {
        self.window
    }
    pub const fn timeout_tu(&self) -> u16 {
        self.timeout
    }
    /// Negotiated RX permission advertised in the positive ADDBA response.
    pub const fn amsdu_in_ampdu(&self) -> bool {
        self.amsdu
    }
    /// Source RX_START initializes params.amsdu=false independently of the
    /// hardware SUPPORTS_AMSDU_IN_AMPDU bit advertised in its air response.
    pub const fn firmware_amsdu(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum Action {
    /// Allocate/activate the exact native RX reorder owner and program its
    /// actual firmware BA state. Stop must cancel/drain those actual users.
    Program {
        ticket: Ticket,
        session: Arc<RxSession>,
        enable: bool,
    },
    /// Actual wire bytes, not an air ACK. Some(session) identifies a newly
    /// acknowledged active agreement; no session is returned for a refusal.
    Transmit {
        ticket: Ticket,
        context: Arc<AssociationContext>,
        bytes: Vec<u8>,
        session: Option<Arc<RxSession>>,
    },
    /// Apply this actual peer/TID's observed BAR SSN only to this active queue.
    Bar {
        session: Arc<RxSession>,
        start_sequence: u16,
    },
    Tx(tx::Action),
    None,
}

#[derive(Debug)]
enum State {
    Installing,
    CancelingInstall,
    Active,
    Stopping {
        ticket: Ticket,
        restart: Option<wire::Request>,
        notify: Option<u16>,
    },
    Quarantined,
}
#[derive(Debug)]
struct Record {
    session: Arc<RxSession>,
    state: State,
}
#[derive(Debug)]
pub(super) struct Sessions {
    context: Option<Arc<AssociationContext>>,
    limits: Option<Limits>,
    records: [Option<Record>; TIDS],
}
impl Sessions {
    pub(super) fn new() -> Self {
        Self {
            context: None,
            limits: None,
            records: core::array::from_fn(|_| None),
        }
    }
}

impl Station {
    /// Native key-batch preflight only: all canonical pending, active, stopping
    /// and quarantined RX/TX agreements must be gone. This is not a hardware,
    /// DMA/IRQ, reordered-buffer or external deferred-user drain proof.
    pub(in crate::net::wifi) fn block_ack_idle(&self) -> bool {
        self.rx_ba.records.iter().all(Option::is_none) && self.tx_ba.is_idle()
    }

    fn ba_context(&self) -> Result<Arc<AssociationContext>, Error> {
        if self.phase != Phase::Associated {
            return Err(Error::Stale);
        }
        let context = self.context.as_ref().ok_or(Error::Unsupported)?;
        self.validate_association_context(context)?;
        let n = context.negotiated();
        if n.ht.is_none() && n.he.is_none() {
            return Err(Error::Unsupported);
        }
        Ok(Arc::clone(context))
    }

    /// Set the actual native RX window and A-MSDU-in-A-MPDU capability after
    /// current association configuration. These values cannot enable a session;
    /// its real native program/ACK and independent radio admission remain needed.
    pub fn configure_rx_block_ack(
        &mut self,
        maximum_window: u16,
        amsdu: bool,
    ) -> Result<(), Error> {
        if maximum_window == 0 || maximum_window > MAX_AMPDU_BUF_EHT {
            return Err(Error::InvalidLimits);
        }
        let context = self.ba_context()?;
        let limits = Limits {
            window: maximum_window,
            amsdu,
        };
        if self.rx_ba.records.iter().any(Option::is_some)
            && (self.rx_ba.limits != Some(limits)
                || self
                    .rx_ba
                    .context
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &context)))
        {
            return Err(Error::Busy);
        }
        self.rx_ba.context = Some(context);
        self.rx_ba.limits = Some(limits);
        Ok(())
    }

    /// Identity/lifecycle preflight only; the native owner must also retain its
    /// actual queue/peer/key context through every RX completion and release.
    pub fn validate_rx_block_ack(&self, session: &RxSession) -> Result<(), Error> {
        self.validate_association_context(&session.context)?;
        if self.phase != Phase::Associated {
            return Err(Error::Stale);
        }
        let record = self
            .rx_ba
            .records
            .get(usize::from(session.tid))
            .and_then(Option::as_ref)
            .ok_or(Error::NoSession)?;
        if !core::ptr::eq(record.session.as_ref(), session)
            || !matches!(record.state, State::Active)
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    pub fn active_rx_block_ack(&self, tid: u8) -> Option<&Arc<RxSession>> {
        let record = self.rx_ba.records.get(usize::from(tid))?.as_ref()?;
        self.validate_rx_block_ack(&record.session).ok()?;
        Some(&record.session)
    }

    /// Recheck the private pending action immediately before its actual native
    /// publication. This does not grant radio authority or establish an ACK.
    /// Stopping remains possible after disconnect/revocation without TX grants.
    pub fn validate_rx_block_ack_program(
        &self,
        ticket: Ticket,
        session: &RxSession,
        enable: bool,
    ) -> Result<(), Error> {
        if session.ticket.epoch() != self.epoch
            || self
                .context
                .as_ref()
                .is_none_or(|c| !core::ptr::eq(c.as_ref(), session.context.as_ref()))
        {
            return Err(Error::Stale);
        }
        let record = self
            .rx_ba
            .records
            .get(usize::from(session.tid))
            .and_then(Option::as_ref)
            .ok_or(Error::NoSession)?;
        if !core::ptr::eq(record.session.as_ref(), session) {
            return Err(Error::Stale);
        }
        let matches = if enable {
            self.phase == Phase::Associated
                && ticket == session.ticket
                && matches!(record.state, State::Installing)
        } else {
            matches!(record.state, State::Stopping { ticket: pending, .. } if pending == ticket)
        };
        if matches { Ok(()) } else { Err(Error::Stale) }
    }

    fn ba_response(
        &mut self,
        request: wire::Request,
        window: u16,
        status: u16,
        session: Option<Arc<RxSession>>,
    ) -> Result<Action, Error> {
        let context = self.ba_context()?;
        let limits = self.rx_ba.limits.ok_or(Error::InvalidLimits)?;
        let ticket = self.ticket()?;
        let bytes = wire::response(
            self.local,
            context.bssid(),
            self.sequence,
            request,
            wire::Reply {
                window,
                status,
                amsdu: limits.amsdu,
                he: context.negotiated().he.is_some(),
            },
        );
        self.sequence = next_sequence(self.sequence);
        Ok(Action::Transmit {
            ticket,
            context,
            bytes,
            session,
        })
    }

    fn ba_receive_request(&mut self, request: wire::Request) -> Result<Action, Error> {
        let context = self.ba_context()?;
        let limits = self.rx_ba.limits.ok_or(Error::InvalidLimits)?;
        if self
            .rx_ba
            .context
            .as_ref()
            .is_none_or(|c| !Arc::ptr_eq(c, &context))
        {
            return Err(Error::Stale);
        }
        let n = context.negotiated();
        let maximum = if n.eht.is_some() {
            MAX_AMPDU_BUF_EHT
        } else if n.he.is_some() {
            MAX_AMPDU_BUF_HE
        } else {
            MAX_AMPDU_BUF_HT
        };
        if request.tid >= TIDS as u8 {
            return self.ba_response(request, request.window, DECLINED, None);
        }
        if !request.immediate || request.window > maximum {
            return self.ba_response(request, request.window, INVALID_QOS, None);
        }
        let window = if request.window == 0 {
            maximum
        } else {
            request.window
        }
        .min(limits.window);
        let index = usize::from(request.tid);
        if let Some(record) = self.rx_ba.records[index].as_ref() {
            // The selected driver-reorder source profile has no generic tid_rx
            // to update. A same-dialog retransmission therefore declines.
            if !matches!(record.state, State::Active) || record.session.dialog == request.dialog {
                return self.ba_response(request, window, DECLINED, None);
            }
            let ticket = self.ticket()?;
            let record = self.rx_ba.records[index].as_mut().unwrap();
            record.state = State::Stopping {
                ticket,
                restart: Some(request),
                notify: None,
            };
            return Ok(Action::Program {
                ticket,
                session: Arc::clone(&record.session),
                enable: false,
            });
        }
        let ticket = self.ticket()?;
        let session = Arc::new(RxSession {
            ticket,
            context,
            tid: request.tid,
            start: request.start,
            window,
            timeout: request.timeout,
            dialog: request.dialog,
            amsdu: limits.amsdu,
            extension: request.extension,
        });
        self.rx_ba.records[index] = Some(Record {
            session: Arc::clone(&session),
            state: State::Installing,
        });
        Ok(Action::Program {
            ticket,
            session,
            enable: true,
        })
    }

    /// `epoch` is retained from the actual source RX owner; do not retag old
    /// deferred input with a fresh current epoch. The present non-PMF path only
    /// accepts ordinary unprotected management; protected-management ingress is
    /// separate and must authenticate before extending this path.
    pub fn receive_block_ack(
        &mut self,
        epoch: u64,
        frame: &Mpdu,
        now_us: u64,
    ) -> Result<Action, Error> {
        self.clock(now_us)?;
        let context = self.ba_context()?;
        if epoch != self.epoch {
            return Err(Error::Stale);
        }
        let channel = self.operating_definition().ok_or(Error::Stale)?.control;
        if (
            frame.radio.band,
            frame.radio.channel,
            frame.radio.frequency_mhz,
        ) != (channel.band, channel.number, channel.frequency_mhz)
        {
            return Err(Error::Station(super::Error::WrongChannel));
        }
        if frame.fcs_error
            || frame.monitor_only
            || frame.aggregation != crate::net::wifi::Aggregation::default()
            || frame.header().fragmented()
        {
            return Err(Error::InvalidFrame);
        }
        if frame.header().control & TYPE_SUBTYPE == BLOCK_ACK_REQUEST {
            let (tid, sequence) = wire::bar(frame, self.local, context.bssid())?;
            let session = self.active_rx_block_ack(tid).ok_or(Error::NoSession)?;
            return Ok(Action::Bar {
                session: Arc::clone(session),
                start_sequence: sequence,
            });
        }
        if context.pmf().is_some() {
            return Err(Error::Unsupported);
        }
        super::wire::check_peer(frame, self.local, context.bssid()).map_err(super::Error::Wire)?;
        let action = wire::action(
            frame,
            context.negotiated().he.is_some(),
            context.negotiated().eht.is_some(),
        )?;
        self.receive_ba_action(action)
    }

    /// Internal native boundary, never an authentication constructor. The caller
    /// must own the original authenticated plaintext and current retained key
    /// session, and hold both real OS/hardware guards while applying this action.
    /// The original protected header and body are kept separate and unchanged.
    pub(in crate::net::wifi) fn receive_authenticated_block_ack(
        &mut self,
        original: &AssociationContext,
        frame: &Mpdu,
        body: &[u8],
        now_us: u64,
    ) -> Result<Action, Error> {
        self.validate_association_context(original)?;
        let context = self.ba_context()?;
        let h = frame.header();
        if h.control & TYPE_SUBTYPE != crate::net::wifi::frame::ACTION
            || !h.protected()
            || h.control & 0x830c != 0
            || h.length != 24
            || h.fragmented()
            || h.receiver != self.local
            || h.transmitter != Some(context.bssid())
            || frame.bytes()[16..22] != context.bssid().0
            || frame.fcs_error
            || frame.monitor_only
            || frame.aggregation != crate::net::wifi::Aggregation::default()
        {
            return Err(Error::InvalidFrame);
        }
        if (
            frame.radio.band,
            frame.radio.channel,
            frame.radio.frequency_mhz,
        ) != (
            context.channel().band,
            context.channel().number,
            context.channel().frequency_mhz,
        ) {
            return Err(Error::Station(super::Error::WrongChannel));
        }
        let action = wire::action_body(
            body,
            context.negotiated().he.is_some(),
            context.negotiated().eht.is_some(),
        )?;
        self.clock(now_us)?;
        self.receive_ba_action(action)
    }

    fn receive_ba_action(&mut self, action: wire::Management) -> Result<Action, Error> {
        match action {
            wire::Management::Request(request) => self.ba_receive_request(request),
            wire::Management::Delete {
                tid,
                initiator: true,
                ..
            } => {
                let Some(record) = self
                    .rx_ba
                    .records
                    .get_mut(usize::from(tid))
                    .and_then(Option::as_mut)
                else {
                    return Ok(Action::None);
                };
                match &mut record.state {
                    State::Installing => {
                        // A late install ACK must lead to stop/drain, never a
                        // positive response or a revived agreement. If native
                        // publication has not started, its preflight now fails.
                        record.state = State::CancelingInstall;
                        Ok(Action::None)
                    }
                    State::CancelingInstall => Ok(Action::None),
                    State::Stopping {
                        restart, notify, ..
                    } => {
                        // Preserve the existing actual stop ticket/owner while
                        // cancelling the queued replacement and local reply.
                        *restart = None;
                        *notify = None;
                        Ok(Action::None)
                    }
                    State::Active | State::Quarantined => self.stop_rx_block_ack(tid, None),
                }
            }
            wire::Management::Response {
                dialog,
                tid,
                window,
                timeout,
                status,
                amsdu,
            } => self
                .tx_ba_response(dialog, tid, window, timeout, status, amsdu)
                .map(Action::Tx),
            wire::Management::Delete {
                tid,
                initiator: false,
                ..
            } => {
                if self.tx_ba.has_session(tid) {
                    self.stop_tx_block_ack(tid, false).map(Action::Tx)
                } else {
                    Ok(Action::Tx(tx::Action::None))
                }
            }
        }
    }

    /// Invalidate before native stop. A local reason sends DELBA only after an
    /// actual acknowledged stop/drain; peer/replacement teardown passes None.
    pub fn stop_rx_block_ack(&mut self, tid: u8, reason: Option<u16>) -> Result<Action, Error> {
        if usize::from(tid) >= TIDS {
            return Err(Error::NoSession);
        }
        let record = self.rx_ba.records[usize::from(tid)]
            .as_ref()
            .ok_or(Error::NoSession)?;
        if matches!(record.state, State::Stopping { .. }) {
            return Err(Error::Busy);
        }
        let ticket = self.ticket()?;
        let record = self.rx_ba.records[usize::from(tid)].as_mut().unwrap();
        record.state = State::Stopping {
            ticket,
            restart: None,
            notify: reason,
        };
        Ok(Action::Program {
            ticket,
            session: Arc::clone(&record.session),
            enable: false,
        })
    }

    /// # Safety
    /// The result belongs to this exact pending program ticket and physical
    /// peer/association. Accepted start means the real reorder owner is ready
    /// and firmware BA install ACKed. Accepted stop means actual BA disable ACK,
    /// session reorder/timer cancellation and retirement of buffered/callback/
    /// already-owned old-session RX users. Controller DMA/requester/key owners
    /// remain independently retained; this is not requester-wide DMA quiescence
    /// or a claim that frames carry a wire BA generation. Preserve already
    /// classified/deferred batches' original context rather than retagging them.
    /// RejectedAndIdle for an install requires independently established idle/
    /// retired resources; a rejected stop always retains its owner. Otherwise
    /// report Uncertain and retain all actual owners. This is not a
    /// way to qualify a command encoder or synthesize a firmware completion.
    pub unsafe fn complete_rx_block_ack(
        &mut self,
        ticket: Ticket,
        result: Completion,
    ) -> Result<Action, Error> {
        let index = self
            .rx_ba
            .records
            .iter()
            .position(|record| {
                record.as_ref().is_some_and(|r| match r.state {
                    State::Installing | State::CancelingInstall => r.session.ticket == ticket,
                    State::Stopping {
                        ticket: pending, ..
                    } => pending == ticket,
                    _ => false,
                })
            })
            .ok_or(Error::Stale)?;
        let installing = matches!(
            self.rx_ba.records[index].as_ref().unwrap().state,
            State::Installing | State::CancelingInstall
        );
        let canceled = matches!(
            self.rx_ba.records[index].as_ref().unwrap().state,
            State::CancelingInstall
        );
        if installing && !canceled && self.phase != Phase::Associated {
            return Err(Error::Stale);
        }
        if result == Completion::Uncertain {
            self.rx_ba.records[index].as_mut().unwrap().state = State::Quarantined;
            return Ok(Action::None);
        }
        // A rejected stop is not proof of retirement; keep its actual owner.
        if !installing && result != Completion::Accepted {
            self.rx_ba.records[index].as_mut().unwrap().state = State::Quarantined;
            return Ok(Action::None);
        }
        if canceled {
            if result == Completion::Accepted {
                return self.stop_rx_block_ack(index as u8, None);
            }
            self.rx_ba.records[index] = None;
            return Ok(Action::None);
        }
        if installing {
            let session = Arc::clone(&self.rx_ba.records[index].as_ref().unwrap().session);
            self.validate_association_context(&session.context)?;
            let request = wire::Request {
                dialog: session.dialog,
                tid: session.tid,
                start: session.start,
                window: session.window,
                timeout: session.timeout,
                immediate: true,
                extension: session.extension,
            };
            if result == Completion::Accepted {
                self.rx_ba.records[index].as_mut().unwrap().state = State::Active;
                self.ba_response(request, session.window, 0, Some(session))
            } else {
                self.rx_ba.records[index] = None;
                self.ba_response(request, session.window, DECLINED, None)
            }
        } else {
            let record = self.rx_ba.records[index].take().unwrap();
            let State::Stopping {
                restart, notify, ..
            } = record.state
            else {
                unreachable!()
            };
            // Disconnect revokes transmission/new agreements immediately even
            // though an independently completed stop can retire the old queue.
            if self.phase != Phase::Associated {
                return Ok(Action::None);
            }
            self.validate_association_context(&record.session.context)?;
            if let Some(request) = restart {
                return self.ba_receive_request(request);
            }
            if let Some(reason) = notify {
                let ticket = self.ticket()?;
                let bytes = wire::delete(
                    self.local,
                    record.session.context.bssid(),
                    self.sequence,
                    record.session.tid,
                    false,
                    reason,
                );
                self.sequence = next_sequence(self.sequence);
                return Ok(Action::Transmit {
                    ticket,
                    context: record.session.context.clone(),
                    bytes,
                    session: None,
                });
            }
            Ok(Action::None)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::net::wifi::security::SecurityStatus;
    use crate::net::wifi::station::ba::{Action as BaAction, Error as BaError, RxSession};
    use crate::net::wifi::station::{tests::*, *};

    pub(crate) fn associated(maximum: u16, amsdu: bool) -> Station {
        let mut s = Station::new(LOCAL).unwrap();
        let j = modern_join();
        let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
        s.complete_configuration(ticket(&a), Completion::Accepted, 3)
            .unwrap();
        s.configure_rx_block_ack(maximum, amsdu).unwrap();
        s
    }
    pub(crate) fn request(
        dialog: u8,
        tid: u8,
        window: u16,
        timeout: u16,
        start: u16,
        immediate: bool,
    ) -> Mpdu {
        let parameters = u16::from(tid) << 2 | (window & 1023) << 6 | if immediate { 2 } else { 0 };
        let mut body = vec![3, 0, dialog];
        body.extend_from_slice(&parameters.to_le_bytes());
        body.extend_from_slice(&timeout.to_le_bytes());
        body.extend_from_slice(&(start << 4).to_le_bytes());
        if window >= 1024 {
            body.extend_from_slice(&[159, 1, 1 | ((window >> 10) as u8) << 5]);
        }
        response(0xd0, &body)
    }
    pub(crate) fn receive(s: &mut Station, frame: &Mpdu) -> Result<BaAction, BaError> {
        s.receive_block_ack(s.association_epoch().unwrap(), frame, s.now + 1)
    }
    pub(crate) fn program(a: BaAction, enable: bool) -> (Ticket, Arc<RxSession>) {
        let BaAction::Program {
            ticket,
            session,
            enable: actual,
        } = a
        else {
            panic!("program expected")
        };
        assert_eq!(actual, enable);
        (ticket, session)
    }
    pub(crate) fn status(a: BaAction) -> (u16, Vec<u8>) {
        let BaAction::Transmit {
            bytes,
            session: None,
            ..
        } = a
        else {
            panic!("refusal wire expected")
        };
        (u16::from_le_bytes(bytes[27..29].try_into().unwrap()), bytes)
    }
    pub(crate) fn active(s: &mut Station, dialog: u8, tid: u8) -> Arc<RxSession> {
        let (ticket, planned) = program(
            receive(s, &request(dialog, tid, 64, 0, 10, true)).unwrap(),
            true,
        );
        s.validate_rx_block_ack_program(ticket, &planned, true)
            .unwrap();
        // SAFETY: this pure fixture models exact completed native install/queue readiness.
        let a = unsafe { s.complete_rx_block_ack(ticket, Completion::Accepted) }.unwrap();
        let BaAction::Transmit {
            session: Some(installed),
            bytes,
            ..
        } = a
        else {
            panic!("positive reply")
        };
        assert_eq!(u16::from_le_bytes(bytes[27..29].try_into().unwrap()), 0);
        assert!(Arc::ptr_eq(&planned, &installed));
        s.validate_rx_block_ack(&installed).unwrap();
        installed
    }

    #[test]
    fn only_real_current_native_install_completion_activates_exact_session_and_positive_reply() {
        let mut s = associated(1024, true);
        let (t, session) = program(
            receive(&mut s, &request(7, 3, 1024, 19, 4095, true)).unwrap(),
            true,
        );
        assert!(s.active_rx_block_ack(3).is_none());
        assert!(s.validate_rx_block_ack(&session).is_err());
        assert_eq!(
            (
                session.tid(),
                session.start_sequence(),
                session.window(),
                session.timeout_tu()
            ),
            (3, 4095, 1024, 19)
        );
        assert!(session.amsdu_in_ampdu());
        assert!(!session.firmware_amsdu());
        s.validate_rx_block_ack_program(t, &session, true).unwrap();
        // SAFETY: modeled exact native command/queue acknowledgement only.
        let a = unsafe { s.complete_rx_block_ack(t, Completion::Accepted) }.unwrap();
        let BaAction::Transmit {
            bytes,
            session: Some(installed),
            context,
            ..
        } = a
        else {
            panic!("positive reply")
        };
        assert_eq!(&bytes[24..], &[3, 1, 7, 0, 0, 15, 0, 19, 0, 159, 1, 0x21]);
        assert!(Arc::ptr_eq(&context, session.context()));
        assert!(Arc::ptr_eq(&installed, &session));
        assert!(s.validate_rx_block_ack_program(t, &session, true).is_err());
        assert!(s.validate_rx_block_ack(&session).is_ok());
        // SAFETY: duplicate completion must not mutate or return another positive reply.
        assert!(matches!(
            unsafe { s.complete_rx_block_ack(t, Completion::Accepted) },
            Err(BaError::Stale)
        ));
    }

    #[test]
    fn default_window_and_actual_hardware_clamp_are_applied_after_source_validation() {
        let mut s = associated(256, false);
        let (_, session) = program(
            receive(&mut s, &request(1, 0, 0, 0, 10, true)).unwrap(),
            true,
        );
        assert_eq!(session.window(), 256);
        assert!(!session.amsdu_in_ampdu());
        assert_eq!(s.configure_rx_block_ack(512, false), Err(BaError::Busy));
        assert_eq!(
            s.configure_rx_block_ack(0, false),
            Err(BaError::InvalidLimits)
        );
        assert_eq!(
            s.configure_rx_block_ack(1025, false),
            Err(BaError::InvalidLimits)
        );
    }

    #[test]
    fn unrelated_generic_ie_errors_ignore_extension_and_keep_valid_base_addba_request() {
        for tail in [vec![3, 0], vec![0, 0, 0, 0], vec![196, 0]] {
            let mut s = associated(1024, true);
            let original = request(1, 3, 32, 0, 10, true);
            let mut bytes = original.bytes().to_vec();
            bytes.extend_from_slice(&[159, 1, 0x21]);
            bytes.extend_from_slice(&tail);
            let frame = Mpdu::new(bytes, original.radio, original.security).unwrap();
            let (_, session) = program(receive(&mut s, &frame).unwrap(), true);
            assert_eq!(session.window(), 32);
        }
    }

    #[test]
    fn source_invalid_tid_policy_and_oversize_refusals_keep_actual_air_parameters() {
        for (tid, window, immediate, expected) in [
            (15, 512, true, 37),
            (3, 512, false, 38),
            (3, 2048, true, 38),
        ] {
            let mut s = associated(64, true);
            let (code, bytes) =
                status(receive(&mut s, &request(9, tid, window, 7, 10, immediate)).unwrap());
            assert_eq!(code, expected);
            let parameters = u16::from_le_bytes(bytes[29..31].try_into().unwrap());
            assert_eq!((parameters >> 2) & 15, u16::from(tid));
            assert_eq!(parameters >> 6, window & 1023);
            assert_eq!(bytes[35] >> 5, (window >> 10) as u8);
            assert!(s.active_rx_block_ack(tid).is_none());
        }
    }

    #[test]
    fn same_dialog_source_driver_reorder_profile_declines_without_resetting_live_queue() {
        let mut s = associated(1024, true);
        let session = active(&mut s, 7, 3);
        for timeout in [0, 90] {
            assert_eq!(
                status(receive(&mut s, &request(7, 3, 32, timeout, 20, true)).unwrap()).0,
                37
            );
            assert!(Arc::ptr_eq(s.active_rx_block_ack(3).unwrap(), &session));
        }
    }

    #[test]
    fn replacement_stops_and_invalidates_old_session_before_programming_new_exact_ssn() {
        let mut s = associated(1024, true);
        let old = active(&mut s, 1, 3);
        let (stop, stopping) = program(
            receive(&mut s, &request(2, 3, 32, 9, 22, true)).unwrap(),
            false,
        );
        assert!(Arc::ptr_eq(&old, &stopping));
        assert!(s.active_rx_block_ack(3).is_none());
        assert!(s.validate_rx_block_ack(&old).is_err());
        s.validate_rx_block_ack_program(stop, &old, false).unwrap();
        // SAFETY: pure model supplies actual completed stop/drain.
        let (install, next) = program(
            unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
            true,
        );
        assert_ne!(install, old.ticket());
        assert!(!Arc::ptr_eq(&next, &old));
        assert_eq!(
            (next.start_sequence(), next.window(), next.timeout_tu()),
            (22, 32, 9)
        );
        assert!(s.validate_rx_block_ack(&next).is_err());
        // SAFETY: second native install is independently acknowledged.
        unsafe { s.complete_rx_block_ack(install, Completion::Accepted) }.unwrap();
        s.validate_rx_block_ack(&next).unwrap();
        assert!(s.validate_rx_block_ack(&old).is_err());
    }

    #[test]
    fn rejected_idle_install_refuses_peer_while_uncertain_install_retains_and_cannot_retry() {
        for outcome in [Completion::RejectedAndIdle, Completion::Uncertain] {
            let mut s = associated(1024, true);
            let (ticket, old) = program(
                receive(&mut s, &request(1, 0, 64, 0, 5, true)).unwrap(),
                true,
            );
            // SAFETY: fixture explicitly distinguishes a truly idle rejection from uncertainty.
            let action = unsafe { s.complete_rx_block_ack(ticket, outcome) }.unwrap();
            if outcome == Completion::RejectedAndIdle {
                assert_eq!(status(action).0, 37);
                program(
                    receive(&mut s, &request(2, 0, 64, 0, 9, true)).unwrap(),
                    true,
                );
            } else {
                assert!(matches!(action, BaAction::None));
                assert_eq!(
                    status(receive(&mut s, &request(2, 0, 64, 0, 9, true)).unwrap()).0,
                    37
                );
                let (stop, held) = program(s.stop_rx_block_ack(0, None).unwrap(), false);
                assert!(Arc::ptr_eq(&held, &old));
                // SAFETY: only subsequent actual stop/drain can retire this owner.
                assert!(matches!(
                    unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
                    BaAction::None
                ));
            }
            assert!(s.validate_rx_block_ack(&old).is_err());
        }
    }

    #[test]
    fn failed_stop_never_releases_or_restarts_the_old_ownership() {
        let mut s = associated(1024, true);
        let old = active(&mut s, 1, 0);
        let (ticket, _) = program(s.stop_rx_block_ack(0, Some(37)).unwrap(), false);
        // SAFETY: a rejected disable is not actual retirement and stays quarantined.
        assert!(matches!(
            unsafe { s.complete_rx_block_ack(ticket, Completion::RejectedAndIdle) }.unwrap(),
            BaAction::None
        ));
        assert!(s.active_rx_block_ack(0).is_none());
        assert_eq!(
            status(receive(&mut s, &request(2, 0, 64, 0, 10, true)).unwrap()).0,
            37
        );
        let (again, held) = program(s.stop_rx_block_ack(0, None).unwrap(), false);
        assert!(Arc::ptr_eq(&held, &old));
        assert_ne!(again, ticket);
    }

    #[test]
    fn local_delba_is_sent_only_after_disable_drain_with_recipient_direction() {
        let mut s = associated(1024, true);
        let old = active(&mut s, 1, 3);
        let (ticket, _) = program(s.stop_rx_block_ack(3, Some(37)).unwrap(), false);
        assert!(s.validate_rx_block_ack(&old).is_err());
        // SAFETY: native firmware stop and real queue retirement acknowledged.
        let BaAction::Transmit {
            bytes,
            session: None,
            ..
        } = unsafe { s.complete_rx_block_ack(ticket, Completion::Accepted) }.unwrap()
        else {
            panic!("DELBA after stop")
        };
        assert_eq!(&bytes[24..], &[3, 2, 0, 0x30, 37, 0]);
    }

    #[test]
    fn actual_peer_initiator_delba_stops_rx_without_sending_a_reply() {
        let mut s = associated(1024, true);
        active(&mut s, 1, 3);
        let frame = response(0xd0, &[3, 2, 0, 0x38, 37, 0]);
        let (ticket, _) = program(receive(&mut s, &frame).unwrap(), false);
        // SAFETY: actual native stop/drain completed in the fixture.
        assert!(matches!(
            unsafe { s.complete_rx_block_ack(ticket, Completion::Accepted) }.unwrap(),
            BaAction::None
        ));
    }

    #[test]
    fn peer_delba_cancels_pending_install_and_late_ack_requires_stop_instead_of_success() {
        for result in [
            Completion::Accepted,
            Completion::RejectedAndIdle,
            Completion::Uncertain,
        ] {
            let mut s = associated(1024, true);
            let (install, session) = program(
                receive(&mut s, &request(1, 3, 64, 0, 10, true)).unwrap(),
                true,
            );
            let delba = response(0xd0, &[3, 2, 0, 0x38, 37, 0]);
            assert!(matches!(receive(&mut s, &delba).unwrap(), BaAction::None));
            assert!(
                s.validate_rx_block_ack_program(install, &session, true)
                    .is_err()
            );
            // SAFETY: model returns the real outstanding install outcome after cancellation.
            let next = unsafe { s.complete_rx_block_ack(install, result) }.unwrap();
            assert!(s.active_rx_block_ack(3).is_none());
            if result == Completion::Accepted {
                let (stop, held) = program(next, false);
                assert!(Arc::ptr_eq(&held, &session));
                // SAFETY: only stop/drain of the late successful install retires it.
                assert!(matches!(
                    unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
                    BaAction::None
                ));
            } else {
                assert!(matches!(next, BaAction::None));
            }
            assert!(s.validate_rx_block_ack(&session).is_err());
        }
    }

    #[test]
    fn peer_delba_cancels_replacement_while_old_disable_is_still_pending() {
        let mut s = associated(1024, true);
        let old = active(&mut s, 1, 3);
        let (stop, _) = program(
            receive(&mut s, &request(2, 3, 32, 0, 90, true)).unwrap(),
            false,
        );
        let delba = response(0xd0, &[3, 2, 0, 0x38, 37, 0]);
        assert!(matches!(receive(&mut s, &delba).unwrap(), BaAction::None));
        s.validate_rx_block_ack_program(stop, &old, false).unwrap();
        // SAFETY: completing this old stop cannot trigger the cancelled new install.
        assert!(matches!(
            unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
            BaAction::None
        ));
        assert!(s.active_rx_block_ack(3).is_none());
    }

    #[test]
    fn wrong_peer_radio_epoch_integrity_and_protected_actions_cannot_create_agreements() {
        let original = request(1, 0, 64, 0, 5, true);
        for mutation in 0..5 {
            let mut s = associated(1024, true);
            let mut frame = original.clone();
            match mutation {
                0 => frame.radio.channel += 4,
                1 => frame.fcs_error = true,
                2 => frame.monitor_only = true,
                3 => {
                    let mut b = frame.bytes().to_vec();
                    b[10] ^= 4;
                    frame = Mpdu::new(b, frame.radio, frame.security).unwrap();
                }
                _ => {
                    let mut b = frame.bytes().to_vec();
                    b[1] |= 0x40;
                    frame = Mpdu::new(b, frame.radio, frame.security).unwrap();
                }
            }
            assert!(receive(&mut s, &frame).is_err());
            assert!(s.active_rx_block_ack(0).is_none());
        }
        let mut s = associated(1024, true);
        assert!(matches!(
            s.receive_block_ack(s.epoch + 1, &original, 4),
            Err(BaError::Stale)
        ));
    }

    #[test]
    fn bar_requires_exact_current_peer_tid_and_acknowledged_active_queue() {
        let mut s = associated(1024, true);
        let current = active(&mut s, 1, 3);
        let mut bytes = vec![0; 20];
        bytes[..2].copy_from_slice(&0x0084u16.to_le_bytes());
        bytes[4..10].copy_from_slice(&LOCAL.0);
        bytes[10..16].copy_from_slice(&AP.0);
        bytes[16..18].copy_from_slice(&0x3004u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x1230u16.to_le_bytes());
        let frame = Mpdu::new(
            bytes.clone(),
            response(0xd0, &[]).radio,
            SecurityStatus::default(),
        )
        .unwrap();
        let BaAction::Bar {
            session,
            start_sequence,
        } = receive(&mut s, &frame).unwrap()
        else {
            panic!("actual BAR")
        };
        assert!(Arc::ptr_eq(&session, &current));
        assert_eq!(start_sequence, 0x123);
        bytes[17] = 0x40;
        let other = Mpdu::new(bytes, frame.radio.clone(), SecurityStatus::default()).unwrap();
        assert!(matches!(receive(&mut s, &other), Err(BaError::NoSession)));
        s.stop_rx_block_ack(3, None).unwrap();
        assert!(matches!(receive(&mut s, &frame), Err(BaError::NoSession)));
    }

    #[test]
    fn disconnect_revokes_pending_install_and_active_sessions_but_allows_actual_stop() {
        let mut s = associated(1024, true);
        let installed = active(&mut s, 1, 3);
        let (pending, plan) = program(
            receive(&mut s, &request(2, 4, 64, 0, 5, true)).unwrap(),
            true,
        );
        let removal = s.disconnect().unwrap();
        assert!(s.validate_rx_block_ack(&installed).is_err());
        assert!(
            s.validate_rx_block_ack_program(pending, &plan, true)
                .is_err()
        );
        // SAFETY: late ACK is rejected; it cannot revive a disconnected association.
        assert!(matches!(
            unsafe { s.complete_rx_block_ack(pending, Completion::Accepted) },
            Err(BaError::Stale)
        ));
        let (stop, old) = program(s.stop_rx_block_ack(3, Some(37)).unwrap(), false);
        s.validate_rx_block_ack_program(stop, &old, false).unwrap();
        // SAFETY: acknowledged stop during disconnect cannot send a new management frame.
        assert!(matches!(
            unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
            BaAction::None
        ));
        s.complete_removal(ticket(&removal), Completion::Accepted)
            .unwrap();
        assert!(matches!(
            s.stop_rx_block_ack(4, None),
            Err(BaError::NoSession)
        ));
    }
}
