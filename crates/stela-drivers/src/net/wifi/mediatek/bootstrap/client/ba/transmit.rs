// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
//! Native source TX_START/TX_OPERATIONAL/TX_STOP owners. Canonical Station owns
//! the management exchange/counters; firmware owns actual air sequence/PN.
use super::*;
use station::ba::tx::{Action, Agreement, Session};
#[cfg(test)]
mod tests;

pub(crate) struct Transmit<C: 'static> {
    _resource: Arc<C>,
    session: Arc<Session>,
    blocked: bool,
    agreement: Option<Agreement>,
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// Request the same actual source TID's aggregation exchange. New borrowed
    /// Ethernet submissions return Busy while blocked; their caller retains
    /// those bytes. Already-published packets stay in the original DataRing.
    pub fn begin_tx_block_ack(&mut self, tid: u8, timeout_tu: u16, now: u64) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated || s.modern.is_none() {
            return Err(Error::WrongPhase);
        }
        s.ba_actions.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let action = s
            .station
            .begin_tx_block_ack(tid, timeout_tu, now)
            .map_err(Error::BlockAck)?;
        Self::queue_tx_ba(s, action, now)
    }

    pub(super) fn queue_tx_ba(
        s: &mut Owned<I, Q, C>,
        action: Action,
        now: u64,
    ) -> Result<(), Error> {
        match action {
            Action::None => match Self::reconcile_tx_ba(s, now) {
                Ok(_) | Err(Error::NeedsDrain) => Ok(()),
                Err(error) => Err(error),
            },
            Action::Operational { session, agreement } => {
                let native = s.transmit_ba[usize::from(session.tid())]
                    .as_mut()
                    .ok_or(Error::WrongPhase)?;
                if !Arc::ptr_eq(&native.session, &session) {
                    return Err(Error::WrongPhase);
                }
                s.station
                    .validate_tx_block_ack(&session)
                    .map_err(Error::BlockAck)?;
                native.agreement = Some(agreement);
                native.blocked = false;
                Ok(())
            }
            Action::ResumeLegacy { session } => {
                let native = s.transmit_ba[usize::from(session.tid())]
                    .as_ref()
                    .ok_or(Error::WrongPhase)?;
                if !Arc::ptr_eq(&native.session, &session)
                    || s.controller
                        .state()
                        .data_tx
                        .as_ref()
                        .unwrap()
                        .has_pending_context(|p| p.tid == Some(session.tid()))
                {
                    return Err(Error::NeedsDrain);
                }
                s.transmit_ba[usize::from(session.tid())] = None;
                Ok(())
            }
            action => {
                s.ba_actions.try_reserve(1).map_err(|_| Error::NoMemory)?;
                match &action {
                    Action::Prepare { session, .. } => {
                        let index = usize::from(session.tid());
                        if s.transmit_ba[index].is_some() {
                            return Err(Error::Busy);
                        }
                        s.transmit_ba[index] = Some(Transmit {
                            _resource: s.controller.state().resource.clone(),
                            session: session.clone(),
                            blocked: true,
                            agreement: None,
                        });
                    }
                    Action::Program { session, .. } => {
                        let native = s.transmit_ba[usize::from(session.tid())]
                            .as_mut()
                            .ok_or(Error::WrongPhase)?;
                        if !Arc::ptr_eq(&native.session, session) {
                            return Err(Error::WrongPhase);
                        }
                        native.blocked = true;
                    }
                    _ => {}
                }
                s.ba_actions.push_back(BaAction::Tx(action));
                Ok(())
            }
        }
    }

    fn tx_ba_pending(s: &Owned<I, Q, C>, session: &Arc<Session>) -> bool {
        s.controller
            .state()
            .data_tx
            .as_ref()
            .unwrap()
            .has_pending_context(|p| {
                p.tid == Some(session.tid())
                    || p.tx_ba
                        .as_ref()
                        .is_some_and(|old| Arc::ptr_eq(old, session))
            })
    }

    /// The front action is still privately queued: successful publication
    /// removes it immediately, and uncertain publication quarantines Client.
    /// Canonical cancellation alone never proves this native fact or idle TX.
    pub(super) fn reconcile_tx_ba(s: &mut Owned<I, Q, C>, now: u64) -> Result<bool, Error> {
        let Some(BaAction::Tx(action)) = s.ba_actions.front() else {
            return Ok(false);
        };
        if s.station
            .validate_tx_block_ack_cancellation(action)
            .is_err()
        {
            return Ok(false);
        }
        let (ticket, session) = match action {
            Action::Prepare { ticket, session }
            | Action::Transmit {
                ticket, session, ..
            }
            | Action::Program {
                ticket, session, ..
            } => (*ticket, session.clone()),
            _ => return Err(Error::WrongPhase),
        };
        let native = s.transmit_ba[usize::from(session.tid())]
            .as_ref()
            .ok_or(Error::WrongPhase)?;
        if !Arc::ptr_eq(&native.session, &session) || !native.blocked {
            return Err(Error::WrongPhase);
        }
        if Self::tx_ba_pending(s, &session) {
            return Err(Error::NeedsDrain);
        }
        // SAFETY: the exact canceled action remains unpublished at the private
        // front; real descriptor consumption, TX-free and unmap have retired
        // this TID's preceding packets, and the same native owner stays held.
        let next = unsafe {
            match action {
                Action::Prepare { .. } => s.station.complete_tx_block_ack_prepare(
                    ticket,
                    Completion::RejectedAndIdle,
                    None,
                    now,
                ),
                Action::Transmit { .. } => s.station.complete_tx_block_ack_transmit(
                    ticket,
                    Completion::RejectedAndIdle,
                    now,
                ),
                Action::Program { .. } => s
                    .station
                    .complete_tx_block_ack_program(ticket, Completion::RejectedAndIdle),
                _ => unreachable!(),
            }
        }
        .map_err(Error::BlockAck)?;
        // Keep the successor in the already allocated queue slot. In particular
        // an allocation failure must not lose a required disable/resume owner.
        *s.ba_actions.front_mut().unwrap() = BaAction::Tx(next);
        if let Some(BaAction::Tx(Action::ResumeLegacy { session })) = s.ba_actions.front() {
            let session = session.clone();
            Self::queue_tx_ba(s, Action::ResumeLegacy { session }, now)?;
            s.ba_actions.pop_front();
        }
        Ok(true)
    }

    pub(super) unsafe fn progress_tx_ba<
        H: wifi::regulatory::HardwarePolicy,
        O: wifi::regulatory::OsPolicy,
    >(
        s: &mut Owned<I, Q, C>,
        authority: &mut wifi::regulatory::Owner<H, O>,
        admission: wifi::regulatory::AssociationAdmission,
        source: &dyn PageSource,
        now: u64,
    ) -> Result<(), Error> {
        let Some(BaAction::Tx(action)) = s.ba_actions.front() else {
            return Err(Error::WrongPhase);
        };
        match action {
            Action::Prepare { ticket, session } => {
                let (ticket, session) = (*ticket, session.clone());
                s.station
                    .validate_tx_block_ack_prepare(ticket, &session)
                    .map_err(Error::BlockAck)?;
                if s.controller
                    .state()
                    .data_tx
                    .as_ref()
                    .unwrap()
                    .has_pending_context(|p| p.tid == Some(session.tid()))
                {
                    return Err(Error::NeedsDrain);
                }
                // Serialized TID block plus actual descriptor/TX-free/unmap
                // retirement precede this real canonical software snapshot.
                // It is never a hardware observation or an invented zero.
                let next = s
                    .station
                    .next_qos_sequence(session.context(), session.tid())
                    .map_err(Error::Station)?;
                // SAFETY: covered by this function's own safety contract.
                let action = unsafe {
                    s.station.complete_tx_block_ack_prepare(
                        ticket,
                        Completion::Accepted,
                        Some(next),
                        now,
                    )
                }
                .map_err(Error::BlockAck)?;
                s.ba_actions.pop_front();
                Self::queue_tx_ba(s, action, now)
            }
            Action::Transmit {
                ticket,
                session,
                bytes,
            } => {
                let (ticket, session) = (*ticket, session.clone());
                s.station
                    .validate_tx_block_ack_transmit(ticket, &session, bytes)
                    .map_err(Error::BlockAck)?;
                let mut prepared = Self::prepare_submission(s, bytes, None, true, true)?;
                prepared.1.tx_ba = Some(session.clone());
                // SAFETY: covered by this function's own safety contract.
                let result = unsafe {
                    authority.publish_association(
                        admission,
                        &s.station,
                        wifi::regulatory::AssociationUse::Management,
                        |_, _| Self::publish_submission(&mut s.controller, source, bytes, prepared),
                    )
                }
                .map_err(Error::Regulatory)?;
                match result {
                    Ok(_) => {
                        s.ba_actions.pop_front();
                        // SAFETY: covered by this function's own safety contract.
                        let action = unsafe {
                            s.station.complete_tx_block_ack_transmit(
                                ticket,
                                Completion::Accepted,
                                now,
                            )
                        }
                        .map_err(Error::BlockAck)?;
                        Self::queue_tx_ba(s, action, now)
                    }
                    Err(error) => {
                        if s.controller.state().data_tx.as_ref().unwrap().is_poisoned() {
                            // SAFETY: covered by this function's own safety contract.
                            let _ = unsafe {
                                s.station.complete_tx_block_ack_transmit(
                                    ticket,
                                    Completion::Uncertain,
                                    now,
                                )
                            };
                            s.phase = Phase::Quarantined;
                        }
                        Err(error)
                    }
                }
            }
            Action::Program {
                ticket,
                session,
                agreement,
            } => {
                if agreement.is_none() {
                    return Self::stop_tx_ba_action(s, now);
                }
                let (ticket, session, agreement) = (*ticket, session.clone(), *agreement);
                s.station
                    .validate_tx_block_ack_program(ticket, &session, agreement)
                    .map_err(Error::BlockAck)?;
                let agreement = agreement.unwrap();
                // Generic TX_OPERATIONAL's source params.ssn is0; the request
                // software snapshot is a separate management input, not this.
                let body = wire::modern::ba_request(
                    s.profile.ok_or(Error::WrongProfile)?,
                    session.tid(),
                    0,
                    agreement.window(),
                    agreement.amsdu_in_ampdu(),
                    true,
                    true,
                )
                .map_err(Error::Codec)?;
                let mut started = false;
                // SAFETY: covered by this function's own safety contract.
                let result = unsafe {
                    authority.publish_association(
                        admission,
                        &s.station,
                        wifi::regulatory::AssociationUse::Management,
                        |_, _| {
                            started = true;
                            Self::command_parts(
                                &mut s.controller,
                                &mut s.replies,
                                Command::StationRecord,
                                &body,
                            )
                        },
                    )
                }
                .map_err(Error::Regulatory)?;
                match result {
                    Ok(()) => {
                        s.ba_actions.pop_front();
                        // SAFETY: covered by this function's own safety contract.
                        let action = unsafe {
                            s.station
                                .complete_tx_block_ack_program(ticket, Completion::Accepted)
                        }
                        .map_err(Error::BlockAck)?;
                        Self::queue_tx_ba(s, action, now)
                    }
                    Err(error) => {
                        if started {
                            // SAFETY: covered by this function's own safety contract.
                            let _ = unsafe {
                                s.station
                                    .complete_tx_block_ack_program(ticket, Completion::Uncertain)
                            };
                            s.phase = Phase::Quarantined;
                        }
                        Err(error)
                    }
                }
            }
            _ => Err(Error::WrongPhase),
        }
    }

    pub(super) fn stop_tx_ba_action(s: &mut Owned<I, Q, C>, now: u64) -> Result<(), Error> {
        let Some(BaAction::Tx(Action::Program {
            ticket,
            session,
            agreement: None,
        })) = s.ba_actions.front()
        else {
            return Err(Error::WrongPhase);
        };
        let (ticket, session) = (*ticket, session.clone());
        s.station
            .validate_tx_block_ack_program(ticket, &session, None)
            .map_err(Error::BlockAck)?;
        if Self::tx_ba_pending(s, &session) {
            return Err(Error::NeedsDrain);
        }
        let body = wire::modern::ba_request(
            s.profile.ok_or(Error::WrongProfile)?,
            session.tid(),
            0,
            1,
            false,
            false,
            true,
        )
        .map_err(Error::Codec)?;
        if let Err(error) = Self::command(s, Command::StationRecord, &body) {
            // SAFETY: an uncertain publication retains every owner, as the contract requires.
            let _ = unsafe {
                s.station
                    .complete_tx_block_ack_program(ticket, Completion::Uncertain)
            };
            s.phase = Phase::Quarantined;
            return Err(error);
        }
        s.ba_actions.pop_front();
        // SAFETY: firmware acknowledged the disable and no TX for this TID is pending.
        let action = unsafe {
            s.station
                .complete_tx_block_ack_program(ticket, Completion::Accepted)
        }
        .map_err(Error::BlockAck)?;
        Self::queue_tx_ba(s, action, now)?;
        s.phase = Phase::Associated;
        Ok(())
    }
}
