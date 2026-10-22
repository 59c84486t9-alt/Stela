// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
//! Native source TX_START/TX_OPERATIONAL/TX_STOP owners. Canonical Station owns
//! the management exchange/counters; firmware owns actual air sequence/PN.
use super::*;
use station::ba::tx::{Action, Agreement, Session};

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
        _now: u64,
    ) -> Result<(), Error> {
        match action {
            Action::None => Ok(()),
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
                        let action = unsafe {
                            s.station
                                .complete_tx_block_ack_program(ticket, Completion::Accepted)
                        }
                        .map_err(Error::BlockAck)?;
                        Self::queue_tx_ba(s, action, now)
                    }
                    Err(error) => {
                        if started {
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
        if s.controller
            .state()
            .data_tx
            .as_ref()
            .unwrap()
            .has_pending_context(|p| p.tid == Some(session.tid()))
        {
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
            let _ = unsafe {
                s.station
                    .complete_tx_block_ack_program(ticket, Completion::Uncertain)
            };
            return Err(error);
        }
        s.ba_actions.pop_front();
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
