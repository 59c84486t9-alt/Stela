// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Actual scan/ROC command ownership, source grants and explicit native drain.
use super::*;

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    pub fn begin_scan(
        &mut self,
        request: scan::Request,
        now: u64,
        budget: u64,
        policy: &mut impl scan::Policy,
    ) -> Result<scan::Ticket, Error> {
        let s = self.state_mut();
        if s.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        let actual_policy = s
            .controller
            .state()
            .policy
            .as_ref()
            .ok_or(Error::WrongProfile)?;
        if request.channels().iter().any(|ch| {
            ch.number > 255 || !actual_policy.initial_channel_present(ch.band, ch.number as u8)
        }) {
            return Err(Error::WrongProfile);
        }
        s.transport_facts
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        let ticket = s
            .scanner
            .begin(request, now, budget, policy)
            .map_err(Error::Scan)?;
        s.scan_ticket = Some(ticket);
        s.scan_sequence = (s.scan_sequence + 1) & 127;
        let request = wire::scan(
            s.interface.registered_context().unwrap(),
            s.scan_sequence,
            s.scanner.request().unwrap(),
        )
        .map_err(Error::Codec)?;
        s.scanner
            .validate_submission(ticket, now, policy)
            .map_err(Error::Scan)?;
        s.scanner.submitted(ticket).map_err(Error::Scan)?;
        s.phase = Phase::Quarantined;
        let fact = s
            .controller
            .state_mut()
            .mailbox
            .as_mut()
            .unwrap()
            .initial(&request)
            .map_err(Error::Transport)?;
        s.transport_facts.push(fact);
        s.phase = Phase::Scanning;
        Ok(ticket)
    }
    /// The source cancel's generic completion is retained, never treated as
    /// abort completion/drain. A terminal actual event or independent reset is
    /// still required before scan resource retirement.
    pub fn cancel_scan(&mut self) -> Result<(), Error> {
        let s = self.state_mut();
        let t = s.scan_ticket.ok_or(Error::WrongPhase)?;
        s.scanner.cancel(t).map_err(Error::Scan)?;
        let request = wire::cancel_scan(s.interface.registered_context().unwrap(), s.scan_sequence);
        s.transport_facts
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        s.phase = Phase::Quarantined;
        let f = s
            .controller
            .state_mut()
            .mailbox
            .as_mut()
            .unwrap()
            .initial(&request)
            .map_err(Error::Transport)?;
        s.transport_facts.push(f);
        s.phase = Phase::Scanning;
        Ok(())
    }
    /// # Safety
    /// This completed scan's actual radio/channel restoration, DMA/IRQ/work and
    /// all delayed scan notifications are drained. The source basic event has
    /// no host generation cookie; an event alone cannot qualify reuse.
    pub unsafe fn retire_scan_after_drain(&mut self) -> Result<scan::Outcome, Error> {
        let s = self.state_mut();
        if s.phase != Phase::ScanCompleted {
            return Err(Error::WrongPhase);
        }
        if !s.pending_rx.is_empty()
            || !s.controller.state().data_assembly.is_idle()
            || !s
                .controller
                .state()
                .mailbox
                .as_ref()
                .unwrap()
                .receive_idle()
        {
            return Err(Error::NeedsDrain);
        }
        let outcome = s
            .scanner
            .retire(s.scan_ticket.unwrap(), scan::Retirement::Confirmed)
            .map_err(Error::Scan)?
            .ok_or(Error::NeedsDrain)?;
        s.scan_ticket = None;
        s.phase = Phase::Idle;
        Ok(outcome)
    }
    pub(super) fn abort_channel(s: &mut Owned<I, Q, C>) -> Result<(), Error> {
        if s.roc_deadline.is_none() {
            return Ok(());
        }
        let req = s
            .profile
            .ok_or(Error::WrongProfile)?
            .abort_roc(s.roc_token)
            .map_err(Error::Codec)?;
        s.transport_facts
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        let old = s.phase;
        s.phase = Phase::Quarantined;
        let fact = s
            .controller
            .state_mut()
            .mailbox
            .as_mut()
            .unwrap()
            .initial(&req)
            .map_err(Error::Transport)?;
        s.transport_facts.push(fact);
        s.roc_deadline = None;
        s.phase = old;
        Ok(())
    }
    pub(super) fn reserve_channel(s: &mut Owned<I, Q, C>) -> Result<(), Error> {
        Self::abort_channel(s)?;
        // Source's 8-bit ROC token has no firmware epoch. Never silently reuse
        // one in this owner while an old notification could still exist.
        let token = s.roc_token.checked_add(1).ok_or(Error::NeedsDrain)?;
        let p = s.profile.ok_or(Error::WrongProfile)?;
        let req = p.roc(token, 1000).map_err(Error::Codec)?;
        s.transport_facts
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        s.asynchronous
            .try_reserve(64)
            .map_err(|_| Error::NoMemory)?;
        s.phase = Phase::Quarantined;
        s.roc_token = token;
        let fact = s
            .controller
            .state_mut()
            .mailbox
            .as_mut()
            .unwrap()
            .initial(&req)
            .map_err(Error::Transport)?;
        s.transport_facts.push(fact);
        let clock = s.controller.state().control.clock;
        let deadline = clock.deadline(4_000_000);
        loop {
            let frames = s
                .controller
                .state_mut()
                .mailbox
                .as_mut()
                .unwrap()
                .poll_events()
                .map_err(|e| Error::Bootstrap(super::super::Error::Mailbox(e)))?;
            let mut match_grant = None;
            for f in frames {
                s.asynchronous.try_reserve(1).map_err(|_| Error::NoMemory)?;
                s.asynchronous.push(f);
                let retained = s.asynchronous.last().unwrap();
                if !retained.drop
                    && let Ok(e) =
                        crate::net::wifi::mediatek::mcu::Event::parse(Chip::Mt7925, &retained.bytes)
                    && e.is_unsolicited()
                    && e.event_id == 0x27
                {
                    for g in wire::roc_grants(e.payload).map_err(Error::Codec)? {
                        if g.bss == p.interface.bss_index
                            && g.token == token
                            && g.channel == p.channel.number as u8
                            && g.center == g.channel
                            && g.center2 == 0
                            && g.band
                                == if p.channel.band == wifi::Band::Ghz2 {
                                    1
                                } else {
                                    2
                                }
                            && g.width == 0
                            && g.sco == 0
                            && g.request_type == 0
                            && g.hardware_band <= 3
                            && g.duration_ms > 0
                        {
                            match_grant = Some(g);
                        }
                    }
                }
            }
            if let Some(g) = match_grant {
                let mut actual = p;
                actual.interface.band_index = g.hardware_band;
                s.profile = Some(actual);
                s.roc_deadline = Some(
                    clock
                        .now_us()
                        .checked_add(u64::from(g.duration_ms) * 1000)
                        .ok_or(Error::NeedsDrain)?,
                );
                s.phase = Phase::Joining;
                return Ok(());
            }
            if deadline.passed() {
                // Source set_roc's timeout sends the actual matching abort.
                // Generic abort completion still cannot retire uncertain radio
                // users or establish a new peer/notification epoch.
                let abort = p.abort_roc(token).map_err(Error::Codec)?;
                s.transport_facts
                    .try_reserve(1)
                    .map_err(|_| Error::NoMemory)?;
                let fact = s
                    .controller
                    .state_mut()
                    .mailbox
                    .as_mut()
                    .unwrap()
                    .initial(&abort)
                    .map_err(Error::Transport)?;
                s.transport_facts.push(fact);
                return Err(Error::GrantTimeout);
            }
            core::hint::spin_loop();
        }
    }
}
